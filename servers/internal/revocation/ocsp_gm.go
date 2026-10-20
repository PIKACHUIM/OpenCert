// Package revocation - SM2 CA 的 OCSP 响应编码。
//
// golang.org/x/crypto/ocsp 的 CreateResponse 在推导签名算法时只认识
// RSA/ECDSA/Ed25519（见其内部 signingParamsForPublicKey），遇到 SM2 公钥
// （底层也是 *ecdsa.PublicKey，但曲线是 sm2.P256()）会按 ECDSA-SHA256 处理，
// 产出的签名算法 OID 错误、摘要也没有按 SM3(Z‖M) 计算，无法被标准国密
// 客户端验证。因此 SM2 CA 的 OCSP 响应需要按 RFC 6960 自行编码：
//   - CertID 的摘要算法使用 SM3（OID 1.2.156.10197.1.401）；
//   - 整个响应的签名算法使用 SM2WithSM3（OID 1.2.156.10197.1.501）；
//   - 签名通过 crypto.Signer.Sign(rand, rawTBS, sm2.DefaultSM2SignerOpts)
//     完成，由 gmsm 内部计算 SM3(Z‖TBS) 后签名，与证书/CRL 签名路径一致。
//
// 下面复刻的 ASN.1 结构与 golang.org/x/crypto/ocsp 内部私有类型字段
// 一一对应（RFC 6960 Appendix B.2），保证产出的 DER 除签名算法外，
// 结构上与标准 OCSP 响应完全一致。
package revocation

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
	"golang.org/x/crypto/ocsp"
)

// oidSM3 是 SM3 摘要算法的 OID（供 OCSP CertID.HashAlgorithm 使用）。
var oidSM3 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 401}

// oidSM2WithSM3Resp 是 SM2WithSM3 签名算法 OID。
var oidSM2WithSM3Resp = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 501}

// idPKIXOCSPBasicGM 是 RFC 6960 定义的 OCSP 基础响应类型 OID（1.3.6.1.5.5.7.48.1.1）。
var idPKIXOCSPBasicGM = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}

// ---- RFC 6960 Appendix B.2 ASN.1 结构（与 x/crypto/ocsp 内部私有类型字段对应）----

type gmCertID struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	NameHash      []byte
	IssuerKeyHash []byte
	SerialNumber  *big.Int
}

type gmRevokedInfo struct {
	RevocationTime time.Time       `asn1:"generalized"`
	Reason         asn1.Enumerated `asn1:"explicit,tag:0,optional"`
}

type gmSingleResponse struct {
	CertID           gmCertID
	Good             asn1.Flag        `asn1:"tag:0,optional"`
	Revoked          gmRevokedInfo    `asn1:"tag:1,optional"`
	Unknown          asn1.Flag        `asn1:"tag:2,optional"`
	ThisUpdate       time.Time        `asn1:"generalized"`
	NextUpdate       time.Time        `asn1:"generalized,explicit,tag:0,optional"`
	SingleExtensions []pkix.Extension `asn1:"explicit,tag:1,optional"`
}

type gmResponseData struct {
	Raw            asn1.RawContent
	Version        int `asn1:"optional,default:0,explicit,tag:0"`
	RawResponderID asn1.RawValue
	ProducedAt     time.Time `asn1:"generalized"`
	Responses      []gmSingleResponse
}

type gmBasicResponse struct {
	TBSResponseData    gmResponseData
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
	Certificates       []asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

type gmResponseBytes struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}

type gmResponseASN1 struct {
	Status   asn1.Enumerated
	Response gmResponseBytes `asn1:"explicit,tag:0,optional"`
}

// CreateOCSPResponseSM2 为 SM2 CA 生成已签名的 OCSP 响应 DER。
//
// issuer：被查询证书的颁发 CA；responderCert：实际签名该响应的证书
// （通常与 issuer 相同，即 CA 自身直接签 OCSP，也支持委托响应证书）；
// priv 必须是 SM2 私钥的 crypto.Signer（直接是 *sm2.PrivateKey，或任意
// 透传 opts 的包装器——务必不要替换调用时传入的 SignerOpts，否则签名不符合
// SM2WithSM3 规范，见 ca 包 sm2Signer 的说明）。
func CreateOCSPResponseSM2(issuer, responderCert *x509.Certificate, template ocsp.Response, priv crypto.Signer) ([]byte, error) {
	// issuerNameHash / issuerKeyHash 按 SM3 计算（与标准 OCSP 的 SHA1 对应，
	// 仅摘要算法不同，结构完全一致）。
	var publicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &publicKeyInfo); err != nil {
		return nil, fmt.Errorf("解析颁发者公钥信息失败: %w", err)
	}

	issuerKeyHash := sm3Sum(publicKeyInfo.PublicKey.RightAlign())
	issuerNameHash := sm3Sum(issuer.RawSubject)

	innerResponse := gmSingleResponse{
		CertID: gmCertID{
			HashAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm:  oidSM3,
				Parameters: asn1.RawValue{Tag: 5 /* ASN.1 NULL */},
			},
			NameHash:      issuerNameHash,
			IssuerKeyHash: issuerKeyHash,
			SerialNumber:  template.SerialNumber,
		},
		ThisUpdate:       template.ThisUpdate.UTC(),
		SingleExtensions: template.ExtraExtensions,
	}
	// NextUpdate 是可选字段：零值会被编码成公元 1 年，部分校验器会直接判为非法响应
	if !template.NextUpdate.IsZero() {
		innerResponse.NextUpdate = template.NextUpdate.UTC()
	}

	switch template.Status {
	case ocsp.Good:
		innerResponse.Good = true
	case ocsp.Unknown:
		innerResponse.Unknown = true
	case ocsp.Revoked:
		innerResponse.Revoked = gmRevokedInfo{
			RevocationTime: template.RevokedAt.UTC(),
			Reason:         asn1.Enumerated(template.RevocationReason),
		}
	}

	rawResponderID := asn1.RawValue{
		Class:      2, // context-specific
		Tag:        1, // Name（显式标签）
		IsCompound: true,
		Bytes:      responderCert.RawSubject,
	}
	tbsResponseData := gmResponseData{
		Version:        0,
		RawResponderID: rawResponderID,
		ProducedAt:     time.Now().Truncate(time.Minute).UTC(),
		Responses:      []gmSingleResponse{innerResponse},
	}

	tbsResponseDataDER, err := asn1.Marshal(tbsResponseData)
	if err != nil {
		return nil, fmt.Errorf("编码 OCSP TBS 响应数据失败: %w", err)
	}

	// 与证书/CRL 签名路径一致：直接把原始 TBS 字节 + 默认 SM2 签名选项交给
	// Signer，由 gmsm 内部完成 SM3(Z‖TBS) 预处理与签名（见 ca 包 sm2Signer 注释）。
	signature, err := priv.Sign(rand.Reader, tbsResponseDataDER, sm2.DefaultSM2SignerOpts)
	if err != nil {
		return nil, fmt.Errorf("SM2 签名 OCSP 响应失败: %w", err)
	}

	response := gmBasicResponse{
		TBSResponseData:    tbsResponseData,
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSM2WithSM3Resp},
		Signature: asn1.BitString{
			Bytes:     signature,
			BitLength: 8 * len(signature),
		},
	}
	if template.Certificate != nil {
		response.Certificates = []asn1.RawValue{{FullBytes: template.Certificate.Raw}}
	}
	responseDER, err := asn1.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("编码 OCSP 基础响应失败: %w", err)
	}

	return asn1.Marshal(gmResponseASN1{
		Status: asn1.Enumerated(ocsp.Success),
		Response: gmResponseBytes{
			ResponseType: idPKIXOCSPBasicGM,
			Response:     responseDER,
		},
	})
}

// sm3Sum 计算 SM3 摘要。
func sm3Sum(data []byte) []byte {
	h := sm3.New()
	h.Write(data) //nolint:errcheck // hash.Hash.Write 不会返回错误
	return h.Sum(nil)
}

// isSM2PubKey 判断给定证书公钥是否为 SM2 公钥（曲线固定为 sm2.P256()）。
// revocation 包不依赖 ca 的内部符号，这里独立实现一份判定逻辑：
// gmsm 的 SM2 公钥类型就是标准库的 *ecdsa.PublicKey，仅曲线不同。
func isSM2PubKey(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	k, ok := cert.PublicKey.(*ecdsa.PublicKey)
	return ok && k.Curve == sm2.P256()
}
