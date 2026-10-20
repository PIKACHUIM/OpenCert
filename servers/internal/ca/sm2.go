// Package ca - SM2 国密算法支持（基于 github.com/emmansun/gmsm，无需 build tag）。
//
// 覆盖范围：密钥生成、公私钥提取、SM2WithSM3 证书/CRL 的签发与解析、
// 私钥的 PKCS#8 编解码。所有调用方都应通过 x509gm.go 提供的分派函数，
// 由分派函数在 SM2 与标准算法之间选择实现。
package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"io"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

// oidSM2WithSM3 是 GM/T 0006 定义的 SM2-with-SM3 签名算法 OID（1.2.156.10197.1.501）。
var oidSM2WithSM3 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 501}

// IsSM2Available 返回当前构建是否已启用 SM2 国密算法。
// 引入 gmsm 后恒定可用，保留该函数供元数据接口与前端展示使用。
func IsSM2Available() bool {
	return true
}

// generateSM2Key 生成 SM2 P256 密钥对。
func generateSM2Key() (crypto.PrivateKey, error) {
	return sm2.GenerateKey(rand.Reader)
}

// isSM2Key 判断给定私钥是否为 SM2 密钥。
// sm2.PrivateKey 内嵌 ecdsa.PrivateKey，曲线固定为 sm2.P256()。
func isSM2Key(v interface{}) bool {
	switch k := v.(type) {
	case *sm2.PrivateKey:
		return true
	case *ecdsa.PrivateKey:
		return k.Curve == sm2.P256()
	default:
		return false
	}
}

// isSM2PublicKey 判断给定公钥是否为 SM2 公钥。
// gmsm 的公钥类型就是标准库的 *ecdsa.PublicKey，曲线固定为 sm2.P256()。
func isSM2PublicKey(pub crypto.PublicKey) bool {
	k, ok := pub.(*ecdsa.PublicKey)
	return ok && k.Curve == sm2.P256()
}

// sm2PublicKeyOf 从 SM2 私钥提取公钥。
func sm2PublicKeyOf(key *sm2.PrivateKey) crypto.PublicKey {
	return &key.PublicKey
}

// sm2Signer 包装 SM2 私钥，透传 crypto.Signer 调用。
//
// 关键约定（务必保持透传，不能替换 opts）：
// gmsm 的 smx509.CreateCertificate/CreateRevocationList 对 SM2WithSM3 签名的
// 处理方式是——不预先对 TBS 字节做哈希，而是把 *原始* TBS 字节连同
// sm2.DefaultSM2SignerOpts（ForceGMSign=true，默认用户 ID）一起传给
// crypto.Signer.Sign；由 Sign 内部按 GB/T 32918 计算 SM3(Z‖M) 再签名。
// 若此处的 Sign 方法把 opts 替换为 nil，会导致 gmsm 把"未哈希的原始 TBS"
// 当作"已经算好的摘要"直接做 SM2 原始签名运算，产生不符合标准、
// 无法被任何验证方校验通过的签名。因此这里必须原样转发 rand 与 opts，
// 让 gmsm 自行判断是否需要做 SM3 预处理。
type sm2Signer struct {
	key *sm2.PrivateKey
}

// Public 返回 SM2 公钥。
func (s *sm2Signer) Public() crypto.PublicKey {
	return &s.key.PublicKey
}

// Sign 透传给 sm2.PrivateKey.Sign，不改写 opts（见类型注释）。
func (s *sm2Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.key.Sign(rand, digest, opts)
}

// asSM2Signer 将 SM2 私钥包装为 crypto.Signer。
func asSM2Signer(key *sm2.PrivateKey) crypto.Signer {
	return &sm2Signer{key: key}
}

// marshalSM2PKCS8 / parseSM2PKCS8：SM2 私钥的 PKCS#8 编解码委托给 x509gm.go
// 中的 marshalPrivateKeyAnyImpl / parsePrivateKeyAnyImpl 统一处理，此处不再重复定义。

// isSM2Signature 判断证书是否由 SM2WithSM3 签名。
//
// Go 标准库解析 SM2 证书时，SignatureAlgorithm 会保持为
// x509.UnknownSignatureAlgorithm（0），因为标准库不认识该 OID；
// 真正可靠的判定方式是检查证书公钥是否为 SM2 曲线公钥——
// 按 GM/T 0015 要求，SM2 证书只能由 SM2 密钥签发、只能签给 SM2 公钥，
// 因此"证书公钥是 SM2"与"证书是 SM2WithSM3 签名"在本系统的使用场景下等价。
func isSM2Signature(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	return isSM2PublicKey(cert.PublicKey)
}

// sm2SignatureAlgorithmOID 返回 SM2WithSM3 的算法标识（供 OCSP 编码使用）。
func sm2SignatureAlgorithmOID() asn1.ObjectIdentifier {
	return oidSM2WithSM3
}

// toGMCertificate 将标准库证书转换为 smx509 证书视图。
//
// smx509.Certificate 定义为 `type Certificate x509.Certificate`（完全相同的
// 底层结构），因此可以直接做类型转换，不需要逐字段拷贝。
func toGMCertificate(c *x509.Certificate) *smx509.Certificate {
	if c == nil {
		return nil
	}
	return (*smx509.Certificate)(c)
}

// fromGMCertificate 将 smx509 证书转换回标准库证书视图（同样是直接类型转换）。
func fromGMCertificate(c *smx509.Certificate) *x509.Certificate {
	if c == nil {
		return nil
	}
	return (*x509.Certificate)(c)
}
