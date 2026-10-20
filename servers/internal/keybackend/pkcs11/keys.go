package pkcs11

import (
	"crypto/elliptic"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"strings"

	"github.com/globaltrusts/server-card/internal/keybackend"
)

// 摘要算法 OID。
var (
	oidMD5      = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5}
	oidSHA1     = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	oidSHA3_256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 8}
	oidSHA3_384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 9}
	oidSHA3_512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 10}
)

// CKM_SHA* 系列机制（用于 PSS 参数中的哈希标识）。
const (
	ckmSHA1     ckULong = 0x00000220
	ckmSHA256   ckULong = 0x00000250
	ckmSHA384   ckULong = 0x00000251
	ckmSHA512   ckULong = 0x00000252
	ckmSHA3_256 ckULong = 0x000002B0
	ckmSHA3_384 ckULong = 0x000002C0
	ckmSHA3_512 ckULong = 0x000002D0
)

// normalKeyType 把上层 keyType 归一为 rsa/ec/ed25519。
func normalKeyType(keyType string) string {
	kt := strings.ToLower(strings.TrimSpace(keyType))
	switch {
	case strings.HasPrefix(kt, "rsa"):
		return "rsa"
	case strings.HasPrefix(kt, "ec"), strings.HasPrefix(kt, "p25"), strings.HasPrefix(kt, "p38"), strings.HasPrefix(kt, "p52"):
		return "ec"
	case kt == "ed25519":
		return "ed25519"
	default:
		return kt
	}
}

// rsaBits 解析 RSA 密钥长度。
func rsaBits(keyType string) (int, error) {
	switch strings.ToLower(strings.TrimSpace(keyType)) {
	case "rsa1024":
		return 1024, nil
	case "rsa2048", "":
		return 2048, nil
	case "rsa3072":
		return 3072, nil
	case "rsa4096":
		return 4096, nil
	case "rsa8192":
		return 8192, nil
	default:
		return 0, fmt.Errorf("不支持的 RSA 密钥长度: %s", keyType)
	}
}

// curveByName 解析曲线名。
func curveByName(keyType string) (elliptic.Curve, error) {
	switch strings.ToLower(strings.TrimSpace(keyType)) {
	case "ec256", "p256":
		return elliptic.P256(), nil
	case "ec384", "p384":
		return elliptic.P384(), nil
	case "ec521", "p521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("不支持的 EC 曲线: %s", keyType)
	}
}

// curveOID 返回曲线的 DER 编码 OID（CKA_EC_PARAMS 要求）。
func curveOID(keyType string) ([]byte, error) {
	curve, err := curveByName(keyType)
	if err != nil {
		return nil, err
	}
	return curveOIDByCurve(curve)
}

func curveOIDByCurve(curve elliptic.Curve) ([]byte, error) {
	var oid asn1.ObjectIdentifier
	switch curve {
	case elliptic.P256():
		oid = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	case elliptic.P384():
		oid = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	case elliptic.P521():
		oid = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
	default:
		return nil, fmt.Errorf("不支持的椭圆曲线: %s", curve.Params().Name)
	}
	return asn1.Marshal(oid)
}

// keybackendParseKey 解析 PKCS#8/PKCS#1/SEC1 私钥。
func keybackendParseKey(der []byte) (any, error) {
	return keybackend.ParsePrivateKey(der)
}

// keybackendPublicKey 提取公钥。
func keybackendPublicKey(priv any) (any, error) {
	return keybackend.PublicKeyOf(priv)
}

// signRequest 是一次待执行的签名请求。
type signRequest struct {
	mech  *mechBuffer
	input []byte
}

// buildSignRequest 把上层的 mechanism 映射为 Cryptoki 机制与输入数据。
//
// 约定：
//   - RSA PKCS#1 v1.5：本地计算摘要并构造 DigestInfo，使用 CKM_RSA_PKCS（兼容性最好）；
//   - RSA-PSS：本地计算摘要，使用 CKM_RSA_PKCS_PSS（盐长度=摘要长度）；
//   - ECDSA：本地计算摘要，使用 CKM_ECDSA（返回 r||s，与软件实现输出一致）。
func buildSignRequest(l layout, mechanism string, keyType string, data []byte) (*signRequest, error) {
	m := strings.ToUpper(strings.TrimSpace(mechanism))
	if m == "" {
		m = "SHA256_RSA_PKCS"
	}
	kt := normalKeyType(keyType)

	if strings.HasPrefix(m, "ECDSA") {
		if kt != "ec" {
			return nil, fmt.Errorf("机制 %s 只能用于 EC 密钥", mechanism)
		}
		input := data
		if m != "ECDSA" {
			info, _, err := keybackend.MechanismDigest(m)
			if err != nil {
				return nil, err
			}
			input = info.Digest(data)
		}
		return &signRequest{mech: newMechBuffer(l, ckmECDSA, nil), input: input}, nil
	}

	if kt != "rsa" {
		return nil, fmt.Errorf("机制 %s 只能用于 RSA 密钥", mechanism)
	}

	if strings.HasSuffix(m, "_PSS") {
		info, _, err := keybackend.MechanismDigest(m)
		if err != nil {
			return nil, err
		}
		hashMech, mgf, ok := pssHashParams(info.Name)
		if !ok {
			return nil, fmt.Errorf("令牌暂不支持 %s（PKCS#11 未定义对应哈希标识）", mechanism)
		}
		params := l.pssParams(hashMech, mgf, ckULong(info.DigestLen))
		return &signRequest{
			mech:  newMechBuffer(l, ckmRSAPKCSPSS, params),
			input: info.Digest(data),
		}, nil
	}

	info, _, err := keybackend.MechanismDigest(m)
	if err != nil {
		return nil, err
	}
	digestInfo, err := digestInfoDER(info.Name, info.Digest(data))
	if err != nil {
		return nil, err
	}
	return &signRequest{mech: newMechBuffer(l, ckmRSAPKCS, nil), input: digestInfo}, nil
}

// pssHashParams 返回 PSS 参数中的哈希机制与 MGF 标识。
func pssHashParams(name string) (ckULong, ckULong, bool) {
	switch strings.ToUpper(name) {
	case "SHA1":
		return ckmSHA1, ckgMGF1SHA1, true
	case "SHA256":
		return ckmSHA256, ckgMGF1SHA256, true
	case "SHA384":
		return ckmSHA384, ckgMGF1SHA384, true
	case "SHA512":
		return ckmSHA512, ckgMGF1SHA512, true
	case "SHA3_256":
		return ckmSHA3_256, ckgMGF1SHA256, true
	case "SHA3_384":
		return ckmSHA3_384, ckgMGF1SHA384, true
	case "SHA3_512":
		return ckmSHA3_512, ckgMGF1SHA512, true
	default:
		return 0, 0, false
	}
}

// oidForDigest 返回摘要算法 OID。
func oidForDigest(name string) (asn1.ObjectIdentifier, error) {
	switch strings.ToUpper(name) {
	case "MD5":
		return oidMD5, nil
	case "SHA1":
		return oidSHA1, nil
	case "SHA256":
		return oidSHA256, nil
	case "SHA384":
		return oidSHA384, nil
	case "SHA512":
		return oidSHA512, nil
	case "SHA3_256":
		return oidSHA3_256, nil
	case "SHA3_384":
		return oidSHA3_384, nil
	case "SHA3_512":
		return oidSHA3_512, nil
	default:
		return nil, fmt.Errorf("未知摘要算法: %s", name)
	}
}

// digestInfoDER 按 RFC 8017 构造 DigestInfo（CKM_RSA_PKCS 的输入）。
func digestInfoDER(digestName string, digest []byte) ([]byte, error) {
	oid, err := oidForDigest(digestName)
	if err != nil {
		return nil, err
	}
	type digestInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		Digest    []byte
	}
	return asn1.Marshal(digestInfo{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: oid, Parameters: asn1.NullRawValue},
		Digest:    digest,
	})
}

// decryptRequest 是一次待执行的解密请求。
type decryptRequest struct {
	mech *mechBuffer
}

// buildDecryptMechanism 把 mechanism 映射为解密机制。
func buildDecryptMechanism(l layout, mechanism string) (*decryptRequest, error) {
	m := strings.ToUpper(strings.TrimSpace(mechanism))
	switch m {
	case "", "RSA_PKCS", "RSA_PKCS1":
		return &decryptRequest{mech: newMechBuffer(l, ckmRSAPKCS, nil)}, nil
	case "RSA_OAEP", "RSA_OAEP_SHA256":
		params := l.oaepParams(ckmSHA256, ckgMGF1SHA256, ckzDataSpecified)
		return &decryptRequest{mech: newMechBuffer(l, ckmRSAPKCSOAEP, params)}, nil
	default:
		return nil, fmt.Errorf("不支持的解密算法: %s", mechanism)
	}
}
