package keybackend

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/md5" //nolint:gosec // MD5 仅为兼容遗留签名机制保留
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // SHA1 仅为兼容遗留签名机制保留
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/smx509"
	"golang.org/x/crypto/sha3"
)

// GenerateKeyMaterial 生成密钥对，返回私钥与 SubjectPublicKeyInfo DER。
//
// 支持的 keyType：
//   - RSA：rsa1024, rsa2048, rsa3072, rsa4096, rsa8192
//   - ECDSA：ec256/p256, ec384/p384, ec521/p521
//   - EdDSA：ed25519（主要用于签名，不用于加密）
func GenerateKeyMaterial(keyType string) (crypto.PrivateKey, []byte, error) {
	var privKey crypto.PrivateKey
	var err error

	switch strings.ToLower(strings.TrimSpace(keyType)) {
	case "rsa1024":
		privKey, err = rsa.GenerateKey(rand.Reader, 1024)
	case "rsa2048", "":
		privKey, err = rsa.GenerateKey(rand.Reader, 2048)
	case "rsa3072":
		privKey, err = rsa.GenerateKey(rand.Reader, 3072)
	case "rsa4096":
		privKey, err = rsa.GenerateKey(rand.Reader, 4096)
	case "rsa8192":
		privKey, err = rsa.GenerateKey(rand.Reader, 8192)
	case "ec256", "p256":
		privKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ec384", "p384":
		privKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "ec521", "p521":
		privKey, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case "ed25519":
		_, privKey, err = ed25519.GenerateKey(rand.Reader)
	case "sm2":
		privKey, err = sm2.GenerateKey(rand.Reader)
	default:
		return nil, nil, fmt.Errorf("不支持的密钥类型: %s", keyType)
	}
	if err != nil {
		return nil, nil, err
	}

	pubKey, err := PublicKeyOf(privKey)
	if err != nil {
		return nil, nil, err
	}
	pubDER, err := marshalPublicKeyAny(pubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("序列化公钥失败: %w", err)
	}
	return privKey, pubDER, nil
}

// isSM2 判断私钥/公钥是否为 SM2（曲线固定为 sm2.P256()）。
func isSM2(v interface{}) bool {
	switch k := v.(type) {
	case *sm2.PrivateKey:
		return true
	case *ecdsa.PrivateKey:
		return k.Curve == sm2.P256()
	case *ecdsa.PublicKey:
		return k.Curve == sm2.P256()
	default:
		return false
	}
}

// marshalPublicKeyAny 序列化公钥为 PKIX DER，SM2 走国密库。
func marshalPublicKeyAny(pub crypto.PublicKey) ([]byte, error) {
	if isSM2(pub) {
		return smx509.MarshalPKIXPublicKey(pub)
	}
	return x509.MarshalPKIXPublicKey(pub)
}

// PublicKeyOf 从私钥提取公钥。
func PublicKeyOf(privKey crypto.PrivateKey) (crypto.PublicKey, error) {
	switch k := privKey.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &k.PublicKey, nil
	case *sm2.PrivateKey:
		return &k.PublicKey, nil
	case ed25519.PrivateKey:
		return k.Public(), nil
	case crypto.Signer:
		return k.Public(), nil
	default:
		return nil, fmt.Errorf("不支持的私钥类型: %T", privKey)
	}
}

// KeyTypeOf 推断私钥对应的 keyType 名称。
func KeyTypeOf(privKey crypto.PrivateKey) string {
	switch k := privKey.(type) {
	case *rsa.PrivateKey:
		return fmt.Sprintf("rsa%d", k.N.BitLen())
	case *sm2.PrivateKey:
		return "sm2"
	case *ecdsa.PrivateKey:
		if k.Curve == sm2.P256() {
			return "sm2"
		}
		switch k.Curve {
		case elliptic.P256():
			return "ec256"
		case elliptic.P384():
			return "ec384"
		case elliptic.P521():
			return "ec521"
		}
		return "ec"
	case ed25519.PrivateKey:
		return "ed25519"
	default:
		return ""
	}
}

// MarshalPKCS8 把私钥统一序列化为 PKCS#8 DER（SM2 走国密库）。
func MarshalPKCS8(privKey crypto.PrivateKey) ([]byte, error) {
	if isSM2(privKey) {
		der, err := smx509.MarshalPKCS8PrivateKey(privKey)
		if err != nil {
			return nil, fmt.Errorf("序列化 SM2 私钥失败: %w", err)
		}
		return der, nil
	}
	der, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("序列化私钥失败: %w", err)
	}
	return der, nil
}

// ParsePrivateKey 解析 DER 格式私钥（PKCS#8 / PKCS#1 / SEC1 / SM2）。
func ParsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if len(der) == 0 {
		return nil, fmt.Errorf("私钥数据为空")
	}
	// smx509.ParsePKCS8PrivateKey 内部会识别 SM2 OID，其它类型回退到标准库。
	if key, err := smx509.ParsePKCS8PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("无法解析私钥格式")
}

// PKCS8PEM 把 DER 私钥统一转换为 PKCS#8 PEM。
func PKCS8PEM(der []byte) ([]byte, error) {
	if _, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
	}
	key, err := ParsePrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("解析私钥失败: %w", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("序列化私钥失败: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), nil
}

// SignWithKey 使用私钥按指定机制签名。
func SignWithKey(privKey crypto.PrivateKey, mechanism string, data []byte) ([]byte, error) {
	switch key := privKey.(type) {
	case *rsa.PrivateKey:
		return signRSA(key, mechanism, data)
	case *sm2.PrivateKey:
		return signSM2(key, mechanism, data)
	case *ecdsa.PrivateKey:
		if key.Curve == sm2.P256() {
			sm2Key := new(sm2.PrivateKey)
			if _, err := sm2Key.FromECPrivateKey(key); err != nil {
				return nil, fmt.Errorf("转换 SM2 私钥失败: %w", err)
			}
			return signSM2(sm2Key, mechanism, data)
		}
		return signECDSA(key, mechanism, data)
	case ed25519.PrivateKey:
		// Ed25519 对任意长度消息直接签名，mechanism 参数被忽略（Ed25519 内置 SHA-512）。
		return ed25519.Sign(key, data), nil
	default:
		return nil, fmt.Errorf("不支持的私钥类型: %T", privKey)
	}
}

// signSM2 对消息进行 SM2 签名。mechanism 为 "SM2_SM3" 或 "SM2" 时均按
// GB/T 32918 使用默认用户 ID 计算 SM3(Z‖M) 后签名；data 为签名原文（非摘要）。
//
// 必须显式传入 sm2.DefaultSM2SignerOpts（ForceGMSign=true）：若传 nil，
// gmsm 会把 data 当作"已经算好的摘要"直接做 SM2 原始签名运算，跳过
// SM3(Z‖M) 预处理，产出不符合 GM/T 0009（PKCS#11 国密机制 CKM_SM2 的
// 输入约定：原文，由实现计算 Z 值与 SM3）的签名。
func signSM2(key *sm2.PrivateKey, mechanism string, data []byte) ([]byte, error) {
	switch strings.ToUpper(strings.TrimSpace(mechanism)) {
	case "SM2_SM3", "SM2", "":
		return key.Sign(rand.Reader, data, sm2.DefaultSM2SignerOpts)
	default:
		return nil, fmt.Errorf("不支持的 SM2 签名算法: %s", mechanism)
	}
}

// sm3Digest 计算 SM3 摘要（供 MechanismDigest/Digest 以外的直接调用场景使用）。
func sm3Digest(data []byte) []byte {
	h := sm3.New()
	h.Write(data) //nolint:errcheck // hash.Hash.Write 不会返回错误
	return h.Sum(nil)
}

// DecryptWithKey 使用私钥解密（仅 RSA）。
func DecryptWithKey(privKey crypto.PrivateKey, mechanism string, ciphertext []byte) ([]byte, error) {
	rsaKey, ok := privKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("解密仅支持 RSA 私钥")
	}
	switch strings.ToUpper(strings.TrimSpace(mechanism)) {
	case "RSA_PKCS", "RSA_PKCS1", "":
		return rsa.DecryptPKCS1v15(rand.Reader, rsaKey, ciphertext)
	case "RSA_OAEP", "RSA_OAEP_SHA256":
		return rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaKey, ciphertext, nil)
	default:
		return nil, fmt.Errorf("不支持的解密算法: %s", mechanism)
	}
}

// DigestInfo 描述某个签名机制对应的摘要算法。
type DigestInfo struct {
	Name       string // 机制前缀，如 SHA256
	Hash       crypto.Hash
	DigestLen  int  // 摘要长度（字节）
	PSSSupport bool // 是否可作为 RSA-PSS 的哈希
}

// MechanismDigest 返回签名机制对应的摘要算法信息；第二个返回值表示是否为 PSS 机制。
func MechanismDigest(mechanism string) (DigestInfo, bool, error) {
	m := strings.ToUpper(strings.TrimSpace(mechanism))
	isPSS := strings.HasSuffix(m, "_PSS")
	base := strings.TrimSuffix(m, "_RSA_PSS")
	base = strings.TrimSuffix(base, "_RSA_PKCS")
	base = strings.TrimPrefix(base, "ECDSA_")
	if base == "ECDSA" || base == "" {
		// 裸 ECDSA：调用方传入的已是摘要
		return DigestInfo{Name: "", DigestLen: 0}, false, nil
	}
	switch base {
	case "MD5":
		return DigestInfo{Name: "MD5", Hash: crypto.MD5, DigestLen: md5.Size}, isPSS, nil
	case "SHA1":
		return DigestInfo{Name: "SHA1", Hash: crypto.SHA1, DigestLen: sha1.Size}, isPSS, nil
	case "SHA256":
		return DigestInfo{Name: "SHA256", Hash: crypto.SHA256, DigestLen: sha256.Size}, isPSS, nil
	case "SHA384":
		return DigestInfo{Name: "SHA384", Hash: crypto.SHA384, DigestLen: sha512.Size384}, isPSS, nil
	case "SHA512":
		return DigestInfo{Name: "SHA512", Hash: crypto.SHA512, DigestLen: sha512.Size}, isPSS, nil
	case "SHA3_256":
		return DigestInfo{Name: "SHA3_256", Hash: crypto.SHA3_256, DigestLen: 32}, isPSS, nil
	case "SHA3_384":
		return DigestInfo{Name: "SHA3_384", Hash: crypto.SHA3_384, DigestLen: 48}, isPSS, nil
	case "SHA3_512":
		return DigestInfo{Name: "SHA3_512", Hash: crypto.SHA3_512, DigestLen: 64}, isPSS, nil
	case "SM3":
		return DigestInfo{Name: "SM3", DigestLen: 32}, isPSS, nil
	default:
		return DigestInfo{}, false, fmt.Errorf("不支持的签名算法: %s", mechanism)
	}
}

// Digest 计算数据摘要。
func (d DigestInfo) Digest(data []byte) []byte {
	switch d.Hash {
	case crypto.MD5:
		h := md5.Sum(data) //nolint:gosec // 兼容遗留
		return h[:]
	case crypto.SHA1:
		h := sha1.Sum(data) //nolint:gosec // 兼容遗留
		return h[:]
	case crypto.SHA256:
		h := sha256.Sum256(data)
		return h[:]
	case crypto.SHA384:
		h := sha512.Sum384(data)
		return h[:]
	case crypto.SHA512:
		h := sha512.Sum512(data)
		return h[:]
	case crypto.SHA3_256:
		h := sha3.Sum256(data)
		return h[:]
	case crypto.SHA3_384:
		h := sha3.Sum384(data)
		return h[:]
	case crypto.SHA3_512:
		h := sha3.Sum512(data)
		return h[:]
	default:
		if d.Name == "SM3" {
			return sm3Digest(data)
		}
		return data
	}
}

func signRSA(key *rsa.PrivateKey, mechanism string, data []byte) ([]byte, error) {
	switch mechanism {
	// ---- PKCS#1 v1.5 ----
	case "MD5_RSA_PKCS":
		h := md5.Sum(data) //nolint:gosec // 兼容遗留
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.MD5, h[:])
	case "SHA1_RSA_PKCS":
		h := sha1.Sum(data) //nolint:gosec // 兼容遗留
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, h[:])
	case "SHA256_RSA_PKCS":
		h := sha256.Sum256(data)
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	case "SHA384_RSA_PKCS":
		h := sha512.Sum384(data)
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA384, h[:])
	case "SHA512_RSA_PKCS":
		h := sha512.Sum512(data)
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA512, h[:])
	case "SHA3_256_RSA_PKCS":
		h := sha3.Sum256(data)
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA3_256, h[:])
	case "SHA3_384_RSA_PKCS":
		h := sha3.Sum384(data)
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA3_384, h[:])
	case "SHA3_512_RSA_PKCS":
		h := sha3.Sum512(data)
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA3_512, h[:])
	// ---- RSA-PSS ----
	case "SHA256_RSA_PSS":
		h := sha256.Sum256(data)
		return rsa.SignPSS(rand.Reader, key, crypto.SHA256, h[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto})
	case "SHA384_RSA_PSS":
		h := sha512.Sum384(data)
		return rsa.SignPSS(rand.Reader, key, crypto.SHA384, h[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto})
	case "SHA512_RSA_PSS":
		h := sha512.Sum512(data)
		return rsa.SignPSS(rand.Reader, key, crypto.SHA512, h[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto})
	case "SHA3_256_RSA_PSS":
		h := sha3.Sum256(data)
		return rsa.SignPSS(rand.Reader, key, crypto.SHA3_256, h[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto})
	case "SHA3_384_RSA_PSS":
		h := sha3.Sum384(data)
		return rsa.SignPSS(rand.Reader, key, crypto.SHA3_384, h[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto})
	case "SHA3_512_RSA_PSS":
		h := sha3.Sum512(data)
		return rsa.SignPSS(rand.Reader, key, crypto.SHA3_512, h[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto})

	// ---- 已摘要变体（_DIGEST）：data 已经是调用方算好的摘要，不再二次哈希 ----
	// 供 keybackend.Signer（crypto.Signer 适配器）使用：标准库 x509.CreateCertificate
	// 等函数在调用 Signer.Sign 前已完成哈希，不能再对摘要重新哈希一次。
	case "MD5_RSA_PKCS_DIGEST":
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.MD5, data)
	case "SHA1_RSA_PKCS_DIGEST":
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, data)
	case "SHA256_RSA_PKCS_DIGEST":
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, data)
	case "SHA384_RSA_PKCS_DIGEST":
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA384, data)
	case "SHA512_RSA_PKCS_DIGEST":
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA512, data)
	case "SHA256_RSA_PSS_DIGEST":
		return rsa.SignPSS(rand.Reader, key, crypto.SHA256, data, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto})
	case "SHA384_RSA_PSS_DIGEST":
		return rsa.SignPSS(rand.Reader, key, crypto.SHA384, data, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto})
	case "SHA512_RSA_PSS_DIGEST":
		return rsa.SignPSS(rand.Reader, key, crypto.SHA512, data, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto})
	default:
		return nil, fmt.Errorf("不支持的 RSA 签名算法: %s", mechanism)
	}
}

func signECDSA(key *ecdsa.PrivateKey, mechanism string, data []byte) ([]byte, error) {
	var digest []byte
	switch mechanism {
	case "ECDSA":
		digest = data
	case "ECDSA_SHA1":
		h := sha1.Sum(data) //nolint:gosec // 兼容遗留
		digest = h[:]
	case "ECDSA_SHA256":
		h := sha256.Sum256(data)
		digest = h[:]
	case "ECDSA_SHA384":
		h := sha512.Sum384(data)
		digest = h[:]
	case "ECDSA_SHA512":
		h := sha512.Sum512(data)
		digest = h[:]
	case "ECDSA_SHA3_256":
		h := sha3.Sum256(data)
		digest = h[:]
	case "ECDSA_SHA3_384":
		h := sha3.Sum384(data)
		digest = h[:]
	case "ECDSA_SHA3_512":
		h := sha3.Sum512(data)
		digest = h[:]
	default:
		return nil, fmt.Errorf("不支持的 ECDSA 签名算法: %s", mechanism)
	}

	r, s, err := ecdsa.Sign(rand.Reader, key, digest)
	if err != nil {
		return nil, fmt.Errorf("ECDSA 签名失败: %w", err)
	}

	keyBytes := (key.Curve.Params().BitSize + 7) / 8
	result := make([]byte, 2*keyBytes)
	rBytes, sBytes := r.Bytes(), s.Bytes()
	copy(result[keyBytes-len(rBytes):keyBytes], rBytes)
	copy(result[2*keyBytes-len(sBytes):], sBytes)
	return result, nil
}
