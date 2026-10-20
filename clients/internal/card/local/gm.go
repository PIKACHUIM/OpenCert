package local

import (
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"math/big"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm4"
	"github.com/emmansun/gmsm/smx509"
	"github.com/globaltrusts/client-card/pkg/pkcs11types"
)

// ---- 国密算法（SM2 / SM3 / SM4）----
//
// 约定（与 pkcs11-mock 驱动保持一致）：
//   - CKM_SM2 的输入是原文：本文件负责计算 Z 值与 SM3 摘要后签名，签名输出为 r‖s（各 32 字节）；
//   - 用户 ID 使用标准默认值 1234567812345678（gmsm 的 defaultUID）；
//   - 加密使用 C1C3C2 编码（gmsm 默认），与主流国密实现一致。

// sm2RawSigLen 是 SM2 原始签名的长度（r‖s）。
const sm2RawSigLen = 64

// generateSM2 生成 SM2 密钥对，返回 PKCS#8 私钥 DER 与 PKIX 公钥 DER。
func generateSM2() (privDER, pubDER []byte, err error) {
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("生成 SM2 密钥失败: %w", err)
	}
	privDER, err = smx509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("序列化 SM2 私钥失败: %w", err)
	}
	pubDER, err = smx509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("序列化 SM2 公钥失败: %w", err)
	}
	return privDER, pubDER, nil
}

// sm2SignRaw 对原文签名，返回 r‖s 形式的原始签名（PKCS#11 约定）。
func sm2SignRaw(key *sm2.PrivateKey, data []byte) ([]byte, error) {
	digest, err := sm2.CalculateSM2Hash(&key.PublicKey, data, nil)
	if err != nil {
		return nil, fmt.Errorf("计算 SM2 摘要失败: %w", err)
	}
	// gmsm 的兼容签名接口接收标准库私钥（SM2 私钥内嵌 ecdsa.PrivateKey）
	r, s, err := sm2.Sign(rand.Reader, &key.PrivateKey, digest)
	if err != nil {
		return nil, fmt.Errorf("SM2 签名失败: %w", err)
	}
	out := make([]byte, sm2RawSigLen)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out, nil
}

// sm2VerifyRaw 校验 r‖s 形式的原始签名。
func sm2VerifyRaw(pub *ecdsa.PublicKey, data, sig []byte) bool {
	// 也接受 ASN.1 编码的签名（部分应用直接用标准库格式）
	if len(sig) != sm2RawSigLen {
		digest, err := sm2.CalculateSM2Hash(pub, data, nil)
		if err != nil {
			return false
		}
		return sm2.VerifyASN1(pub, digest, sig)
	}
	digest, err := sm2.CalculateSM2Hash(pub, data, nil)
	if err != nil {
		return false
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	return sm2.Verify(pub, digest, r, s)
}

// sm2Encrypt 用公钥加密（C1C3C2）。
func sm2Encrypt(pub *ecdsa.PublicKey, plaintext []byte) ([]byte, error) {
	out, err := sm2.Encrypt(rand.Reader, pub, plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("SM2 加密失败: %w", err)
	}
	return out, nil
}

// sm2Decrypt 用私钥解密（自动识别 C1C3C2 / ASN.1 编码）。
func sm2Decrypt(key *sm2.PrivateKey, ciphertext []byte) ([]byte, error) {
	out, err := sm2.Decrypt(key, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("SM2 解密失败: %w", err)
	}
	return out, nil
}

// ---- SM4 ----

// sm4EncryptCBC 使用 SM4-CBC + PKCS#7 填充加密。
func sm4EncryptCBC(key, iv, plaintext []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("SM4 密钥无效: %w", err)
	}
	if len(iv) != block.BlockSize() {
		return nil, fmt.Errorf("SM4-CBC 需要 %d 字节 IV", block.BlockSize())
	}
	padded := pkcs7Pad(plaintext, block.BlockSize())
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
	return out, nil
}

// sm4DecryptCBC 解密 SM4-CBC 并去除 PKCS#7 填充。
func sm4DecryptCBC(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("SM4 密钥无效: %w", err)
	}
	if len(iv) != block.BlockSize() {
		return nil, fmt.Errorf("SM4-CBC 需要 %d 字节 IV", block.BlockSize())
	}
	if len(ciphertext) == 0 || len(ciphertext)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("SM4 密文长度不合法")
	}
	out := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ciphertext)
	return pkcs7Unpad(out, block.BlockSize())
}

// sm4EncryptGCM 使用 SM4-GCM 加密，返回密文与 16 字节认证标签（PKCS#11 约定标签附在密文后）。
func sm4EncryptGCM(key, iv, plaintext, aad []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("SM4 密钥无效: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("初始化 SM4-GCM 失败: %w", err)
	}
	if len(iv) != gcm.NonceSize() {
		return nil, fmt.Errorf("SM4-GCM 需要 %d 字节 IV", gcm.NonceSize())
	}
	return gcm.Seal(nil, iv, plaintext, aad), nil
}

// sm4DecryptGCM 解密 SM4-GCM（密文尾部带 16 字节标签）。
func sm4DecryptGCM(key, iv, ciphertext, aad []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("SM4 密钥无效: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("初始化 SM4-GCM 失败: %w", err)
	}
	if len(iv) != gcm.NonceSize() {
		return nil, fmt.Errorf("SM4-GCM 需要 %d 字节 IV", gcm.NonceSize())
	}
	out, err := gcm.Open(nil, iv, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("SM4-GCM 校验失败: %w", err)
	}
	return out, nil
}

// pkcs7Pad 按块大小做 PKCS#7 填充。
func pkcs7Pad(data []byte, blockSize int) []byte {
	pad := blockSize - len(data)%blockSize
	out := make([]byte, len(data)+pad)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}

// pkcs7Unpad 去除 PKCS#7 填充，使用恒定时间比较避免填充预言。
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, fmt.Errorf("填充不合法")
	}
	pad := int(data[len(data)-1])
	if pad == 0 || pad > blockSize || pad > len(data) {
		return nil, fmt.Errorf("填充不合法")
	}
	for i := len(data) - pad; i < len(data); i++ {
		if subtle.ConstantTimeByteEq(data[i], byte(pad)) != 1 {
			return nil, fmt.Errorf("填充不合法")
		}
	}
	return data[:len(data)-pad], nil
}

// ---- 解析辅助 ----

// parseGMPKCS8 解析 PKCS#8 私钥，支持 SM2（smx509 内部会回退到标准库处理其它算法）。
func parseGMPKCS8(der []byte) (any, error) {
	return smx509.ParsePKCS8PrivateKey(der)
}

// parseGMPKIX 解析 PKIX 公钥，支持 SM2。
func parseGMPKIX(der []byte) (any, error) {
	return smx509.ParsePKIXPublicKey(der)
}

// parseGMCertificate 解析证书，支持 SM2 证书。
func parseGMCertificate(der []byte) (*smx509.Certificate, error) {
	return smx509.ParseCertificate(der)
}

// asSM2PrivateKey 把任意私钥断言为 SM2 私钥。
func asSM2PrivateKey(key any) (*sm2.PrivateKey, bool) {
	k, ok := key.(*sm2.PrivateKey)
	return k, ok
}

// IsGMMechanism 判断机制是否属于国密算法。
// TPM 与 Windows CNG/KSP 没有国密算法标识，相关卡型必须明确拒绝。
func IsGMMechanism(m pkcs11types.MechanismType) bool {
	switch m {
	case pkcs11types.CKM_SM2_KEY_PAIR_GEN,
		pkcs11types.CKM_SM2,
		pkcs11types.CKM_SM3,
		pkcs11types.CKM_SM4_CBC,
		pkcs11types.CKM_SM4_GCM:
		return true
	default:
		return false
	}
}
