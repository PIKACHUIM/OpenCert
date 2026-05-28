// Package api：云端证书下发相关的纯函数工具（证书解析、PEM 转换、私钥 AES 加密）。
package api

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/globaltrusts/client-card/internal/card/local"
)

// parseCertBasics 从 PEM 证书中提取基本信息：CN、序列号、有效期。
func parseCertBasics(certPEM string) (cn, serial string, notBefore, notAfter time.Time, err error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return "", "", time.Time{}, time.Time{}, fmt.Errorf("证书 PEM 格式错误")
	}
	crt, parseErr := local.ParseCertLenient(block.Bytes)
	if parseErr != nil {
		return "", "", time.Time{}, time.Time{}, fmt.Errorf("解析证书失败: %w", parseErr)
	}
	return crt.Subject.CommonName, crt.SerialNumber.String(), crt.NotBefore, crt.NotAfter, nil
}

// certPEMToDER 把 PEM 证书转成 DER 字节。
func certPEMToDER(certPEM string) ([]byte, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("证书 PEM 格式错误")
	}
	return block.Bytes, nil
}

// parseCertPublicKeyPEM 从 PEM 证书中提取公钥的 PKIX DER 编码。
func parseCertPublicKeyPEM(certPEM string) ([]byte, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("证书 PEM 格式错误")
	}
	crt, err := local.ParseCertLenient(block.Bytes)
	if err != nil {
		return nil, err
	}
	if crt.PublicKey == nil {
		return nil, fmt.Errorf("证书公钥解析失败")
	}
	return x509.MarshalPKIXPublicKey(crt.PublicKey)
}

// parsePrivateKeyPEM 从 PEM 私钥中提取 PKCS8 DER 与密钥算法（rsa2048/ec256/...）。
// 兼容 PRIVATE KEY (PKCS8)、RSA PRIVATE KEY (PKCS1)、EC PRIVATE KEY (SEC1) 三种常见格式。
func parsePrivateKeyPEM(keyPEM string) (derPKCS8 []byte, keyType string, err error) {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, "", fmt.Errorf("私钥 PEM 格式错误")
	}

	var key any
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		// 尝试按 PKCS8 兜底
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	if err != nil {
		return nil, "", fmt.Errorf("解析私钥失败: %w", err)
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, "", fmt.Errorf("序列化 PKCS8 失败: %w", err)
	}
	return pkcs8, detectKeyType(key), nil
}

// detectKeyType 根据具体私钥类型推断 keyType 字符串（与 local.KeyManager 保持一致）。
func detectKeyType(key any) string {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		bits := k.N.BitLen()
		switch {
		case bits <= 1024:
			return "rsa1024"
		case bits <= 2048:
			return "rsa2048"
		case bits <= 4096:
			return "rsa4096"
		default:
			return "rsa8192"
		}
	case *ecdsa.PrivateKey:
		switch k.Curve {
		case elliptic.P256():
			return "ec256"
		case elliptic.P384():
			return "ec384"
		case elliptic.P521():
			return "ec521"
		}
		return "ec256"
	case ed25519.PrivateKey:
		return "ed25519"
	default:
		return "unknown"
	}
}

// ---- AES-256-GCM 密钥管理（用于加密下发的私钥 PEM）----

const deliverKeyFile = ".deliver.key"
const deliverKeyLen = 32 // AES-256

// loadOrCreateDeliverKey 读取或首次生成下发用的对称密钥；文件权限 0600。
// 该密钥仅用于保护 pki_certs.private_key_enc 字段，不影响卡片主密钥体系。
func loadOrCreateDeliverKey(dataDir string) ([]byte, error) {
	if dataDir == "" {
		dataDir = "."
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	p := filepath.Join(dataDir, deliverKeyFile)

	data, err := os.ReadFile(p)
	if err == nil {
		if len(data) == deliverKeyLen {
			return data, nil
		}
		// 长度异常，重新生成
	}
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	key := make([]byte, deliverKeyLen)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(p, key, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

// aesEncrypt 使用 AES-256-GCM 加密任意明文，返回 nonce || ciphertext。
func aesEncrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, 0, len(nonce)+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// matchPubKeyAgainstCardCert 把 cardCertContent 当作 DER 证书或 PKIX 公钥 DER 解析，
// 与给定的 pubPKIXDER 比较；任一匹配即返回 true。
func matchPubKeyAgainstCardCert(pubPKIXDER, cardCertContent []byte) bool {
	if len(pubPKIXDER) == 0 || len(cardCertContent) == 0 {
		return false
	}
	// 1. 作为 X.509 证书解析（宽松模式，兼容不合规扩展）
	if crt, err := local.ParseCertLenient(cardCertContent); err == nil {
		if crt.PublicKey != nil {
			if der, err := x509.MarshalPKIXPublicKey(crt.PublicKey); err == nil {
				if string(der) == string(pubPKIXDER) {
					return true
				}
			}
		}
	}
	// 2. 作为 PKIX 公钥 DER 直接比较
	if string(cardCertContent) == string(pubPKIXDER) {
		return true
	}
	// 3. 作为 PKIX 公钥再归一化一次（防止编码差异）
	if pub, err := x509.ParsePKIXPublicKey(cardCertContent); err == nil {
		if der, err := x509.MarshalPKIXPublicKey(pub); err == nil {
			return string(der) == string(pubPKIXDER)
		}
	}
	return false
}
