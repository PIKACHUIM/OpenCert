// Package ca - 加密工具函数。
package ca

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"

	"github.com/emmansun/gmsm/sm2"
)

// parseCertPEM 解析 PEM 格式的证书（取第一个证书）。
//
// 同时兼容 SM2 证书（标准库无法识别其签名算法，回退到国密库解析）。
func parseCertPEM(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("无效的 PEM 证书")
	}
	cert, _, err := parseCertificateAny(block.Bytes)
	return cert, err
}

// parsePrivateKeyAny 依次尝试以 PKCS8（含 SM2）/ PKCS1 RSA / EC 格式解析私钥 DER。
func parsePrivateKeyAny(der []byte) (crypto.PrivateKey, error) {
	if k, err := parsePrivateKeyAnyImpl(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	return nil, fmt.Errorf("未知的私钥格式")
}

// verifyKeyPair 校验私钥与证书公钥匹配（对比公钥 DER）。
func verifyKeyPair(cert *x509.Certificate, priv crypto.PrivateKey) error {
	privPub, err := extractPublicKey(priv)
	if err != nil {
		return err
	}
	privPubDER, err := marshalPublicKeyAny(privPub)
	if err != nil {
		return fmt.Errorf("序列化私钥对应公钥失败: %w", err)
	}
	certPubDER, err := marshalPublicKeyAny(cert.PublicKey)
	if err != nil {
		return fmt.Errorf("序列化证书公钥失败: %w", err)
	}
	if !bytes.Equal(privPubDER, certPubDER) {
		return fmt.Errorf("证书公钥与私钥不匹配")
	}
	return nil
}

// extractPublicKey 从任意私钥类型提取对应的公钥接口。
func extractPublicKey(priv crypto.PrivateKey) (crypto.PublicKey, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &k.PublicKey, nil
	case ed25519.PrivateKey:
		return k.Public(), nil
	case *sm2.PrivateKey:
		return sm2PublicKeyOf(k), nil
	default:
		return nil, fmt.Errorf("不支持的私钥类型 %T", priv)
	}
}

// decryptPrivateKey 使用主密钥 AES-256-GCM 解密私钥，返回 crypto.Signer。
func decryptPrivateKey(masterKey, encData []byte) (crypto.Signer, error) {
	privDER, err := aesGCMDecrypt(masterKey, encData)
	if err != nil {
		return nil, err
	}
	return signerFromDER(privDER)
}

// signerFromDER 从 PKCS#8 私钥 DER 构造 crypto.Signer（支持 SM2）。
func signerFromDER(privDER []byte) (crypto.Signer, error) {
	key, err := parsePrivateKeyAnyImpl(privDER)
	if err != nil {
		return nil, fmt.Errorf("解析私钥失败: %w", err)
	}
	if k, ok := key.(*sm2.PrivateKey); ok {
		return asSM2Signer(k), nil
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("私钥不支持签名操作")
	}
	return signer, nil
}

// encryptPrivateKey 使用主密钥 AES-256-GCM 加密私钥 DER。
func encryptPrivateKey(masterKey, privDER []byte) ([]byte, error) {
	return aesGCMEncrypt(masterKey, privDER)
}

// aesGCMEncrypt 使用 AES-256-GCM 加密数据。
func aesGCMEncrypt(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("创建 AES cipher 失败: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("创建 GCM 失败: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("生成 nonce 失败: %w", err)
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

// aesGCMDecrypt 使用 AES-256-GCM 解密数据。
func aesGCMDecrypt(key, blob []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("创建 AES cipher 失败: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("创建 GCM 失败: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(blob) < nonceSize {
		return nil, fmt.Errorf("密文太短")
	}

	nonce, ciphertext := blob[:nonceSize], blob[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
