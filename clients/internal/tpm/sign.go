// Package tpm - 私钥序列化与签名/解密的内部共享工具，供 swstub 与 mock 后端复用。
//
// 真 TPM 实现（windows-cng / linux-tpm2）不会用这些函数，
// 它们的 Sign/Decrypt 直接走硬件接口。
package tpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
)

func marshalPKCS8(priv crypto.PrivateKey) ([]byte, error) {
	b, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("序列化私钥失败: %w", err)
	}
	return b, nil
}

func marshalPKIX(pub crypto.PublicKey) ([]byte, error) {
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("序列化公钥失败: %w", err)
	}
	return b, nil
}

func parsePKCS8(der []byte) (crypto.PrivateKey, error) {
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("解析私钥失败: %w", err)
	}
	return k, nil
}

func signWithKey(priv crypto.PrivateKey, digest []byte, scheme SignScheme) ([]byte, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		hash, isPSS, err := schemeToHashRSA(scheme, len(digest))
		if err != nil {
			return nil, err
		}
		if isPSS {
			return rsa.SignPSS(rand.Reader, k, hash, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto})
		}
		return rsa.SignPKCS1v15(rand.Reader, k, hash, digest)
	case *ecdsa.PrivateKey:
		if err := validateECDigestLen(scheme, len(digest)); err != nil {
			return nil, err
		}
		return ecdsa.SignASN1(rand.Reader, k, digest)
	case ed25519.PrivateKey:
		return ed25519.Sign(k, digest), nil
	default:
		return nil, fmt.Errorf("不支持的私钥类型: %T", priv)
	}
}

func decryptWithKey(priv crypto.PrivateKey, ciphertext []byte) ([]byte, error) {
	rsaKey, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("Decrypt 仅支持 RSA 私钥")
	}
	return rsa.DecryptPKCS1v15(rand.Reader, rsaKey, ciphertext)
}

func decryptOAEPWithKey(priv crypto.PrivateKey, ciphertext, label []byte) ([]byte, error) {
	rsaKey, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("DecryptOAEP 仅支持 RSA 私钥")
	}
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaKey, ciphertext, label)
}

// extractPubAndAlg 从已解析的私钥中提取公钥和对应的 KeyAlg。
func extractPubAndAlg(priv crypto.PrivateKey) (crypto.PublicKey, KeyAlg, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		bits := k.N.BitLen()
		var alg KeyAlg
		switch {
		case bits <= 2048:
			alg = KeyAlgRSA2048
		case bits <= 3072:
			alg = KeyAlgRSA3072
		default:
			alg = KeyAlgRSA4096
		}
		return &k.PublicKey, alg, nil
	case *ecdsa.PrivateKey:
		bits := k.Curve.Params().BitSize
		var alg KeyAlg
		switch bits {
		case 256:
			alg = KeyAlgECP256
		case 384:
			alg = KeyAlgECP384
		case 521:
			alg = KeyAlgECP521
		default:
			return nil, "", fmt.Errorf("不支持的 EC 曲线位数: %d", bits)
		}
		return &k.PublicKey, alg, nil
	case ed25519.PrivateKey:
		return k.Public(), KeyAlgECP256, nil // Ed25519 暂映射到 ECP256（TPM 不原生支持）
	default:
		return nil, "", fmt.Errorf("不支持的私钥类型: %T", priv)
	}
}
