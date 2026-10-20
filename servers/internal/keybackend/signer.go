package keybackend

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"strings"
)

// Signer 把 Provider.Sign 包装为标准的 crypto.Signer，使存储区域内的
// 私钥（无论在本地数据库、TPM 还是 HSM 中）都能直接用于 x509 证书/CRL/OCSP 签名。
//
// 实现说明：
//   - x509.CreateCertificate 等标准库函数会把待签哈希连同 SignerOpts
//     一起交给 Signer.Sign；
//   - 这里把 (公钥类型, SignerOpts) 映射为 Provider.Sign 认识的 mechanism
//     字符串（与 /api/cards/{uuid}/sign 接口一致），并把已计算好的摘要
//     传给 Provider；
//   - ECDSA 的 Provider.Sign 返回 r‖s 定长拼接（历史约定），而
//     crypto.Signer 要求返回 ASN.1 DER，这里负责转换。
//   - 仅支持 RSA / ECDSA（SM2 不经过此路径，由 ca 包的国密分派层直接
//     使用 sm2.PrivateKey.Sign，因为标准库完全不认识 SM2 算法标识）。
type Signer struct {
	ctx      context.Context
	provider Provider
	handle   KeyHandle
	pub      crypto.PublicKey
}

// NewSigner 构造一个 crypto.Signer，签名时通过 provider.Sign 完成。
//
// ctx 保存在结构体内部而不是通过 Sign 方法参数传递，因为 crypto.Signer
// 接口本身不支持传 context——这是适配标准库接口时的已知工程妥协。
func NewSigner(ctx context.Context, provider Provider, handle KeyHandle, pub crypto.PublicKey) crypto.Signer {
	return &Signer{ctx: ctx, provider: provider, handle: handle, pub: pub}
}

// Public 返回公钥。
func (s *Signer) Public() crypto.PublicKey {
	return s.pub
}

// Sign 按 opts 推断签名机制，调用 provider.Sign 完成签名。
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	mechanism, err := mechanismFor(s.pub, opts)
	if err != nil {
		return nil, err
	}
	sig, err := s.provider.Sign(s.ctx, s.handle, mechanism, digest)
	if err != nil {
		return nil, fmt.Errorf("存储区域签名失败: %w", err)
	}
	if pub, ok := s.pub.(*ecdsa.PublicKey); ok {
		// r‖s 必须是曲线坐标宽度两倍；长度不符说明后端返回了 DER 或截断数据，
		// 直接报错比悄悄编码出错误签名更安全
		size := (pub.Curve.Params().BitSize + 7) / 8
		if len(sig) != size*2 {
			return nil, fmt.Errorf("ECDSA 签名长度异常: 期望 %d，实际 %d", size*2, len(sig))
		}
		return ecdsaRawToASN1(sig)
	}
	return sig, nil
}

// mechanismFor 根据公钥类型与 SignerOpts 推断 Provider.Sign 需要的机制名。
//
// crypto.Signer.Sign 收到的 digest 已经是调用方算好的摘要，因此 RSA 必须
// 使用 "_DIGEST" 变体（不再二次哈希）；ECDSA 的裸 "ECDSA" 机制本身就是
// "按已摘要处理"，不需要额外变体。
func mechanismFor(pub crypto.PublicKey, opts crypto.SignerOpts) (string, error) {
	switch pub.(type) {
	case *rsa.PublicKey:
		name, err := hashMechanismName(opts.HashFunc())
		if err != nil {
			return "", err
		}
		if _, isPSS := opts.(*rsa.PSSOptions); isPSS {
			return name + "_RSA_PSS_DIGEST", nil
		}
		return name + "_RSA_PKCS_DIGEST", nil
	case *ecdsa.PublicKey:
		if isSM2(pub) {
			// SM2 的签名语义（SM3(Z‖原文) 预处理）与此处"digest 已经是
			// 调用方算好的摘要"的约定不兼容，且按设计 SM2 CA 私钥只落在
			// 本地数据库（不托管到 HSM/TPM），因此这里直接拒绝，避免
			// 产出不符合 GM/T 0015 的签名。
			return "", fmt.Errorf("SM2 私钥不支持通过该适配器签名，请使用本地加密存储")
		}
		return "ECDSA", nil
	default:
		return "", fmt.Errorf("不支持的公钥类型: %T", pub)
	}
}

// hashMechanismName 把 crypto.Hash 映射为机制名前缀。
func hashMechanismName(h crypto.Hash) (string, error) {
	switch h {
	case crypto.MD5:
		return "MD5", nil
	case crypto.SHA1:
		return "SHA1", nil
	case crypto.SHA256:
		return "SHA256", nil
	case crypto.SHA384:
		return "SHA384", nil
	case crypto.SHA512:
		return "SHA512", nil
	case crypto.SHA3_256:
		return "SHA3_256", nil
	case crypto.SHA3_384:
		return "SHA3_384", nil
	case crypto.SHA3_512:
		return "SHA3_512", nil
	default:
		return "", fmt.Errorf("不支持的摘要算法: %v", h)
	}
}

// ecdsaSig 用于 ASN.1 编码 ECDSA 签名的 (r, s) 对。
type ecdsaSig struct {
	R, S *big.Int
}

// ecdsaRawToASN1 把 r‖s 定长拼接转换为 ASN.1 DER（SEQUENCE{INTEGER r, INTEGER s}）。
func ecdsaRawToASN1(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw)%2 != 0 {
		return nil, fmt.Errorf("签名长度不合法: %d", len(raw))
	}
	half := len(raw) / 2
	r := new(big.Int).SetBytes(raw[:half])
	s := new(big.Int).SetBytes(raw[half:])
	der, err := asn1.Marshal(ecdsaSig{R: r, S: s})
	if err != nil {
		return nil, fmt.Errorf("编码 ECDSA 签名失败: %w", err)
	}
	return der, nil
}

// ParseMechanism 从机制名解析出哈希名与是否为 PSS（供上层展示/日志复用）。
func ParseMechanism(mechanism string) (hashName string, isPSS bool) {
	m := strings.ToUpper(strings.TrimSpace(mechanism))
	isPSS = strings.HasSuffix(m, "_RSA_PSS")
	m = strings.TrimSuffix(m, "_RSA_PSS")
	m = strings.TrimSuffix(m, "_RSA_PKCS")
	m = strings.TrimPrefix(m, "ECDSA_")
	return m, isPSS
}
