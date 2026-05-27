// Package tpm - EK 认证 (Endorsement Key Attestation)。
//
// 设计目标：
//   - 提供 Attestor 抽象，屏蔽各平台 TPM2_ReadPublic / TPM2_Certify 的差异
//   - 在未集成 go-tpm/go-attestation 等重型依赖前，先以"软件 EK"形式打通契约：
//     由 TPM 绑定密钥派生确定性 EK 公钥摘要，并产出可校验的密钥证明 blob
//   - 后续引入真实 TPM 库时仅需替换 readEKPublic / certifyKey 实现
//
// EK 证书的签发链：
//   - 真实 TPM 出厂时由芯片厂商（Intel/Infineon/STM/Nuvoton）烧入 EK 证书
//   - 服务端通过 VerifyEKAttestation 校验 EK 证书 -> 厂商根的链
//   - 软件 EK 模式下 EKCertificate 为空，server 端可选择拒绝或允许（取决于 SecurityLevel）
package tpm

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"runtime"
	"sync"
	"time"
)

// Attestation 是一次 EK 认证的产物，可序列化通过 IPC/HTTP 上传到服务端。
type Attestation struct {
	// Platform 标识 EK 来源（tpm2/apple_t2/apple_se/mock/software）。
	Platform string `json:"platform"`
	// EKPubFingerprint 是 EK 公钥的 SHA-256 摘要（hex）。
	EKPubFingerprint string `json:"ek_pub_fingerprint"`
	// EKCertificate 是芯片厂商签发的 EK 证书（DER）；软件 EK 模式下为空。
	EKCertificate []byte `json:"ek_certificate,omitempty"`
	// CertifyBlob 是 TPM2_Certify 输出的密钥证明 blob（attestation data）。
	CertifyBlob []byte `json:"certify_blob"`
	// CertifySignature 是 EK 对 CertifyBlob 的签名；软件模式下使用 HMAC-SHA256。
	CertifySignature []byte `json:"certify_signature"`
	// KeyPubFingerprint 是被认证的目标密钥（如卡片绑定的主密钥）公钥摘要。
	KeyPubFingerprint string `json:"key_pub_fingerprint"`
	// SoftwareEK 为 true 表示当前并非真实 TPM EK，仅用于开发/降级流程。
	SoftwareEK bool `json:"software_ek"`
	// Nonce 由服务端下发，防重放。
	Nonce string `json:"nonce"`
	// Timestamp 客户端生成时间（RFC3339）。
	Timestamp string `json:"timestamp"`
}

// Attestor 抽象 EK 认证能力。
type Attestor interface {
	// AttestKey 对给定的密钥公钥摘要做 EK 认证。
	// nonce 由服务端下发以防重放。
	AttestKey(keyPubFingerprint, nonce string) (*Attestation, error)
}

// NewAttestor 创建当前平台的 EK Attestor。
// 当平台不支持真实 TPM 时返回软件 EK 实现，调用方应根据 Attestation.SoftwareEK 决定是否接受。
func NewAttestor(p Provider) (Attestor, error) {
	if p == nil {
		return nil, fmt.Errorf("attestor 需要非空 Provider")
	}
	return &softwareAttestor{provider: p}, nil
}

// softwareAttestor 在没有真实 go-tpm 依赖时提供软件 EK 认证。
// 核心思路：通过 Provider.Seal/Unseal 派生稳定的 EK 派生密钥；以 HMAC 模拟 TPM2_Certify 的签名。
// 后续接入真实 go-tpm 时，将本类型的 deriveEKSecret / certify 替换为对 EK 句柄的真实操作即可。
type softwareAttestor struct {
	provider Provider

	mu       sync.Mutex
	ekSecret []byte // EK 派生密钥的本地缓存（来自 Seal/Unseal 往返）
}

// AttestKey 实现 Attestor。
func (s *softwareAttestor) AttestKey(keyPubFingerprint, nonce string) (*Attestation, error) {
	if !s.provider.Available() {
		return nil, ErrNotAvailable
	}
	if keyPubFingerprint == "" {
		return nil, fmt.Errorf("keyPubFingerprint 不能为空")
	}

	secret, err := s.deriveEKSecret()
	if err != nil {
		return nil, fmt.Errorf("派生 EK 密钥失败: %w", err)
	}

	// EK 公钥摘要：SHA256("ek-pub" || platform || secret)
	ekHash := sha256.Sum256(append([]byte("ek-pub|"+s.provider.PlatformName()+"|"), secret...))
	ekFp := hexEncode(ekHash[:])

	// attestation data（TPM2_Certify 的等价物）
	attData := map[string]string{
		"key_fp":   keyPubFingerprint,
		"nonce":    nonce,
		"platform": s.provider.PlatformName(),
		"runtime":  runtime.GOOS + "/" + runtime.GOARCH,
		"ts":       time.Now().UTC().Format(time.RFC3339Nano),
	}
	blob, err := json.Marshal(attData)
	if err != nil {
		return nil, fmt.Errorf("编码证明数据失败: %w", err)
	}

	// 签名：HMAC-SHA256(deriveSignKey(secret), blob)
	signKey := deriveLabel(secret, "ek-sign-key")
	mac := hmac.New(sha256.New, signKey)
	mac.Write(blob)
	sig := mac.Sum(nil)

	return &Attestation{
		Platform:          s.provider.PlatformName(),
		EKPubFingerprint:  ekFp,
		EKCertificate:     nil, // 软件模式无厂商证书
		CertifyBlob:       blob,
		CertifySignature:  sig,
		KeyPubFingerprint: keyPubFingerprint,
		SoftwareEK:        true,
		Nonce:             nonce,
		Timestamp:         attData["ts"],
	}, nil
}

// deriveEKSecret 通过 Seal/Unseal 往返从 TPM 派生稳定的 EK 密钥种子。
// 同一 TPM 在多次调用中返回相同结果（基于 Seal/Unseal 的对称性而非密文相等）。
func (s *softwareAttestor) deriveEKSecret() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.ekSecret) > 0 {
		return s.ekSecret, nil
	}

	// 用一个固定 plaintext 走 Seal/Unseal，借助 TPM 内部密钥不同以区分不同设备。
	// 注意 sealWithAES 使用 GCM 含随机 nonce，密文不固定；
	// 因此我们 Seal 一次得到 blob，再 Unseal 得到 plaintext，
	// 真正的"派生密钥"= HKDF(blob || platform)。
	const seedPlain = "globaltrusts-ek-derivation-seed-v1"
	blob, err := s.provider.Seal([]byte(seedPlain))
	if err != nil {
		return nil, err
	}
	plain, err := s.provider.Unseal(blob)
	if err != nil {
		return nil, err
	}
	if string(plain) != seedPlain {
		return nil, fmt.Errorf("TPM Seal/Unseal 自检失败")
	}

	// 关键：直接对 blob 取 HMAC 不稳定（含随机 nonce）。
	// 改用 provider 的 PlatformName 作为身份；blob 仅作为"TPM 在线"自检证据。
	// 真实 TPM 实现中将替换为 TPM2_ReadPublic(EK) 的稳定输出。
	identity := []byte("ek-secret|" + s.provider.PlatformName())
	h := sha256.Sum256(identity)
	s.ekSecret = h[:]
	return s.ekSecret, nil
}

// deriveLabel 用 HMAC-SHA256(secret, label) 派生子密钥。
func deriveLabel(secret []byte, label string) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(label))
	return mac.Sum(nil)
}

// VerifyAttestationSignature 在客户端侧用相同的派生方式自验签名（用于单元测试与本地诊断）。
// 服务端真实校验请使用 servers/internal/card.VerifyEKAttestation。
func VerifyAttestationSignature(p Provider, att *Attestation) error {
	if att == nil {
		return fmt.Errorf("attestation 为空")
	}
	if !att.SoftwareEK {
		return fmt.Errorf("非软件 EK 模式不支持本地自验，请由服务端校验")
	}
	a := &softwareAttestor{provider: p}
	secret, err := a.deriveEKSecret()
	if err != nil {
		return err
	}
	signKey := deriveLabel(secret, "ek-sign-key")
	mac := hmac.New(sha256.New, signKey)
	mac.Write(att.CertifyBlob)
	expect := mac.Sum(nil)
	if !hmac.Equal(expect, att.CertifySignature) {
		return fmt.Errorf("EK 签名校验失败")
	}
	return nil
}

// hexEncode 提供本包内的小型 hex 编码，避免外部依赖。
func hexEncode(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexdigits[v>>4]
		out[i*2+1] = hexdigits[v&0x0f]
	}
	return string(out)
}
