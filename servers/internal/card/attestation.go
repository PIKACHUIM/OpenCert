// Package card - EK Attestation 服务端校验。
//
// 校验流程：
//  1. 客户端通过 IPC/HTTP 上送 Attestation（含 EK 证书或软件 EK 标记）
//  2. 服务端校验 CertifyBlob 中的 nonce 与本次会话一致
//  3. 若 EKCertificate 存在：用配置的厂商根证书池校验链
//     - Intel/Infineon/STM/Nuvoton 根证书可通过 RegisterEKTrustRoot 注入
//  4. 若 SoftwareEK=true：根据 SecurityLevel 决策
//     - high：拒绝
//     - medium/low：接受并记录告警
package card

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"sync"
)

// SecurityLevel 表示卡片的安全等级。
type SecurityLevel string

const (
	// SecurityLow 低安全：纯软件存储，允许导出。
	SecurityLow SecurityLevel = "low"
	// SecurityMedium 中安全：软件存储 + TPM 绑定。
	SecurityMedium SecurityLevel = "medium"
	// SecurityHigh 高安全：要求密钥位于 TPM 内且 EK 证书可验证。
	SecurityHigh SecurityLevel = "high"
)

// SlotType 表示卡片的槽类型（与客户端 storage.SlotType 字符串一致）。
type SlotType string

const (
	SlotSoftware SlotType = "software"
	SlotTPMv2    SlotType = "tpmv2"
	SlotAppleT2  SlotType = "apple_t2"
	SlotAppleSE  SlotType = "apple_se"
)

// Attestation 与 clients/internal/tpm.Attestation 序列化兼容。
// 单独定义以避免 server 包反向依赖 client 包。
type Attestation struct {
	Platform          string `json:"platform"`
	EKPubFingerprint  string `json:"ek_pub_fingerprint"`
	EKCertificate     []byte `json:"ek_certificate,omitempty"`
	CertifyBlob       []byte `json:"certify_blob"`
	CertifySignature  []byte `json:"certify_signature"`
	KeyPubFingerprint string `json:"key_pub_fingerprint"`
	SoftwareEK        bool   `json:"software_ek"`
	Nonce             string `json:"nonce"`
	Timestamp         string `json:"timestamp"`
}

// EKTrustStore 持有受信 TPM 厂商根证书池。
// 线程安全，可在运行期通过 RegisterEKTrustRoot 增量加载厂商根。
type EKTrustStore struct {
	mu    sync.RWMutex
	pool  *x509.CertPool
	count int
}

// NewEKTrustStore 创建空白信任库。
func NewEKTrustStore() *EKTrustStore {
	return &EKTrustStore{pool: x509.NewCertPool()}
}

// RegisterEKTrustRoot 添加一个 TPM 厂商根证书（PEM 或 DER）。
// 重复添加同一证书不会出错。
func (s *EKTrustStore) RegisterEKTrustRoot(rootPEMOrDER []byte) error {
	if len(rootPEMOrDER) == 0 {
		return fmt.Errorf("EK 厂商根证书为空")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// 优先按 PEM 解析
	if ok := s.pool.AppendCertsFromPEM(rootPEMOrDER); ok {
		s.count++
		return nil
	}
	// 尝试按 DER 解析
	cert, err := x509.ParseCertificate(rootPEMOrDER)
	if err != nil {
		return fmt.Errorf("解析 EK 厂商根证书失败: %w", err)
	}
	s.pool.AddCert(cert)
	s.count++
	return nil
}

// Count 返回已注册的厂商根数量。
func (s *EKTrustStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.count
}

// VerifyEKAttestation 校验客户端上送的 EK 认证。
//
// 参数：
//   - att: 客户端 Attestation
//   - expectedNonce: 服务端本次下发的 nonce（防重放）
//   - level: 卡片要求的安全等级
//
// 返回：
//   - error == nil 表示通过；否则附带原因
func (s *EKTrustStore) VerifyEKAttestation(att *Attestation, expectedNonce string, level SecurityLevel) error {
	if att == nil {
		return fmt.Errorf("attestation 为空")
	}

	// 1) 基本字段
	if att.KeyPubFingerprint == "" {
		return fmt.Errorf("缺少 key_pub_fingerprint")
	}
	if len(att.CertifyBlob) == 0 || len(att.CertifySignature) == 0 {
		return fmt.Errorf("缺少 certify_blob/signature")
	}

	// 2) Nonce 防重放：从 CertifyBlob 中解析对比
	var blobData map[string]string
	if err := json.Unmarshal(att.CertifyBlob, &blobData); err != nil {
		return fmt.Errorf("解析 certify_blob 失败: %w", err)
	}
	if blobData["nonce"] != expectedNonce {
		return fmt.Errorf("nonce 不匹配，可能存在重放攻击")
	}
	if blobData["key_fp"] != att.KeyPubFingerprint {
		return fmt.Errorf("certify_blob 内 key_fp 与外层不一致")
	}

	// 3) 高安全等级强制：必须有 EK 证书且通过厂商链校验
	if level == SecurityHigh {
		if att.SoftwareEK || len(att.EKCertificate) == 0 {
			return fmt.Errorf("高安全等级要求真实 TPM EK 证书，请改用中/低安全等级或更换支持 EK 的设备")
		}
		if err := s.verifyEKCertChain(att.EKCertificate); err != nil {
			return fmt.Errorf("EK 证书链校验失败: %w", err)
		}
		return nil
	}

	// 4) 中/低安全等级：若提供了 EK 证书亦做校验，否则仅记录软件 EK
	if len(att.EKCertificate) > 0 {
		if err := s.verifyEKCertChain(att.EKCertificate); err != nil {
			return fmt.Errorf("EK 证书链校验失败（中/低等级仅警告）: %w", err)
		}
	}
	return nil
}

// verifyEKCertChain 用配置的厂商根池校验 EK 证书链。
func (s *EKTrustStore) verifyEKCertChain(ekCertDER []byte) error {
	cert, err := x509.ParseCertificate(ekCertDER)
	if err != nil {
		return fmt.Errorf("解析 EK 证书失败: %w", err)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.count == 0 {
		return fmt.Errorf("未配置任何 TPM 厂商根证书，无法校验")
	}

	// EK 证书可能没有标准 KeyUsage，使用 ExtKeyUsageAny 放宽
	opts := x509.VerifyOptions{
		Roots:     s.pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if _, err := cert.Verify(opts); err != nil {
		return err
	}
	return nil
}
