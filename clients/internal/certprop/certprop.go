// Package certprop 实现证书传播功能，将 PKI 证书自动注册到操作系统证书存储。
//
// Windows: 写入 CurrentUser\MY 证书存储，并关联密钥容器到 CSP/KSP
// Linux/macOS: 当前为空实现（no-op）
package certprop

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"log/slog"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

// IsSM2Cert 判断 DER 证书是否为国密 SM2 证书。
//
// Windows 的 CNG 没有国密算法标识，KSP 无法承载 SM2 私钥；
// 这类证书只在 PKCS#11 中使用，不注册到系统证书存储。
func IsSM2Cert(der []byte) bool {
	if len(der) == 0 {
		return false
	}
	if cert, err := x509.ParseCertificate(der); err == nil {
		pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		return ok && pub.Curve == sm2.P256()
	}
	gmCert, err := smx509.ParseCertificate(der)
	if err != nil {
		return false
	}
	pub, ok := gmCert.PublicKey.(*ecdsa.PublicKey)
	return ok && pub.Curve == sm2.P256()
}

// ContainerPrefix 是密钥容器名称前缀。
const ContainerPrefix = "OpenCert_"

// CSPName 是注册到 Windows 的 KSP 名称（OpenCert 自定义 KSP）。
const CSPName = "OpenCert Key Storage Provider"

// PropagateResult 是单个证书传播的结果。
type PropagateResult struct {
	CertUUID   string `json:"cert_uuid"`
	CommonName string `json:"common_name"`
	Action     string `json:"action"` // "added", "updated", "skipped", "removed", "error"
	Error      string `json:"error,omitempty"`
}

// SyncResult 是一次完整同步的结果。
type SyncResult struct {
	Added   int               `json:"added"`
	Updated int               `json:"updated"`
	Removed int               `json:"removed"`
	Skipped int               `json:"skipped"`
	Errors  int               `json:"errors"`
	Details []PropagateResult `json:"details,omitempty"`
}

// CertInfo 是传递给平台实现的证书信息。
type CertInfo struct {
	UUID       string // 证书 UUID（用于生成容器名）
	CardUUID   string // 所属卡片 UUID
	CommonName string // 证书 CN
	CertPEM    string // 证书 PEM 内容
	CertDER    []byte // 证书 DER 编码
	HasKey     bool   // 是否有关联私钥
	KeyType    string // 密钥类型 (rsa2048, ec256, ...)
}

// ContainerName 生成密钥容器名称。
func (c *CertInfo) ContainerName() string {
	if c.CardUUID != "" {
		return ContainerPrefix + c.CardUUID + "_" + c.UUID
	}
	return ContainerPrefix + c.UUID
}

// Propagator 是证书传播器接口。
type Propagator interface {
	// Sync 将证书列表同步到系统证书存储。
	// 新增的证书会被添加，已删除的证书会被移除。
	Sync(ctx context.Context, certs []CertInfo) (*SyncResult, error)

	// Add 将单个证书添加到系统证书存储。
	Add(ctx context.Context, cert CertInfo) error

	// Remove 从系统证书存储中移除指定证书。
	Remove(ctx context.Context, certUUID string) error

	// RemoveAll 移除所有由本程序注册的证书。
	RemoveAll(ctx context.Context) error
}

// logger 返回带模块标识的 logger。
func logger() *slog.Logger {
	return slog.Default().With("module", "certprop")
}
