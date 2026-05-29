package api

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http"

	"github.com/globaltrusts/client-card/internal/card/local"
	"github.com/globaltrusts/client-card/internal/certprop"
	"github.com/globaltrusts/client-card/internal/storage"
)

// handlePropagateCerts POST /api/pki/certs/propagate
// 手动触发证书传播：将所有证书同步到操作系统证书存储。
// 同时查询 pki_certs 表和 certificates 表。
func (s *Server) handlePropagateCerts(w http.ResponseWriter, r *http.Request) {
	if s.certPropagator == nil {
		writeError(w, http.StatusServiceUnavailable, "证书传播器未初始化")
		return
	}

	ctx := r.Context()
	var certInfos []certprop.CertInfo

	// 1. 查询 PKI 证书（pki_certs 表）
	pkiCerts, _, err := s.pkiCertRepo.List(ctx, 1, 1000)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "查询 PKI 证书列表失败: "+err.Error())
		return
	}
	for _, c := range pkiCerts {
		if c.Revoked || c.CertPEM == "" {
			continue
		}
		// 对于有 CardUUID 的 PKI 证书，需要用 certificates 表中密钥记录的 UUID 作为容器标识，
		// 否则 KSP resolveContainer 在 certificates 表中按 UUID 搜索时找不到私钥。
		certUUID := c.UUID
		if c.CardUUID != "" && c.HasPrivateKey {
			if keyCertUUID := s.findKeyCertUUID(ctx, c); keyCertUUID != "" {
				certUUID = keyCertUUID
			}
		}
		certInfos = append(certInfos, certprop.CertInfo{
			UUID:       certUUID,
			CardUUID:   c.CardUUID,
			CommonName: c.CommonName,
			CertPEM:    c.CertPEM,
			HasKey:     c.HasPrivateKey,
			KeyType:    c.KeyType,
		})
	}

	// 2. 查询智能卡证书（certificates 表，仅 X.509 类型）
	scCerts, err := s.certRepo.ListX509All(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "查询智能卡证书列表失败: "+err.Error())
		return
	}
	for _, c := range scCerts {
		if len(c.CertContent) == 0 {
			continue
		}
		hasKey := len(c.PrivateData) > 0
		certInfos = append(certInfos, certprop.CertInfo{
			UUID:     c.UUID,
			CardUUID: c.CardUUID,
			CertDER:  c.DERContent(),
			HasKey:   hasKey,
			KeyType:  c.KeyType,
		})
	}

	// 执行同步
	result, err := s.certPropagator.Sync(ctx, certInfos)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "证书传播失败: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, Response{
		Code:    0,
		Message: "证书传播完成",
		Data: map[string]interface{}{
			"pki_count":       len(pkiCerts),
			"smartcard_count": len(scCerts),
			"result":          result,
		},
	})
}

// findKeyCertUUID 根据 PKI 证书的公钥，在 certificates 表中找到对应密钥记录的 UUID。
// 这样证书传播时容器名使用密钥 UUID，KSP 后端才能正确查找私钥。
func (s *Server) findKeyCertUUID(ctx context.Context, pkiCert *storage.PKICert) string {
	if pkiCert.CardUUID == "" {
		return ""
	}

	// 解析 PKI 证书的公钥
	block, _ := pem.Decode([]byte(pkiCert.CertPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return ""
	}
	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	pkiPubDER, err := x509.MarshalPKIXPublicKey(x509Cert.PublicKey)
	if err != nil {
		return ""
	}

	// 在 certificates 表中查找同一卡片下公钥匹配的密钥记录
	certs, err := s.certRepo.ListByCard(ctx, pkiCert.CardUUID)
	if err != nil {
		return ""
	}
	for _, c := range certs {
		if len(c.CertContent) == 0 {
			continue
		}
		certPubDER := local.ExtractPublicKeyDER(c.CertContent)
		if len(certPubDER) > 0 && string(certPubDER) == string(pkiPubDER) {
			return c.UUID
		}
	}
	return ""
}

// 确保未使用的 import 不报错
var _ = (*storage.PKICert)(nil)
