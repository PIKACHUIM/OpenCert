package api

import (
	"net/http"

	"github.com/globaltrusts/client-card/internal/certprop"
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
		certInfos = append(certInfos, certprop.CertInfo{
			UUID:       c.UUID,
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
