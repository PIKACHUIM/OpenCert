// Package api - handler_portal_pki.go：门户公开信任服务（CA / CRL / OCSP 地址）。
//
// 只有被管理员显式标记为公开的 CA 才会出现在目录中，内部 CA 不对外暴露。
// 对外地址统一由请求的 scheme/host 生成，不返回 localhost 或内部端口。
package api

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/globaltrusts/server-card/internal/storage"
)

// pkiEndpoint 是公开信任目录中的一条 CA 记录。
type pkiEndpoint struct {
	CAUUID      string `json:"ca_uuid"`
	Name        string `json:"name"`
	Status      string `json:"status"`
	IsRoot      bool   `json:"is_root"`
	Fingerprint string `json:"fingerprint"` // SHA-256 指纹（冒号分隔大写十六进制）
	Subject     string `json:"subject"`
	Issuer      string `json:"issuer"`
	NotBefore   string `json:"not_before"`
	NotAfter    string `json:"not_after"`
	// CAURL 为 DER 格式根/中间证书下载地址
	CAURL string `json:"ca_url"`
	// ChainURL 为 PEM 格式完整证书链下载地址
	ChainURL string `json:"chain_url"`
	CRLURL   string `json:"crl_url"`
	OCSPURL  string `json:"ocsp_url"`
	// CustomPath 为 true 表示该 CA 使用吊销服务中配置的自定义路径
	CustomPath bool `json:"custom_path"`
}

// handlePortalPKIEndpoints GET /api/portal/pki-endpoints
// 返回可对外公开的 CA 及其 CRL/OCSP/证书下载地址。
func (s *Server) handlePortalPKIEndpoints(w http.ResponseWriter, r *http.Request) {
	base := fmt.Sprintf("%s://%s", scheme(r), r.Host)

	rows, err := s.db.QueryContext(r.Context(),
		`SELECT uuid, name, cert_pem, parent_uuid, status, not_before, not_after
		 FROM cas WHERE is_public = 1 ORDER BY parent_uuid = '' DESC, created_at ASC`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	// 自定义吊销路径：优先使用 revocation_services 中启用的配置
	customPaths := map[string]string{}
	if svcRows, err := s.db.QueryContext(r.Context(),
		`SELECT ca_uuid, path FROM revocation_services WHERE enabled = 1`); err == nil {
		for svcRows.Next() {
			var caUUID, path string
			if err := svcRows.Scan(&caUUID, &path); err == nil && path != "" {
				customPaths[caUUID] = path
			}
		}
		svcRows.Close() //nolint:errcheck
	}

	items := []pkiEndpoint{}
	for rows.Next() {
		var (
			caUUID, name, certPEM, parentUUID, status string
			notBefore, notAfter                       time.Time
		)
		if err := rows.Scan(&caUUID, &name, &certPEM, &parentUUID, &status, &notBefore, &notAfter); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}

		item := pkiEndpoint{
			CAUUID:    caUUID,
			Name:      name,
			Status:    status,
			IsRoot:    parentUUID == "",
			NotBefore: notBefore.Format(time.RFC3339),
			NotAfter:  notAfter.Format(time.RFC3339),
			CAURL:     fmt.Sprintf("%s/ca/%s", base, caUUID),
			ChainURL:  fmt.Sprintf("%s/api/portal/pki/cas/%s/chain", base, caUUID),
			CRLURL:    fmt.Sprintf("%s/crl/%s", base, caUUID),
			OCSPURL:   fmt.Sprintf("%s/ocsp/%s", base, caUUID),
		}

		// 指纹与主体信息（证书无法解析时保持为空，不影响地址展示）
		if block, _ := pem.Decode([]byte(certPEM)); block != nil {
			sum := sha256.Sum256(block.Bytes)
			item.Fingerprint = formatFingerprint(sum[:])
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				item.Subject = cert.Subject.String()
				item.Issuer = cert.Issuer.String()
			}
		}

		// 若配置了自定义吊销路径，改用该路径对外提供 CRL/OCSP
		if path, ok := customPaths[caUUID]; ok {
			item.CustomPath = true
			item.CRLURL = fmt.Sprintf("%s/pki/crl/%s", base, path)
			item.OCSPURL = fmt.Sprintf("%s/pki/ocsp/%s", base, path)
		}

		items = append(items, item)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "total": len(items)})
}

// handlePortalCAChain GET /api/portal/pki/cas/{uuid}/chain
// 返回公开 CA 的 PEM 证书链；未公开的 CA 一律视为不存在。
func (s *Server) handlePortalCAChain(w http.ResponseWriter, r *http.Request) {
	caUUID := r.PathValue("uuid")

	var isPublic int
	if err := s.db.QueryRowContext(r.Context(),
		`SELECT is_public FROM cas WHERE uuid = ?`, caUUID).Scan(&isPublic); err != nil {
		writeError(w, http.StatusNotFound, "CA 不存在")
		return
	}
	if isPublic != 1 {
		writeError(w, http.StatusNotFound, "CA 不存在")
		return
	}

	chain, err := s.caSvc.GetChain(r.Context(), caUUID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, chain) //nolint:errcheck
}

// handleUpdateCAPublish PUT /api/cas/{uuid}/publish（管理员）
// 控制某个 CA 是否出现在门户公开信任目录中。
func (s *Server) handleUpdateCAPublish(w http.ResponseWriter, r *http.Request) {
	caUUID := r.PathValue("uuid")

	var req struct {
		Public bool `json:"public"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}

	// 已吊销/已过期的 CA 不允许公开
	if req.Public {
		var status string
		if err := s.db.QueryRowContext(r.Context(),
			`SELECT status FROM cas WHERE uuid = ?`, caUUID).Scan(&status); err != nil {
			writeError(w, http.StatusNotFound, "CA 不存在")
			return
		}
		if status != "active" {
			writeError(w, http.StatusBadRequest, "仅可用于状态为 active 的 CA："+status)
			return
		}
	}

	res, err := s.db.ExecContext(r.Context(),
		`UPDATE cas SET is_public = ?, updated_at = ? WHERE uuid = ?`,
		boolToIntLocal(req.Public), time.Now(), caUUID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeError(w, http.StatusNotFound, "CA 不存在")
		return
	}

	s.auditLogRepo.Create(r.Context(), &storage.AuditLog{ //nolint:errcheck
		UserUUID:     claimsFromCtx(r.Context()).UserUUID,
		Action:       fmt.Sprintf("publish_ca:%t", req.Public),
		ResourceType: "ca",
		ResourceUUID: caUUID,
		IPAddress:    r.RemoteAddr,
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message":   "已更新公开状态",
		"ca_uuid":   caUUID,
		"is_public": req.Public,
	})
}

// formatFingerprint 把证书指纹格式化为常见的大写冒号分隔形式。
func formatFingerprint(b []byte) string {
	h := strings.ToUpper(hex.EncodeToString(b))
	parts := make([]string, 0, len(h)/2)
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}
