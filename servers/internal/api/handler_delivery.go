// Package api - handler_delivery.go：证书交付（公开材料与受控私钥下发）。
//
// 与 `GET /api/certs/{uuid}/export`（面向下载文件的浏览器场景）不同，
// 本文件提供客户端可编程调用的一次性交付接口，契约对齐客户端
// `cloud.DeliveredCert`：POST /api/certificates/{uuid}/download。
//
// 安全边界：
//   - 公开材料（证书、证书链）只要求登录 + 归属校验；
//   - 私钥交付额外要求：证书关联的密钥存储模板允许文件下载、下发额度未用尽，
//     并记录下发流水，管理员身份不会绕过模板策略。
package api

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/globaltrusts/server-card/internal/auth"
	"github.com/globaltrusts/server-card/internal/keybackend"
	"github.com/globaltrusts/server-card/internal/storage"
)

// deliverCertRequest 是交付请求体。
type deliverCertRequest struct {
	// IncludeKey 为 true 时才尝试交付私钥；默认只交付公开材料
	IncludeKey bool `json:"include_key"`
	// Password 用于同时生成受保护的 PKCS#12（可选）
	Password string `json:"password,omitempty"`
	// Method 记录下发方式，默认 download
	Method string `json:"method,omitempty"`
	// DeviceInfo 记录目标设备信息（便于审计）
	DeviceInfo string `json:"device_info,omitempty"`
}

// deliveredCert 是交付响应，字段命名与客户端 DeliveredCert 对齐。
type deliveredCert struct {
	CertPEM      string   `json:"cert_pem"`
	KeyPEM       string   `json:"key_pem,omitempty"`
	ChainPEM     string   `json:"chain_pem,omitempty"`
	PFXBase64    string   `json:"pfx_base64,omitempty"`
	Algorithm    string   `json:"algorithm"`
	CanRedeliver bool     `json:"can_redeliver"`
	Remaining    int      `json:"remaining_deliveries"`
	SerialNumber string   `json:"serial_number"`
	CommonName   string   `json:"common_name"`
	NotBefore    string   `json:"not_before"`
	NotAfter     string   `json:"not_after"`
	Revoked      bool     `json:"revoked"`
	SANs         []string `json:"sans,omitempty"`
}

// normalizeCertPEM 把 PEM 或 DER 证书统一为 PEM 文本。
//
// 历史上不同签发路径分别写入了 PEM 与 DER，这里做一次归一化，
// 避免出现"二次 PEM 包装"导致解析失败。
func normalizeCertPEM(raw []byte) (string, error) {
	if len(raw) == 0 {
		return "", fmt.Errorf("证书内容为空")
	}
	if block, _ := pem.Decode(raw); block != nil {
		return string(raw), nil
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})), nil
}

// handleDeliverCertificate POST /api/certificates/{uuid}/download
func (s *Server) handleDeliverCertificate(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	certUUID := r.PathValue("uuid")

	var req deliverCertRequest
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req) //nolint:errcheck
	}
	if req.Method == "" {
		req.Method = "download"
	}

	certRepo := storage.NewCertRepo(s.db)
	cert, err := certRepo.GetByUUID(r.Context(), certUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, "证书不存在")
		return
	}

	// 归属校验：优先按证书归属，兼容仅能通过卡片判断归属的历史数据
	if !s.canAccessCert(r, cert, claims) {
		writeError(w, http.StatusForbidden, "无权访问此证书")
		return
	}

	certPEM, err := normalizeCertPEM(cert.CertContent)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	resp := &deliveredCert{
		CertPEM:      certPEM,
		Algorithm:    cert.KeyType,
		SerialNumber: cert.SerialNumber,
		CommonName:   cert.SubjectDN,
		Revoked:      cert.RevocationStatus == "revoked",
		SANs:         collectSANs(cert),
	}
	if cert.NotBefore != nil {
		resp.NotBefore = cert.NotBefore.Format(time.RFC3339)
	}
	if cert.NotAfter != nil {
		resp.NotAfter = cert.NotAfter.Format(time.RFC3339)
	}
	if cert.CAUUID != "" && s.caSvc != nil {
		if chain, err := s.caSvc.GetChain(r.Context(), cert.CAUUID); err == nil {
			resp.ChainPEM = chain
		}
	}

	// 仅交付公开材料
	if !req.IncludeKey {
		resp.CanRedeliver = true
		resp.Remaining = -1
		writeJSON(w, http.StatusOK, resp)
		return
	}

	// ---- 以下为私钥交付，需要策略与额度校验 ----
	// 私钥位于 TPM/HSM 时由硬件保护，PKCS#12 必须内嵌明文私钥，无法交付
	if keybackend.IsHardware(cert.KeyBackend) {
		writeError(w, http.StatusBadRequest, fmt.Sprintf(
			"该证书的私钥位于 %s，由硬件保护不可导出，无法交付私钥材料；"+
				"请改用云卡远程签名接口，或把证书签发到「本地加密存储」存储区域",
			keybackend.DriverText(cert.KeyBackend)))
		return
	}
	if len(cert.PrivateData) == 0 {
		writeError(w, http.StatusBadRequest, "该证书没有托管的私钥，无法下发私钥材料")
		return
	}

	keyStorage, err := s.resolveKeyStorageTemplate(r, cert)
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	keyStorageTmplUUID := keyStorage.UUID

	// 下载格式以签发时的密钥存储模板快照为准：模板只提供 PEM 时不能打包 PKCS#12
	formats := parseJSONStringArrayLocal(keyStorage.DownloadFormats)
	if req.Password != "" {
		if isSM2CertKeyType(cert.KeyType) {
			writeError(w, http.StatusBadRequest, "国密 SM2 证书不提供 PKCS#12，请下载 PEM 证书与私钥")
			return
		}
		if len(formats) > 0 && !containsStrLocal(formats, "pkcs12") {
			writeError(w, http.StatusBadRequest, "该证书的存储策略不允许导出 PKCS#12")
			return
		}
	}
	if len(formats) > 0 && !containsStrLocal(formats, "pem") && req.Password == "" {
		writeError(w, http.StatusBadRequest, "该证书的存储策略只允许导出 PKCS#12，请设置导出密码")
		return
	}

	remaining, err := s.tmplSvc.CheckReissue(r.Context(), cert.UUID, keyStorageTmplUUID)
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}

	keyPEM, err := s.cardSvc.ExportPrivateKeyPEM(r.Context(), cert)
	if err != nil {
		// 私钥不可导出属于策略限制而非服务故障，返回 400 便于调用方区分
		if errors.Is(err, keybackend.ErrNotExportable) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// 可选：同时给出受口令保护的 PKCS#12
	if req.Password != "" {
		pfx, err := s.cardSvc.ExportPKCS12(r.Context(), cert, req.Password, []string{resp.ChainPEM})
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		resp.PFXBase64 = base64.StdEncoding.EncodeToString(pfx)
	}

	// 先记录下发流水与额度，成功后再返回材料
	deviceInfo := req.DeviceInfo
	if deviceInfo == "" {
		deviceInfo = r.UserAgent()
	}
	if err := s.tmplSvc.RecordReissue(r.Context(), cert.UUID, keyStorageTmplUUID,
		claims.UserUUID, req.Method, deviceInfo); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}

	resp.KeyPEM = keyPEM
	resp.Remaining = remaining - 1
	resp.CanRedeliver = remaining < 0 || remaining > 1

	s.auditLogRepo.Create(r.Context(), &storage.AuditLog{ //nolint:errcheck
		UserUUID:     claims.UserUUID,
		Action:       "deliver_cert_private_key",
		ResourceType: "certificate",
		ResourceUUID: cert.UUID,
		Detail:       fmt.Sprintf(`{"method":%q,"device":%q}`, req.Method, deviceInfo),
		IPAddress:    r.RemoteAddr,
	})

	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, resp)
}

// canAccessCert 判断当前用户是否可以访问该证书。
//
// 新流程签发的证书直接带 UserUUID；历史证书可能为空，此时回退到卡片归属判断，
// 避免"证书没有卡片就一律拒绝"而阻断合法用户。
func (s *Server) canAccessCert(r *http.Request, cert *storage.Certificate, claims *auth.Claims) bool {
	if auth.IsAdmin(claims.Role) {
		return true
	}
	if cert.UserUUID != "" {
		return cert.UserUUID == claims.UserUUID
	}
	if cert.CardUUID == "" {
		return false
	}
	_, err := s.cardSvc.GetCard(r.Context(), cert.CardUUID, claims.UserUUID)
	return err == nil
}

// isSM2CertKeyType 判断证书密钥算法是否为国密 SM2。
func isSM2CertKeyType(keyType string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(keyType)), "sm2")
}

// resolveKeyStorageTemplate 解析证书适用的密钥存储模板，并校验允许文件下载。
//
// 优先使用证书上保存的模板快照（key_storage_tmpl_uuid）：之后修改模板只影响新签发的证书，
// 已签发证书的下发格式与次数上限始终按签发当时的约定执行；历史证书没有快照时回退到
// 颁发模板当前关联的密钥存储模板。
//
// 任何一环缺失都直接拒绝：敏感导出不能因为"配置为空"而放行。
func (s *Server) resolveKeyStorageTemplate(r *http.Request, cert *storage.Certificate) (*storage.KeyStorageTemplate, error) {
	if s.tmplSvc == nil {
		return nil, fmt.Errorf("模板服务不可用，禁止导出私钥")
	}
	var ks *storage.KeyStorageTemplate
	if cert.KeyStorageTmplUUID != "" {
		loaded, err := s.tmplSvc.GetByUUID(r.Context(), cert.KeyStorageTmplUUID)
		if err != nil {
			return nil, fmt.Errorf("读取密钥存储模板失败，禁止导出私钥: %w", err)
		}
		ks = loaded
	} else {
		if cert.IssuanceTmplUUID == "" || s.issuanceSvc == nil {
			return nil, fmt.Errorf("该证书未关联颁发模板，未配置密钥存储策略，禁止导出私钥")
		}
		tmpl, err := s.issuanceSvc.GetIssuanceTemplate(r.Context(), cert.IssuanceTmplUUID)
		if err != nil {
			return nil, fmt.Errorf("读取颁发模板失败，禁止导出私钥: %w", err)
		}
		if tmpl.KeyStorageTmplUUID == "" {
			return nil, fmt.Errorf("颁发模板未关联密钥存储模板，禁止导出私钥")
		}
		loaded, err := s.tmplSvc.GetByUUID(r.Context(), tmpl.KeyStorageTmplUUID)
		if err != nil {
			return nil, fmt.Errorf("读取密钥存储模板失败，禁止导出私钥: %w", err)
		}
		ks = loaded
	}
	if ks.KeyGenLocation == storage.KeyGenCSR {
		return nil, fmt.Errorf("该证书的私钥由申请者自行保管，平台没有可下发的私钥")
	}
	if !ks.HasMethod(storage.StorageFileDownload) {
		return nil, fmt.Errorf("该证书的密钥存储策略为「%s」，不允许导出私钥", ks.Name)
	}
	return ks, nil
}

// collectSANs 汇总证书的 SAN 列表，供客户端展示。
func collectSANs(cert *storage.Certificate) []string {
	sans := make([]string, 0, 8)
	appendJSONArray := func(raw, prefix string) {
		if strings.TrimSpace(raw) == "" {
			return
		}
		var items []string
		if err := json.Unmarshal([]byte(raw), &items); err != nil {
			return
		}
		for _, item := range items {
			if item != "" {
				sans = append(sans, prefix+item)
			}
		}
	}
	appendJSONArray(cert.SANDNS, "")
	appendJSONArray(cert.SANIP, "")
	appendJSONArray(cert.SANEmail, "email:")
	appendJSONArray(cert.SANURI, "uri:")
	return sans
}
