// Package api - handler_public_apply.go：公开证书申请（无需认证）。
//
// 门户用户无需登录即可提交证书申请，提交后获得申请 UUID，
// 可通过 UUID 查询审核状态。管理员在后台 CertApplications 页面审核。
package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/globaltrusts/server-card/internal/storage"
)

// PublicCertApplicationRequest 公开证书申请请求体。
// 与认证用户的 CertApplication 不同：
//   - 无 user_uuid（匿名）
//   - 需要填写联系邮箱（用于通知审核结果）
//   - 简化字段：域名列表 + 组织信息 + 密钥类型
type PublicCertApplicationRequest struct {
	// 必填
	Domains      []string `json:"domains"`       // 域名列表（SAN）
	Organization string   `json:"organization"`  // 组织名称
	Email        string   `json:"email"`         // 联系邮箱
	KeyType      string   `json:"key_type"`      // rsa2048 / rsa4096 / ecdsa-p256 / ecdsa-p384

	// 可选
	Country  string `json:"country,omitempty"`
	Province string `json:"province,omitempty"`
	Locality string `json:"locality,omitempty"`
	OrgUnit  string `json:"org_unit,omitempty"`
	Remark   string `json:"remark,omitempty"`
}

// handlePublicCreateCertApplication POST /api/public/cert-applications
// 无需认证，门户用户直接提交。
func (s *Server) handlePublicCreateCertApplication(w http.ResponseWriter, r *http.Request) {
	var req PublicCertApplicationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}

	// 基本校验
	if len(req.Domains) == 0 {
		writeError(w, http.StatusBadRequest, "至少需要一个域名")
		return
	}
	if req.Email == "" || !strings.Contains(req.Email, "@") {
		writeError(w, http.StatusBadRequest, "请提供有效的联系邮箱")
		return
	}
	if req.Organization == "" {
		writeError(w, http.StatusBadRequest, "组织名称不能为空")
		return
	}
	if req.KeyType == "" {
		req.KeyType = "ecdsa-p256" // 默认
	}

	// 构造 SubjectJSON
	subject := map[string]string{
		"CN": req.Domains[0],
		"O":  req.Organization,
	}
	if req.Country != "" {
		subject["C"] = req.Country
	}
	if req.Province != "" {
		subject["ST"] = req.Province
	}
	if req.Locality != "" {
		subject["L"] = req.Locality
	}
	if req.OrgUnit != "" {
		subject["OU"] = req.OrgUnit
	}
	subjectBytes, _ := json.Marshal(subject)

	// 构造 SANJSON
	sanEntries := make([]map[string]string, 0, len(req.Domains))
	for _, d := range req.Domains {
		sanEntries = append(sanEntries, map[string]string{"type": "dns", "value": d})
	}
	if req.Email != "" {
		sanEntries = append(sanEntries, map[string]string{"type": "email", "value": req.Email})
	}
	sanBytes, _ := json.Marshal(sanEntries)

	app := &storage.CertApplication{
		SubjectJSON: string(subjectBytes),
		SANJSON:     string(sanBytes),
		KeyType:     req.KeyType,
		UserUUID:    "public:" + req.Email, // 标记为公开申请，用邮箱作为标识
		Status:      "pending",
	}

	if err := s.workflowSvc.CreateApplication(r.Context(), app); err != nil {
		writeError(w, http.StatusInternalServerError, "提交申请失败: "+err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"uuid":    app.UUID,
		"status":  app.Status,
		"message": "证书申请已提交，请等待管理员审核。您可通过申请 UUID 查询审核状态。",
	})
}

// handlePublicGetCertApplicationStatus GET /api/public/cert-applications/{uuid}
// 无需认证，通过 UUID 查询申请状态。
func (s *Server) handlePublicGetCertApplicationStatus(w http.ResponseWriter, r *http.Request) {
	appUUID := r.PathValue("uuid")
	if appUUID == "" {
		writeError(w, http.StatusBadRequest, "缺少申请 UUID")
		return
	}

	app, err := s.workflowSvc.GetApplication(r.Context(), appUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, "申请不存在")
		return
	}

	// 公开查询只返回有限信息
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"uuid":          app.UUID,
		"status":        app.Status,
		"reject_reason": app.RejectReason,
		"created_at":    app.CreatedAt,
		"updated_at":    app.UpdatedAt,
	})
}
