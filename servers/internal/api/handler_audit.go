package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/globaltrusts/server-card/internal/auth"
	"github.com/globaltrusts/server-card/internal/storage"
	"github.com/google/uuid"
)

// ---- 审计日志处理器 ----

// handleListAuditLogs 分页查询审计日志（管理员）。
func (s *Server) handleListAuditLogs(w http.ResponseWriter, r *http.Request) {
	userUUID := r.URL.Query().Get("user_uuid")
	action := r.URL.Query().Get("action")
	resourceType := r.URL.Query().Get("resource_type")
	page, pageSize := parsePagination(r)

	logs, total, integrityBroken, err := s.auditLogRepo.List(r.Context(), userUUID, action, resourceType, page, pageSize)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if logs == nil {
		logs = []*storage.AuditLog{}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items":            logs,
		"total":            total,
		"page":             page,
		"page_size":        pageSize,
		"integrity_broken": integrityBroken,
	})
}

// ---- 证书开通模板处理器 ----
//
// 职责划分（不允许同一属性两处配置）：
//   - 颁发模板：怎么签（CA 候选与默认值、有效期、算法、KU/EKU、扩展、密钥存储、主体、扩展信息）
//   - 开通模板：谁、在什么条件下可以申请（绑定颁发模板 + 审批/续期策略 + 可申请方式）
//   - 商品规格：怎么卖（价格、库存、在颁发模板允许范围内收窄的有效期/算法/交付方式、SAN 限制）

const certApplyTemplateColumns = `uuid, name, issuance_tmpl_uuid, enabled, require_approval,
	allow_renewal, apply_modes, description, created_at, updated_at`

func scanCertApplyTemplate(scan func(dest ...interface{}) error) (*storage.CertApplyTemplate, error) {
	t := &storage.CertApplyTemplate{}
	var enabled, requireApproval, allowRenewal int
	if err := scan(&t.UUID, &t.Name, &t.IssuanceTmplUUID,
		&enabled, &requireApproval, &allowRenewal, &t.ApplyModes, &t.Description,
		&t.CreatedAt, &t.UpdatedAt); err != nil {
		return nil, err
	}
	t.Enabled = enabled == 1
	t.RequireApproval = requireApproval == 1
	t.AllowRenewal = allowRenewal == 1
	return t, nil
}

// certApplyTemplateWithInherited 是开通模板 + 继承自颁发模板的只读摘要
// （前端用于在开通模板页面展示"继承自颁发模板"的 CA/有效期/算法/资料要求）。
type certApplyTemplateWithInherited struct {
	*storage.CertApplyTemplate
	Inherited *inheritedSummary `json:"inherited,omitempty"`
}

type inheritedSummary struct {
	CAUUIDs           []string `json:"ca_uuids"`
	DefaultCAUUID     string   `json:"default_ca_uuid"`
	ValidDays         []int    `json:"valid_days"`
	DefaultValidDays  int      `json:"default_valid_days"`
	AllowedKeyTypes   []string `json:"allowed_key_types"`
	SubjectTmplUUID   string   `json:"subject_tmpl_uuid"`
	ExtensionTmplUUID string   `json:"extension_tmpl_uuid"`
}

// buildInheritedSummary 读取开通模板关联的颁发模板，组装继承摘要；
// 颁发模板不存在时返回 nil（由调用方决定如何提示）。
func (s *Server) buildInheritedSummary(ctx context.Context, issuanceTmplUUID string) *inheritedSummary {
	if issuanceTmplUUID == "" || s.issuanceSvc == nil {
		return nil
	}
	tmpl, err := s.issuanceSvc.GetIssuanceTemplate(ctx, issuanceTmplUUID)
	if err != nil {
		return nil
	}
	sum := &inheritedSummary{
		DefaultCAUUID:     tmpl.DefaultCAUUID,
		DefaultValidDays:  tmpl.DefaultValidDays,
		SubjectTmplUUID:   tmpl.SubjectTmplUUID,
		ExtensionTmplUUID: tmpl.ExtensionTmplUUID,
	}
	json.Unmarshal([]byte(tmpl.AllowedCAUUIDs), &sum.CAUUIDs)          //nolint:errcheck
	json.Unmarshal([]byte(tmpl.ValidDays), &sum.ValidDays)             //nolint:errcheck
	json.Unmarshal([]byte(tmpl.AllowedKeyTypes), &sum.AllowedKeyTypes) //nolint:errcheck
	return sum
}

// handleListCertApplyTemplates 查询证书开通模板列表。
func (s *Server) handleListCertApplyTemplates(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	onlyEnabled := !auth.IsAdmin(claims.Role) // 管理员可以查看所有模板（包括禁用的）

	rows, err := s.db.QueryContext(r.Context(),
		`SELECT `+certApplyTemplateColumns+` FROM cert_apply_templates WHERE (? = 0 OR enabled = 1) ORDER BY created_at DESC`,
		boolToIntLocal(onlyEnabled),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	templates := []*certApplyTemplateWithInherited{}
	for rows.Next() {
		t, err := scanCertApplyTemplate(rows.Scan)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		templates = append(templates, &certApplyTemplateWithInherited{
			CertApplyTemplate: t,
			Inherited:         s.buildInheritedSummary(r.Context(), t.IssuanceTmplUUID),
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": templates, "total": len(templates)})
}

// handleGetCertApplyTemplate 查询单个证书开通模板（含继承摘要）。
func (s *Server) handleGetCertApplyTemplate(w http.ResponseWriter, r *http.Request) {
	row := s.db.QueryRowContext(r.Context(),
		`SELECT `+certApplyTemplateColumns+` FROM cert_apply_templates WHERE uuid = ?`, r.PathValue("uuid"))
	t, err := scanCertApplyTemplate(row.Scan)
	if err != nil {
		writeError(w, http.StatusNotFound, "证书开通模板不存在")
		return
	}
	writeJSON(w, http.StatusOK, &certApplyTemplateWithInherited{
		CertApplyTemplate: t,
		Inherited:         s.buildInheritedSummary(r.Context(), t.IssuanceTmplUUID),
	})
}

// validApplyModes 是可申请方式的合法取值集合。
var validApplyModes = map[string]bool{"order": true, "self": true, "subscription": true}

// validateCertApplyTemplate 只校验业务字段：名称、关联颁发模板是否存在、可申请方式是否合法。
// CA、有效期、算法、资料要求均继承自颁发模板，不在这里重复校验。
func (s *Server) validateCertApplyTemplate(r *http.Request, t *storage.CertApplyTemplate) error {
	if t.Name == "" {
		return fmt.Errorf("模板名称不能为空")
	}
	if t.IssuanceTmplUUID == "" {
		return fmt.Errorf("请选择颁发模板")
	}
	var n int
	if err := s.db.QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM issuance_templates WHERE uuid = ?`, t.IssuanceTmplUUID).Scan(&n); err != nil || n == 0 {
		return fmt.Errorf("颁发模板不存在")
	}
	if t.ApplyModes == "" {
		t.ApplyModes = `["order","self","subscription"]`
	}
	var modes []string
	if err := json.Unmarshal([]byte(t.ApplyModes), &modes); err != nil || len(modes) == 0 {
		return fmt.Errorf("可申请方式格式错误")
	}
	for _, m := range modes {
		if !validApplyModes[m] {
			return fmt.Errorf("不支持的申请方式: %s", m)
		}
	}
	return nil
}

// handleCreateCertApplyTemplate 创建证书开通模板（管理员）。
func (s *Server) handleCreateCertApplyTemplate(w http.ResponseWriter, r *http.Request) {
	var t storage.CertApplyTemplate
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if err := s.validateCertApplyTemplate(r, &t); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	t.UUID = uuid.New().String()
	t.CreatedAt = time.Now()
	t.UpdatedAt = t.CreatedAt

	_, err := s.db.ExecContext(r.Context(),
		`INSERT INTO cert_apply_templates (uuid, name, issuance_tmpl_uuid, enabled, require_approval,
		 allow_renewal, apply_modes, description, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.UUID, t.Name, t.IssuanceTmplUUID,
		storage.BoolToInt(t.Enabled), storage.BoolToInt(t.RequireApproval), storage.BoolToInt(t.AllowRenewal),
		t.ApplyModes, t.Description, t.CreatedAt, t.UpdatedAt,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	claims := claimsFromCtx(r.Context())
	s.auditLogRepo.Create(r.Context(), &storage.AuditLog{ //nolint:errcheck
		UserUUID:     claims.UserUUID,
		Action:       "create_cert_apply_template",
		ResourceType: "cert_apply_template",
		ResourceUUID: t.UUID,
		Detail:       fmt.Sprintf(`{"name":%q}`, t.Name),
		IPAddress:    r.RemoteAddr,
	})
	writeJSON(w, http.StatusCreated, t)
}

// handleUpdateCertApplyTemplate 更新证书开通模板（管理员）。
func (s *Server) handleUpdateCertApplyTemplate(w http.ResponseWriter, r *http.Request) {
	tmplUUID := r.PathValue("uuid")
	var t storage.CertApplyTemplate
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if err := s.validateCertApplyTemplate(r, &t); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	res, err := s.db.ExecContext(r.Context(),
		`UPDATE cert_apply_templates SET name=?, issuance_tmpl_uuid=?, enabled=?, require_approval=?,
		 allow_renewal=?, apply_modes=?, description=?, updated_at=?
		 WHERE uuid=?`,
		t.Name, t.IssuanceTmplUUID,
		storage.BoolToInt(t.Enabled), storage.BoolToInt(t.RequireApproval), storage.BoolToInt(t.AllowRenewal),
		t.ApplyModes, t.Description, time.Now(), tmplUUID,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeError(w, http.StatusNotFound, "证书开通模板不存在")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "证书开通模板已更新"})
}

// handleDeleteCertApplyTemplate 删除证书申请模板（管理员）。
// 已被商品规格或订单引用的模板不能删除，只能停用，避免历史订单无法签发。
func (s *Server) handleDeleteCertApplyTemplate(w http.ResponseWriter, r *http.Request) {
	tmplUUID := r.PathValue("uuid")
	var refs int
	err := s.db.QueryRowContext(r.Context(),
		`SELECT (SELECT COUNT(*) FROM portal_product_skus WHERE cert_apply_tmpl_uuid = ?) +
		        (SELECT COUNT(*) FROM cert_orders WHERE cert_apply_tmpl_uuid = ?)`, tmplUUID, tmplUUID).Scan(&refs)
	if err != nil && err != sql.ErrNoRows {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if refs > 0 {
		writeError(w, http.StatusConflict, "该模板已被商品规格或订单引用，请改为停用")
		return
	}
	if _, err := s.db.ExecContext(r.Context(), `DELETE FROM cert_apply_templates WHERE uuid = ?`, tmplUUID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "证书申请模板已删除"})
}
