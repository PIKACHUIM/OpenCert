package api

import (
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

// ---- 证书开通模板（证书申请模板）处理器 ----
//
// 职责划分：
//   - 颁发模板：怎么签（CA 候选、有效期、算法、KU/EKU、扩展、密钥存储）
//   - 开通模板：怎么申请（绑定颁发模板 + 主体模板 + 扩展信息模板 + 审批/续期策略）
//   - 商品规格：怎么卖（价格、库存、SAN 数量与格式限制）

const certApplyTemplateColumns = `uuid, name, issuance_tmpl_uuid, valid_days, ca_uuid, enabled, require_approval,
	allow_renewal, allowed_key_types, price_cents, description, subject_tmpl_uuid, extension_tmpl_uuid,
	created_at, updated_at`

func scanCertApplyTemplate(scan func(dest ...interface{}) error) (*storage.CertApplyTemplate, error) {
	t := &storage.CertApplyTemplate{}
	var enabled, requireApproval, allowRenewal int
	if err := scan(&t.UUID, &t.Name, &t.IssuanceTmplUUID, &t.ValidDays, &t.CAUUID,
		&enabled, &requireApproval, &allowRenewal, &t.AllowedKeyTypes, &t.PriceCents, &t.Description,
		&t.SubjectTmplUUID, &t.ExtensionTmplUUID, &t.CreatedAt, &t.UpdatedAt); err != nil {
		return nil, err
	}
	t.Enabled = enabled == 1
	t.RequireApproval = requireApproval == 1
	t.AllowRenewal = allowRenewal == 1
	return t, nil
}

// handleListCertApplyTemplates 查询证书申请模板列表。
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

	templates := []*storage.CertApplyTemplate{}
	for rows.Next() {
		t, err := scanCertApplyTemplate(rows.Scan)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		templates = append(templates, t)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": templates, "total": len(templates)})
}

// handleGetCertApplyTemplate 查询单个证书申请模板。
func (s *Server) handleGetCertApplyTemplate(w http.ResponseWriter, r *http.Request) {
	row := s.db.QueryRowContext(r.Context(),
		`SELECT `+certApplyTemplateColumns+` FROM cert_apply_templates WHERE uuid = ?`, r.PathValue("uuid"))
	t, err := scanCertApplyTemplate(row.Scan)
	if err != nil {
		writeError(w, http.StatusNotFound, "证书申请模板不存在")
		return
	}
	writeJSON(w, http.StatusOK, t)
}

// validateCertApplyTemplate 校验开通模板的引用关系，避免保存后签发时才发现配置断链。
func (s *Server) validateCertApplyTemplate(r *http.Request, t *storage.CertApplyTemplate) error {
	if t.Name == "" {
		return fmt.Errorf("模板名称不能为空")
	}
	if t.IssuanceTmplUUID == "" {
		return fmt.Errorf("请选择颁发模板")
	}
	exists := func(table, id string) bool {
		if id == "" {
			return true
		}
		var n int
		err := s.db.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM `+table+` WHERE uuid = ?`, id).Scan(&n)
		return err == nil && n > 0
	}
	if !exists("issuance_templates", t.IssuanceTmplUUID) {
		return fmt.Errorf("颁发模板不存在")
	}
	if !exists("subject_templates", t.SubjectTmplUUID) {
		return fmt.Errorf("主体模板不存在")
	}
	if !exists("extension_templates", t.ExtensionTmplUUID) {
		return fmt.Errorf("扩展信息模板不存在")
	}
	if !exists("cas", t.CAUUID) {
		return fmt.Errorf("指定的签发 CA 不存在")
	}
	if t.ValidDays < 0 || t.ValidDays > 3650 {
		return fmt.Errorf("有效期需在 0-3650 天之间（0 表示使用颁发模板缺省值）")
	}
	var keyTypes []string
	if t.AllowedKeyTypes == "" {
		t.AllowedKeyTypes = `["ec256","rsa2048"]`
	}
	if err := json.Unmarshal([]byte(t.AllowedKeyTypes), &keyTypes); err != nil || len(keyTypes) == 0 {
		return fmt.Errorf("允许的密钥算法格式错误")
	}
	return nil
}

// handleCreateCertApplyTemplate 创建证书申请模板（管理员）。
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
		`INSERT INTO cert_apply_templates (uuid, name, issuance_tmpl_uuid, valid_days, ca_uuid, enabled, require_approval,
		 allow_renewal, allowed_key_types, price_cents, description, subject_tmpl_uuid, extension_tmpl_uuid, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.UUID, t.Name, t.IssuanceTmplUUID, t.ValidDays, t.CAUUID,
		storage.BoolToInt(t.Enabled), storage.BoolToInt(t.RequireApproval), storage.BoolToInt(t.AllowRenewal),
		t.AllowedKeyTypes, t.PriceCents, t.Description, t.SubjectTmplUUID, t.ExtensionTmplUUID, t.CreatedAt, t.UpdatedAt,
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

// handleUpdateCertApplyTemplate 更新证书申请模板（管理员）。
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
		`UPDATE cert_apply_templates SET name=?, issuance_tmpl_uuid=?, valid_days=?, ca_uuid=?, enabled=?, require_approval=?,
		 allow_renewal=?, allowed_key_types=?, price_cents=?, description=?, subject_tmpl_uuid=?, extension_tmpl_uuid=?, updated_at=?
		 WHERE uuid=?`,
		t.Name, t.IssuanceTmplUUID, t.ValidDays, t.CAUUID,
		storage.BoolToInt(t.Enabled), storage.BoolToInt(t.RequireApproval), storage.BoolToInt(t.AllowRenewal),
		t.AllowedKeyTypes, t.PriceCents, t.Description, t.SubjectTmplUUID, t.ExtensionTmplUUID, time.Now(), tmplUUID,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeError(w, http.StatusNotFound, "证书申请模板不存在")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "证书申请模板已更新"})
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
