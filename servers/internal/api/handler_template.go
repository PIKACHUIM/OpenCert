package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/globaltrusts/server-card/internal/identity"
	"github.com/globaltrusts/server-card/internal/storage"
	"github.com/google/uuid"
)

// ---- 密钥存储类型模板处理器 ----

func (s *Server) handleListKeyStorageTemplates(w http.ResponseWriter, r *http.Request) {
	templates, err := s.tmplSvc.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"templates": templates,
		"total":     len(templates),
	})
}

// KeyStorageTemplateRequest 是创建/更新密钥存储类型模板的请求体。
type KeyStorageTemplateRequest struct {
	Name            string   `json:"name"`
	StorageMethods  uint32   `json:"storage_methods"`
	SecurityLevel   string   `json:"security_level"`
	AllowReimport   bool     `json:"allow_reimport"`
	CloudBackup     bool     `json:"cloud_backup"`
	AllowReissue    bool     `json:"allow_reissue"`
	MaxReissueCount int      `json:"max_reissue_count"`
	StorageZoneUUID string   `json:"storage_zone_uuid"`
	KeyGenLocation  string   `json:"key_gen_location"`
	DownloadFormats []string `json:"download_formats"`
}

func (req *KeyStorageTemplateRequest) toTemplate() *storage.KeyStorageTemplate {
	formats := req.DownloadFormats
	if formats == nil {
		formats = []string{"pem", "pkcs12"}
	}
	rawFormats, _ := json.Marshal(formats)
	return &storage.KeyStorageTemplate{
		Name:            req.Name,
		StorageMethods:  storage.StorageMethod(req.StorageMethods),
		SecurityLevel:   storage.SecurityLevel(req.SecurityLevel),
		AllowReimport:   req.AllowReimport,
		CloudBackup:     req.CloudBackup,
		AllowReissue:    req.AllowReissue,
		MaxReissueCount: req.MaxReissueCount,
		StorageZoneUUID: req.StorageZoneUUID,
		KeyGenLocation:  req.KeyGenLocation,
		DownloadFormats: string(rawFormats),
	}
}

func (s *Server) handleCreateKeyStorageTemplate(w http.ResponseWriter, r *http.Request) {
	var req KeyStorageTemplateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}

	tmpl := req.toTemplate()
	if err := s.tmplSvc.Create(r.Context(), tmpl); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, tmpl)
}

func (s *Server) handleGetKeyStorageTemplate(w http.ResponseWriter, r *http.Request) {
	templateUUID := r.PathValue("uuid")
	tmpl, err := s.tmplSvc.GetByUUID(r.Context(), templateUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, tmpl)
}

func (s *Server) handleUpdateKeyStorageTemplate(w http.ResponseWriter, r *http.Request) {
	var req KeyStorageTemplateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}

	tmpl := req.toTemplate()
	tmpl.UUID = r.PathValue("uuid")
	if err := s.tmplSvc.Update(r.Context(), tmpl); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, tmpl)
}

func (s *Server) handleDeleteKeyStorageTemplate(w http.ResponseWriter, r *http.Request) {
	templateUUID := r.PathValue("uuid")
	if err := s.tmplSvc.Delete(r.Context(), templateUUID); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "模板已删除"})
}

// ---- 颁发模板处理器 ----

func (s *Server) handleListIssuanceTemplates(w http.ResponseWriter, r *http.Request) {
	category := r.URL.Query().Get("category")
	templates, err := s.issuanceSvc.ListIssuanceTemplates(r.Context(), category, false)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"templates": templates, "total": len(templates)})
}

func (s *Server) handleCreateIssuanceTemplate(w http.ResponseWriter, r *http.Request) {
	var t storage.IssuanceTemplate
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if err := s.issuanceSvc.CreateIssuanceTemplate(r.Context(), &t); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, t)
}

func (s *Server) handleGetIssuanceTemplate(w http.ResponseWriter, r *http.Request) {
	tmplUUID := r.PathValue("uuid")
	t, err := s.issuanceSvc.GetIssuanceTemplate(r.Context(), tmplUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, t)
}

func (s *Server) handleUpdateIssuanceTemplate(w http.ResponseWriter, r *http.Request) {
	tmplUUID := r.PathValue("uuid")
	var t storage.IssuanceTemplate
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	t.UUID = tmplUUID
	if err := s.issuanceSvc.UpdateIssuanceTemplate(r.Context(), &t); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "颁发模板已更新"})
}

func (s *Server) handleDeleteIssuanceTemplate(w http.ResponseWriter, r *http.Request) {
	tmplUUID := r.PathValue("uuid")
	if err := s.issuanceSvc.DeleteIssuanceTemplate(r.Context(), tmplUUID); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "颁发模板已删除"})
}

func (s *Server) handleListSubjectTemplates(w http.ResponseWriter, r *http.Request) {
	templates, err := s.issuanceSvc.ListSubjectTemplates(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"templates": templates, "total": len(templates)})
}

// validateSubjectTemplate 规范化并校验主体模板（字段定义、有效期、认证接口）。
func (s *Server) validateSubjectTemplate(r *http.Request, t *storage.SubjectTemplate) error {
	if strings.TrimSpace(t.Name) == "" {
		return fmt.Errorf("模板名称不能为空")
	}
	fields, err := identity.ParseSubjectFields(t.Fields)
	if err != nil {
		return err
	}
	if len(fields) == 0 {
		return fmt.Errorf("请至少配置一个主体字段")
	}
	raw, _ := json.Marshal(fields)
	t.Fields = string(raw)
	if _, err := identity.ParseValidity(t.VerifyValidity); err != nil {
		return err
	}
	if identity.SubjectVerifyMode(fields) == identity.VerifyAuto {
		if t.VerifyProviderUUID == "" {
			return fmt.Errorf("存在「自动接口」验证的字段，请选择实名认证接口")
		}
		if s.identityStore != nil {
			p, err := s.identityStore.Get(r.Context(), t.VerifyProviderUUID)
			if err != nil || p.Kind != identity.KindIdentity {
				return fmt.Errorf("所选实名认证接口不存在")
			}
		}
	}
	return nil
}

func (s *Server) handleCreateSubjectTemplate(w http.ResponseWriter, r *http.Request) {
	var t storage.SubjectTemplate
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if err := s.validateSubjectTemplate(r, &t); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.issuanceSvc.CreateSubjectTemplate(r.Context(), &t); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, t)
}

func (s *Server) handleUpdateSubjectTemplate(w http.ResponseWriter, r *http.Request) {
	var t storage.SubjectTemplate
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	t.UUID = r.PathValue("uuid")
	if err := s.validateSubjectTemplate(r, &t); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.issuanceSvc.UpdateSubjectTemplate(r.Context(), &t); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, t)
}

// handleSubjectFieldKeys GET /api/meta/subject-field-keys：主体模板可选字段。
func (s *Server) handleSubjectFieldKeys(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": identity.SubjectFieldKeys})
}

// normalizeExtensionTemplate 校验扩展信息模板的验证策略。
func normalizeExtensionTemplate(t *storage.ExtensionTemplate) error {
	if strings.TrimSpace(t.Name) == "" {
		return fmt.Errorf("模板名称不能为空")
	}
	p, err := identity.ParseExtensionPolicy(t.VerifyPolicy)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(p)
	t.VerifyPolicy = string(raw)
	// 兼容旧字段：数量限制已迁移到商品规格，此处不再限制
	t.MaxDNS, t.MaxEmail, t.MaxIP, t.MaxURI = 100, 100, 100, 100
	t.RequireDNSVerify = p.Domain.Mode != identity.VerifyNone
	t.RequireEmailVerify = p.Email.Mode != identity.VerifyNone
	if d, err := identity.ParseValidity(p.Domain.Validity); err == nil && d > 0 {
		t.VerifyExpiresDays = int(d.Hours()/24 + 0.5)
		if t.VerifyExpiresDays < 1 {
			t.VerifyExpiresDays = 1
		}
	}
	return nil
}

func (s *Server) handleUpdateExtensionTemplate(w http.ResponseWriter, r *http.Request) {
	var t storage.ExtensionTemplate
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	t.UUID = r.PathValue("uuid")
	if err := normalizeExtensionTemplate(&t); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.issuanceSvc.UpdateExtensionTemplate(r.Context(), &t); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, t)
}

func (s *Server) handleDeleteSubjectTemplate(w http.ResponseWriter, r *http.Request) {
	tmplUUID := r.PathValue("uuid")
	if err := s.issuanceSvc.DeleteSubjectTemplate(r.Context(), tmplUUID); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "主体模板已删除"})
}

func (s *Server) handleListExtensionTemplates(w http.ResponseWriter, r *http.Request) {
	templates, err := s.issuanceSvc.ListExtensionTemplates(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"templates": templates, "total": len(templates)})
}

func (s *Server) handleCreateExtensionTemplate(w http.ResponseWriter, r *http.Request) {
	var t storage.ExtensionTemplate
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if err := normalizeExtensionTemplate(&t); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.issuanceSvc.CreateExtensionTemplate(r.Context(), &t); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, t)
}

func (s *Server) handleDeleteExtensionTemplate(w http.ResponseWriter, r *http.Request) {
	tmplUUID := r.PathValue("uuid")
	if err := s.issuanceSvc.DeleteExtensionTemplate(r.Context(), tmplUUID); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "扩展信息模板已删除"})
}

func (s *Server) handleListKeyUsageTemplates(w http.ResponseWriter, r *http.Request) {
	templates, err := s.issuanceSvc.ListKeyUsageTemplates(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"templates": templates, "total": len(templates)})
}

func (s *Server) handleCreateKeyUsageTemplate(w http.ResponseWriter, r *http.Request) {
	var t storage.KeyUsageTemplate
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if err := normalizeKeyUsageTemplate(&t); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.issuanceSvc.CreateKeyUsageTemplate(r.Context(), &t); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, t)
}

func (s *Server) handleUpdateKeyUsageTemplate(w http.ResponseWriter, r *http.Request) {
	var t storage.KeyUsageTemplate
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	t.UUID = r.PathValue("uuid")
	if err := normalizeKeyUsageTemplate(&t); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.issuanceSvc.UpdateKeyUsageTemplate(r.Context(), &t); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, t)
}

// normalizeKeyUsageTemplate 校验密钥用途模板：名称必填，扩展密钥用途必须是合法 OID 的 JSON 数组。
func normalizeKeyUsageTemplate(t *storage.KeyUsageTemplate) error {
	if strings.TrimSpace(t.Name) == "" {
		return fmt.Errorf("模板名称不能为空")
	}
	if t.ExtKeyUsages == "" {
		t.ExtKeyUsages = "[]"
	}
	var ekus []string
	if err := json.Unmarshal([]byte(t.ExtKeyUsages), &ekus); err != nil {
		return fmt.Errorf("扩展密钥用途格式错误")
	}
	for _, e := range ekus {
		if !isValidOIDString(e) && !knownEKUName(e) {
			return fmt.Errorf("扩展密钥用途 %q 不是合法的 OID 或已知名称", e)
		}
	}
	return nil
}

// knownEKUName 判断是否为签发引擎认识的扩展密钥用途名称。
func knownEKUName(name string) bool {
	switch strings.ToLower(name) {
	case "serverauth", "clientauth", "codesigning", "emailprotection", "timestamping", "ocspsigning":
		return true
	}
	return false
}

// isValidOIDString 校验点分十进制 OID（至少两段，首段 0-2）。
func isValidOIDString(s string) bool {
	parts := strings.Split(strings.TrimSpace(s), ".")
	if len(parts) < 2 {
		return false
	}
	for i, p := range parts {
		if p == "" {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
		if i == 0 && p != "0" && p != "1" && p != "2" {
			return false
		}
	}
	return true
}

func (s *Server) handleDeleteKeyUsageTemplate(w http.ResponseWriter, r *http.Request) {
	tmplUUID := r.PathValue("uuid")
	if err := s.issuanceSvc.DeleteKeyUsageTemplate(r.Context(), tmplUUID); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "密钥用途模板已删除"})
}

// ---- 证书拓展模板处理器 ----

func (s *Server) handleListCertExtTemplates(w http.ResponseWriter, r *http.Request) {
	templates, err := s.issuanceSvc.ListCertExtTemplates(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"templates": templates, "total": len(templates)})
}

// validateCertExtTemplate 校验证书扩展模板：各列表字段必须是 JSON 字符串数组，
// 分发点 / 服务地址必须是 http(s) URL，EV 策略必须是合法 OID。
func validateCertExtTemplate(t *storage.CertExtTemplate) error {
	if strings.TrimSpace(t.Name) == "" {
		return fmt.Errorf("模板名称不能为空")
	}
	lists := []struct {
		label string
		value *string
		isURL bool
	}{
		{"CRL 分发点", &t.CRLDistPoints, true},
		{"OCSP 服务器", &t.OCSPServers, true},
		{"颁发者访问地址", &t.AIAIssuers, true},
		{"证书透明度服务器", &t.CTServers, true},
	}
	for _, l := range lists {
		if *l.value == "" {
			*l.value = "[]"
		}
		var items []string
		if err := json.Unmarshal([]byte(*l.value), &items); err != nil {
			return fmt.Errorf("%s格式错误", l.label)
		}
		for _, it := range items {
			if l.isURL && !strings.HasPrefix(it, "http://") && !strings.HasPrefix(it, "https://") {
				return fmt.Errorf("%s需为 http 或 https 地址: %s", l.label, it)
			}
		}
	}
	if t.EVPolicyOID != "" && !isValidOIDString(t.EVPolicyOID) {
		return fmt.Errorf("EV 策略 OID 格式错误")
	}
	if t.ASN1Extensions == "" {
		t.ASN1Extensions = "[]"
	}
	var exts []map[string]interface{}
	if err := json.Unmarshal([]byte(t.ASN1Extensions), &exts); err != nil {
		return fmt.Errorf("自定义扩展格式错误")
	}
	return nil
}

func (s *Server) handleCreateCertExtTemplate(w http.ResponseWriter, r *http.Request) {
	var t storage.CertExtTemplate
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if err := validateCertExtTemplate(&t); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.issuanceSvc.CreateCertExtTemplate(r.Context(), &t); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, t)
}

func (s *Server) handleUpdateCertExtTemplate(w http.ResponseWriter, r *http.Request) {
	var t storage.CertExtTemplate
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	t.UUID = r.PathValue("uuid")
	if err := validateCertExtTemplate(&t); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.issuanceSvc.UpdateCertExtTemplate(r.Context(), &t); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, t)
}

func (s *Server) handleDeleteCertExtTemplate(w http.ResponseWriter, r *http.Request) {
	tmplUUID := r.PathValue("uuid")
	if err := s.issuanceSvc.DeleteCertExtTemplate(r.Context(), tmplUUID); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "证书拓展模板已删除"})
}

// 存储区域处理器见 handler_storage_zone.go（支持数据库/TPM/HSM 驱动）。

// ---- OID 管理处理器 ----

func (s *Server) handleListOIDs(w http.ResponseWriter, r *http.Request) {
	usageType := r.URL.Query().Get("usage_type")
	query := `SELECT uuid, oid_value, name, description, usage_type, asn1_type, is_critical, created_at, updated_at FROM custom_oids`
	var args []interface{}
	if usageType != "" {
		query += ` WHERE usage_type = ?`
		args = append(args, usageType)
	}
	query += ` ORDER BY created_at DESC`
	rows, err := s.db.QueryContext(r.Context(), query, args...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	var oids []storage.CustomOID
	for rows.Next() {
		var o storage.CustomOID
		var isCritical int
		if err := rows.Scan(&o.UUID, &o.OIDValue, &o.Name, &o.Description, &o.UsageType, &o.ASN1Type, &isCritical, &o.CreatedAt, &o.UpdatedAt); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		o.IsCritical = isCritical == 1
		oids = append(oids, o)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"oids": oids, "total": len(oids)})
}

// validOIDUsageTypes 是自定义 OID 的用途分类。
var validOIDUsageTypes = map[string]bool{
	"ext_key_usage": true, "subject_field": true, "ev_policy": true, "asn1_extension": true,
}

// validASN1Types 是自定义扩展值支持的 ASN.1 类型。
var validASN1Types = map[string]bool{
	"UTF8String": true, "PrintableString": true, "IA5String": true, "OCTET STRING": true,
	"INTEGER": true, "BOOLEAN": true, "NULL": true,
}

// normalizeOID 校验并规范化自定义 OID。
func normalizeOID(o *storage.CustomOID) error {
	o.OIDValue = strings.TrimSpace(o.OIDValue)
	o.Name = strings.TrimSpace(o.Name)
	if o.OIDValue == "" || o.Name == "" {
		return fmt.Errorf("OID 值和名称不能为空")
	}
	if !isValidOIDString(o.OIDValue) {
		return fmt.Errorf("OID 格式错误，应为点分十进制，如 1.3.6.1.5.5.7.3.1")
	}
	if o.UsageType == "" {
		o.UsageType = "asn1_extension"
	}
	if !validOIDUsageTypes[o.UsageType] {
		return fmt.Errorf("不支持的 OID 用途: %s", o.UsageType)
	}
	if o.ASN1Type == "" {
		o.ASN1Type = "UTF8String"
	}
	if !validASN1Types[o.ASN1Type] {
		return fmt.Errorf("不支持的 ASN.1 类型: %s", o.ASN1Type)
	}
	return nil
}

func (s *Server) handleCreateOID(w http.ResponseWriter, r *http.Request) {
	var o storage.CustomOID
	if err := json.NewDecoder(r.Body).Decode(&o); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if err := normalizeOID(&o); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	o.UUID = uuid.New().String()
	o.CreatedAt = time.Now()
	o.UpdatedAt = o.CreatedAt
	_, err := s.db.ExecContext(r.Context(),
		`INSERT INTO custom_oids (uuid, oid_value, name, description, usage_type, asn1_type, is_critical, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		o.UUID, o.OIDValue, o.Name, o.Description, o.UsageType, o.ASN1Type, boolToIntLocal(o.IsCritical), o.CreatedAt, o.UpdatedAt)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			writeError(w, http.StatusConflict, "该 OID 已存在")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, o)
}

func (s *Server) handleUpdateOID(w http.ResponseWriter, r *http.Request) {
	var o storage.CustomOID
	if err := json.NewDecoder(r.Body).Decode(&o); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	o.UUID = r.PathValue("uuid")
	if err := normalizeOID(&o); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	res, err := s.db.ExecContext(r.Context(),
		`UPDATE custom_oids SET oid_value = ?, name = ?, description = ?, usage_type = ?, asn1_type = ?, is_critical = ?, updated_at = ?
		 WHERE uuid = ?`,
		o.OIDValue, o.Name, o.Description, o.UsageType, o.ASN1Type, boolToIntLocal(o.IsCritical), time.Now(), o.UUID)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			writeError(w, http.StatusConflict, "该 OID 已存在")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeError(w, http.StatusNotFound, "OID 不存在")
		return
	}
	writeJSON(w, http.StatusOK, o)
}

func (s *Server) handleDeleteOID(w http.ResponseWriter, r *http.Request) {
	oidUUID := r.PathValue("uuid")

	// 被密钥用途模板 / 证书扩展模板 / EV 策略引用时不能删除
	var oidValue string
	if err := s.db.QueryRowContext(r.Context(), `SELECT oid_value FROM custom_oids WHERE uuid = ?`, oidUUID).Scan(&oidValue); err != nil {
		writeError(w, http.StatusNotFound, "OID 不存在")
		return
	}
	needle := "%" + oidValue + "%"
	var refs int
	if err := s.db.QueryRowContext(r.Context(),
		`SELECT (SELECT COUNT(*) FROM key_usage_templates WHERE ext_key_usages LIKE ?) +
		        (SELECT COUNT(*) FROM cert_ext_templates WHERE ev_policy_oid = ? OR asn1_extensions LIKE ?)`,
		needle, oidValue, needle).Scan(&refs); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if refs > 0 {
		writeError(w, http.StatusConflict, fmt.Sprintf("该 OID 已被 %d 个模板使用，请先从模板中移除", refs))
		return
	}

	if _, err := s.db.ExecContext(r.Context(), `DELETE FROM custom_oids WHERE uuid = ?`, oidUUID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "OID 已删除"})
}
