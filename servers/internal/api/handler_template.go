package api

import (
	"encoding/json"
	"net/http"
	"time"

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

// CreateKeyStorageTemplateRequest 是创建模板请求体。
type CreateKeyStorageTemplateRequest struct {
	Name            string `json:"name"`
	StorageMethods  uint32 `json:"storage_methods"`
	SecurityLevel   string `json:"security_level"`
	AllowReimport   bool   `json:"allow_reimport"`
	CloudBackup     bool   `json:"cloud_backup"`
	AllowReissue    bool   `json:"allow_reissue"`
	MaxReissueCount int    `json:"max_reissue_count"`
}

func (s *Server) handleCreateKeyStorageTemplate(w http.ResponseWriter, r *http.Request) {
	var req CreateKeyStorageTemplateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}

	tmpl := &storage.KeyStorageTemplate{
		Name:            req.Name,
		StorageMethods:  storage.StorageMethod(req.StorageMethods),
		SecurityLevel:   storage.SecurityLevel(req.SecurityLevel),
		AllowReimport:   req.AllowReimport,
		CloudBackup:     req.CloudBackup,
		AllowReissue:    req.AllowReissue,
		MaxReissueCount: req.MaxReissueCount,
	}

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

// UpdateKeyStorageTemplateRequest 是更新模板请求体（仅允许修改非安全属性）。
type UpdateKeyStorageTemplateRequest struct {
	Name            string `json:"name"`
	MaxReissueCount int    `json:"max_reissue_count"`
}

func (s *Server) handleUpdateKeyStorageTemplate(w http.ResponseWriter, r *http.Request) {
	templateUUID := r.PathValue("uuid")
	var req UpdateKeyStorageTemplateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}

	if err := s.tmplSvc.Update(r.Context(), templateUUID, req.Name, req.MaxReissueCount); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "模板已更新"})
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

func (s *Server) handleCreateSubjectTemplate(w http.ResponseWriter, r *http.Request) {
	var t storage.SubjectTemplate
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if err := s.issuanceSvc.CreateSubjectTemplate(r.Context(), &t); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, t)
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
	if err := s.issuanceSvc.CreateKeyUsageTemplate(r.Context(), &t); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, t)
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

func (s *Server) handleCreateCertExtTemplate(w http.ResponseWriter, r *http.Request) {
	var t storage.CertExtTemplate
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if t.Name == "" {
		writeError(w, http.StatusBadRequest, "模板名称不能为空")
		return
	}
	if err := s.issuanceSvc.CreateCertExtTemplate(r.Context(), &t); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, t)
}

func (s *Server) handleDeleteCertExtTemplate(w http.ResponseWriter, r *http.Request) {
	tmplUUID := r.PathValue("uuid")
	if err := s.issuanceSvc.DeleteCertExtTemplate(r.Context(), tmplUUID); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "证书拓展模板已删除"})
}

// ---- 存储区域处理器 ----

func (s *Server) handleListStorageZones(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.QueryContext(r.Context(),
		`SELECT uuid, name, storage_type, hsm_driver, status, created_at, updated_at FROM storage_zones ORDER BY created_at DESC`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	var zones []storage.StorageZone
	for rows.Next() {
		var z storage.StorageZone
		if err := rows.Scan(&z.UUID, &z.Name, &z.StorageType, &z.HSMDriver, &z.Status, &z.CreatedAt, &z.UpdatedAt); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		zones = append(zones, z)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"zones": zones, "total": len(zones)})
}

func (s *Server) handleCreateStorageZone(w http.ResponseWriter, r *http.Request) {
	var z storage.StorageZone
	if err := json.NewDecoder(r.Body).Decode(&z); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if z.Name == "" {
		writeError(w, http.StatusBadRequest, "区域名称不能为空")
		return
	}
	z.UUID = uuid.New().String()
	z.CreatedAt = time.Now()
	z.UpdatedAt = time.Now()
	if z.Status == "" {
		z.Status = "active"
	}
	_, err := s.db.ExecContext(r.Context(),
		`INSERT INTO storage_zones (uuid, name, storage_type, hsm_driver, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		z.UUID, z.Name, z.StorageType, z.HSMDriver, z.Status, z.CreatedAt, z.UpdatedAt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, z)
}

func (s *Server) handleDeleteStorageZone(w http.ResponseWriter, r *http.Request) {
	zoneUUID := r.PathValue("uuid")
	_, err := s.db.ExecContext(r.Context(), `DELETE FROM storage_zones WHERE uuid = ?`, zoneUUID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "存储区域已删除"})
}

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

func (s *Server) handleCreateOID(w http.ResponseWriter, r *http.Request) {
	var o storage.CustomOID
	if err := json.NewDecoder(r.Body).Decode(&o); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if o.OIDValue == "" || o.Name == "" {
		writeError(w, http.StatusBadRequest, "OID 值和名称不能为空")
		return
	}
	if o.ASN1Type == "" {
		o.ASN1Type = "UTF8String" // 默认 ASN.1 类型
	}
	o.UUID = uuid.New().String()
	o.CreatedAt = time.Now()
	o.UpdatedAt = time.Now()
	_, err := s.db.ExecContext(r.Context(),
		`INSERT INTO custom_oids (uuid, oid_value, name, description, usage_type, asn1_type, is_critical, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		o.UUID, o.OIDValue, o.Name, o.Description, o.UsageType, o.ASN1Type, boolToIntLocal(o.IsCritical), o.CreatedAt, o.UpdatedAt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, o)
}

func (s *Server) handleDeleteOID(w http.ResponseWriter, r *http.Request) {
	oidUUID := r.PathValue("uuid")
	_, err := s.db.ExecContext(r.Context(), `DELETE FROM custom_oids WHERE uuid = ?`, oidUUID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "OID 已删除"})
}
