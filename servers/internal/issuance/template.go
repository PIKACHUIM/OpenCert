// Package issuance 提供证书颁发模板管理和签发流程。
package issuance

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/globaltrusts/server-card/internal/storage"
	"github.com/google/uuid"
)

// Service 是证书颁发模板管理服务。
type Service struct {
	db *storage.DB
}

// NewService 创建颁发模板服务。
func NewService(db *storage.DB) *Service {
	return &Service{db: db}
}

// ---- 颁发模板 CRUD ----
//
// 颁发模板是唯一的技术配置来源：CA 候选与默认值、有效期、算法、密钥用途/
// 证书扩展/密钥存储/主体/扩展信息模板全部在这里配置，开通模板与商品规格
// 只能在这些范围内收窄，不能独立配置（见 ValidateIssuanceTemplate）。

const issuanceTemplateColumns = `uuid, name, is_ca, path_len, valid_days, default_valid_days,
	allowed_key_types, allowed_sig_algs, allowed_ca_uuids, default_ca_uuid,
	subject_tmpl_uuid, extension_tmpl_uuid, key_usage_tmpl_uuid, key_storage_tmpl_uuid, cert_ext_tmpl_uuid,
	category, enabled, created_at, updated_at`

func scanIssuanceTemplate(scan func(dest ...interface{}) error) (*storage.IssuanceTemplate, error) {
	t := &storage.IssuanceTemplate{}
	var isCA, enabled int
	if err := scan(&t.UUID, &t.Name, &isCA, &t.PathLen, &t.ValidDays, &t.DefaultValidDays,
		&t.AllowedKeyTypes, &t.AllowedSigAlgs, &t.AllowedCAUUIDs, &t.DefaultCAUUID,
		&t.SubjectTmplUUID, &t.ExtensionTmplUUID, &t.KeyUsageTmplUUID, &t.KeyStorageTmplUUID, &t.CertExtTmplUUID,
		&t.Category, &enabled, &t.CreatedAt, &t.UpdatedAt); err != nil {
		return nil, err
	}
	t.IsCA = isCA == 1
	t.Enabled = enabled == 1
	return t, nil
}

// ValidateIssuanceTemplate 校验颁发模板的内部一致性：
//   - 默认有效期必须在可选有效期列表中（列表非空时）；
//   - 默认 CA 必须在候选 CA 列表中（列表非空时）；
//   - IsCA=true 时必须关联 CA 类密钥用途模板（校验留给调用方传入 keyUsageIsCA）。
func ValidateIssuanceTemplate(t *storage.IssuanceTemplate) error {
	if strings.TrimSpace(t.Name) == "" {
		return fmt.Errorf("模板名称不能为空")
	}
	if allowed := parseJSONIntArr(t.ValidDays); len(allowed) > 0 && t.DefaultValidDays != 0 {
		if !containsInt(allowed, t.DefaultValidDays) {
			return fmt.Errorf("默认有效期 %d 天不在可选列表 %v 中", t.DefaultValidDays, allowed)
		}
	}
	if allowed := parseJSONStrArr(t.AllowedCAUUIDs); len(allowed) > 0 && t.DefaultCAUUID != "" {
		if !containsStr(allowed, t.DefaultCAUUID) {
			return fmt.Errorf("默认 CA 不在候选 CA 列表中")
		}
	}
	return nil
}

// CreateIssuanceTemplate 创建颁发模板。
func (s *Service) CreateIssuanceTemplate(ctx context.Context, t *storage.IssuanceTemplate) error {
	if err := s.ValidateIssuanceTemplateDeep(ctx, t); err != nil {
		return err
	}
	t.UUID = uuid.New().String()
	t.CreatedAt = time.Now()
	t.UpdatedAt = time.Now()
	if t.AllowedSigAlgs == "" {
		t.AllowedSigAlgs = "[]"
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO issuance_templates (`+issuanceTemplateColumns+`)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.UUID, t.Name, boolToInt(t.IsCA), t.PathLen, t.ValidDays, t.DefaultValidDays,
		t.AllowedKeyTypes, t.AllowedSigAlgs, t.AllowedCAUUIDs, t.DefaultCAUUID,
		t.SubjectTmplUUID, t.ExtensionTmplUUID, t.KeyUsageTmplUUID, t.KeyStorageTmplUUID, t.CertExtTmplUUID,
		t.Category, boolToInt(t.Enabled), t.CreatedAt, t.UpdatedAt,
	)
	return err
}

// GetIssuanceTemplate 按 UUID 查询颁发模板。
func (s *Service) GetIssuanceTemplate(ctx context.Context, tmplUUID string) (*storage.IssuanceTemplate, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+issuanceTemplateColumns+` FROM issuance_templates WHERE uuid = ?`, tmplUUID)
	t, err := scanIssuanceTemplate(row.Scan)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("颁发模板不存在: %s", tmplUUID)
	}
	return t, err
}

// ListIssuanceTemplates 查询所有颁发模板。
func (s *Service) ListIssuanceTemplates(ctx context.Context, category string, enabledOnly bool) ([]*storage.IssuanceTemplate, error) {
	query := `SELECT ` + issuanceTemplateColumns + ` FROM issuance_templates WHERE 1=1`
	var args []interface{}

	if category != "" {
		query += ` AND category = ?`
		args = append(args, category)
	}
	if enabledOnly {
		query += ` AND enabled = 1`
	}
	query += ` ORDER BY created_at DESC`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	templates := []*storage.IssuanceTemplate{}
	for rows.Next() {
		t, err := scanIssuanceTemplate(rows.Scan)
		if err != nil {
			return nil, err
		}
		templates = append(templates, t)
	}
	return templates, rows.Err()
}

// UpdateIssuanceTemplate 更新颁发模板。
func (s *Service) UpdateIssuanceTemplate(ctx context.Context, t *storage.IssuanceTemplate) error {
	if err := s.ValidateIssuanceTemplateDeep(ctx, t); err != nil {
		return err
	}
	t.UpdatedAt = time.Now()
	_, err := s.db.ExecContext(ctx,
		`UPDATE issuance_templates SET name = ?, is_ca = ?, path_len = ?, valid_days = ?, default_valid_days = ?,
		 allowed_key_types = ?, allowed_sig_algs = ?, allowed_ca_uuids = ?, default_ca_uuid = ?,
		 subject_tmpl_uuid = ?, extension_tmpl_uuid = ?, key_usage_tmpl_uuid = ?,
		 key_storage_tmpl_uuid = ?, cert_ext_tmpl_uuid = ?, category = ?, enabled = ?, updated_at = ?
		 WHERE uuid = ?`,
		t.Name, boolToInt(t.IsCA), t.PathLen, t.ValidDays, t.DefaultValidDays,
		t.AllowedKeyTypes, t.AllowedSigAlgs, t.AllowedCAUUIDs, t.DefaultCAUUID,
		t.SubjectTmplUUID, t.ExtensionTmplUUID, t.KeyUsageTmplUUID, t.KeyStorageTmplUUID, t.CertExtTmplUUID,
		t.Category, boolToInt(t.Enabled), t.UpdatedAt, t.UUID,
	)
	return err
}

// DeleteIssuanceTemplate 删除颁发模板。删除前检查是否被开通模板引用。
func (s *Service) DeleteIssuanceTemplate(ctx context.Context, tmplUUID string) error {
	var refCount int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM cert_apply_templates WHERE issuance_tmpl_uuid = ?`, tmplUUID,
	).Scan(&refCount); err != nil {
		return err
	}
	if refCount > 0 {
		return fmt.Errorf("该颁发模板被 %d 个开通模板引用，无法删除", refCount)
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM issuance_templates WHERE uuid = ?`, tmplUUID)
	return err
}

// ---- 小工具：JSON 数组解析（颁发模板校验与 ResolvePolicy 共用）----

func parseJSONIntArr(s string) []int {
	if s == "" || s == "[]" {
		return nil
	}
	var arr []int
	if err := json.Unmarshal([]byte(s), &arr); err != nil {
		return nil
	}
	return arr
}

func parseJSONStrArr(s string) []string {
	if s == "" || s == "[]" {
		return nil
	}
	var arr []string
	if err := json.Unmarshal([]byte(s), &arr); err != nil {
		return nil
	}
	return arr
}

func containsInt(arr []int, v int) bool {
	for _, x := range arr {
		if x == v {
			return true
		}
	}
	return false
}

func containsStr(arr []string, v string) bool {
	for _, x := range arr {
		if x == v {
			return true
		}
	}
	return false
}

// ---- 主体模板 CRUD ----

const subjectTemplateColumns = `uuid, name, description, fields, verify_provider_uuid, verify_validity, created_at, updated_at`

func scanSubjectTemplate(scan func(dest ...interface{}) error) (*storage.SubjectTemplate, error) {
	t := &storage.SubjectTemplate{}
	err := scan(&t.UUID, &t.Name, &t.Description, &t.Fields, &t.VerifyProviderUUID, &t.VerifyValidity, &t.CreatedAt, &t.UpdatedAt)
	return t, err
}

// CreateSubjectTemplate 创建主体模板（字段结构由调用方校验）。
func (s *Service) CreateSubjectTemplate(ctx context.Context, t *storage.SubjectTemplate) error {
	t.UUID = uuid.New().String()
	t.CreatedAt = time.Now()
	t.UpdatedAt = t.CreatedAt
	if t.VerifyValidity == "" {
		t.VerifyValidity = "365d"
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO subject_templates (`+subjectTemplateColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		t.UUID, t.Name, t.Description, t.Fields, t.VerifyProviderUUID, t.VerifyValidity, t.CreatedAt, t.UpdatedAt,
	)
	return err
}

// UpdateSubjectTemplate 更新主体模板。已提交的主体信息保留原字段值，重新验证时按新模板执行。
func (s *Service) UpdateSubjectTemplate(ctx context.Context, t *storage.SubjectTemplate) error {
	if t.VerifyValidity == "" {
		t.VerifyValidity = "365d"
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE subject_templates SET name = ?, description = ?, fields = ?, verify_provider_uuid = ?, verify_validity = ?, updated_at = ?
		 WHERE uuid = ?`,
		t.Name, t.Description, t.Fields, t.VerifyProviderUUID, t.VerifyValidity, time.Now(), t.UUID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("主体模板不存在")
	}
	return nil
}

// GetSubjectTemplate 按 UUID 查询主体模板。
func (s *Service) GetSubjectTemplate(ctx context.Context, tmplUUID string) (*storage.SubjectTemplate, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+subjectTemplateColumns+` FROM subject_templates WHERE uuid = ?`, tmplUUID)
	t, err := scanSubjectTemplate(row.Scan)
	if err != nil {
		return nil, fmt.Errorf("主体模板不存在: %s", tmplUUID)
	}
	return t, nil
}

// ListSubjectTemplates 查询所有主体模板。
func (s *Service) ListSubjectTemplates(ctx context.Context) ([]*storage.SubjectTemplate, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+subjectTemplateColumns+` FROM subject_templates ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	templates := []*storage.SubjectTemplate{}
	for rows.Next() {
		t, err := scanSubjectTemplate(rows.Scan)
		if err != nil {
			return nil, err
		}
		templates = append(templates, t)
	}
	return templates, rows.Err()
}

// DeleteSubjectTemplate 删除主体模板：被颁发模板引用时拒绝。
func (s *Service) DeleteSubjectTemplate(ctx context.Context, tmplUUID string) error {
	if err := s.ensureUnreferenced(ctx, "subject_tmpl_uuid", tmplUUID, "主体模板"); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM subject_templates WHERE uuid = ?`, tmplUUID)
	return err
}

// ---- 扩展信息模板 CRUD ----

// CreateExtensionTemplate 创建扩展信息模板。
func (s *Service) CreateExtensionTemplate(ctx context.Context, t *storage.ExtensionTemplate) error {
	t.UUID = uuid.New().String()
	t.CreatedAt = time.Now()
	t.UpdatedAt = time.Now()
	if t.VerifyExpiresDays <= 0 {
		t.VerifyExpiresDays = 90
	}
	if t.VerifyPolicy == "" {
		t.VerifyPolicy = "{}"
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO extension_templates (uuid, name, max_dns, max_email, max_ip, max_uri, max_rid, max_other,
		 allow_uri, allow_rid, allow_other, require_dns_verify, require_email_verify, verify_expires_days, verify_policy,
		 created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.UUID, t.Name, t.MaxDNS, t.MaxEmail, t.MaxIP, t.MaxURI, t.MaxRID, t.MaxOther,
		boolToInt(t.AllowURI), boolToInt(t.AllowRID), boolToInt(t.AllowOther),
		boolToInt(t.RequireDNSVerify), boolToInt(t.RequireEmailVerify), t.VerifyExpiresDays, t.VerifyPolicy,
		t.CreatedAt, t.UpdatedAt,
	)
	return err
}

// UpdateExtensionTemplate 更新扩展信息模板（名称与验证策略）。
func (s *Service) UpdateExtensionTemplate(ctx context.Context, t *storage.ExtensionTemplate) error {
	if t.VerifyPolicy == "" {
		t.VerifyPolicy = "{}"
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE extension_templates SET name = ?, verify_policy = ?, require_dns_verify = ?, require_email_verify = ?,
		 verify_expires_days = ?, updated_at = ? WHERE uuid = ?`,
		t.Name, t.VerifyPolicy, boolToInt(t.RequireDNSVerify), boolToInt(t.RequireEmailVerify),
		t.VerifyExpiresDays, time.Now(), t.UUID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("扩展信息模板不存在")
	}
	return nil
}

const extensionTemplateColumns = `uuid, name, max_dns, max_email, max_ip, max_uri, max_rid, max_other,
	allow_uri, allow_rid, allow_other, require_dns_verify, require_email_verify, verify_expires_days, verify_policy,
	created_at, updated_at`

func scanExtensionTemplate(scan func(dest ...interface{}) error) (*storage.ExtensionTemplate, error) {
	t := &storage.ExtensionTemplate{}
	var dnsVerify, emailVerify, allowURI, allowRID, allowOther int
	if err := scan(&t.UUID, &t.Name, &t.MaxDNS, &t.MaxEmail, &t.MaxIP, &t.MaxURI, &t.MaxRID, &t.MaxOther,
		&allowURI, &allowRID, &allowOther, &dnsVerify, &emailVerify, &t.VerifyExpiresDays, &t.VerifyPolicy,
		&t.CreatedAt, &t.UpdatedAt); err != nil {
		return nil, err
	}
	t.RequireDNSVerify = dnsVerify == 1
	t.RequireEmailVerify = emailVerify == 1
	t.AllowURI = allowURI == 1
	t.AllowRID = allowRID == 1
	t.AllowOther = allowOther == 1
	return t, nil
}

// ListExtensionTemplates 查询所有扩展信息模板。
func (s *Service) ListExtensionTemplates(ctx context.Context) ([]*storage.ExtensionTemplate, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+extensionTemplateColumns+` FROM extension_templates ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	templates := []*storage.ExtensionTemplate{}
	for rows.Next() {
		t, err := scanExtensionTemplate(rows.Scan)
		if err != nil {
			return nil, err
		}
		templates = append(templates, t)
	}
	return templates, rows.Err()
}

// GetExtensionTemplate 按 UUID 查询扩展信息模板。
func (s *Service) GetExtensionTemplate(ctx context.Context, tmplUUID string) (*storage.ExtensionTemplate, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+extensionTemplateColumns+` FROM extension_templates WHERE uuid = ?`, tmplUUID)
	return scanExtensionTemplate(row.Scan)
}

// DeleteExtensionTemplate 删除扩展信息模板：被颁发模板引用时拒绝。
func (s *Service) DeleteExtensionTemplate(ctx context.Context, tmplUUID string) error {
	if err := s.ensureUnreferenced(ctx, "extension_tmpl_uuid", tmplUUID, "扩展信息模板"); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM extension_templates WHERE uuid = ?`, tmplUUID)
	return err
}

// ---- 密钥用途模板 CRUD ----

// CreateKeyUsageTemplate 创建密钥用途模板。
func (s *Service) CreateKeyUsageTemplate(ctx context.Context, t *storage.KeyUsageTemplate) error {
	t.UUID = uuid.New().String()
	t.CreatedAt = time.Now()
	t.UpdatedAt = time.Now()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO key_usage_templates (uuid, name, key_usage, ext_key_usages, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		t.UUID, t.Name, t.KeyUsage, t.ExtKeyUsages, t.CreatedAt, t.UpdatedAt,
	)
	return err
}

// ListKeyUsageTemplates 查询所有密钥用途模板。
func (s *Service) ListKeyUsageTemplates(ctx context.Context) ([]*storage.KeyUsageTemplate, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT uuid, name, key_usage, ext_key_usages, created_at, updated_at FROM key_usage_templates ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var templates []*storage.KeyUsageTemplate
	for rows.Next() {
		t := &storage.KeyUsageTemplate{}
		if err := rows.Scan(&t.UUID, &t.Name, &t.KeyUsage, &t.ExtKeyUsages, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		templates = append(templates, t)
	}
	return templates, rows.Err()
}

// DeleteKeyUsageTemplate 删除密钥用途模板：被颁发模板引用时拒绝。
func (s *Service) DeleteKeyUsageTemplate(ctx context.Context, tmplUUID string) error {
	if err := s.ensureUnreferenced(ctx, "key_usage_tmpl_uuid", tmplUUID, "密钥用途模板"); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM key_usage_templates WHERE uuid = ?`, tmplUUID)
	return err
}

// ---- 证书扩展模板 CRUD ----

// CreateCertExtTemplate 创建证书拓展模板。
func (s *Service) CreateCertExtTemplate(ctx context.Context, t *storage.CertExtTemplate) error {
	t.UUID = uuid.New().String()
	t.CreatedAt = time.Now()
	t.UpdatedAt = time.Now()
	if t.CRLDistPoints == "" {
		t.CRLDistPoints = "[]"
	}
	if t.OCSPServers == "" {
		t.OCSPServers = "[]"
	}
	if t.AIAIssuers == "" {
		t.AIAIssuers = "[]"
	}
	if t.CTServers == "" {
		t.CTServers = "[]"
	}
	if t.ASN1Extensions == "" {
		t.ASN1Extensions = "[]"
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO cert_ext_templates (uuid, name, crl_dist_points, ocsp_servers, aia_issuers, ct_servers, ev_policy_oid, netscape_config, csp_config, asn1_extensions, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.UUID, t.Name, t.CRLDistPoints, t.OCSPServers, t.AIAIssuers, t.CTServers, t.EVPolicyOID,
		t.NetscapeConfig, t.CSPConfig, t.ASN1Extensions, t.CreatedAt, t.UpdatedAt,
	)
	return err
}

// ListCertExtTemplates 查询所有证书拓展模板。
func (s *Service) ListCertExtTemplates(ctx context.Context) ([]*storage.CertExtTemplate, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT uuid, name, crl_dist_points, ocsp_servers, aia_issuers, ct_servers, ev_policy_oid, netscape_config, csp_config, asn1_extensions, created_at, updated_at
		 FROM cert_ext_templates ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var templates []*storage.CertExtTemplate
	for rows.Next() {
		t := &storage.CertExtTemplate{}
		if err := rows.Scan(&t.UUID, &t.Name, &t.CRLDistPoints, &t.OCSPServers, &t.AIAIssuers, &t.CTServers, &t.EVPolicyOID,
			&t.NetscapeConfig, &t.CSPConfig, &t.ASN1Extensions, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		templates = append(templates, t)
	}
	return templates, rows.Err()
}

// DeleteCertExtTemplate 删除证书扩展模板：被颁发模板引用时拒绝。
func (s *Service) DeleteCertExtTemplate(ctx context.Context, tmplUUID string) error {
	if err := s.ensureUnreferenced(ctx, "cert_ext_tmpl_uuid", tmplUUID, "证书扩展模板"); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM cert_ext_templates WHERE uuid = ?`, tmplUUID)
	return err
}

// UpdateCertExtTemplate 全量更新证书扩展模板。
func (s *Service) UpdateCertExtTemplate(ctx context.Context, t *storage.CertExtTemplate) error {
	if strings.TrimSpace(t.Name) == "" {
		return fmt.Errorf("模板名称不能为空")
	}
	for _, f := range []*string{&t.CRLDistPoints, &t.OCSPServers, &t.AIAIssuers, &t.CTServers, &t.ASN1Extensions} {
		if *f == "" {
			*f = "[]"
		}
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE cert_ext_templates SET name = ?, crl_dist_points = ?, ocsp_servers = ?, aia_issuers = ?, ct_servers = ?,
		 ev_policy_oid = ?, netscape_config = ?, csp_config = ?, asn1_extensions = ?, updated_at = ? WHERE uuid = ?`,
		t.Name, t.CRLDistPoints, t.OCSPServers, t.AIAIssuers, t.CTServers, t.EVPolicyOID,
		t.NetscapeConfig, t.CSPConfig, t.ASN1Extensions, time.Now(), t.UUID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("证书扩展模板不存在")
	}
	return nil
}

// UpdateKeyUsageTemplate 全量更新密钥用途模板。
// 被颁发模板引用的 CA 用途模板不允许去掉「证书签名」，避免已配置的 CA 模板失效。
func (s *Service) UpdateKeyUsageTemplate(ctx context.Context, t *storage.KeyUsageTemplate) error {
	if strings.TrimSpace(t.Name) == "" {
		return fmt.Errorf("模板名称不能为空")
	}
	if t.ExtKeyUsages == "" {
		t.ExtKeyUsages = "[]"
	}
	const keyUsageCertSign = 1 << 5
	if t.KeyUsage&keyUsageCertSign == 0 {
		var n int
		if err := s.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM issuance_templates WHERE key_usage_tmpl_uuid = ? AND is_ca = 1`, t.UUID).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return fmt.Errorf("该用途模板被 %d 个 CA 颁发模板使用，必须保留「证书签名」", n)
		}
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE key_usage_templates SET name = ?, key_usage = ?, ext_key_usages = ?, updated_at = ? WHERE uuid = ?`,
		t.Name, t.KeyUsage, t.ExtKeyUsages, time.Now(), t.UUID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("密钥用途模板不存在")
	}
	return nil
}

// ensureUnreferenced 检查某类模板是否仍被颁发模板引用；column 为 issuance_templates 中的关联列名。
func (s *Service) ensureUnreferenced(ctx context.Context, column, tmplUUID, label string) error {
	switch column {
	case "subject_tmpl_uuid", "extension_tmpl_uuid", "key_usage_tmpl_uuid", "cert_ext_tmpl_uuid", "key_storage_tmpl_uuid":
	default:
		return fmt.Errorf("内部错误：未知的关联列 %s", column)
	}
	var count int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM issuance_templates WHERE `+column+` = ?`, tmplUUID).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return fmt.Errorf("%s已被 %d 个颁发模板引用，请先解除关联后再删除", label, count)
	}
	return nil
}

// RenewCert 续期证书（使用原证书的 CA 和密钥重新签发）。
// 返回新证书记录，原证书保持不变。
func (s *Service) RenewCert(ctx context.Context, cert *storage.Certificate, validDays int) (*storage.Certificate, error) {
	if cert.RevocationStatus == "revoked" {
		return nil, fmt.Errorf("已吊销的证书不能续期")
	}
	if cert.CAUUID == "" {
		return nil, fmt.Errorf("证书没有关联的 CA，无法续期")
	}

	// 检查颁发模板是否允许续期
	if cert.IssuanceTmplUUID != "" {
		tmpl, err := s.GetIssuanceTemplate(ctx, cert.IssuanceTmplUUID)
		if err == nil {
			// 检查请求的有效期是否在模板允许列表中
			if tmpl.ValidDays != "" && tmpl.ValidDays != "[]" {
				if !isValidDayAllowed(tmpl.ValidDays, validDays) {
					return nil, fmt.Errorf("有效期 %d 天不在模板允许的有效期列表中", validDays)
				}
			}
		}
	}

	// 解析原证书获取主体信息
	if len(cert.CertContent) == 0 {
		return nil, fmt.Errorf("证书内容为空，无法续期")
	}

	x509Cert, err := x509.ParseCertificate(cert.CertContent)
	if err != nil {
		// 尝试 PEM 解码
		block, _ := pem.Decode(cert.CertContent)
		if block != nil {
			x509Cert, err = x509.ParseCertificate(block.Bytes)
		}
		if err != nil {
			return nil, fmt.Errorf("解析证书失败: %w", err)
		}
	}

	// 创建新证书记录（复制原证书的基本信息，更新有效期）
	newCert := &storage.Certificate{
		CardUUID:            cert.CardUUID,
		CertType:            cert.CertType,
		KeyType:             cert.KeyType,
		PrivateData:         cert.PrivateData, // 复用原私钥
		Remark:              cert.Remark + " (续期)",
		CAUUID:              cert.CAUUID,
		IssuanceTmplUUID:    cert.IssuanceTmplUUID,
		StoragePolicy:       cert.StoragePolicy,
		SANDNS:              cert.SANDNS,
		SANIP:               cert.SANIP,
		SANEmail:            cert.SANEmail,
		SANURI:              cert.SANURI,
		CertificatePolicies: cert.CertificatePolicies,
		RevocationStatus:    "active",
	}

	// 记录原证书的主体信息（用于日志）
	_ = x509Cert.Subject.CommonName

	// 将新证书记录存入数据库（实际签发由 CA 服务完成，这里记录待签发状态）
	certRepo := storage.NewCertRepo(s.db)
	if err := certRepo.Create(ctx, newCert); err != nil {
		return nil, fmt.Errorf("创建续期证书记录失败: %w", err)
	}

	return newCert, nil
}

// isValidDayAllowed 检查有效期是否在 JSON 数组中。
func isValidDayAllowed(validDaysJSON string, days int) bool {
	// 简单解析 JSON 数组 "[30,90,365]"
	if validDaysJSON == "" || validDaysJSON == "[]" {
		return true
	}
	target := fmt.Sprintf("%d", days)
	// 在 JSON 字符串中查找数字
	for i := 0; i < len(validDaysJSON); i++ {
		if validDaysJSON[i] >= '0' && validDaysJSON[i] <= '9' {
			j := i
			for j < len(validDaysJSON) && validDaysJSON[j] >= '0' && validDaysJSON[j] <= '9' {
				j++
			}
			if validDaysJSON[i:j] == target {
				return true
			}
			i = j
		}
	}
	return false
}

// ---- 工具函数 ----

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
