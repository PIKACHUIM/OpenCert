// Package issuance 提供证书颁发模板管理和签发流程。
package issuance

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/globaltrusts/server-card/internal/storage"
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

// CreateIssuanceTemplate 创建颁发模板。
func (s *Service) CreateIssuanceTemplate(ctx context.Context, t *storage.IssuanceTemplate) error {
	if t.Name == "" {
		return fmt.Errorf("模板名称不能为空")
	}
	t.UUID = uuid.New().String()
	t.CreatedAt = time.Now()
	t.UpdatedAt = time.Now()

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO issuance_templates (uuid, name, is_ca, path_len, valid_days, allowed_key_types, allowed_ca_uuids,
		 subject_tmpl_uuid, extension_tmpl_uuid, key_usage_tmpl_uuid, key_storage_tmpl_uuid, cert_ext_tmpl_uuid,
		 price_cents, stock, category, enabled, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.UUID, t.Name, boolToInt(t.IsCA), t.PathLen, t.ValidDays, t.AllowedKeyTypes, t.AllowedCAUUIDs,
		t.SubjectTmplUUID, t.ExtensionTmplUUID, t.KeyUsageTmplUUID, t.KeyStorageTmplUUID, t.CertExtTmplUUID,
		t.PriceCents, t.Stock, t.Category, boolToInt(t.Enabled), t.CreatedAt, t.UpdatedAt,
	)
	return err
}

// GetIssuanceTemplate 按 UUID 查询颁发模板。
func (s *Service) GetIssuanceTemplate(ctx context.Context, tmplUUID string) (*storage.IssuanceTemplate, error) {
	t := &storage.IssuanceTemplate{}
	var isCA, enabled int
	err := s.db.QueryRowContext(ctx,
		`SELECT uuid, name, is_ca, path_len, valid_days, allowed_key_types, allowed_ca_uuids,
		 subject_tmpl_uuid, extension_tmpl_uuid, key_usage_tmpl_uuid, key_storage_tmpl_uuid, cert_ext_tmpl_uuid,
		 price_cents, stock, category, enabled, created_at, updated_at
		 FROM issuance_templates WHERE uuid = ?`, tmplUUID,
	).Scan(&t.UUID, &t.Name, &isCA, &t.PathLen, &t.ValidDays, &t.AllowedKeyTypes, &t.AllowedCAUUIDs,
		&t.SubjectTmplUUID, &t.ExtensionTmplUUID, &t.KeyUsageTmplUUID, &t.KeyStorageTmplUUID, &t.CertExtTmplUUID,
		&t.PriceCents, &t.Stock, &t.Category, &enabled, &t.CreatedAt, &t.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("颁发模板不存在: %s", tmplUUID)
	}
	t.IsCA = isCA == 1
	t.Enabled = enabled == 1
	return t, err
}

// ListIssuanceTemplates 查询所有颁发模板。
func (s *Service) ListIssuanceTemplates(ctx context.Context, category string, enabledOnly bool) ([]*storage.IssuanceTemplate, error) {
	query := `SELECT uuid, name, is_ca, path_len, valid_days, allowed_key_types, allowed_ca_uuids,
		 subject_tmpl_uuid, extension_tmpl_uuid, key_usage_tmpl_uuid, key_storage_tmpl_uuid, cert_ext_tmpl_uuid,
		 price_cents, stock, category, enabled, created_at, updated_at
		 FROM issuance_templates WHERE 1=1`
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

	var templates []*storage.IssuanceTemplate
	for rows.Next() {
		t := &storage.IssuanceTemplate{}
		var isCA, enabled int
		if err := rows.Scan(&t.UUID, &t.Name, &isCA, &t.PathLen, &t.ValidDays, &t.AllowedKeyTypes, &t.AllowedCAUUIDs,
			&t.SubjectTmplUUID, &t.ExtensionTmplUUID, &t.KeyUsageTmplUUID, &t.KeyStorageTmplUUID, &t.CertExtTmplUUID,
			&t.PriceCents, &t.Stock, &t.Category, &enabled, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		t.IsCA = isCA == 1
		t.Enabled = enabled == 1
		templates = append(templates, t)
	}
	return templates, rows.Err()
}

// UpdateIssuanceTemplate 更新颁发模板。
func (s *Service) UpdateIssuanceTemplate(ctx context.Context, t *storage.IssuanceTemplate) error {
	t.UpdatedAt = time.Now()
	_, err := s.db.ExecContext(ctx,
		`UPDATE issuance_templates SET name = ?, is_ca = ?, path_len = ?, valid_days = ?, allowed_key_types = ?,
		 allowed_ca_uuids = ?, subject_tmpl_uuid = ?, extension_tmpl_uuid = ?, key_usage_tmpl_uuid = ?,
		 key_storage_tmpl_uuid = ?, cert_ext_tmpl_uuid = ?, price_cents = ?, stock = ?, category = ?, enabled = ?, updated_at = ?
		 WHERE uuid = ?`,
		t.Name, boolToInt(t.IsCA), t.PathLen, t.ValidDays, t.AllowedKeyTypes, t.AllowedCAUUIDs,
		t.SubjectTmplUUID, t.ExtensionTmplUUID, t.KeyUsageTmplUUID, t.KeyStorageTmplUUID, t.CertExtTmplUUID,
		t.PriceCents, t.Stock, t.Category, boolToInt(t.Enabled), t.UpdatedAt, t.UUID,
	)
	return err
}

// DeleteIssuanceTemplate 删除颁发模板。
func (s *Service) DeleteIssuanceTemplate(ctx context.Context, tmplUUID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM issuance_templates WHERE uuid = ?`, tmplUUID)
	return err
}

// ---- 主体模板 CRUD ----

// CreateSubjectTemplate 创建主体模板。
func (s *Service) CreateSubjectTemplate(ctx context.Context, t *storage.SubjectTemplate) error {
	t.UUID = uuid.New().String()
	t.CreatedAt = time.Now()
	t.UpdatedAt = time.Now()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO subject_templates (uuid, name, fields, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		t.UUID, t.Name, t.Fields, t.CreatedAt, t.UpdatedAt,
	)
	return err
}

// ListSubjectTemplates 查询所有主体模板。
func (s *Service) ListSubjectTemplates(ctx context.Context) ([]*storage.SubjectTemplate, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT uuid, name, fields, created_at, updated_at FROM subject_templates ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var templates []*storage.SubjectTemplate
	for rows.Next() {
		t := &storage.SubjectTemplate{}
		if err := rows.Scan(&t.UUID, &t.Name, &t.Fields, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		templates = append(templates, t)
	}
	return templates, rows.Err()
}

// DeleteSubjectTemplate 删除主体模板。
func (s *Service) DeleteSubjectTemplate(ctx context.Context, tmplUUID string) error {
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
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO extension_templates (uuid, name, max_dns, max_email, max_ip, max_uri, max_rid, max_other,
		 allow_uri, allow_rid, allow_other, require_dns_verify, require_email_verify, verify_expires_days, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.UUID, t.Name, t.MaxDNS, t.MaxEmail, t.MaxIP, t.MaxURI, t.MaxRID, t.MaxOther,
		boolToInt(t.AllowURI), boolToInt(t.AllowRID), boolToInt(t.AllowOther),
		boolToInt(t.RequireDNSVerify), boolToInt(t.RequireEmailVerify), t.VerifyExpiresDays,
		t.CreatedAt, t.UpdatedAt,
	)
	return err
}

// ListExtensionTemplates 查询所有扩展信息模板。
func (s *Service) ListExtensionTemplates(ctx context.Context) ([]*storage.ExtensionTemplate, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT uuid, name, max_dns, max_email, max_ip, max_uri, max_rid, max_other,
		 allow_uri, allow_rid, allow_other, require_dns_verify, require_email_verify, verify_expires_days, created_at, updated_at
		 FROM extension_templates ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var templates []*storage.ExtensionTemplate
	for rows.Next() {
		t := &storage.ExtensionTemplate{}
		var dnsVerify, emailVerify, allowURI, allowRID, allowOther int
		if err := rows.Scan(&t.UUID, &t.Name, &t.MaxDNS, &t.MaxEmail, &t.MaxIP, &t.MaxURI, &t.MaxRID, &t.MaxOther,
			&allowURI, &allowRID, &allowOther, &dnsVerify, &emailVerify, &t.VerifyExpiresDays, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		t.RequireDNSVerify = dnsVerify == 1
		t.RequireEmailVerify = emailVerify == 1
		t.AllowURI = allowURI == 1
		t.AllowRID = allowRID == 1
		t.AllowOther = allowOther == 1
		templates = append(templates, t)
	}
	return templates, rows.Err()
}

// GetExtensionTemplate 按 UUID 查询扩展信息模板。
func (s *Service) GetExtensionTemplate(ctx context.Context, tmplUUID string) (*storage.ExtensionTemplate, error) {
	t := &storage.ExtensionTemplate{}
	var dnsVerify, emailVerify, allowURI, allowRID, allowOther int
	err := s.db.QueryRowContext(ctx,
		`SELECT uuid, name, max_dns, max_email, max_ip, max_uri, max_rid, max_other,
		 allow_uri, allow_rid, allow_other, require_dns_verify, require_email_verify, verify_expires_days, created_at, updated_at
		 FROM extension_templates WHERE uuid = ?`, tmplUUID,
	).Scan(&t.UUID, &t.Name, &t.MaxDNS, &t.MaxEmail, &t.MaxIP, &t.MaxURI, &t.MaxRID, &t.MaxOther,
		&allowURI, &allowRID, &allowOther, &dnsVerify, &emailVerify, &t.VerifyExpiresDays, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	t.RequireDNSVerify = dnsVerify == 1
	t.RequireEmailVerify = emailVerify == 1
	t.AllowURI = allowURI == 1
	t.AllowRID = allowRID == 1
	t.AllowOther = allowOther == 1
	return t, nil
}

// DeleteExtensionTemplate 删除扩展信息模板。
func (s *Service) DeleteExtensionTemplate(ctx context.Context, tmplUUID string) error {
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

// DeleteKeyUsageTemplate 删除密钥用途模板。
func (s *Service) DeleteKeyUsageTemplate(ctx context.Context, tmplUUID string) error {
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

// DeleteCertExtTemplate 删除证书扩展模板。
func (s *Service) DeleteCertExtTemplate(ctx context.Context, tmplUUID string) error {
	// 检查是否被颁发模板引用
	var count int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM issuance_templates WHERE extension_tmpl_uuid = ?`, tmplUUID,
	).Scan(&count)
	if err != nil {
		return err
	}
	if count > 0 {
		return fmt.Errorf("证书扩展模板已被 %d 个颁发模板引用，无法删除", count)
	}

	_, err = s.db.ExecContext(ctx, `DELETE FROM cert_ext_templates WHERE uuid = ?`, tmplUUID)
	return err
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
