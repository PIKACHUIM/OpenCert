// Package storage - 内置默认数据（幂等 seed）。
//
// 与 alterTables 系列的结构变更不同，这里只在"没有任何同类数据"时创建一条
// 默认记录，用于保证全新安装开箱即用：有 CA 类颁发模板可用于创建 CA、
// 有默认的域名验证接口可供扩展信息模板选择。重复调用安全（不存在才插入）。
package storage

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/google/uuid"
)

// EnsureBuiltins 创建系统运行所需的默认数据（已存在则跳过）。
// 应在 migrate 完成后、服务启动早期调用一次。
func (db *DB) EnsureBuiltins(ctx context.Context) error {
	if err := db.ensureCABuiltins(ctx); err != nil {
		return err
	}
	if err := db.ensureDomainProviders(ctx); err != nil {
		return err
	}
	return nil
}

// ensureCABuiltins 若系统中没有任何 CA 类（is_ca=1）颁发模板，
// 创建一个 CA 专用密钥用途模板，以及"根 CA 证书""中间 CA 证书"两个颁发模板。
func (db *DB) ensureCABuiltins(ctx context.Context) error {
	var caTmplCount int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM issuance_templates WHERE is_ca = 1`).Scan(&caTmplCount); err != nil {
		return err
	}
	if caTmplCount > 0 {
		return nil
	}

	now := time.Now()
	keyUsageUUID := uuid.New().String()
	// KU：keyCertSign(1<<5) | cRLSign(1<<6) = 0x60 = 96。
	// 与 x509.KeyUsageCertSign|x509.KeyUsageCRLSign 的位值保持一致。
	const kuCertSignCRLSign = 96
	if _, err := db.ExecContext(ctx,
		`INSERT INTO key_usage_templates (uuid, name, key_usage, ext_key_usages, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		keyUsageUUID, "CA 签发与吊销", kuCertSignCRLSign, "[]", now, now,
	); err != nil {
		return err
	}

	allowedKeyTypes, _ := json.Marshal([]string{"ec256", "ec384", "rsa2048", "rsa4096", "sm2"})

	rootValidDays, _ := json.Marshal([]int{3650, 7300})
	if err := db.insertIssuanceTemplate(ctx, issuanceTemplateSeed{
		UUID: uuid.New().String(), Name: "根 CA 证书", IsCA: true, PathLen: -1,
		ValidDays: string(rootValidDays), AllowedKeyTypes: string(allowedKeyTypes),
		KeyUsageTmplUUID: keyUsageUUID, Category: "ca", Enabled: true, Now: now,
	}); err != nil {
		return err
	}

	interValidDays, _ := json.Marshal([]int{1825, 3650})
	if err := db.insertIssuanceTemplate(ctx, issuanceTemplateSeed{
		UUID: uuid.New().String(), Name: "中间 CA 证书", IsCA: true, PathLen: 0,
		ValidDays: string(interValidDays), AllowedKeyTypes: string(allowedKeyTypes),
		KeyUsageTmplUUID: keyUsageUUID, Category: "ca", Enabled: true, Now: now,
	}); err != nil {
		return err
	}

	slog.Info("已内置 CA 类颁发模板", "templates", []string{"根 CA 证书", "中间 CA 证书"})
	return nil
}

// issuanceTemplateSeed 是内置颁发模板的最小字段集合。
type issuanceTemplateSeed struct {
	UUID             string
	Name             string
	IsCA             bool
	PathLen          int
	ValidDays        string
	AllowedKeyTypes  string
	KeyUsageTmplUUID string
	Category         string
	Enabled          bool
	Now              time.Time
}

func (db *DB) insertIssuanceTemplate(ctx context.Context, t issuanceTemplateSeed) error {
	enabled, isCA := 0, 0
	if t.Enabled {
		enabled = 1
	}
	if t.IsCA {
		isCA = 1
	}
	_, err := db.ExecContext(ctx,
		`INSERT INTO issuance_templates (uuid, name, is_ca, path_len, valid_days, allowed_key_types, allowed_ca_uuids,
		 subject_tmpl_uuid, extension_tmpl_uuid, key_usage_tmpl_uuid, key_storage_tmpl_uuid, cert_ext_tmpl_uuid,
		 price_cents, stock, category, enabled, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, '[]', '', '', ?, '', '', 0, -1, ?, ?, ?, ?)`,
		t.UUID, t.Name, isCA, t.PathLen, t.ValidDays, t.AllowedKeyTypes,
		t.KeyUsageTmplUUID, t.Category, enabled, t.Now, t.Now,
	)
	return err
}

// ensureDomainProviders 若系统中没有任何 kind=domain 的认证接口，
// 创建 DNS TXT / HTTP 文件 / TLS-ALPN 三个默认接口（均无需填写配置，开箱即用）。
func (db *DB) ensureDomainProviders(ctx context.Context) error {
	var count int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM verify_providers WHERE kind = 'domain'`).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}

	now := time.Now()
	defaults := []struct {
		Name, Driver string
	}{
		{"DNS TXT 验证", "dns_txt"},
		{"HTTP 文件验证", "http_file"},
		{"TLS-ALPN 验证", "tls_alpn"},
	}
	for _, d := range defaults {
		if _, err := db.ExecContext(ctx,
			`INSERT INTO verify_providers (uuid, name, kind, driver, config_enc, enabled, created_at, updated_at)
			 VALUES (?, ?, 'domain', ?, '{}', 1, ?, ?)`,
			uuid.New().String(), d.Name, d.Driver, now, now,
		); err != nil {
			return err
		}
	}
	slog.Info("已内置域名验证接口", "providers", []string{"DNS TXT 验证", "HTTP 文件验证", "TLS-ALPN 验证"})
	return nil
}
