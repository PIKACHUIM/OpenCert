// Package storage 提供 servers 的数据存储层。
// 支持 SQLite（默认）、MySQL、PostgreSQL 三种数据库后端。
// 通过 DATABASE_URL 环境变量识别驱动类型：
//   - 未设置：使用 SQLite（零配置开箱即用）
//   - postgres://...：使用 PostgreSQL
//   - mysql://...：使用 MySQL
package storage

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

// DriverType 是数据库驱动类型。
type DriverType string

const (
	DriverSQLite   DriverType = "sqlite"
	DriverPostgres DriverType = "postgres"
	DriverMySQL    DriverType = "mysql"
)

// DB 封装数据库连接。
type DB struct {
	*sql.DB
	Driver DriverType // 当前使用的驱动类型
}

// Open 打开数据库并执行迁移。
// 当 databaseURL 非空时，根据 URL 前缀选择驱动；否则使用 SQLite（path 参数）。
func Open(path, databaseURL string) (*DB, error) {
	driver, dsn, err := resolveDSN(path, databaseURL)
	if err != nil {
		return nil, err
	}

	// SQLite 需要确保目录存在
	if driver == DriverSQLite {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return nil, fmt.Errorf("创建数据库目录失败: %w", err)
		}
	}

	db, err := sql.Open(string(driver), dsn)
	if err != nil {
		return nil, fmt.Errorf("打开数据库失败 (%s): %w", driver, err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("数据库连接失败 (%s): %w", driver, err)
	}

	wrapped := &DB{DB: db, Driver: driver}
	if err := wrapped.migrate(); err != nil {
		return nil, fmt.Errorf("数据库迁移失败: %w", err)
	}

	return wrapped, nil
}

// resolveDSN 根据 databaseURL 解析驱动类型和 DSN。
func resolveDSN(path, databaseURL string) (DriverType, string, error) {
	if databaseURL == "" {
		// 默认 SQLite。
		// 必须显式设置 busy_timeout：SQLite 同一时刻只允许一个写事务，
		// 缺少忙等待时并发写会立即返回 SQLITE_BUSY 而不是短暂等待后重试。
		dsn := path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
		return DriverSQLite, dsn, nil
	}

	switch {
	case strings.HasPrefix(databaseURL, "postgres://") || strings.HasPrefix(databaseURL, "postgresql://"):
		return DriverPostgres, databaseURL, nil
	case strings.HasPrefix(databaseURL, "mysql://"):
		// 将 mysql:// 转换为 go-sql-driver/mysql 格式
		dsn := convertMySQLDSN(databaseURL)
		return DriverMySQL, dsn, nil
	default:
		// 未知前缀，尝试作为 SQLite 路径
		dsn := databaseURL + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
		return DriverSQLite, dsn, nil
	}
}

// convertMySQLDSN 将 mysql://user:pass@host:port/db 转换为 user:pass@tcp(host:port)/db?parseTime=true
func convertMySQLDSN(url string) string {
	// 去掉 mysql:// 前缀
	s := strings.TrimPrefix(url, "mysql://")
	// 找到 @ 分隔用户信息和主机
	atIdx := strings.LastIndex(s, "@")
	if atIdx < 0 {
		return s + "?parseTime=true&charset=utf8mb4"
	}
	userInfo := s[:atIdx]
	hostDB := s[atIdx+1:]
	// 找到 / 分隔主机和数据库
	slashIdx := strings.Index(hostDB, "/")
	if slashIdx < 0 {
		return userInfo + "@tcp(" + hostDB + ")/?parseTime=true&charset=utf8mb4"
	}
	host := hostDB[:slashIdx]
	dbPart := hostDB[slashIdx:]
	return userInfo + "@tcp(" + host + ")" + dbPart + "?parseTime=true&charset=utf8mb4"
}

// Placeholder 返回当前驱动的占位符（SQLite/MySQL 用 ?，PostgreSQL 用 $1,$2...）。
func (db *DB) Placeholder(n int) string {
	if db.Driver == DriverPostgres {
		return fmt.Sprintf("$%d", n)
	}
	return "?"
}

// migrate 执行数据库 Schema 迁移（创建表 + 增量 ALTER TABLE）。
func (db *DB) migrate() error {
	// 第一步：创建基础表结构
	if err := db.createTables(); err != nil {
		return fmt.Errorf("创建表失败: %w", err)
	}
	// 第二步：增量添加新字段（ALTER TABLE IF NOT EXISTS 方式）
	if err := db.alterTables(); err != nil {
		return fmt.Errorf("升级表结构失败: %w", err)
	}
	return nil
}

// execIgnoreError 执行 SQL，忽略"列已存在"等幂等错误。
func (db *DB) execIgnoreError(sql string) {
	db.Exec(sql) //nolint:errcheck // ALTER TABLE 幂等操作，忽略"列已存在"错误
}

// alterTables 增量添加新字段（幂等，可重复执行）。
func (db *DB) alterTables() error {
	// cards 表：增加 storage_zone_uuid, pin_data, puk_data, admin_key_data, pin_retries, pin_failed_count, pin_locked
	db.execIgnoreError(`ALTER TABLE cards ADD COLUMN storage_zone_uuid TEXT NOT NULL DEFAULT ''`)
	db.execIgnoreError(`ALTER TABLE cards ADD COLUMN pin_data TEXT`)
	db.execIgnoreError(`ALTER TABLE cards ADD COLUMN puk_data TEXT`)
	db.execIgnoreError(`ALTER TABLE cards ADD COLUMN admin_key_data TEXT`)
	db.execIgnoreError(`ALTER TABLE cards ADD COLUMN pin_retries INTEGER NOT NULL DEFAULT 3`)
	db.execIgnoreError(`ALTER TABLE cards ADD COLUMN pin_failed_count INTEGER NOT NULL DEFAULT 0`)
	db.execIgnoreError(`ALTER TABLE cards ADD COLUMN pin_locked INTEGER NOT NULL DEFAULT 0`)

	// certificates 表：增加完整元数据字段
	db.execIgnoreError(`ALTER TABLE certificates ADD COLUMN subject_dn TEXT NOT NULL DEFAULT ''`)
	db.execIgnoreError(`ALTER TABLE certificates ADD COLUMN issuer_dn TEXT NOT NULL DEFAULT ''`)
	db.execIgnoreError(`ALTER TABLE certificates ADD COLUMN serial_hex TEXT NOT NULL DEFAULT ''`)
	db.execIgnoreError(`ALTER TABLE certificates ADD COLUMN not_before DATETIME`)
	db.execIgnoreError(`ALTER TABLE certificates ADD COLUMN not_after DATETIME`)
	db.execIgnoreError(`ALTER TABLE certificates ADD COLUMN key_usage INTEGER NOT NULL DEFAULT 0`)
	db.execIgnoreError(`ALTER TABLE certificates ADD COLUMN ext_key_usage TEXT NOT NULL DEFAULT '[]'`)
	db.execIgnoreError(`ALTER TABLE certificates ADD COLUMN san_dns TEXT NOT NULL DEFAULT '[]'`)
	db.execIgnoreError(`ALTER TABLE certificates ADD COLUMN san_ip TEXT NOT NULL DEFAULT '[]'`)
	db.execIgnoreError(`ALTER TABLE certificates ADD COLUMN san_email TEXT NOT NULL DEFAULT '[]'`)
	db.execIgnoreError(`ALTER TABLE certificates ADD COLUMN revoke_reason INTEGER NOT NULL DEFAULT 0`)
	db.execIgnoreError(`ALTER TABLE certificates ADD COLUMN user_uuid TEXT NOT NULL DEFAULT ''`)
	db.execIgnoreError(`ALTER TABLE certificates ADD COLUMN template_uuid TEXT NOT NULL DEFAULT ''`)
	db.execIgnoreError(`ALTER TABLE certificates ADD COLUMN card_uuid_ref TEXT NOT NULL DEFAULT ''`)

	// custom_oids 表：增加 asn1_type 字段
	db.execIgnoreError(`ALTER TABLE custom_oids ADD COLUMN asn1_type TEXT NOT NULL DEFAULT 'UTF8String'`)

	// issuance_templates 表：增加 cert_ext_tmpl_uuid 关联字段
	db.execIgnoreError(`ALTER TABLE issuance_templates ADD COLUMN cert_ext_tmpl_uuid TEXT NOT NULL DEFAULT ''`)

	// cert_ext_templates 表：增加 netscape_config, csp_config, asn1_extensions 字段
	db.execIgnoreError(`ALTER TABLE cert_ext_templates ADD COLUMN netscape_config TEXT NOT NULL DEFAULT ''`)
	db.execIgnoreError(`ALTER TABLE cert_ext_templates ADD COLUMN csp_config TEXT NOT NULL DEFAULT ''`)
	db.execIgnoreError(`ALTER TABLE cert_ext_templates ADD COLUMN asn1_extensions TEXT NOT NULL DEFAULT '[]'`)

	// cert_orders 表：增加完整状态机字段
	db.execIgnoreError(`ALTER TABLE cert_orders ADD COLUMN paid_at DATETIME`)
	db.execIgnoreError(`ALTER TABLE cert_orders ADD COLUMN cert_apply_tmpl_uuid TEXT NOT NULL DEFAULT ''`)
	db.execIgnoreError(`ALTER TABLE cert_orders ADD COLUMN frozen_cents INTEGER NOT NULL DEFAULT 0`)

	// extension_templates 表：增加 verify_expires_days（验证有效期天数，默认 90）
	db.execIgnoreError(`ALTER TABLE extension_templates ADD COLUMN verify_expires_days INTEGER NOT NULL DEFAULT 90`)

	// extension_infos 表：增加 tmpl_uuid（关联扩展信息模板）和 verify_code_hash（6 位验证码的 SHA-256）
	db.execIgnoreError(`ALTER TABLE extension_infos ADD COLUMN tmpl_uuid TEXT NOT NULL DEFAULT ''`)
	db.execIgnoreError(`ALTER TABLE extension_infos ADD COLUMN verify_code_hash TEXT NOT NULL DEFAULT ''`)

	// T23：certificates 补 san_uris（URI SAN）和 certificate_policies（证书策略 OID）
	db.execIgnoreError(`ALTER TABLE certificates ADD COLUMN san_uris TEXT NOT NULL DEFAULT '[]'`)
	db.execIgnoreError(`ALTER TABLE certificates ADD COLUMN certificate_policies TEXT NOT NULL DEFAULT '[]'`)

	// T23：extension_templates 补 URI/RID/Other SAN 上限与开关
	db.execIgnoreError(`ALTER TABLE extension_templates ADD COLUMN max_rid INTEGER NOT NULL DEFAULT 0`)
	db.execIgnoreError(`ALTER TABLE extension_templates ADD COLUMN max_other INTEGER NOT NULL DEFAULT 0`)
	db.execIgnoreError(`ALTER TABLE extension_templates ADD COLUMN allow_uri INTEGER NOT NULL DEFAULT 1`)
	db.execIgnoreError(`ALTER TABLE extension_templates ADD COLUMN allow_rid INTEGER NOT NULL DEFAULT 0`)
	db.execIgnoreError(`ALTER TABLE extension_templates ADD COLUMN allow_other INTEGER NOT NULL DEFAULT 0`)

	// T23：custom_oids 补 is_critical
	db.execIgnoreError(`ALTER TABLE custom_oids ADD COLUMN is_critical INTEGER NOT NULL DEFAULT 0`)

	// 门户：cert_orders 补对外单号与商品快照字段（兼容既有订单，历史行为空）
	db.execIgnoreError(`ALTER TABLE cert_orders ADD COLUMN order_no TEXT NOT NULL DEFAULT ''`)
	db.execIgnoreError(`ALTER TABLE cert_orders ADD COLUMN product_code TEXT NOT NULL DEFAULT ''`)
	db.execIgnoreError(`ALTER TABLE cert_orders ADD COLUMN sku_code TEXT NOT NULL DEFAULT ''`)
	db.execIgnoreError(`ALTER TABLE cert_orders ADD COLUMN spec_json TEXT NOT NULL DEFAULT '{}'`)
	db.execIgnoreError(`ALTER TABLE cert_orders ADD COLUMN applicant_email TEXT NOT NULL DEFAULT ''`)
	db.execIgnoreError(`CREATE UNIQUE INDEX IF NOT EXISTS idx_cert_orders_order_no ON cert_orders(order_no) WHERE order_no <> ''`)

	// 支付：退款工单支持业务订单（证书订单等）与渠道原路退款
	db.execIgnoreError(`ALTER TABLE refund_requests ADD COLUMN biz_type TEXT NOT NULL DEFAULT 'recharge'`)
	db.execIgnoreError(`ALTER TABLE refund_requests ADD COLUMN biz_uuid TEXT NOT NULL DEFAULT ''`)
	db.execIgnoreError(`ALTER TABLE refund_requests ADD COLUMN channel TEXT NOT NULL DEFAULT ''`)
	db.execIgnoreError(`ALTER TABLE refund_requests ADD COLUMN fail_reason TEXT NOT NULL DEFAULT ''`)
	db.execIgnoreError(`ALTER TABLE refund_requests ADD COLUMN refund_no TEXT NOT NULL DEFAULT ''`)

	// 申请：支持用户自带 CSR（私钥不进入服务端）
	db.execIgnoreError(`ALTER TABLE cert_applications ADD COLUMN csr_pem TEXT NOT NULL DEFAULT ''`)
	db.execIgnoreError(`ALTER TABLE cert_applications ADD COLUMN applicant_email TEXT NOT NULL DEFAULT ''`)

	// 证书：记录签发时的申请来源与下发目标，便于排障
	db.execIgnoreError(`ALTER TABLE certificates ADD COLUMN csr_pem TEXT NOT NULL DEFAULT ''`)

	// 门户：CA 是否对外公开发布（内部 CA 默认不进入公开信任目录）
	db.execIgnoreError(`ALTER TABLE cas ADD COLUMN is_public INTEGER NOT NULL DEFAULT 0`)

	// 业务模式：卡片来源订单（销售模式下凭已支付订单开卡）与卡片类型
	//   card_kind = user    用户智能卡（可远程签名/解密）
	//   card_kind = hosting 系统证书托管容器（文件下载型证书的存放位置，不支持远程密码运算）
	db.execIgnoreError(`ALTER TABLE cards ADD COLUMN order_no TEXT NOT NULL DEFAULT ''`)
	db.execIgnoreError(`ALTER TABLE cards ADD COLUMN card_kind TEXT NOT NULL DEFAULT 'user'`)
	db.execIgnoreError(`CREATE INDEX IF NOT EXISTS idx_cards_order_no ON cards(order_no)`)

	// 申请：签发目标卡片（为空时按交付方式落到托管容器）
	db.execIgnoreError(`ALTER TABLE cert_applications ADD COLUMN card_uuid TEXT NOT NULL DEFAULT ''`)

	db.alterTablesV2()
	return nil
}

// alterTablesV2 业务重构：OCSP 响应服务、证书策略、身份认证接口、模板职责调整、优惠与订阅。
func (db *DB) alterTablesV2() {
	// ---- 独立 OCSP 响应服务：一个签名证书可响应多个 CA 的证书状态 ----
	db.execIgnoreError(`CREATE TABLE IF NOT EXISTS ocsp_responders (
	    uuid                TEXT PRIMARY KEY,
	    name                TEXT NOT NULL,
	    path                TEXT NOT NULL UNIQUE,
	    signer_type         TEXT NOT NULL DEFAULT 'ca',
	    signer_ref          TEXT NOT NULL DEFAULT '',
	    ca_uuids            TEXT NOT NULL DEFAULT '[]',
	    next_update_minutes INTEGER NOT NULL DEFAULT 60,
	    enabled             INTEGER NOT NULL DEFAULT 1,
	    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	    updated_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`)
	// 未在本平台登记的序列号如何响应：unknown（RFC 6960 推荐）/ good（兼容未登记的外部签发）
	db.execIgnoreError(`ALTER TABLE ocsp_responders ADD COLUMN unknown_policy TEXT NOT NULL DEFAULT 'unknown'`)

	// ---- 证书策略（CP/CPS）页面 ----
	db.execIgnoreError(`CREATE TABLE IF NOT EXISTS cert_policies (
	    uuid         TEXT PRIMARY KEY,
	    name         TEXT NOT NULL,
	    path         TEXT NOT NULL UNIQUE,
	    content_type TEXT NOT NULL DEFAULT 'markdown',
	    content      TEXT NOT NULL DEFAULT '',
	    version      TEXT NOT NULL DEFAULT '',
	    enabled      INTEGER NOT NULL DEFAULT 1,
	    is_public    INTEGER NOT NULL DEFAULT 1,
	    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	    updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`)

	// ---- 身份认证接口（邮件 / 实名）与实名认证会话 ----
	db.execIgnoreError(`CREATE TABLE IF NOT EXISTS verify_providers (
	    uuid       TEXT PRIMARY KEY,
	    name       TEXT NOT NULL,
	    kind       TEXT NOT NULL,
	    driver     TEXT NOT NULL,
	    config_enc TEXT NOT NULL DEFAULT '',
	    enabled    INTEGER NOT NULL DEFAULT 1,
	    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`)
	db.execIgnoreError(`CREATE TABLE IF NOT EXISTS identity_sessions (
	    uuid              TEXT PRIMARY KEY,
	    provider_uuid     TEXT NOT NULL,
	    subject_info_uuid TEXT NOT NULL,
	    user_uuid         TEXT NOT NULL,
	    external_id       TEXT NOT NULL DEFAULT '',
	    status            TEXT NOT NULL DEFAULT 'pending',
	    message           TEXT NOT NULL DEFAULT '',
	    expires_at        DATETIME,
	    created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	    updated_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`)
	db.execIgnoreError(`CREATE INDEX IF NOT EXISTS idx_identity_sessions_subject ON identity_sessions(subject_info_uuid)`)

	// 主体模板：字段级验证方式之外的模板级认证接口与有效期
	db.execIgnoreError(`ALTER TABLE subject_templates ADD COLUMN verify_provider_uuid TEXT NOT NULL DEFAULT ''`)
	db.execIgnoreError(`ALTER TABLE subject_templates ADD COLUMN verify_validity TEXT NOT NULL DEFAULT '365d'`)
	db.execIgnoreError(`ALTER TABLE subject_templates ADD COLUMN description TEXT NOT NULL DEFAULT ''`)
	// 扩展信息模板：按类型的验证策略（方式、认证接口、有效期），数量限制迁移到商品规格
	db.execIgnoreError(`ALTER TABLE extension_templates ADD COLUMN verify_policy TEXT NOT NULL DEFAULT '{}'`)
	// 主体信息：有效期、驳回原因、验证方式
	db.execIgnoreError(`ALTER TABLE subject_infos ADD COLUMN expires_at DATETIME`)
	db.execIgnoreError(`ALTER TABLE subject_infos ADD COLUMN reject_reason TEXT NOT NULL DEFAULT ''`)
	db.execIgnoreError(`ALTER TABLE subject_infos ADD COLUMN verify_mode TEXT NOT NULL DEFAULT 'manual'`)
	// 扩展信息：人工审核驳回原因、验证码错误次数（防暴力破解）
	db.execIgnoreError(`ALTER TABLE extension_infos ADD COLUMN reject_reason TEXT NOT NULL DEFAULT ''`)
	db.execIgnoreError(`ALTER TABLE extension_infos ADD COLUMN verify_attempts INTEGER NOT NULL DEFAULT 0`)

	// ---- 模板职责：开通模板绑定主体/扩展模板；规格承载 SAN 限制 ----
	db.execIgnoreError(`ALTER TABLE cert_apply_templates ADD COLUMN subject_tmpl_uuid TEXT NOT NULL DEFAULT ''`)
	db.execIgnoreError(`ALTER TABLE cert_apply_templates ADD COLUMN extension_tmpl_uuid TEXT NOT NULL DEFAULT ''`)
	db.execIgnoreError(`ALTER TABLE portal_product_skus ADD COLUMN san_policy TEXT NOT NULL DEFAULT '{}'`)

	// ---- 优惠码、兑换码与订阅 ----
	db.execIgnoreError(`ALTER TABLE cert_orders ADD COLUMN subscription_uuid TEXT NOT NULL DEFAULT ''`)
	db.execIgnoreError(`ALTER TABLE cert_orders ADD COLUMN coupon_code TEXT NOT NULL DEFAULT ''`)
	db.execIgnoreError(`ALTER TABLE cert_orders ADD COLUMN discount_cents INTEGER NOT NULL DEFAULT 0`)
	db.execIgnoreError(`CREATE INDEX IF NOT EXISTS idx_cert_orders_subscription ON cert_orders(subscription_uuid)`)

	db.execIgnoreError(`CREATE TABLE IF NOT EXISTS promo_coupons (
	    uuid               TEXT PRIMARY KEY,
	    code               TEXT NOT NULL UNIQUE,
	    name               TEXT NOT NULL DEFAULT '',
	    discount_type      TEXT NOT NULL DEFAULT 'amount',
	    discount_value     INTEGER NOT NULL DEFAULT 0,
	    min_amount_cents   INTEGER NOT NULL DEFAULT 0,
	    max_discount_cents INTEGER NOT NULL DEFAULT 0,
	    product_codes      TEXT NOT NULL DEFAULT '[]',
	    total_limit        INTEGER NOT NULL DEFAULT -1,
	    used_count         INTEGER NOT NULL DEFAULT 0,
	    per_user_limit     INTEGER NOT NULL DEFAULT 1,
	    valid_from         DATETIME,
	    valid_until        DATETIME,
	    enabled            INTEGER NOT NULL DEFAULT 1,
	    created_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	    updated_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`)
	db.execIgnoreError(`CREATE TABLE IF NOT EXISTS promo_coupon_usages (
	    uuid           TEXT PRIMARY KEY,
	    coupon_uuid    TEXT NOT NULL,
	    user_uuid      TEXT NOT NULL,
	    order_no       TEXT NOT NULL UNIQUE,
	    discount_cents INTEGER NOT NULL DEFAULT 0,
	    created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`)
	db.execIgnoreError(`CREATE INDEX IF NOT EXISTS idx_coupon_usages_user ON promo_coupon_usages(coupon_uuid, user_uuid)`)

	db.execIgnoreError(`CREATE TABLE IF NOT EXISTS promo_plans (
	    uuid                 TEXT PRIMARY KEY,
	    code                 TEXT NOT NULL UNIQUE,
	    name                 TEXT NOT NULL,
	    description          TEXT NOT NULL DEFAULT '',
	    period_days          INTEGER NOT NULL DEFAULT 365,
	    price_cents          INTEGER NOT NULL DEFAULT 0,
	    items                TEXT NOT NULL DEFAULT '[]',
	    allow_revoke         INTEGER NOT NULL DEFAULT 1,
	    revoke_release_quota INTEGER NOT NULL DEFAULT 0,
	    visible              INTEGER NOT NULL DEFAULT 1,
	    enabled              INTEGER NOT NULL DEFAULT 1,
	    sort_weight          INTEGER NOT NULL DEFAULT 0,
	    created_at           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	    updated_at           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`)
	db.execIgnoreError(`CREATE TABLE IF NOT EXISTS promo_subscriptions (
	    uuid          TEXT PRIMARY KEY,
	    user_uuid     TEXT NOT NULL,
	    plan_uuid     TEXT NOT NULL,
	    plan_snapshot TEXT NOT NULL DEFAULT '{}',
	    source        TEXT NOT NULL,
	    source_ref    TEXT NOT NULL,
	    starts_at     DATETIME NOT NULL,
	    ends_at       DATETIME NOT NULL,
	    status        TEXT NOT NULL DEFAULT 'active',
	    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	    updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`)
	db.execIgnoreError(`CREATE UNIQUE INDEX IF NOT EXISTS idx_subscriptions_source ON promo_subscriptions(source, source_ref)`)
	db.execIgnoreError(`CREATE INDEX IF NOT EXISTS idx_subscriptions_user ON promo_subscriptions(user_uuid)`)

	db.execIgnoreError(`CREATE TABLE IF NOT EXISTS promo_redeem_codes (
	    uuid          TEXT PRIMARY KEY,
	    code          TEXT NOT NULL UNIQUE,
	    batch_name    TEXT NOT NULL DEFAULT '',
	    grant_type    TEXT NOT NULL DEFAULT 'plan',
	    plan_uuid     TEXT NOT NULL DEFAULT '',
	    balance_cents INTEGER NOT NULL DEFAULT 0,
	    max_uses      INTEGER NOT NULL DEFAULT 1,
	    used_count    INTEGER NOT NULL DEFAULT 0,
	    valid_until   DATETIME,
	    enabled       INTEGER NOT NULL DEFAULT 1,
	    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`)
	db.execIgnoreError(`CREATE TABLE IF NOT EXISTS promo_redeem_usages (
	    uuid       TEXT PRIMARY KEY,
	    code_uuid  TEXT NOT NULL,
	    user_uuid  TEXT NOT NULL,
	    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`)
	db.execIgnoreError(`CREATE UNIQUE INDEX IF NOT EXISTS idx_redeem_usages_user ON promo_redeem_usages(code_uuid, user_uuid)`)
}

// createTables 创建所有基础表（幂等，IF NOT EXISTS）。
func (db *DB) createTables() error {
	schema := `
-- 用户表
CREATE TABLE IF NOT EXISTS users (
    uuid            TEXT PRIMARY KEY,
    username        TEXT NOT NULL UNIQUE,
    display_name    TEXT NOT NULL DEFAULT '',
    email           TEXT NOT NULL DEFAULT '',
    password_hash   TEXT NOT NULL,
    role            TEXT NOT NULL DEFAULT 'user',
    public_key      TEXT,
    totp_secret     TEXT NOT NULL DEFAULT '',
    enabled         INTEGER NOT NULL DEFAULT 1,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    DATETIME,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 云端卡片表
CREATE TABLE IF NOT EXISTS cards (
    uuid                TEXT PRIMARY KEY,
    user_uuid           TEXT NOT NULL REFERENCES users(uuid) ON DELETE CASCADE,
    card_name           TEXT NOT NULL,
    remark              TEXT NOT NULL DEFAULT '',
    storage_zone_uuid   TEXT NOT NULL DEFAULT '',
    pin_data            TEXT,
    puk_data            TEXT,
    admin_key_data      TEXT,
    pin_retries         INTEGER NOT NULL DEFAULT 3,
    pin_failed_count    INTEGER NOT NULL DEFAULT 0,
    pin_locked          INTEGER NOT NULL DEFAULT 0,
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 云端证书表（私钥加密存储，不离开服务器）
CREATE TABLE IF NOT EXISTS certificates (
    uuid               TEXT PRIMARY KEY,
    card_uuid          TEXT NOT NULL REFERENCES cards(uuid) ON DELETE CASCADE,
    user_uuid          TEXT NOT NULL DEFAULT '',
    cert_type          TEXT NOT NULL DEFAULT 'x509',
    key_type           TEXT NOT NULL DEFAULT 'ec256',
    cert_content       TEXT,
    private_data       TEXT,
    remark             TEXT NOT NULL DEFAULT '',
    order_no           TEXT NOT NULL DEFAULT '',
    ca_uuid            TEXT NOT NULL DEFAULT '',
    serial_number      TEXT NOT NULL DEFAULT '',
    serial_hex         TEXT NOT NULL DEFAULT '',
    subject_dn         TEXT NOT NULL DEFAULT '',
    issuer_dn          TEXT NOT NULL DEFAULT '',
    not_before         DATETIME,
    not_after          DATETIME,
    key_usage          INTEGER NOT NULL DEFAULT 0,
    ext_key_usage      TEXT NOT NULL DEFAULT '[]',
    san_dns            TEXT NOT NULL DEFAULT '[]',
    san_ip             TEXT NOT NULL DEFAULT '[]',
    san_email          TEXT NOT NULL DEFAULT '[]',
    san_uris           TEXT NOT NULL DEFAULT '[]',
    certificate_policies TEXT NOT NULL DEFAULT '[]',
    issuance_tmpl_uuid TEXT NOT NULL DEFAULT '',
    template_uuid      TEXT NOT NULL DEFAULT '',
    storage_policy     TEXT NOT NULL DEFAULT '',
    revocation_status  TEXT NOT NULL DEFAULT 'active',
    revoke_reason      INTEGER NOT NULL DEFAULT 0,
    revoked_at         DATETIME,
    created_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_certs_revocation ON certificates(revocation_status);
CREATE INDEX IF NOT EXISTS idx_certs_ca ON certificates(ca_uuid);
CREATE INDEX IF NOT EXISTS idx_certs_order ON certificates(order_no);
CREATE INDEX IF NOT EXISTS idx_certs_user ON certificates(user_uuid);

-- 审计日志表（链式哈希完整性）
CREATE TABLE IF NOT EXISTS audit_logs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_uuid     TEXT NOT NULL DEFAULT '',
    action        TEXT NOT NULL,
    resource_type TEXT NOT NULL DEFAULT '',
    resource_uuid TEXT NOT NULL DEFAULT '',
    detail        TEXT NOT NULL DEFAULT '{}',
    ip_address    TEXT NOT NULL DEFAULT '',
    prev_hash     TEXT NOT NULL DEFAULT '',
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_uuid);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at);

-- 操作日志表（兼容旧版）
CREATE TABLE IF NOT EXISTS logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_uuid   TEXT NOT NULL DEFAULT '',
    card_uuid   TEXT NOT NULL DEFAULT '',
    cert_uuid   TEXT NOT NULL DEFAULT '',
    action      TEXT NOT NULL,
    ip_addr     TEXT NOT NULL DEFAULT '',
    user_agent  TEXT NOT NULL DEFAULT '',
    recorded_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_cards_user_uuid ON cards(user_uuid);
CREATE INDEX IF NOT EXISTS idx_certs_card_uuid ON certificates(card_uuid);
CREATE INDEX IF NOT EXISTS idx_logs_user_uuid  ON logs(user_uuid);
CREATE INDEX IF NOT EXISTS idx_logs_recorded_at ON logs(recorded_at);

-- 支付插件配置表
CREATE TABLE IF NOT EXISTS payment_plugins (
    uuid        TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    plugin_type TEXT NOT NULL,
    config_enc  TEXT,
    enabled     INTEGER NOT NULL DEFAULT 1,
    sort_weight INTEGER NOT NULL DEFAULT 0,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 充值订单表
CREATE TABLE IF NOT EXISTS recharge_orders (
    order_no      TEXT PRIMARY KEY,
    user_uuid     TEXT NOT NULL REFERENCES users(uuid),
    amount_cents  INTEGER NOT NULL,
    channel       TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pending',
    callback_data TEXT,
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    paid_at       DATETIME,
    expires_at    DATETIME NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_recharge_orders_user ON recharge_orders(user_uuid);
CREATE INDEX IF NOT EXISTS idx_recharge_orders_status ON recharge_orders(status);

-- 用户余额表
CREATE TABLE IF NOT EXISTS user_balances (
    user_uuid        TEXT PRIMARY KEY REFERENCES users(uuid),
    available_cents  INTEGER NOT NULL DEFAULT 0,
    frozen_cents     INTEGER NOT NULL DEFAULT 0,
    total_recharge   INTEGER NOT NULL DEFAULT 0,
    total_consume    INTEGER NOT NULL DEFAULT 0
);

-- 消费记录表
CREATE TABLE IF NOT EXISTS consume_records (
    uuid         TEXT PRIMARY KEY,
    user_uuid    TEXT NOT NULL REFERENCES users(uuid),
    order_no     TEXT,
    consume_type TEXT NOT NULL,
    amount_cents INTEGER NOT NULL,
    remark       TEXT NOT NULL DEFAULT '',
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_consume_records_user ON consume_records(user_uuid);

-- 退款工单表
CREATE TABLE IF NOT EXISTS refund_requests (
    uuid         TEXT PRIMARY KEY,
    user_uuid    TEXT NOT NULL REFERENCES users(uuid),
    order_no     TEXT NOT NULL,
    amount_cents INTEGER NOT NULL,
    reason       TEXT NOT NULL DEFAULT '',
    status       TEXT NOT NULL DEFAULT 'pending',
    approved_by  TEXT,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    processed_at DATETIME
);

-- 密钥存储类型模板表
CREATE TABLE IF NOT EXISTS key_storage_templates (
    uuid              TEXT PRIMARY KEY,
    name              TEXT NOT NULL,
    storage_methods   INTEGER NOT NULL DEFAULT 0,
    security_level    TEXT NOT NULL DEFAULT '',
    allow_reimport    INTEGER NOT NULL DEFAULT 0,
    cloud_backup      INTEGER NOT NULL DEFAULT 0,
    allow_reissue     INTEGER NOT NULL DEFAULT 0,
    max_reissue_count INTEGER NOT NULL DEFAULT 0,
    created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 证书下发记录表
CREATE TABLE IF NOT EXISTS cert_issuance_records (
    uuid            TEXT PRIMARY KEY,
    cert_uuid       TEXT NOT NULL,
    user_uuid       TEXT NOT NULL,
    issuance_method TEXT NOT NULL,
    device_info     TEXT NOT NULL DEFAULT '',
    issued_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_cert_issuance_cert ON cert_issuance_records(cert_uuid);

-- 证书重新下发计数器表
CREATE TABLE IF NOT EXISTS cert_reissue_counters (
    cert_uuid     TEXT NOT NULL,
    template_uuid TEXT NOT NULL REFERENCES key_storage_templates(uuid),
    issued_count  INTEGER NOT NULL DEFAULT 0,
    max_count     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (cert_uuid, template_uuid)
);

-- CA 证书颁发机构表
CREATE TABLE IF NOT EXISTS cas (
    uuid         TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    cert_pem     TEXT NOT NULL,
    private_enc  TEXT NOT NULL,
    parent_uuid  TEXT NOT NULL DEFAULT '',
    status       TEXT NOT NULL DEFAULT 'active',
    not_before   DATETIME NOT NULL,
    not_after    DATETIME NOT NULL,
    issued_count INTEGER NOT NULL DEFAULT 0,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_cas_parent ON cas(parent_uuid);
CREATE INDEX IF NOT EXISTS idx_cas_status ON cas(status);

-- 已吊销证书表
CREATE TABLE IF NOT EXISTS revoked_certs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ca_uuid       TEXT NOT NULL REFERENCES cas(uuid),
    serial_number TEXT NOT NULL,
    revoked_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reason        INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_revoked_certs_ca ON revoked_certs(ca_uuid);
CREATE UNIQUE INDEX IF NOT EXISTS idx_revoked_certs_serial ON revoked_certs(ca_uuid, serial_number);

-- 主体模板表
CREATE TABLE IF NOT EXISTS subject_templates (
    uuid       TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    fields     TEXT NOT NULL DEFAULT '[]',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 扩展信息模板表（SAN 配置）
CREATE TABLE IF NOT EXISTS extension_templates (
    uuid                 TEXT PRIMARY KEY,
    name                 TEXT NOT NULL,
    max_dns              INTEGER NOT NULL DEFAULT 10,
    max_email            INTEGER NOT NULL DEFAULT 5,
    max_ip               INTEGER NOT NULL DEFAULT 5,
    max_uri              INTEGER NOT NULL DEFAULT 5,
    max_rid              INTEGER NOT NULL DEFAULT 0,
    max_other            INTEGER NOT NULL DEFAULT 0,
    allow_uri            INTEGER NOT NULL DEFAULT 1,
    allow_rid            INTEGER NOT NULL DEFAULT 0,
    allow_other          INTEGER NOT NULL DEFAULT 0,
    require_dns_verify   INTEGER NOT NULL DEFAULT 0,
    require_email_verify INTEGER NOT NULL DEFAULT 0,
    created_at           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 密钥用途模板表
CREATE TABLE IF NOT EXISTS key_usage_templates (
    uuid           TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    key_usage      INTEGER NOT NULL DEFAULT 0,
    ext_key_usages TEXT NOT NULL DEFAULT '[]',
    created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 证书扩展模板表
CREATE TABLE IF NOT EXISTS cert_ext_templates (
    uuid             TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    crl_dist_points  TEXT NOT NULL DEFAULT '[]',
    ocsp_servers     TEXT NOT NULL DEFAULT '[]',
    aia_issuers      TEXT NOT NULL DEFAULT '[]',
    ct_servers       TEXT NOT NULL DEFAULT '[]',
    ev_policy_oid    TEXT NOT NULL DEFAULT '',
    netscape_config  TEXT NOT NULL DEFAULT '',
    csp_config       TEXT NOT NULL DEFAULT '',
    asn1_extensions  TEXT NOT NULL DEFAULT '[]',
    created_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 证书颁发模板表
CREATE TABLE IF NOT EXISTS issuance_templates (
    uuid                  TEXT PRIMARY KEY,
    name                  TEXT NOT NULL,
    is_ca                 INTEGER NOT NULL DEFAULT 0,
    path_len              INTEGER NOT NULL DEFAULT 0,
    valid_days            TEXT NOT NULL DEFAULT '[365]',
    allowed_key_types     TEXT NOT NULL DEFAULT '["ec256","rsa2048"]',
    allowed_ca_uuids      TEXT NOT NULL DEFAULT '[]',
    subject_tmpl_uuid     TEXT NOT NULL DEFAULT '',
    extension_tmpl_uuid   TEXT NOT NULL DEFAULT '',
    key_usage_tmpl_uuid   TEXT NOT NULL DEFAULT '',
    key_storage_tmpl_uuid TEXT NOT NULL DEFAULT '',
    cert_ext_tmpl_uuid    TEXT NOT NULL DEFAULT '',
    price_cents           INTEGER NOT NULL DEFAULT 0,
    stock                 INTEGER NOT NULL DEFAULT -1,
    category              TEXT NOT NULL DEFAULT 'custom',
    enabled               INTEGER NOT NULL DEFAULT 1,
    created_at            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_issuance_templates_category ON issuance_templates(category);
CREATE INDEX IF NOT EXISTS idx_issuance_templates_enabled ON issuance_templates(enabled);

-- 证书申请模板表（面向用户的产品化配置）
CREATE TABLE IF NOT EXISTS cert_apply_templates (
    uuid                  TEXT PRIMARY KEY,
    name                  TEXT NOT NULL,
    issuance_tmpl_uuid    TEXT NOT NULL DEFAULT '',
    valid_days            INTEGER NOT NULL DEFAULT 365,
    ca_uuid               TEXT NOT NULL DEFAULT '',
    enabled               INTEGER NOT NULL DEFAULT 1,
    require_approval      INTEGER NOT NULL DEFAULT 0,
    allow_renewal         INTEGER NOT NULL DEFAULT 0,
    allowed_key_types     TEXT NOT NULL DEFAULT '["ec256","rsa2048"]',
    price_cents           INTEGER NOT NULL DEFAULT 0,
    description           TEXT NOT NULL DEFAULT '',
    created_at            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_cert_apply_templates_enabled ON cert_apply_templates(enabled);

-- 吊销服务配置表
CREATE TABLE IF NOT EXISTS revocation_services (
    uuid         TEXT PRIMARY KEY,
    ca_uuid      TEXT NOT NULL REFERENCES cas(uuid),
    service_type TEXT NOT NULL,
    path         TEXT NOT NULL,
    enabled      INTEGER NOT NULL DEFAULT 1,
    crl_interval INTEGER NOT NULL DEFAULT 60
);

CREATE INDEX IF NOT EXISTS idx_revocation_services_ca ON revocation_services(ca_uuid);

-- 证书订单表
CREATE TABLE IF NOT EXISTS cert_orders (
    uuid                   TEXT PRIMARY KEY,
    user_uuid              TEXT NOT NULL REFERENCES users(uuid),
    issuance_tmpl_uuid     TEXT NOT NULL DEFAULT '',
    cert_apply_tmpl_uuid   TEXT NOT NULL DEFAULT '',
    key_storage_tmpl_uuid  TEXT NOT NULL DEFAULT '',
    amount_cents           INTEGER NOT NULL DEFAULT 0,
    frozen_cents           INTEGER NOT NULL DEFAULT 0,
    status                 TEXT NOT NULL DEFAULT 'pending_payment',
    paid_at                DATETIME,
    created_at             DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at             DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_cert_orders_user ON cert_orders(user_uuid);
CREATE INDEX IF NOT EXISTS idx_cert_orders_status ON cert_orders(status);

-- 证书申请表
CREATE TABLE IF NOT EXISTS cert_applications (
    uuid           TEXT PRIMARY KEY,
    order_uuid     TEXT NOT NULL REFERENCES cert_orders(uuid),
    user_uuid      TEXT NOT NULL REFERENCES users(uuid),
    subject_json   TEXT NOT NULL DEFAULT '{}',
    san_json       TEXT NOT NULL DEFAULT '{}',
    key_type       TEXT NOT NULL DEFAULT 'ec256',
    status         TEXT NOT NULL DEFAULT 'pending',
    approved_by    TEXT,
    approved_at    DATETIME,
    reject_reason  TEXT NOT NULL DEFAULT '',
    cert_uuid      TEXT NOT NULL DEFAULT '',
    created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_cert_applications_user ON cert_applications(user_uuid);
CREATE INDEX IF NOT EXISTS idx_cert_applications_order ON cert_applications(order_uuid);
CREATE INDEX IF NOT EXISTS idx_cert_applications_status ON cert_applications(status);

-- 主体信息表（用户提交的主体信息，需审核）
CREATE TABLE IF NOT EXISTS subject_infos (
    uuid              TEXT PRIMARY KEY,
    user_uuid         TEXT NOT NULL REFERENCES users(uuid),
    subject_tmpl_uuid TEXT NOT NULL DEFAULT '',
    field_values      TEXT NOT NULL DEFAULT '{}',
    status            TEXT NOT NULL DEFAULT 'pending',
    reviewed_by       TEXT,
    reviewed_at       DATETIME,
    created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_subject_infos_user ON subject_infos(user_uuid);
CREATE INDEX IF NOT EXISTS idx_subject_infos_status ON subject_infos(status);

-- 扩展信息表（域名/邮箱/IP 验证）
CREATE TABLE IF NOT EXISTS extension_infos (
    uuid           TEXT PRIMARY KEY,
    user_uuid      TEXT NOT NULL REFERENCES users(uuid),
    info_type      TEXT NOT NULL,
    value          TEXT NOT NULL,
    verify_method  TEXT NOT NULL DEFAULT '',
    verify_token   TEXT NOT NULL DEFAULT '',
    verify_status  TEXT NOT NULL DEFAULT 'pending',
    verified_at    DATETIME,
    expires_at     DATETIME,
    created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_extension_infos_user ON extension_infos(user_uuid);
CREATE INDEX IF NOT EXISTS idx_extension_infos_status ON extension_infos(verify_status);
CREATE UNIQUE INDEX IF NOT EXISTS idx_extension_infos_value ON extension_infos(user_uuid, info_type, value);

-- 云端智能卡存储区域表
CREATE TABLE IF NOT EXISTS storage_zones (
    uuid         TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    storage_type TEXT NOT NULL DEFAULT 'database',
    hsm_driver   TEXT NOT NULL DEFAULT '',
    hsm_auth_enc TEXT,
    status       TEXT NOT NULL DEFAULT 'active',
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 自定义 OID 表
CREATE TABLE IF NOT EXISTS custom_oids (
    uuid        TEXT PRIMARY KEY,
    oid_value   TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    usage_type  TEXT NOT NULL,
    asn1_type   TEXT NOT NULL DEFAULT 'UTF8String',
    is_critical INTEGER NOT NULL DEFAULT 0,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_custom_oids_usage ON custom_oids(usage_type);

-- 云端 TOTP 条目表
CREATE TABLE IF NOT EXISTS user_totps (
    uuid       TEXT PRIMARY KEY,
    user_uuid  TEXT NOT NULL REFERENCES users(uuid),
    issuer     TEXT NOT NULL DEFAULT '',
    account    TEXT NOT NULL DEFAULT '',
    secret_enc TEXT NOT NULL,
    algorithm  TEXT NOT NULL DEFAULT 'SHA1',
    digits     INTEGER NOT NULL DEFAULT 6,
    period     INTEGER NOT NULL DEFAULT 30,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_user_totps_user ON user_totps(user_uuid);

-- ACME 服务配置表
CREATE TABLE IF NOT EXISTS acme_configs (
    uuid               TEXT PRIMARY KEY,
    path               TEXT NOT NULL UNIQUE,
    ca_uuid            TEXT NOT NULL DEFAULT '',
    issuance_tmpl_uuid TEXT NOT NULL DEFAULT '',
    enabled            INTEGER NOT NULL DEFAULT 1
);

-- ACME 账户表
CREATE TABLE IF NOT EXISTS acme_accounts (
    uuid       TEXT PRIMARY KEY,
    config_id  TEXT NOT NULL REFERENCES acme_configs(uuid),
    key_id     TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    contact    TEXT NOT NULL DEFAULT '[]',
    status     TEXT NOT NULL DEFAULT 'valid',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ACME 订单表
CREATE TABLE IF NOT EXISTS acme_orders (
    uuid          TEXT PRIMARY KEY,
    account_uuid  TEXT NOT NULL REFERENCES acme_accounts(uuid),
    status        TEXT NOT NULL DEFAULT 'pending',
    identifiers   TEXT NOT NULL DEFAULT '[]',
    not_before    DATETIME,
    not_after     DATETIME,
    cert_url      TEXT NOT NULL DEFAULT '',
    finalize_url  TEXT NOT NULL DEFAULT '',
    expires       DATETIME NOT NULL,
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_acme_orders_account ON acme_orders(account_uuid);
CREATE INDEX IF NOT EXISTS idx_acme_orders_status ON acme_orders(status);

-- ACME 授权表
CREATE TABLE IF NOT EXISTS acme_authorizations (
    uuid        TEXT PRIMARY KEY,
    order_uuid  TEXT NOT NULL REFERENCES acme_orders(uuid),
    identifier  TEXT NOT NULL DEFAULT '{}',
    status      TEXT NOT NULL DEFAULT 'pending',
    expires     DATETIME NOT NULL,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_acme_authz_order ON acme_authorizations(order_uuid);

-- ACME 挑战表
CREATE TABLE IF NOT EXISTS acme_challenges (
    uuid         TEXT PRIMARY KEY,
    authz_uuid   TEXT NOT NULL REFERENCES acme_authorizations(uuid),
    type         TEXT NOT NULL,
    token        TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending',
    validated_at DATETIME,
    error        TEXT NOT NULL DEFAULT '',
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_acme_challenges_authz ON acme_challenges(authz_uuid);

-- CT 提交记录表
CREATE TABLE IF NOT EXISTS ct_entries (
    uuid         TEXT PRIMARY KEY,
    cert_uuid    TEXT NOT NULL DEFAULT '',
    ca_uuid      TEXT NOT NULL DEFAULT '',
    cert_hash    TEXT NOT NULL,
    ct_server    TEXT NOT NULL,
    sct_data     TEXT,
    status       TEXT NOT NULL DEFAULT 'pending',
    submitted_by TEXT NOT NULL DEFAULT '',
    submitted_at DATETIME,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_ct_entries_cert ON ct_entries(cert_uuid);
CREATE INDEX IF NOT EXISTS idx_ct_entries_hash ON ct_entries(cert_hash);

-- ---- 门户（官网/商城）相关表 ----

-- 门户商品表（决定"卖什么"）
CREATE TABLE IF NOT EXISTS portal_products (
    uuid           TEXT PRIMARY KEY,
    code           TEXT NOT NULL UNIQUE,
    name           TEXT NOT NULL,
    category       TEXT NOT NULL DEFAULT 'ssl',
    level          TEXT NOT NULL DEFAULT '',
    summary        TEXT NOT NULL DEFAULT '',
    description    TEXT NOT NULL DEFAULT '',
    features       TEXT NOT NULL DEFAULT '[]',
    highlights     TEXT NOT NULL DEFAULT '[]',
    badge          TEXT NOT NULL DEFAULT '',
    cover_image    TEXT NOT NULL DEFAULT '',
    sort_weight    INTEGER NOT NULL DEFAULT 0,
    visible        INTEGER NOT NULL DEFAULT 0,
    enabled        INTEGER NOT NULL DEFAULT 1,
    created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_portal_products_category ON portal_products(category);
CREATE INDEX IF NOT EXISTS idx_portal_products_visible ON portal_products(visible, enabled);

-- 门户商品规格表（决定"按什么规格和价格卖"）
CREATE TABLE IF NOT EXISTS portal_product_skus (
    uuid                 TEXT PRIMARY KEY,
    product_uuid         TEXT NOT NULL REFERENCES portal_products(uuid) ON DELETE CASCADE,
    code                 TEXT NOT NULL UNIQUE,
    name                 TEXT NOT NULL,
    price_cents          INTEGER NOT NULL DEFAULT 0,
    currency             TEXT NOT NULL DEFAULT 'CNY',
    stock                INTEGER NOT NULL DEFAULT -1,
    min_qty              INTEGER NOT NULL DEFAULT 1,
    max_qty              INTEGER NOT NULL DEFAULT 10,
    duration_months      INTEGER NOT NULL DEFAULT 12,
    delivery_mode        TEXT NOT NULL DEFAULT 'cloud_card',
    key_types            TEXT NOT NULL DEFAULT '["ec256","rsa2048"]',
    san_included         INTEGER NOT NULL DEFAULT 1,
    cert_apply_tmpl_uuid TEXT NOT NULL DEFAULT '',
    cloud_card_tmpl_uuid TEXT NOT NULL DEFAULT '',
    enabled              INTEGER NOT NULL DEFAULT 1,
    sort_weight          INTEGER NOT NULL DEFAULT 0,
    created_at           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_portal_skus_product ON portal_product_skus(product_uuid);

-- 站点配置表（门户可配置文案、联系方式、下载项等）
CREATE TABLE IF NOT EXISTS site_settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL DEFAULT '',
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ---- 支付与退款 ----

-- 支付尝试表：一次"以某个渠道支付某笔业务订单"的尝试。
-- 金额、渠道与业务归属均在服务端持久化，回调据此校验，避免仅凭单号前缀判断。
CREATE TABLE IF NOT EXISTS payment_attempts (
    uuid            TEXT PRIMARY KEY,
    biz_type        TEXT NOT NULL DEFAULT 'cert_order', -- cert_order / recharge
    biz_uuid        TEXT NOT NULL DEFAULT '',
    order_no        TEXT NOT NULL,
    user_uuid       TEXT NOT NULL DEFAULT '',
    channel         TEXT NOT NULL,
    amount_cents    INTEGER NOT NULL DEFAULT 0,
    currency        TEXT NOT NULL DEFAULT 'CNY',
    status          TEXT NOT NULL DEFAULT 'pending',    -- pending/paid/failed/closed
    transaction_id  TEXT NOT NULL DEFAULT '',           -- 渠道交易号
    raw_callback    TEXT NOT NULL DEFAULT '',
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    paid_at         DATETIME,
    expires_at      DATETIME
);

CREATE INDEX IF NOT EXISTS idx_payment_attempts_order ON payment_attempts(order_no);
CREATE INDEX IF NOT EXISTS idx_payment_attempts_biz ON payment_attempts(biz_type, biz_uuid);
-- 同一业务订单同时只允许存在一笔待支付尝试（换渠道时先关闭旧尝试）
CREATE UNIQUE INDEX IF NOT EXISTS idx_payment_attempts_pending
    ON payment_attempts(biz_type, biz_uuid) WHERE status = 'pending';
-- 渠道交易号全局唯一，防止同一笔渠道交易被重复入账
CREATE UNIQUE INDEX IF NOT EXISTS idx_payment_attempts_txn
    ON payment_attempts(channel, transaction_id) WHERE transaction_id <> '';
`
	_, err := db.Exec(schema)
	return err
}
