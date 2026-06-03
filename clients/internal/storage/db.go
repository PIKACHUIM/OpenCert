// Package storage 提供 SQLite 数据库访问层。
// 支持 SQLCipher 加密（需要 CGO）或 modernc.org/sqlite（纯 Go 回退）。
package storage

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/globaltrusts/client-card/internal/crypto"
	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

// DB 封装 SQLite 数据库连接。
type DB struct {
	conn      *sql.DB
	encrypted bool   // 是否使用加密数据库
	path      string // 数据库文件路径
}

// OpenOptions 是数据库打开选项。
type OpenOptions struct {
	Path       string // 数据库文件路径
	EncryptKey string // 加密密钥（为空则不加密）
}

// Open 打开（或创建）SQLite 数据库。
func Open(path string) (*DB, error) {
	return OpenWithOptions(OpenOptions{Path: path})
}

// OpenEncrypted 打开加密的 SQLite 数据库。
// encryptKey 是 Argon2id 派生的密钥（hex 编码）或用户主密码。
func OpenEncrypted(path string, encryptKey string) (*DB, error) {
	return OpenWithOptions(OpenOptions{Path: path, EncryptKey: encryptKey})
}

// OpenWithOptions 使用选项打开数据库。
func OpenWithOptions(opts OpenOptions) (*DB, error) {
	// 确保目录存在
	dir := filepath.Dir(opts.Path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("创建数据库目录失败: %w", err)
	}

	// 启用 WAL 模式和外键约束
	dsn := fmt.Sprintf("%s?_journal_mode=WAL&_foreign_keys=on&_busy_timeout=5000", opts.Path)
	conn, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("打开数据库失败: %w", err)
	}

	conn.SetMaxOpenConns(5)
	conn.SetMaxIdleConns(2)
	conn.SetConnMaxLifetime(30 * time.Minute)

	db := &DB{conn: conn, path: opts.Path}

	// 如果提供了加密密钥，设置 PRAGMA key（SQLCipher 模式）
	// 注意：使用 modernc.org/sqlite 时 PRAGMA key 会被忽略
	// 生产环境应替换为 go-sqlcipher 驱动
	if opts.EncryptKey != "" {
		_, err := conn.Exec(fmt.Sprintf("PRAGMA key = '%s'", opts.EncryptKey))
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("设置数据库加密密钥失败: %w", err)
		}
		db.encrypted = true
	}

	if err := db.migrate(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("数据库迁移失败: %w", err)
	}

	return db, nil
}

// IsEncrypted 返回数据库是否加密。
func (db *DB) IsEncrypted() bool {
	return db.encrypted
}

// MigrateToEncrypted 将明文数据库迁移为加密数据库。
// 创建新的加密数据库，复制所有数据，然后替换原文件。
func MigrateToEncrypted(srcPath, encryptKey string) error {
	dstPath := srcPath + ".encrypted"

	// 打开源数据库（明文）
	srcDB, err := Open(srcPath)
	if err != nil {
		return fmt.Errorf("打开源数据库失败: %w", err)
	}
	defer srcDB.Close()

	// 使用 SQLCipher 的 ATTACH + sqlcipher_export 进行迁移
	// 注意：这需要 SQLCipher 驱动支持
	// 在纯 Go 模式下，此功能不可用
	_, err = srcDB.conn.Exec(fmt.Sprintf(
		"ATTACH DATABASE '%s' AS encrypted KEY '%s'",
		dstPath, encryptKey,
	))
	if err != nil {
		return fmt.Errorf("附加加密数据库失败（需要 SQLCipher 驱动）: %w", err)
	}

	_, err = srcDB.conn.Exec("SELECT sqlcipher_export('encrypted')")
	if err != nil {
		return fmt.Errorf("导出数据到加密数据库失败: %w", err)
	}

	_, err = srcDB.conn.Exec("DETACH DATABASE encrypted")
	if err != nil {
		return fmt.Errorf("分离加密数据库失败: %w", err)
	}

	srcDB.Close()

	// 备份原文件并替换
	backupPath := srcPath + ".bak"
	if err := os.Rename(srcPath, backupPath); err != nil {
		return fmt.Errorf("备份原数据库失败: %w", err)
	}
	if err := os.Rename(dstPath, srcPath); err != nil {
		// 恢复备份
		os.Rename(backupPath, srcPath)
		return fmt.Errorf("替换数据库文件失败: %w", err)
	}

	return nil
}

// Close 关闭数据库连接。
func (db *DB) Close() error {
	return db.conn.Close()
}

// Conn 返回底层 *sql.DB，供 Repository 使用。
func (db *DB) Conn() *sql.DB {
	return db.conn
}

// migrate 执行数据库表结构初始化。
func (db *DB) migrate() error {
	_, err := db.conn.Exec(schema)
	if err != nil {
		return fmt.Errorf("执行 schema 失败: %w", err)
	}
	// 兼容旧数据库：若列不存在则添加
	_, _ = db.conn.Exec(`ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'`)
	_, _ = db.conn.Exec(`ALTER TABLE users ADD COLUMN username TEXT NOT NULL DEFAULT ''`)
	_, _ = db.conn.Exec(`ALTER TABLE pki_csrs ADD COLUMN extra_subject TEXT NOT NULL DEFAULT '{}'`)
	// 智能卡安全等级迁移：为现有卡片添加新字段
	_, _ = db.conn.Exec(`ALTER TABLE cards ADD COLUMN security_level TEXT NOT NULL DEFAULT 'low'`)
	_, _ = db.conn.Exec(`ALTER TABLE cards ADD COLUMN tpm_cert_key_enc TEXT`)
	_, _ = db.conn.Exec(`ALTER TABLE cards ADD COLUMN tpm_cert_key_salt TEXT`)
	// medium 真 TPM 集成：NV 句柄 + Provider 平台标识
	_, _ = db.conn.Exec(`ALTER TABLE cards ADD COLUMN tpm_cert_key_nv_handle INTEGER NOT NULL DEFAULT 0`)
	_, _ = db.conn.Exec(`ALTER TABLE cards ADD COLUMN tpm_provider TEXT NOT NULL DEFAULT ''`)
	// high 模式：证书表新增 wrapped key blob 字段、TPM 证书密钥盐值
	_, _ = db.conn.Exec(`ALTER TABLE certificates ADD COLUMN tpm_wrapped_blob TEXT`)
	_, _ = db.conn.Exec(`ALTER TABLE certificates ADD COLUMN tpm_cert_key_salt TEXT`)
	// 卡片启用/禁用
	_, _ = db.conn.Exec(`ALTER TABLE cards ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1`)

	// 功能开关字段（默认关闭）
	_, _ = db.conn.Exec(`ALTER TABLE cards ADD COLUMN fido_enabled INTEGER NOT NULL DEFAULT 0`)
	_, _ = db.conn.Exec(`ALTER TABLE cards ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0`)
	_, _ = db.conn.Exec(`ALTER TABLE cards ADD COLUMN credential_enabled INTEGER NOT NULL DEFAULT 0`)
	// 记住密码时间（秒），默认 900（15分钟）
	_, _ = db.conn.Exec(`ALTER TABLE cards ADD COLUMN pin_timeout INTEGER NOT NULL DEFAULT 900`)

	// 2FA 字段迁移
	_, _ = db.conn.Exec(`ALTER TABLE users ADD COLUMN two_fa_enabled INTEGER NOT NULL DEFAULT 0`)
	_, _ = db.conn.Exec(`ALTER TABLE users ADD COLUMN two_fa_secret TEXT NOT NULL DEFAULT ''`)
	_, _ = db.conn.Exec(`ALTER TABLE users ADD COLUMN passwordless_enabled INTEGER NOT NULL DEFAULT 0`)

	// 迁移旧 BLOB 数据为 base64 TEXT
	db.migrateBlobToBase64()
	return nil
}

// migrateBlobToBase64 将旧数据库中的 BLOB 二进制数据迁移为 base64 编码的 TEXT。
// 通过 typeof() 检测数据类型，仅转换 BLOB 类型的数据。
func (db *DB) migrateBlobToBase64() {
	// certificates 表的二进制字段
	blobColumns := []struct {
		table   string
		columns []string
		pk      string
	}{
		{"certificates", []string{"cert_content", "temp_key_salt", "temp_key_enc", "private_data",
			"tpm_public_blob", "tpm_private_blob", "tpm_pcr_policy", "tpm_auth_policy",
			"tpm_wrapped_blob", "tpm_cert_key_salt"}, "uuid"},
		{"users", []string{"auth_token"}, "uuid"},
		{"cards", []string{"tpm_cert_key_enc", "tpm_cert_key_salt"}, "uuid"},
		{"pki_csrs", []string{"private_key_enc"}, "uuid"},
		{"pki_local_cas", []string{"priv_key_enc"}, "uuid"},
		{"pki_certs", []string{"private_key_enc"}, "uuid"},
	}

	for _, tbl := range blobColumns {
		for _, col := range tbl.columns {
			// 查找该列中类型为 blob 的行
			query := fmt.Sprintf(
				`SELECT %s, %s FROM %s WHERE typeof(%s) = 'blob'`,
				tbl.pk, col, tbl.table, col,
			)
			rows, err := db.conn.Query(query)
			if err != nil {
				continue // 表或列可能不存在
			}

			type row struct {
				pk   string
				data []byte
			}
			var toUpdate []row
			for rows.Next() {
				var r row
				if err := rows.Scan(&r.pk, &r.data); err == nil && len(r.data) > 0 {
					toUpdate = append(toUpdate, r)
				}
			}
			rows.Close()

			// 将 BLOB 数据转换为 base64 TEXT 写回
			for _, r := range toUpdate {
				encoded := base64.StdEncoding.EncodeToString(r.data)
				updateSQL := fmt.Sprintf(`UPDATE %s SET %s = ? WHERE %s = ?`, tbl.table, col, tbl.pk)
				_, _ = db.conn.Exec(updateSQL, encoded, r.pk)
			}

			if len(toUpdate) > 0 {
				slog.Info("迁移 BLOB 数据为 base64",
					"table", tbl.table, "column", col, "count", len(toUpdate))
			}
		}
	}
}

// Seed 在数据库为空时创建默认 root 用户（密码 root，角色 admin）。
// 仅当 users 表中没有任何用户时才执行。
func (db *DB) Seed() error {
	ctx := context.Background()

	// 检查是否已有用户
	var count int
	err := db.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&count)
	if err != nil {
		return fmt.Errorf("检查用户数量失败: %w", err)
	}
	if count > 0 {
		return nil // 已有用户，跳过
	}

	// 生成默认密码哈希
	hash, err := crypto.HashPassword("root")
	if err != nil {
		return fmt.Errorf("生成默认密码失败: %w", err)
	}

	now := time.Now()
	_, err = db.conn.ExecContext(ctx, `
		INSERT INTO users (uuid, user_type, role, username, display_name, email, enabled, cloud_url, password_hash, created_at, updated_at)
		VALUES (?, 'local', 'admin', 'root', 'Root', 'root@localhost', 1, '', ?, ?, ?)`,
		uuid.New().String(), hash, now, now,
	)
	if err != nil {
		return fmt.Errorf("创建默认 root 用户失败: %w", err)
	}

	slog.Info("已创建默认用户", "username", "root", "password", "root", "role", "admin")
	return nil
}

// schema 是数据库建表 SQL。
const schema = `
-- 用户管理表
CREATE TABLE IF NOT EXISTS users (
    uuid            TEXT PRIMARY KEY,
    user_type       TEXT NOT NULL DEFAULT 'local',  -- local / cloud
    role            TEXT NOT NULL DEFAULT 'user',   -- admin / user / readonly
    username        TEXT NOT NULL DEFAULT '',       -- 登录用户名（唯一）
    display_name    TEXT NOT NULL,
    email           TEXT NOT NULL DEFAULT '',
    enabled         INTEGER NOT NULL DEFAULT 1,
    cloud_url       TEXT NOT NULL DEFAULT '',
    password_hash   TEXT NOT NULL DEFAULT '',       -- bcrypt，云端留空
    auth_token      TEXT,                           -- 加密存储的 WebToken 或 PIN 加密的密码
    created_at      DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at      DATETIME NOT NULL DEFAULT (datetime('now'))
);

-- 卡片管理表
CREATE TABLE IF NOT EXISTS cards (
    uuid            TEXT PRIMARY KEY,
    slot_type       TEXT NOT NULL,                  -- local / tpm2 / cloud
    card_name       TEXT NOT NULL,
    user_uuid       TEXT NOT NULL,
    enabled         INTEGER NOT NULL DEFAULT 1,     -- 1=启用 0=禁用
    created_at      DATETIME NOT NULL DEFAULT (datetime('now')),
    expires_at      DATETIME,
    card_keys       TEXT NOT NULL,                  -- JSON 数组，存储多个加密的主密钥记录
    remark          TEXT NOT NULL DEFAULT '',
    security_level  TEXT NOT NULL DEFAULT 'low',    -- high / medium / low
    tpm_cert_key_enc  TEXT,                         -- medium：被 ADMINKEY 加密的应急恢复副本
    tpm_cert_key_salt TEXT,                         -- medium：应急恢复副本盐值
    tpm_cert_key_nv_handle INTEGER NOT NULL DEFAULT 0, -- medium：TPM NV 句柄（0=未启用）
    tpm_provider    TEXT NOT NULL DEFAULT '',       -- medium/high：TPM Provider 平台名
    cloud_url       TEXT NOT NULL DEFAULT '',       -- Cloud Slot: servers 服务地址
    cloud_card_uuid TEXT NOT NULL DEFAULT '',       -- Cloud Slot: 在 servers 中的卡片 UUID
    FOREIGN KEY (user_uuid) REFERENCES users(uuid) ON DELETE CASCADE
);

-- 证书/密钥表（本地和 TPM2 卡片使用）
CREATE TABLE IF NOT EXISTS certificates (
    uuid            TEXT PRIMARY KEY,
    slot_type       TEXT NOT NULL,                  -- local / tpm2 / cloud(缓存)
    card_uuid       TEXT NOT NULL,
    cert_type       TEXT NOT NULL,                  -- x509/ssh/gpg/totp/fido-umdf/login/text/note/payment
    key_type        TEXT NOT NULL DEFAULT '',       -- rsa2048/ec256/ed25519/...
    cert_content    TEXT,                           -- 公开部分（X509/SSH/GPG 公钥）
    temp_key_salt   TEXT,                           -- 32 字节随机盐值
    temp_key_enc    TEXT,                           -- AES256 加密的临时密钥
    private_data    TEXT,                           -- 临时密钥加密的私钥/私密数据
    -- TPM2 / 安全等级专用字段
    tpm_platform    TEXT NOT NULL DEFAULT '',       -- tpm2 / apple_t2 / apple_se / sw-stub
    tpm_key_handle  INTEGER,                        -- TPM 持久化句柄
    tpm_public_blob TEXT,                           -- TPM 公钥 Blob
    tpm_private_blob TEXT,                          -- TPM 私钥 Blob
    tpm_pcr_policy  TEXT,                           -- PCR 策略（可选）
    tpm_auth_policy TEXT,                           -- 授权策略哈希
    tpm_wrapped_blob TEXT,                          -- high：tpm.WrappedKey 序列化（JSON）
    tpm_cert_key_salt TEXT,                         -- medium：本证书使用的 TPM 证书密钥派生盐
    remark          TEXT NOT NULL DEFAULT '',
    created_at      DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at      DATETIME NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (card_uuid) REFERENCES cards(uuid) ON DELETE CASCADE
);

-- 日志管理表
CREATE TABLE IF NOT EXISTS logs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    log_type        TEXT NOT NULL DEFAULT 'operation', -- operation / security / error
    slot_type       TEXT NOT NULL DEFAULT '',
    card_uuid       TEXT NOT NULL DEFAULT '',
    user_uuid       TEXT NOT NULL DEFAULT '',
    log_level       TEXT NOT NULL DEFAULT 'info',      -- debug / info / warn / error
    recorded_at     DATETIME NOT NULL DEFAULT (datetime('now')),
    title           TEXT NOT NULL,
    content         TEXT NOT NULL DEFAULT ''
);

-- 索引
CREATE INDEX IF NOT EXISTS idx_cards_user_uuid ON cards(user_uuid);
CREATE INDEX IF NOT EXISTS idx_certs_card_uuid ON certificates(card_uuid);
CREATE INDEX IF NOT EXISTS idx_logs_recorded_at ON logs(recorded_at);
CREATE INDEX IF NOT EXISTS idx_logs_card_uuid ON logs(card_uuid);

-- PKI CSR 表
CREATE TABLE IF NOT EXISTS pki_csrs (
    uuid            TEXT PRIMARY KEY,
    common_name     TEXT NOT NULL,
    organization    TEXT NOT NULL DEFAULT '',
    org_unit        TEXT NOT NULL DEFAULT '',
    country         TEXT NOT NULL DEFAULT '',
    state           TEXT NOT NULL DEFAULT '',
    locality        TEXT NOT NULL DEFAULT '',
    email           TEXT NOT NULL DEFAULT '',
    key_type        TEXT NOT NULL,
    key_storage     TEXT NOT NULL DEFAULT 'database',  -- database / smartcard
    card_uuid       TEXT NOT NULL DEFAULT '',
    san_dns         TEXT NOT NULL DEFAULT '',
    san_ip          TEXT NOT NULL DEFAULT '',
    san_email       TEXT NOT NULL DEFAULT '',
    san_uri         TEXT NOT NULL DEFAULT '',
    key_usage       TEXT NOT NULL DEFAULT '[]',        -- JSON 数组
    ext_key_usage   TEXT NOT NULL DEFAULT '[]',        -- JSON 数组
    csr_pem         TEXT NOT NULL,
    has_private_key INTEGER NOT NULL DEFAULT 0,
    private_key_enc TEXT,                              -- AES256 加密的私钥
    remark          TEXT NOT NULL DEFAULT '',
    created_at      DATETIME NOT NULL DEFAULT (datetime('now'))
);

-- PKI CA 表
CREATE TABLE IF NOT EXISTS pki_cas (
    uuid            TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    common_name     TEXT NOT NULL,
    organization    TEXT NOT NULL DEFAULT '',
    country         TEXT NOT NULL DEFAULT '',
    key_type        TEXT NOT NULL,
    cert_pem        TEXT NOT NULL,
    chain_pem       TEXT NOT NULL DEFAULT '',
    has_priv_key    INTEGER NOT NULL DEFAULT 0,
    priv_key_enc    TEXT,                              -- AES256 加密的私钥
    card_uuid       TEXT NOT NULL DEFAULT '',
    not_before      DATETIME NOT NULL,
    not_after       DATETIME NOT NULL,
    issued_count    INTEGER NOT NULL DEFAULT 0,
    revoked         INTEGER NOT NULL DEFAULT 0,
    created_at      DATETIME NOT NULL DEFAULT (datetime('now'))
);

-- PKI 证书表
CREATE TABLE IF NOT EXISTS pki_certs (
    uuid            TEXT PRIMARY KEY,
    common_name     TEXT NOT NULL,
    serial_number   TEXT NOT NULL DEFAULT '',
    ca_uuid         TEXT NOT NULL DEFAULT '',
    ca_name         TEXT NOT NULL DEFAULT '',
    csr_uuid        TEXT NOT NULL DEFAULT '',
    key_type        TEXT NOT NULL,
    key_storage     TEXT NOT NULL DEFAULT 'database',
    card_uuid       TEXT NOT NULL DEFAULT '',
    cert_pem        TEXT NOT NULL,
    has_private_key INTEGER NOT NULL DEFAULT 0,
    private_key_enc TEXT,
    not_before      DATETIME NOT NULL,
    not_after       DATETIME NOT NULL,
    key_usage       TEXT NOT NULL DEFAULT '[]',
    ext_key_usage   TEXT NOT NULL DEFAULT '[]',
    san_dns         TEXT NOT NULL DEFAULT '',
    san_ip          TEXT NOT NULL DEFAULT '',
    san_email       TEXT NOT NULL DEFAULT '',
    revoked         INTEGER NOT NULL DEFAULT 0,
    remark          TEXT NOT NULL DEFAULT '',
    created_at      DATETIME NOT NULL DEFAULT (datetime('now'))
);

-- PKI 索引
CREATE INDEX IF NOT EXISTS idx_pki_csrs_created_at ON pki_csrs(created_at);
CREATE INDEX IF NOT EXISTS idx_pki_cas_created_at ON pki_cas(created_at);
CREATE INDEX IF NOT EXISTS idx_pki_certs_ca_uuid ON pki_certs(ca_uuid);
CREATE INDEX IF NOT EXISTS idx_pki_certs_created_at ON pki_certs(created_at);
`
