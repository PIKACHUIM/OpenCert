package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// UserRepo 提供用户数据的 CRUD 操作。
type UserRepo struct {
	db *sql.DB
}

// NewUserRepo 创建 UserRepo 实例。
func NewUserRepo(db *DB) *UserRepo {
	return &UserRepo{db: db.Conn()}
}

// Create 创建新用户。
func (r *UserRepo) Create(ctx context.Context, u *User) error {
	if u.UUID == "" {
		u.UUID = uuid.New().String()
	}
	if u.Role == "" {
		u.Role = "user"
	}
	now := time.Now()
	u.CreatedAt = now
	u.UpdatedAt = now

	_, err := r.db.ExecContext(ctx, `
		INSERT INTO users (uuid, user_type, role, username, display_name, email, enabled, cloud_url, password_hash, auth_token, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		u.UUID, string(u.UserType), u.Role, u.Username, u.DisplayName, u.Email,
		boolToInt(u.Enabled), u.CloudURL, u.PasswordHash, u.AuthToken,
		u.CreatedAt, u.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("创建用户失败: %w", err)
	}
	return nil
}

// GetByUUID 根据 UUID 查询用户。
func (r *UserRepo) GetByUUID(ctx context.Context, userUUID string) (*User, error) {
	u := &User{}
	var enabled int
	err := r.db.QueryRowContext(ctx, `
		SELECT uuid, user_type, role, username, display_name, email, enabled, cloud_url, password_hash, auth_token, created_at, updated_at
		FROM users WHERE uuid = ?`, userUUID).
		Scan(&u.UUID, &u.UserType, &u.Role, &u.Username, &u.DisplayName, &u.Email,
			&enabled, &u.CloudURL, &u.PasswordHash, &u.AuthToken,
			&u.CreatedAt, &u.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("查询用户失败: %w", err)
	}
	u.Enabled = enabled == 1
	return u, nil
}

// GetByUsername 根据用户名查询用户（含密码哈希）。
func (r *UserRepo) GetByUsername(ctx context.Context, username string) (*User, error) {
	u := &User{}
	var enabled int
	err := r.db.QueryRowContext(ctx, `
		SELECT uuid, user_type, role, username, display_name, email, enabled, cloud_url, password_hash, auth_token, created_at, updated_at
		FROM users WHERE username = ?`, username).
		Scan(&u.UUID, &u.UserType, &u.Role, &u.Username, &u.DisplayName, &u.Email,
			&enabled, &u.CloudURL, &u.PasswordHash, &u.AuthToken,
			&u.CreatedAt, &u.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("查询用户失败: %w", err)
	}
	u.Enabled = enabled == 1
	return u, nil
}

// GetByEmail 根据邮筱查询用户。
func (r *UserRepo) GetByEmail(ctx context.Context, email string) (*User, error) {
	u := &User{}
	var enabled int
	err := r.db.QueryRowContext(ctx, `
		SELECT uuid, user_type, role, username, display_name, email, enabled, cloud_url, password_hash, auth_token, created_at, updated_at
		FROM users WHERE email = ?`, email).
		Scan(&u.UUID, &u.UserType, &u.Role, &u.Username, &u.DisplayName, &u.Email,
			&enabled, &u.CloudURL, &u.PasswordHash, &u.AuthToken,
			&u.CreatedAt, &u.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("查询用户失败: %w", err)
	}
	u.Enabled = enabled == 1
	return u, nil
}

// List 列出所有用户（不含敏感字段）。
func (r *UserRepo) List(ctx context.Context) ([]*User, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT uuid, user_type, role, username, display_name, email, enabled, cloud_url, created_at, updated_at
		FROM users ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("查询用户列表失败: %w", err)
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		u := &User{}
		var enabled int
		if err := rows.Scan(&u.UUID, &u.UserType, &u.Role, &u.Username, &u.DisplayName, &u.Email,
			&enabled, &u.CloudURL, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, fmt.Errorf("扫描用户数据失败: %w", err)
		}
		u.Enabled = enabled == 1
		users = append(users, u)
	}
	return users, rows.Err()
}

// Update 更新用户信息。
func (r *UserRepo) Update(ctx context.Context, u *User) error {
	u.UpdatedAt = time.Now()
	_, err := r.db.ExecContext(ctx, `
		UPDATE users SET user_type=?, role=?, username=?, display_name=?, email=?, enabled=?, cloud_url=?, password_hash=?, auth_token=?, updated_at=?
		WHERE uuid=?`,
		string(u.UserType), u.Role, u.Username, u.DisplayName, u.Email, boolToInt(u.Enabled),
		u.CloudURL, u.PasswordHash, u.AuthToken, u.UpdatedAt, u.UUID,
	)
	if err != nil {
		return fmt.Errorf("更新用户失败: %w", err)
	}
	return nil
}

// Delete 删除用户。
func (r *UserRepo) Delete(ctx context.Context, userUUID string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM users WHERE uuid=?`, userUUID)
	if err != nil {
		return fmt.Errorf("删除用户失败: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("用户不存在: %s", userUUID)
	}
	return nil
}

// ---- CardRepo ----

// CardRepo 提供卡片数据的 CRUD 操作。
type CardRepo struct {
	db *sql.DB
}

// NewCardRepo 创建 CardRepo 实例。
func NewCardRepo(db *DB) *CardRepo {
	return &CardRepo{db: db.Conn()}
}

// Create 创建新卡片。
func (r *CardRepo) Create(ctx context.Context, c *Card) error {
	if c.UUID == "" {
		c.UUID = uuid.New().String()
	}
	if c.SecurityLevel == "" {
		c.SecurityLevel = SecurityLevelLow
	}
	c.CreatedAt = time.Now()

	keysJSON, err := json.Marshal(c.CardKeys)
	if err != nil {
		return fmt.Errorf("序列化卡片密钥失败: %w", err)
	}

	_, err = r.db.ExecContext(ctx, `
		INSERT INTO cards (uuid, slot_type, card_name, user_uuid, enabled, created_at, expires_at, card_keys, remark, security_level, tpm_cert_key_enc, tpm_cert_key_salt, cloud_url, cloud_card_uuid)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.UUID, string(c.SlotType), c.CardName, c.UserUUID, c.Enabled,
		c.CreatedAt, nullTime(c.ExpiresAt), keysJSON, c.Remark,
		string(c.SecurityLevel), c.TPMCertKeyEnc, c.TPMCertKeySalt,
		c.CloudURL, c.CloudCardUUID,
	)
	if err != nil {
		return fmt.Errorf("创建卡片失败: %w", err)
	}
	return nil
}

// GetByUUID 根据 UUID 查询卡片。
func (r *CardRepo) GetByUUID(ctx context.Context, cardUUID string) (*Card, error) {
	c := &Card{}
	var keysJSON []byte
	var expiresAt sql.NullTime
	err := r.db.QueryRowContext(ctx, `
		SELECT uuid, slot_type, card_name, user_uuid, enabled, created_at, expires_at, card_keys, remark, security_level, tpm_cert_key_enc, tpm_cert_key_salt, cloud_url, cloud_card_uuid
		FROM cards WHERE uuid=?`, cardUUID).
		Scan(&c.UUID, &c.SlotType, &c.CardName, &c.UserUUID, &c.Enabled,
			&c.CreatedAt, &expiresAt, &keysJSON, &c.Remark,
			&c.SecurityLevel, &c.TPMCertKeyEnc, &c.TPMCertKeySalt,
			&c.CloudURL, &c.CloudCardUUID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("查询卡片失败: %w", err)
	}
	if expiresAt.Valid {
		c.ExpiresAt = &expiresAt.Time
	}
	if err := json.Unmarshal(keysJSON, &c.CardKeys); err != nil {
		return nil, fmt.Errorf("解析卡片密钥失败: %w", err)
	}
	return c, nil
}

// ListByUser 列出指定用户的所有卡片。
func (r *CardRepo) ListByUser(ctx context.Context, userUUID string) ([]*Card, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT uuid, slot_type, card_name, user_uuid, enabled, created_at, expires_at, card_keys, remark, security_level, tpm_cert_key_enc, tpm_cert_key_salt, cloud_url, cloud_card_uuid
		FROM cards WHERE user_uuid=? ORDER BY created_at DESC`, userUUID)
	if err != nil {
		return nil, fmt.Errorf("查询卡片列表失败: %w", err)
	}
	defer rows.Close()

	var cards []*Card
	for rows.Next() {
		c := &Card{}
		var keysJSON []byte
		var expiresAt sql.NullTime
		if err := rows.Scan(&c.UUID, &c.SlotType, &c.CardName, &c.UserUUID, &c.Enabled,
			&c.CreatedAt, &expiresAt, &keysJSON, &c.Remark,
			&c.SecurityLevel, &c.TPMCertKeyEnc, &c.TPMCertKeySalt,
			&c.CloudURL, &c.CloudCardUUID); err != nil {
			return nil, fmt.Errorf("扫描卡片数据失败: %w", err)
		}
		if expiresAt.Valid {
			c.ExpiresAt = &expiresAt.Time
		}
		if err := json.Unmarshal(keysJSON, &c.CardKeys); err != nil {
			return nil, fmt.Errorf("解析卡片密钥失败: %w", err)
		}
		cards = append(cards, c)
	}
	return cards, rows.Err()
}

// ListAll 列出所有卡片。
func (r *CardRepo) ListAll(ctx context.Context) ([]*Card, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT uuid, slot_type, card_name, user_uuid, enabled, created_at, expires_at, card_keys, remark, security_level, tpm_cert_key_enc, tpm_cert_key_salt, cloud_url, cloud_card_uuid
		FROM cards ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("查询所有卡片失败: %w", err)
	}
	defer rows.Close()

	var cards []*Card
	for rows.Next() {
		c := &Card{}
		var keysJSON []byte
		var expiresAt sql.NullTime
		if err := rows.Scan(&c.UUID, &c.SlotType, &c.CardName, &c.UserUUID, &c.Enabled,
			&c.CreatedAt, &expiresAt, &keysJSON, &c.Remark,
			&c.SecurityLevel, &c.TPMCertKeyEnc, &c.TPMCertKeySalt,
			&c.CloudURL, &c.CloudCardUUID); err != nil {
			return nil, fmt.Errorf("扫描卡片数据失败: %w", err)
		}
		if expiresAt.Valid {
			c.ExpiresAt = &expiresAt.Time
		}
		if err := json.Unmarshal(keysJSON, &c.CardKeys); err != nil {
			return nil, fmt.Errorf("解析卡片密钥失败: %w", err)
		}
		cards = append(cards, c)
	}
	return cards, rows.Err()
}

// Update 更新卡片信息。
func (r *CardRepo) Update(ctx context.Context, c *Card) error {
	keysJSON, err := json.Marshal(c.CardKeys)
	if err != nil {
		return fmt.Errorf("序列化卡片密钥失败: %w", err)
	}
	_, err = r.db.ExecContext(ctx, `
		UPDATE cards SET slot_type=?, card_name=?, enabled=?, expires_at=?, card_keys=?, remark=?, security_level=?, tpm_cert_key_enc=?, tpm_cert_key_salt=?, cloud_url=?, cloud_card_uuid=?
		WHERE uuid=?`,
		string(c.SlotType), c.CardName, c.Enabled, nullTime(c.ExpiresAt), keysJSON, c.Remark,
		string(c.SecurityLevel), c.TPMCertKeyEnc, c.TPMCertKeySalt,
		c.CloudURL, c.CloudCardUUID, c.UUID,
	)
	if err != nil {
		return fmt.Errorf("更新卡片失败: %w", err)
	}
	return nil
}

// Delete 删除卡片（级联删除证书）。
// 显式清理所有关联表，不依赖外键 ON DELETE CASCADE（modernc.org/sqlite 对外键支持不稳定）。
func (r *CardRepo) Delete(ctx context.Context, cardUUID string) error {
	// 先清理所有关联此卡片的记录
	for _, tbl := range []string{"certificates", "pki_certs", "pki_csrs", "pki_cas"} {
		if _, err := r.db.ExecContext(ctx, `DELETE FROM `+tbl+` WHERE card_uuid=?`, cardUUID); err != nil {
			return fmt.Errorf("清理 %s 失败: %w", tbl, err)
		}
	}

	res, err := r.db.ExecContext(ctx, `DELETE FROM cards WHERE uuid=?`, cardUUID)
	if err != nil {
		return fmt.Errorf("删除卡片失败: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("卡片不存在: %s", cardUUID)
	}
	return nil
}

// ---- 工具函数 ----

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nullTime(t *time.Time) sql.NullTime {
	if t == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *t, Valid: true}
}
