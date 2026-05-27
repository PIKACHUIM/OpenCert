// Package storage - Repository 实现。
package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ---- UserRepo ----

// UserRepo 提供用户数据访问。
type UserRepo struct {
	db *DB
}

// NewUserRepo 创建 UserRepo。
func NewUserRepo(db *DB) *UserRepo {
	return &UserRepo{db: db}
}

// Create 创建用户。
func (r *UserRepo) Create(ctx context.Context, u *User) error {
	u.UUID = uuid.New().String()
	if u.Role == "" {
		u.Role = "user"
	}
	u.CreatedAt = time.Now()
	u.UpdatedAt = time.Now()

	_, err := r.db.ExecContext(ctx,
		`INSERT INTO users (uuid, username, display_name, email, password_hash, role, public_key, totp_secret, enabled, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		u.UUID, u.Username, u.DisplayName, u.Email, u.PasswordHash, u.Role, u.PublicKey, u.TOTPSecret, boolToInt(u.Enabled), u.CreatedAt, u.UpdatedAt,
	)
	return err
}

// GetByUUID 按 UUID 查询用户。
func (r *UserRepo) GetByUUID(ctx context.Context, userUUID string) (*User, error) {
	u := &User{}
	var enabled, failedAttempts int
	var lockedUntil sql.NullTime
	err := r.db.QueryRowContext(ctx,
		`SELECT uuid, username, display_name, email, password_hash, role, public_key, totp_secret, enabled, failed_attempts, locked_until, created_at, updated_at
		 FROM users WHERE uuid = ?`, userUUID,
	).Scan(&u.UUID, &u.Username, &u.DisplayName, &u.Email, &u.PasswordHash, &u.Role, &u.PublicKey, &u.TOTPSecret, &enabled, &failedAttempts, &lockedUntil, &u.CreatedAt, &u.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("用户不存在: %s", userUUID)
	}
	u.Enabled = enabled == 1
	u.FailedAttempts = failedAttempts
	if lockedUntil.Valid {
		u.LockedUntil = &lockedUntil.Time
	}
	return u, err
}

// GetByUsername 按用户名查询用户。
func (r *UserRepo) GetByUsername(ctx context.Context, username string) (*User, error) {
	u := &User{}
	var enabled, failedAttempts int
	var lockedUntil sql.NullTime
	err := r.db.QueryRowContext(ctx,
		`SELECT uuid, username, display_name, email, password_hash, role, public_key, totp_secret, enabled, failed_attempts, locked_until, created_at, updated_at
		 FROM users WHERE username = ?`, username,
	).Scan(&u.UUID, &u.Username, &u.DisplayName, &u.Email, &u.PasswordHash, &u.Role, &u.PublicKey, &u.TOTPSecret, &enabled, &failedAttempts, &lockedUntil, &u.CreatedAt, &u.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("用户不存在: %s", username)
	}
	u.Enabled = enabled == 1
	u.FailedAttempts = failedAttempts
	if lockedUntil.Valid {
		u.LockedUntil = &lockedUntil.Time
	}
	return u, err
}

// GetByEmail 按邮箱查询用户。
func (r *UserRepo) GetByEmail(ctx context.Context, email string) (*User, error) {
	u := &User{}
	var enabled, failedAttempts int
	var lockedUntil sql.NullTime
	err := r.db.QueryRowContext(ctx,
		`SELECT uuid, username, display_name, email, password_hash, role, public_key, totp_secret, enabled, failed_attempts, locked_until, created_at, updated_at
		 FROM users WHERE email = ?`, email,
	).Scan(&u.UUID, &u.Username, &u.DisplayName, &u.Email, &u.PasswordHash, &u.Role, &u.PublicKey, &u.TOTPSecret, &enabled, &failedAttempts, &lockedUntil, &u.CreatedAt, &u.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("用户不存在: %s", email)
	}
	u.Enabled = enabled == 1
	u.FailedAttempts = failedAttempts
	if lockedUntil.Valid {
		u.LockedUntil = &lockedUntil.Time
	}
	return u, err
}

// UpdatePassword 更新用户密码。
func (r *UserRepo) UpdatePassword(ctx context.Context, userUUID, newPasswordHash string) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE users SET password_hash = ?, updated_at = ? WHERE uuid = ?`,
		newPasswordHash, time.Now(), userUUID,
	)
	return err
}

// UpdateProfile 更新用户个人信息。
func (r *UserRepo) UpdateProfile(ctx context.Context, userUUID, displayName, email string) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE users SET display_name = ?, email = ?, updated_at = ? WHERE uuid = ?`,
		displayName, email, time.Now(), userUUID,
	)
	return err
}

// UpdatePublicKey 更新用户云端公钥。
func (r *UserRepo) UpdatePublicKey(ctx context.Context, userUUID string, publicKey Base64Bytes) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE users SET public_key = ?, updated_at = ? WHERE uuid = ?`,
		publicKey, time.Now(), userUUID,
	)
	return err
}

// UpdateRole 更新用户角色。
func (r *UserRepo) UpdateRole(ctx context.Context, userUUID, role string) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE users SET role = ?, updated_at = ? WHERE uuid = ?`,
		role, time.Now(), userUUID,
	)
	return err
}

// UpdateEnabled 启用或禁用用户账号。
func (r *UserRepo) UpdateEnabled(ctx context.Context, userUUID string, enabled bool) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE users SET enabled = ?, updated_at = ? WHERE uuid = ?`,
		boolToInt(enabled), time.Now(), userUUID,
	)
	return err
}

// Delete 删除用户。
func (r *UserRepo) Delete(ctx context.Context, userUUID string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM users WHERE uuid = ?`, userUUID)
	return err
}

// IncrementFailedAttempts 递增登录失败次数，达到阈值时锁定。
func (r *UserRepo) IncrementFailedAttempts(ctx context.Context, userUUID string, maxAttempts int, lockDuration time.Duration) error {
	now := time.Now()
	lockedUntil := now.Add(lockDuration)
	_, err := r.db.ExecContext(ctx,
		`UPDATE users SET
			failed_attempts = failed_attempts + 1,
			locked_until = CASE WHEN failed_attempts + 1 >= ? THEN ? ELSE locked_until END,
			updated_at = ?
		 WHERE uuid = ?`,
		maxAttempts, lockedUntil, now, userUUID,
	)
	return err
}

// ResetFailedAttempts 重置登录失败次数（登录成功时调用）。
func (r *UserRepo) ResetFailedAttempts(ctx context.Context, userUUID string) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE users SET failed_attempts = 0, locked_until = NULL, updated_at = ? WHERE uuid = ?`,
		time.Now(), userUUID,
	)
	return err
}

// IsLocked 检查用户是否被锁定。
func (r *UserRepo) IsLocked(ctx context.Context, userUUID string) (bool, error) {
	var lockedUntil sql.NullTime
	err := r.db.QueryRowContext(ctx,
		`SELECT locked_until FROM users WHERE uuid = ?`, userUUID,
	).Scan(&lockedUntil)
	if err != nil {
		return false, err
	}
	if lockedUntil.Valid && time.Now().Before(lockedUntil.Time) {
		return true, nil
	}
	return false, nil
}

// ListUsers 分页查询用户列表，支持关键字搜索。
func (r *UserRepo) ListUsers(ctx context.Context, keyword string, page, pageSize int) ([]*User, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	where := `WHERE 1=1`
	var args []interface{}
	if keyword != "" {
		where += ` AND (username LIKE ? OR email LIKE ? OR display_name LIKE ?)`
		like := "%" + keyword + "%"
		args = append(args, like, like, like)
	}

	var total int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := r.db.QueryContext(ctx,
		`SELECT uuid, username, display_name, email, role, enabled, failed_attempts, locked_until, created_at, updated_at
		 FROM users `+where+` ORDER BY created_at DESC LIMIT ? OFFSET ?`,
		append(args, pageSize, offset)...,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		u := &User{}
		var enabled, failedAttempts int
		var lockedUntil sql.NullTime
		if err := rows.Scan(&u.UUID, &u.Username, &u.DisplayName, &u.Email, &u.Role,
			&enabled, &failedAttempts, &lockedUntil, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, 0, err
		}
		u.Enabled = enabled == 1
		u.FailedAttempts = failedAttempts
		if lockedUntil.Valid {
			u.LockedUntil = &lockedUntil.Time
		}
		users = append(users, u)
	}
	return users, total, rows.Err()
}

// ---- CardRepo ----

// CardRepo 提供云端卡片数据访问。
type CardRepo struct {
	db *DB
}

// NewCardRepo 创建 CardRepo。
func NewCardRepo(db *DB) *CardRepo {
	return &CardRepo{db: db}
}

// Create 创建卡片。
func (r *CardRepo) Create(ctx context.Context, c *Card) error {
	c.UUID = uuid.New().String()
	c.CreatedAt = time.Now()
	c.UpdatedAt = time.Now()
	if c.PINRetries == 0 {
		c.PINRetries = 3
	}

	_, err := r.db.ExecContext(ctx,
		`INSERT INTO cards (uuid, user_uuid, card_name, remark, storage_zone_uuid, pin_data, puk_data, admin_key_data, pin_retries, pin_failed_count, pin_locked, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.UUID, c.UserUUID, c.CardName, c.Remark, c.StorageZoneUUID, c.PINData, c.PUKData, c.AdminKeyData,
		c.PINRetries, c.PINFailedCount, boolToInt(c.PINLocked), c.CreatedAt, c.UpdatedAt,
	)
	return err
}

// GetByUUID 按 UUID 查询卡片。
func (r *CardRepo) GetByUUID(ctx context.Context, cardUUID string) (*Card, error) {
	c := &Card{}
	var pinLocked int
	err := r.db.QueryRowContext(ctx,
		`SELECT uuid, user_uuid, card_name, remark, storage_zone_uuid, pin_data, puk_data, admin_key_data, pin_retries, pin_failed_count, pin_locked, created_at, updated_at
		 FROM cards WHERE uuid = ?`, cardUUID,
	).Scan(&c.UUID, &c.UserUUID, &c.CardName, &c.Remark, &c.StorageZoneUUID, &c.PINData, &c.PUKData, &c.AdminKeyData,
		&c.PINRetries, &c.PINFailedCount, &pinLocked, &c.CreatedAt, &c.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("卡片不存在: %s", cardUUID)
	}
	c.PINLocked = pinLocked == 1
	return c, err
}

// ListByUser 查询用户的所有卡片（不含敏感 PIN 数据）。
func (r *CardRepo) ListByUser(ctx context.Context, userUUID string) ([]*Card, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT uuid, user_uuid, card_name, remark, storage_zone_uuid, pin_retries, pin_failed_count, pin_locked, created_at, updated_at
		 FROM cards WHERE user_uuid = ? ORDER BY created_at DESC`, userUUID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cards []*Card
	for rows.Next() {
		c := &Card{}
		var pinLocked int
		if err := rows.Scan(&c.UUID, &c.UserUUID, &c.CardName, &c.Remark, &c.StorageZoneUUID,
			&c.PINRetries, &c.PINFailedCount, &pinLocked, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		c.PINLocked = pinLocked == 1
		cards = append(cards, c)
	}
	return cards, rows.Err()
}

// UpdatePINStatus 更新 PIN 失败次数和锁定状态。
func (r *CardRepo) UpdatePINStatus(ctx context.Context, cardUUID string, failedCount int, locked bool) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE cards SET pin_failed_count = ?, pin_locked = ?, updated_at = ? WHERE uuid = ?`,
		failedCount, boolToInt(locked), time.Now(), cardUUID,
	)
	return err
}

// UpdatePINData 更新 PIN 数据（重置 PIN 时调用）。
func (r *CardRepo) UpdatePINData(ctx context.Context, cardUUID string, pinData Base64Bytes) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE cards SET pin_data = ?, pin_failed_count = 0, pin_locked = 0, updated_at = ? WHERE uuid = ?`,
		pinData, time.Now(), cardUUID,
	)
	return err
}

// UpdatePUKData 更新 PUK 数据（重置 PUK 时调用）。
func (r *CardRepo) UpdatePUKData(ctx context.Context, cardUUID string, pukData Base64Bytes) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE cards SET puk_data = ?, updated_at = ? WHERE uuid = ?`,
		pukData, time.Now(), cardUUID,
	)
	return err
}

// Delete 删除卡片（级联删除证书）。
// 显式清理关联的证书记录，不依赖外键 ON DELETE CASCADE。
func (r *CardRepo) Delete(ctx context.Context, cardUUID string) error {
	// 先删除关联的证书
	if _, err := r.db.ExecContext(ctx, `DELETE FROM certificates WHERE card_uuid = ?`, cardUUID); err != nil {
		return fmt.Errorf("清理卡片关联证书失败: %w", err)
	}
	_, err := r.db.ExecContext(ctx, `DELETE FROM cards WHERE uuid = ?`, cardUUID)
	return err
}

// ---- CertRepo ----

// CertRepo 提供云端证书数据访问。
type CertRepo struct {
	db *DB
}

// NewCertRepo 创建 CertRepo。
func NewCertRepo(db *DB) *CertRepo {
	return &CertRepo{db: db}
}

// Create 创建证书。
func (r *CertRepo) Create(ctx context.Context, c *Certificate) error {
	c.UUID = uuid.New().String()
	if c.RevocationStatus == "" {
		c.RevocationStatus = "active"
	}
	c.CreatedAt = time.Now()
	c.UpdatedAt = time.Now()

	_, err := r.db.ExecContext(ctx,
		`INSERT INTO certificates (uuid, card_uuid, user_uuid, cert_type, key_type, cert_content, private_data, remark,
		 order_no, ca_uuid, serial_number, serial_hex, subject_dn, issuer_dn, not_before, not_after,
		 key_usage, ext_key_usage, san_dns, san_ip, san_email, san_uris, certificate_policies,
		 issuance_tmpl_uuid, template_uuid, storage_policy, revocation_status, revoke_reason, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.UUID, c.CardUUID, c.UserUUID, c.CertType, c.KeyType, c.CertContent, c.PrivateData, c.Remark,
		c.OrderNo, c.CAUUID, c.SerialNumber, c.SerialHex, c.SubjectDN, c.IssuerDN, c.NotBefore, c.NotAfter,
		c.KeyUsage, c.ExtKeyUsage, c.SANDNS, c.SANIP, c.SANEmail, c.SANURI, c.CertificatePolicies,
		c.IssuanceTmplUUID, c.TemplateUUID, c.StoragePolicy, c.RevocationStatus, c.RevokeReason, c.CreatedAt, c.UpdatedAt,
	)
	return err
}

// GetByUUID 按 UUID 查询证书（含私钥）。
func (r *CertRepo) GetByUUID(ctx context.Context, certUUID string) (*Certificate, error) {
	c := &Certificate{}
	var revokedAt sql.NullTime
	var notBefore, notAfter sql.NullTime
	err := r.db.QueryRowContext(ctx,
		`SELECT uuid, card_uuid, user_uuid, cert_type, key_type, cert_content, private_data, remark,
		 order_no, ca_uuid, serial_number, serial_hex, subject_dn, issuer_dn, not_before, not_after,
		 key_usage, ext_key_usage, san_dns, san_ip, san_email, san_uris, certificate_policies,
		 issuance_tmpl_uuid, template_uuid, storage_policy, revocation_status, revoke_reason, revoked_at, created_at, updated_at
		 FROM certificates WHERE uuid = ?`, certUUID,
	).Scan(&c.UUID, &c.CardUUID, &c.UserUUID, &c.CertType, &c.KeyType, &c.CertContent, &c.PrivateData, &c.Remark,
		&c.OrderNo, &c.CAUUID, &c.SerialNumber, &c.SerialHex, &c.SubjectDN, &c.IssuerDN, &notBefore, &notAfter,
		&c.KeyUsage, &c.ExtKeyUsage, &c.SANDNS, &c.SANIP, &c.SANEmail, &c.SANURI, &c.CertificatePolicies,
		&c.IssuanceTmplUUID, &c.TemplateUUID, &c.StoragePolicy, &c.RevocationStatus, &c.RevokeReason, &revokedAt, &c.CreatedAt, &c.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("证书不存在: %s", certUUID)
	}
	if revokedAt.Valid {
		c.RevokedAt = &revokedAt.Time
	}
	if notBefore.Valid {
		c.NotBefore = &notBefore.Time
	}
	if notAfter.Valid {
		c.NotAfter = &notAfter.Time
	}
	return c, err
}

// ListByCard 查询卡片的所有证书（不含私钥）。
func (r *CertRepo) ListByCard(ctx context.Context, cardUUID string) ([]*Certificate, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT uuid, card_uuid, user_uuid, cert_type, key_type, cert_content, remark,
		 order_no, ca_uuid, serial_number, serial_hex, subject_dn, issuer_dn, not_before, not_after,
		 key_usage, ext_key_usage, san_dns, san_ip, san_email, san_uris, certificate_policies,
		 issuance_tmpl_uuid, template_uuid, storage_policy, revocation_status, revoke_reason, revoked_at, created_at, updated_at
		 FROM certificates WHERE card_uuid = ? ORDER BY created_at DESC`, cardUUID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var certs []*Certificate
	for rows.Next() {
		c := &Certificate{}
		var revokedAt sql.NullTime
		var notBefore, notAfter sql.NullTime
		if err := rows.Scan(&c.UUID, &c.CardUUID, &c.UserUUID, &c.CertType, &c.KeyType, &c.CertContent, &c.Remark,
			&c.OrderNo, &c.CAUUID, &c.SerialNumber, &c.SerialHex, &c.SubjectDN, &c.IssuerDN, &notBefore, &notAfter,
			&c.KeyUsage, &c.ExtKeyUsage, &c.SANDNS, &c.SANIP, &c.SANEmail, &c.SANURI, &c.CertificatePolicies,
			&c.IssuanceTmplUUID, &c.TemplateUUID, &c.StoragePolicy, &c.RevocationStatus, &c.RevokeReason, &revokedAt, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		if revokedAt.Valid {
			c.RevokedAt = &revokedAt.Time
		}
		if notBefore.Valid {
			c.NotBefore = &notBefore.Time
		}
		if notAfter.Valid {
			c.NotAfter = &notAfter.Time
		}
		certs = append(certs, c)
	}
	return certs, rows.Err()
}

// ListFiltered 按条件筛选查询证书（支持按用户/CA/模板/卡片/类型/状态筛选）。
func (r *CertRepo) ListFiltered(ctx context.Context, userUUID, caUUID, tmplUUID, cardUUID, certType, status string, page, pageSize int) ([]*Certificate, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 50 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	where := `WHERE 1=1`
	var args []interface{}
	if userUUID != "" {
		where += ` AND c.user_uuid = ?`
		args = append(args, userUUID)
	}
	if caUUID != "" {
		where += ` AND c.ca_uuid = ?`
		args = append(args, caUUID)
	}
	if tmplUUID != "" {
		where += ` AND c.issuance_tmpl_uuid = ?`
		args = append(args, tmplUUID)
	}
	if cardUUID != "" {
		where += ` AND c.card_uuid = ?`
		args = append(args, cardUUID)
	}
	if certType != "" {
		where += ` AND c.cert_type = ?`
		args = append(args, certType)
	}
	if status != "" {
		where += ` AND c.revocation_status = ?`
		args = append(args, status)
	}

	var total int
	countQuery := `SELECT COUNT(*) FROM certificates c ` + where
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	selectQuery := `SELECT c.uuid, c.card_uuid, c.user_uuid, c.cert_type, c.key_type, c.cert_content, c.remark,
		 c.order_no, c.ca_uuid, c.serial_number, c.serial_hex, c.subject_dn, c.issuer_dn, c.not_before, c.not_after,
		 c.key_usage, c.ext_key_usage, c.san_dns, c.san_ip, c.san_email, c.san_uris, c.certificate_policies,
		 c.issuance_tmpl_uuid, c.template_uuid, c.storage_policy, c.revocation_status, c.revoke_reason, c.revoked_at, c.created_at, c.updated_at
		 FROM certificates c ` + where + ` ORDER BY c.created_at DESC LIMIT ? OFFSET ?`
	selectArgs := append(args, pageSize, offset)

	rows, err := r.db.QueryContext(ctx, selectQuery, selectArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var certs []*Certificate
	for rows.Next() {
		c := &Certificate{}
		var revokedAt sql.NullTime
		var notBefore, notAfter sql.NullTime
		if err := rows.Scan(&c.UUID, &c.CardUUID, &c.UserUUID, &c.CertType, &c.KeyType, &c.CertContent, &c.Remark,
			&c.OrderNo, &c.CAUUID, &c.SerialNumber, &c.SerialHex, &c.SubjectDN, &c.IssuerDN, &notBefore, &notAfter,
			&c.KeyUsage, &c.ExtKeyUsage, &c.SANDNS, &c.SANIP, &c.SANEmail, &c.SANURI, &c.CertificatePolicies,
			&c.IssuanceTmplUUID, &c.TemplateUUID, &c.StoragePolicy, &c.RevocationStatus, &c.RevokeReason, &revokedAt, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, 0, err
		}
		if revokedAt.Valid {
			c.RevokedAt = &revokedAt.Time
		}
		if notBefore.Valid {
			c.NotBefore = &notBefore.Time
		}
		if notAfter.Valid {
			c.NotAfter = &notAfter.Time
		}
		certs = append(certs, c)
	}
	return certs, total, rows.Err()
}

// Revoke 吊销证书（更新状态和原因码）。
func (r *CertRepo) Revoke(ctx context.Context, certUUID string, reason int) error {
	now := time.Now()
	_, err := r.db.ExecContext(ctx,
		`UPDATE certificates SET revocation_status = 'revoked', revoke_reason = ?, revoked_at = ?, updated_at = ? WHERE uuid = ?`,
		reason, now, now, certUUID,
	)
	return err
}

// AssignToCard 将证书分配到指定智能卡。
func (r *CertRepo) AssignToCard(ctx context.Context, certUUID, targetCardUUID string) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE certificates SET card_uuid = ?, updated_at = ? WHERE uuid = ?`,
		targetCardUUID, time.Now(), certUUID,
	)
	return err
}

// Delete 删除证书。
func (r *CertRepo) Delete(ctx context.Context, certUUID string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM certificates WHERE uuid = ?`, certUUID)
	return err
}

// ---- LogRepo ----

// LogRepo 提供操作日志数据访问（兼容旧版）。
type LogRepo struct {
	db *DB
}

// NewLogRepo 创建 LogRepo。
func NewLogRepo(db *DB) *LogRepo {
	return &LogRepo{db: db}
}

// Create 写入操作日志。
func (r *LogRepo) Create(ctx context.Context, l *Log) error {
	l.RecordedAt = time.Now()
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO logs (user_uuid, card_uuid, cert_uuid, action, ip_addr, user_agent, recorded_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		l.UserUUID, l.CardUUID, l.CertUUID, l.Action, l.IPAddr, l.UserAgent, l.RecordedAt,
	)
	return err
}

// List 分页查询操作日志，支持按用户、操作类型、时间范围筛选。
func (r *LogRepo) List(ctx context.Context, userUUID, action, startTime, endTime string, page, pageSize int) ([]*Log, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	where := `WHERE 1=1`
	var args []interface{}
	if userUUID != "" {
		where += ` AND user_uuid = ?`
		args = append(args, userUUID)
	}
	if action != "" {
		where += ` AND action LIKE ?`
		args = append(args, "%"+action+"%")
	}
	if startTime != "" {
		where += ` AND recorded_at >= ?`
		args = append(args, startTime)
	}
	if endTime != "" {
		where += ` AND recorded_at <= ?`
		args = append(args, endTime)
	}

	var total int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM logs `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := r.db.QueryContext(ctx,
		`SELECT id, user_uuid, card_uuid, cert_uuid, action, ip_addr, user_agent, recorded_at
		 FROM logs `+where+` ORDER BY recorded_at DESC LIMIT ? OFFSET ?`,
		append(args, pageSize, offset)...,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var logs []*Log
	for rows.Next() {
		l := &Log{}
		if err := rows.Scan(&l.ID, &l.UserUUID, &l.CardUUID, &l.CertUUID, &l.Action, &l.IPAddr, &l.UserAgent, &l.RecordedAt); err != nil {
			return nil, 0, err
		}
		logs = append(logs, l)
	}
	return logs, total, rows.Err()
}

// ---- AuditLogRepo ----

// AuditLogRepo 提供审计日志数据访问（链式哈希完整性）。
type AuditLogRepo struct {
	db *DB
}

// NewAuditLogRepo 创建 AuditLogRepo。
func NewAuditLogRepo(db *DB) *AuditLogRepo {
	return &AuditLogRepo{db: db}
}

// Create 写入审计日志（自动记录上一条日志的 prev_hash）。
func (r *AuditLogRepo) Create(ctx context.Context, l *AuditLog) error {
	l.CreatedAt = time.Now()

	// 获取上一条日志的 prev_hash（用于链式完整性）
	var lastPrevHash string
	err := r.db.QueryRowContext(ctx,
		`SELECT prev_hash FROM audit_logs ORDER BY id DESC LIMIT 1`,
	).Scan(&lastPrevHash)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("获取上一条审计日志失败: %w", err)
	}
	l.PrevHash = lastPrevHash

	_, err = r.db.ExecContext(ctx,
		`INSERT INTO audit_logs (user_uuid, action, resource_type, resource_uuid, detail, ip_address, prev_hash, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		l.UserUUID, l.Action, l.ResourceType, l.ResourceUUID, l.Detail, l.IPAddress, l.PrevHash, l.CreatedAt,
	)
	return err
}

// List 分页查询审计日志，并校验链式完整性。
// 返回值：日志列表、总数、是否存在完整性断裂、错误
func (r *AuditLogRepo) List(ctx context.Context, userUUID, action, resourceType string, page, pageSize int) ([]*AuditLog, int, bool, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	where := `WHERE 1=1`
	var args []interface{}
	if userUUID != "" {
		where += ` AND user_uuid = ?`
		args = append(args, userUUID)
	}
	if action != "" {
		where += ` AND action = ?`
		args = append(args, action)
	}
	if resourceType != "" {
		where += ` AND resource_type = ?`
		args = append(args, resourceType)
	}

	var total int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_logs `+where, args...).Scan(&total); err != nil {
		return nil, 0, false, err
	}

	rows, err := r.db.QueryContext(ctx,
		`SELECT id, user_uuid, action, resource_type, resource_uuid, detail, ip_address, prev_hash, created_at
		 FROM audit_logs `+where+` ORDER BY id ASC LIMIT ? OFFSET ?`,
		append(args, pageSize, offset)...,
	)
	if err != nil {
		return nil, 0, false, err
	}
	defer rows.Close()

	var logs []*AuditLog
	integrityBroken := false
	var prevPrevHash string
	for rows.Next() {
		l := &AuditLog{}
		if err := rows.Scan(&l.ID, &l.UserUUID, &l.Action, &l.ResourceType, &l.ResourceUUID,
			&l.Detail, &l.IPAddress, &l.PrevHash, &l.CreatedAt); err != nil {
			return nil, 0, false, err
		}
		// 校验链式完整性：当前条的 prev_hash 应等于上一条的 prev_hash
		if len(logs) > 0 && l.PrevHash != prevPrevHash {
			l.IntegrityBroken = true
			integrityBroken = true
		}
		prevPrevHash = l.PrevHash
		logs = append(logs, l)
	}
	return logs, total, integrityBroken, rows.Err()
}

// ---- 工具函数 ----

// BoolToInt 将 bool 转换为 int（1/0），供各包使用。
func BoolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func boolToInt(b bool) int {
	return BoolToInt(b)
}
