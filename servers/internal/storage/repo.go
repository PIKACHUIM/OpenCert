// Package storage - Repository 实现。
package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrCardCertificateLimit   = errors.New("卡片证书容量已用尽")
	ErrCardServiceUnavailable = errors.New("云端智能卡服务未生效或已到期")
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
	if c.Kind == "" {
		c.Kind = CardKindUser
	}
	if c.ServiceStatus == "" {
		c.ServiceStatus = "active"
	}
	if c.CertificateLimit == 0 {
		c.CertificateLimit = -1
	}
	if c.ReminderDays == nil {
		c.ReminderDays = []int{7, 0}
	}
	reminderDays, err := json.Marshal(c.ReminderDays)
	if err != nil {
		return fmt.Errorf("序列化云卡提醒策略失败: %w", err)
	}

	_, err = r.db.ExecContext(ctx,
		`INSERT INTO cards (uuid, user_uuid, card_name, remark, storage_zone_uuid, pin_data, puk_data, admin_key_data,
		 pin_retries, pin_failed_count, pin_locked, card_kind, order_no, cloud_card_tmpl_uuid, service_status,
		 service_expires_at, certificate_limit, certificate_count, reminder_enabled, reminder_days, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.UUID, c.UserUUID, c.CardName, c.Remark, c.StorageZoneUUID, c.PINData, c.PUKData, c.AdminKeyData,
		c.PINRetries, c.PINFailedCount, boolToInt(c.PINLocked), c.Kind, c.OrderNo, c.CloudCardTmplUUID, c.ServiceStatus,
		c.ServiceExpiresAt, c.CertificateLimit, c.CertificateCount, boolToInt(c.ReminderEnabled), string(reminderDays), c.CreatedAt, c.UpdatedAt,
	)
	return err
}

// GetByUUID 按 UUID 查询卡片。
func (r *CardRepo) GetByUUID(ctx context.Context, cardUUID string) (*Card, error) {
	c := &Card{}
	var pinLocked, reminderEnabled int
	var serviceExpiresAt sql.NullTime
	var reminderDays string
	err := r.db.QueryRowContext(ctx,
		`SELECT uuid, user_uuid, card_name, remark, storage_zone_uuid, pin_data, puk_data, admin_key_data,
		        pin_retries, pin_failed_count, pin_locked, card_kind, order_no, cloud_card_tmpl_uuid, service_status,
		        service_expires_at, certificate_limit, certificate_count, service_version, reminder_enabled, reminder_days, created_at, updated_at
		 FROM cards WHERE uuid = ?`, cardUUID,
	).Scan(&c.UUID, &c.UserUUID, &c.CardName, &c.Remark, &c.StorageZoneUUID, &c.PINData, &c.PUKData, &c.AdminKeyData,
		&c.PINRetries, &c.PINFailedCount, &pinLocked, &c.Kind, &c.OrderNo, &c.CloudCardTmplUUID, &c.ServiceStatus,
		&serviceExpiresAt, &c.CertificateLimit, &c.CertificateCount, &c.ServiceVersion, &reminderEnabled, &reminderDays, &c.CreatedAt, &c.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("卡片不存在: %s", cardUUID)
	}
	c.PINLocked = pinLocked == 1
	c.ReminderEnabled = reminderEnabled == 1
	if serviceExpiresAt.Valid {
		c.ServiceExpiresAt = &serviceExpiresAt.Time
	}
	if err := json.Unmarshal([]byte(reminderDays), &c.ReminderDays); err != nil {
		return nil, fmt.Errorf("解析云卡提醒策略失败: %w", err)
	}
	return c, err
}

// CountUserCards 统计用户的智能卡数量（不含系统托管容器）。
func (r *CardRepo) CountUserCards(ctx context.Context, userUUID string) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM cards WHERE user_uuid = ? AND card_kind <> ? AND service_status <> 'terminated'`, userUUID, CardKindHosting,
	).Scan(&n)
	return n, err
}

// CountByOrderNo 统计某订单已履约的开卡/续费权益。
func (r *CardRepo) CountByOrderNo(ctx context.Context, orderNo string) (int, error) {
	var fulfilled, legacy int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM card_order_fulfillments WHERE order_no = ?`, orderNo).Scan(&fulfilled); err != nil {
		return 0, err
	}
	// 兼容迁移前已开出的历史云卡，避免历史履约额度被重新使用。
	if err := r.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM cards c WHERE c.order_no = ? AND NOT EXISTS
		 (SELECT 1 FROM card_order_fulfillments f WHERE f.order_no = c.order_no AND f.card_uuid = c.uuid)`, orderNo).Scan(&legacy); err != nil {
		return 0, err
	}
	return fulfilled + legacy, nil
}

// UpdateServiceStatus 暂停或恢复云卡服务，不更改其订单与证书历史。
func (r *CardRepo) UpdateServiceStatus(ctx context.Context, cardUUID, status string) error {
	if status != "active" && status != "suspended" {
		return fmt.Errorf("无效的云卡服务状态: %s", status)
	}
	res, err := r.db.ExecContext(ctx,
		`UPDATE cards SET service_status = ?, service_version = service_version + 1, updated_at = ? WHERE uuid = ? AND service_status <> 'terminated'`,
		status, time.Now(), cardUUID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("云卡不存在或已终止")
	}
	return nil
}

// ExtendServiceUntil 通过已支付续费订单延长云卡服务期。
func (r *CardRepo) ExtendServiceUntil(ctx context.Context, cardUUID string, expiresAt time.Time) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE cards SET service_status = 'active', service_expires_at = ?, service_version = service_version + 1, updated_at = ?
		 WHERE uuid = ? AND service_status <> 'terminated'`, expiresAt, time.Now(), cardUUID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("云卡不存在或已终止")
	}
	return nil
}

// ExpireCloudCards 把到期卡片标为 expired；操作入口仍会按到期时间即时阻断，不依赖此任务及时运行。
func (r *CardRepo) ExpireCloudCards(ctx context.Context, now time.Time) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE cards SET service_status = 'expired', service_version = service_version + 1, updated_at = ?
		 WHERE service_status = 'active' AND service_expires_at IS NOT NULL AND service_expires_at <= ?`, now, now)
	return err
}

// ListCloudCardReminderCandidates 返回配置了提醒且具有有效期的云卡。
func (r *CardRepo) ListCloudCardReminderCandidates(ctx context.Context) ([]CloudCardReminderCandidate, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT c.uuid, c.card_name, c.user_uuid, COALESCE(u.email, ''), c.service_expires_at, c.reminder_days
		 FROM cards c JOIN users u ON u.uuid = c.user_uuid
		 WHERE c.card_kind <> ? AND c.service_status <> 'terminated' AND c.reminder_enabled = 1
		   AND c.service_expires_at IS NOT NULL`, CardKindHosting)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	candidates := []CloudCardReminderCandidate{}
	for rows.Next() {
		var item CloudCardReminderCandidate
		var expiresAt sql.NullTime
		var reminderDays string
		if err := rows.Scan(&item.CardUUID, &item.CardName, &item.UserUUID, &item.Email, &expiresAt, &reminderDays); err != nil {
			return nil, err
		}
		if !expiresAt.Valid {
			continue
		}
		item.ExpiresAt = expiresAt.Time
		if err := json.Unmarshal([]byte(reminderDays), &item.ReminderDays); err != nil {
			return nil, fmt.Errorf("解析云卡提醒策略失败: %w", err)
		}
		candidates = append(candidates, item)
	}
	return candidates, rows.Err()
}

// ClaimCloudCardReminder 幂等占用一次提醒发送；失败或过期租约允许后续重试。
func (r *CardRepo) ClaimCloudCardReminder(ctx context.Context, cardUUID string, expiresAt time.Time, daysBefore int, now time.Time) (bool, error) {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO card_reminders (uuid, card_uuid, expires_at, days_before, status, created_at, updated_at)
		 VALUES (?, ?, ?, ?, 'sending', ?, ?)`, uuid.New().String(), cardUUID, expiresAt, daysBefore, now, now)
	if err == nil {
		return true, nil
	}
	lower := strings.ToLower(err.Error())
	if !strings.Contains(lower, "unique") && !strings.Contains(lower, "duplicate") {
		return false, err
	}
	var status string
	var updatedAt time.Time
	if scanErr := r.db.QueryRowContext(ctx,
		`SELECT status, updated_at FROM card_reminders WHERE card_uuid = ? AND expires_at = ? AND days_before = ?`,
		cardUUID, expiresAt, daysBefore).Scan(&status, &updatedAt); scanErr != nil {
		return false, scanErr
	}
	if status == "sent" || (status == "sending" && now.Sub(updatedAt) < time.Hour) {
		return false, nil
	}
	res, err := r.db.ExecContext(ctx,
		`UPDATE card_reminders SET status = 'sending', last_error = '', updated_at = ?
		 WHERE card_uuid = ? AND expires_at = ? AND days_before = ? AND status = ? AND updated_at = ?`,
		now, cardUUID, expiresAt, daysBefore, status, updatedAt)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// CompleteCloudCardReminder 记录提醒发送结果。
func (r *CardRepo) CompleteCloudCardReminder(ctx context.Context, cardUUID string, expiresAt time.Time, daysBefore int, sendErr error, now time.Time) error {
	status, detail := "sent", ""
	var sentAt interface{} = now
	if sendErr != nil {
		status, detail, sentAt = "failed", sendErr.Error(), nil
	}
	_, err := r.db.ExecContext(ctx,
		`UPDATE card_reminders SET status = ?, last_error = ?, sent_at = ?, updated_at = ?
		 WHERE card_uuid = ? AND expires_at = ? AND days_before = ?`,
		status, detail, sentAt, now, cardUUID, expiresAt, daysBefore)
	return err
}

// BindOrder 绑定一次云卡开通权益；容量检查与履约流水落库在同一事务内。
func (r *CardRepo) BindOrder(ctx context.Context, cardUUID, orderNo string, limit int) (bool, error) {
	if orderNo == "" || limit <= 0 {
		return false, fmt.Errorf("云卡订单号或数量上限无效")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback() //nolint:errcheck

	var fulfilled, legacy int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM card_order_fulfillments WHERE order_no = ?`, orderNo).Scan(&fulfilled); err != nil {
		return false, err
	}
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM cards c WHERE c.order_no = ? AND NOT EXISTS
		 (SELECT 1 FROM card_order_fulfillments f WHERE f.order_no = c.order_no AND f.card_uuid = c.uuid)`, orderNo).Scan(&legacy); err != nil {
		return false, err
	}
	used := fulfilled + legacy
	if used >= limit {
		return false, nil
	}

	var templateUUID string
	var expiresAt sql.NullTime
	if err := tx.QueryRowContext(ctx,
		`SELECT cloud_card_tmpl_uuid, service_expires_at FROM cards WHERE uuid = ? AND order_no = ''`, cardUUID,
	).Scan(&templateUUID, &expiresAt); err != nil {
		return false, err
	}
	var expiryValue interface{}
	if expiresAt.Valid {
		expiryValue = expiresAt.Time
	}
	now := time.Now()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO card_order_fulfillments (uuid, order_no, slot_no, card_uuid, template_uuid, fulfillment_type, service_expires_at, created_at)
		 VALUES (?, ?, ?, ?, ?, 'activation', ?, ?)`,
		uuid.New().String(), orderNo, used+1, cardUUID, templateUUID, expiryValue, now); err != nil {
		return false, err
	}
	res, err := tx.ExecContext(ctx, `UPDATE cards SET order_no = ?, service_version = service_version + 1, updated_at = ? WHERE uuid = ? AND order_no = ''`,
		orderNo, now, cardUUID)
	if err != nil {
		return false, err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return false, fmt.Errorf("卡片已绑定其他订单")
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// RenewCloudCardService 使用已付费订单延长同一张云卡服务期，并保留每次续费的权益记录。
func (r *CardRepo) RenewCloudCardService(ctx context.Context, cardUUID, orderNo, templateUUID string, durationMonths, limit int) (*time.Time, bool, error) {
	if orderNo == "" || templateUUID == "" || durationMonths <= 0 || limit <= 0 {
		return nil, false, fmt.Errorf("云卡续费订单参数无效")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback() //nolint:errcheck

	var currentTemplate, status string
	var currentExpiry sql.NullTime
	var serviceVersion int
	if err := tx.QueryRowContext(ctx,
		`SELECT cloud_card_tmpl_uuid, service_status, service_expires_at, service_version FROM cards WHERE uuid = ?`, cardUUID,
	).Scan(&currentTemplate, &status, &currentExpiry, &serviceVersion); err != nil {
		return nil, false, fmt.Errorf("云卡不存在: %w", err)
	}
	if currentTemplate == "" || currentTemplate != templateUUID {
		return nil, false, fmt.Errorf("续费商品与该云卡开通模板不匹配")
	}
	if status == "terminated" {
		return nil, false, fmt.Errorf("已终止的云卡不能续费")
	}

	var fulfilled, legacy int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM card_order_fulfillments WHERE order_no = ?`, orderNo).Scan(&fulfilled); err != nil {
		return nil, false, err
	}
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM cards c WHERE c.order_no = ? AND NOT EXISTS
		 (SELECT 1 FROM card_order_fulfillments f WHERE f.order_no = c.order_no AND f.card_uuid = c.uuid)`, orderNo).Scan(&legacy); err != nil {
		return nil, false, err
	}
	used := fulfilled + legacy
	if used >= limit {
		return nil, false, nil
	}

	now := time.Now()
	start := now
	if currentExpiry.Valid && currentExpiry.Time.After(now) {
		start = currentExpiry.Time
	}
	expiresAt := start.AddDate(0, durationMonths, 0)
	var slotNo int
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(slot_no), 0) + 1 FROM card_order_fulfillments WHERE order_no = ?`, orderNo).Scan(&slotNo); err != nil {
		return nil, false, err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO card_order_fulfillments (uuid, order_no, slot_no, card_uuid, template_uuid, fulfillment_type, service_expires_at, created_at)
		 VALUES (?, ?, ?, ?, ?, 'renewal', ?, ?)`,
		uuid.New().String(), orderNo, slotNo, cardUUID, templateUUID, expiresAt, now); err != nil {
		return nil, false, err
	}
	result, err := tx.ExecContext(ctx,
		`UPDATE cards SET service_status = 'active', service_expires_at = ?, service_version = service_version + 1, updated_at = ?
		 WHERE uuid = ? AND service_version = ?`, expiresAt, now, cardUUID, serviceVersion)
	if err != nil {
		return nil, false, err
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return nil, false, fmt.Errorf("云卡权益发生并发更新，请重试")
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	return &expiresAt, true, nil
}

// GetOrCreateHostingCard 获取（不存在则创建）用户的系统证书托管容器。
//
// 文件下载 / 自带 CSR 类证书不需要远程密码运算，但证书表要求归属某张卡片，
// 因此统一落到每个用户唯一的托管容器中；该容器不计入开卡数量。
func (r *CardRepo) GetOrCreateHostingCard(ctx context.Context, userUUID string) (*Card, error) {
	var cardUUID string
	err := r.db.QueryRowContext(ctx,
		`SELECT uuid FROM cards WHERE user_uuid = ? AND card_kind = ? ORDER BY created_at LIMIT 1`,
		userUUID, CardKindHosting,
	).Scan(&cardUUID)
	if err == nil {
		return r.GetByUUID(ctx, cardUUID)
	}
	if err != sql.ErrNoRows {
		return nil, fmt.Errorf("查询托管容器失败: %w", err)
	}
	c := &Card{
		UserUUID: userUUID,
		CardName: "证书托管容器",
		Remark:   "系统自动创建，用于存放文件下载型证书",
		Kind:     CardKindHosting,
	}
	if err := r.Create(ctx, c); err != nil {
		return nil, fmt.Errorf("创建托管容器失败: %w", err)
	}
	return c, nil
}

// ListAll 查询全部卡片（管理员视图，不返回密钥材料）。
func (r *CardRepo) ListAll(ctx context.Context, userUUID string, page, pageSize int) ([]*Card, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	where := ` WHERE 1=1`
	args := []interface{}{}
	if userUUID != "" {
		where += ` AND user_uuid = ?`
		args = append(args, userUUID)
	}
	var total int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM cards`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.db.QueryContext(ctx,
		`SELECT uuid, user_uuid, card_name, remark, storage_zone_uuid, pin_retries, pin_failed_count, pin_locked,
		        card_kind, order_no, cloud_card_tmpl_uuid, service_status, service_expires_at, certificate_limit,
		        certificate_count, service_version, reminder_enabled, reminder_days, created_at, updated_at
		 FROM cards`+where+` ORDER BY created_at DESC LIMIT ? OFFSET ?`,
		append(args, pageSize, (page-1)*pageSize)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	cards := []*Card{}
	for rows.Next() {
		c := &Card{}
		var pinLocked, reminderEnabled int
		var serviceExpiresAt sql.NullTime
		var reminderDays string
		if err := rows.Scan(&c.UUID, &c.UserUUID, &c.CardName, &c.Remark, &c.StorageZoneUUID,
			&c.PINRetries, &c.PINFailedCount, &pinLocked, &c.Kind, &c.OrderNo, &c.CloudCardTmplUUID,
			&c.ServiceStatus, &serviceExpiresAt, &c.CertificateLimit, &c.CertificateCount, &c.ServiceVersion, &reminderEnabled,
			&reminderDays, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, 0, err
		}
		c.PINLocked = pinLocked == 1
		c.ReminderEnabled = reminderEnabled == 1
		if serviceExpiresAt.Valid {
			c.ServiceExpiresAt = &serviceExpiresAt.Time
		}
		if err := json.Unmarshal([]byte(reminderDays), &c.ReminderDays); err != nil {
			return nil, 0, fmt.Errorf("解析卡片提醒策略失败: %w", err)
		}
		cards = append(cards, c)
	}
	return cards, total, rows.Err()
}

// ListByUser 查询用户的所有卡片（不含敏感 PIN 数据）。
func (r *CardRepo) ListByUser(ctx context.Context, userUUID string) ([]*Card, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT uuid, user_uuid, card_name, remark, storage_zone_uuid, pin_retries, pin_failed_count, pin_locked,
		        card_kind, order_no, cloud_card_tmpl_uuid, service_status, service_expires_at, certificate_limit,
		        certificate_count, service_version, reminder_enabled, reminder_days, created_at, updated_at
		 FROM cards WHERE user_uuid = ? AND service_status <> 'terminated' ORDER BY created_at DESC`, userUUID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cards := []*Card{}
	for rows.Next() {
		c := &Card{}
		var pinLocked, reminderEnabled int
		var serviceExpiresAt sql.NullTime
		var reminderDays string
		if err := rows.Scan(&c.UUID, &c.UserUUID, &c.CardName, &c.Remark, &c.StorageZoneUUID,
			&c.PINRetries, &c.PINFailedCount, &pinLocked, &c.Kind, &c.OrderNo, &c.CloudCardTmplUUID,
			&c.ServiceStatus, &serviceExpiresAt, &c.CertificateLimit, &c.CertificateCount, &c.ServiceVersion, &reminderEnabled,
			&reminderDays, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		c.PINLocked = pinLocked == 1
		c.ReminderEnabled = reminderEnabled == 1
		if serviceExpiresAt.Valid {
			c.ServiceExpiresAt = &serviceExpiresAt.Time
		}
		if err := json.Unmarshal([]byte(reminderDays), &c.ReminderDays); err != nil {
			return nil, fmt.Errorf("解析卡片提醒策略失败: %w", err)
		}
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

// Delete 删除本地/免费卡片；已售云卡仅终止服务，保留订单履约与证书历史。
func (r *CardRepo) Delete(ctx context.Context, cardUUID string) error {
	var orderNo, kind string
	if err := r.db.QueryRowContext(ctx, `SELECT order_no, card_kind FROM cards WHERE uuid = ?`, cardUUID).Scan(&orderNo, &kind); err != nil {
		return err
	}
	if orderNo != "" && kind != CardKindHosting {
		_, err := r.db.ExecContext(ctx,
			`UPDATE cards SET service_status = 'terminated', service_version = service_version + 1, updated_at = ? WHERE uuid = ?`, time.Now(), cardUUID)
		return err
	}
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

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开启证书事务失败: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	var limit int
	var serviceStatus string
	var serviceExpiresAt sql.NullTime
	if err := tx.QueryRowContext(ctx,
		`SELECT certificate_limit, service_status, service_expires_at FROM cards WHERE uuid = ?`, c.CardUUID,
	).Scan(&limit, &serviceStatus, &serviceExpiresAt); err != nil {
		return fmt.Errorf("读取卡片证书权益失败: %w", err)
	}
	serviceCard := &Card{ServiceStatus: serviceStatus}
	if serviceExpiresAt.Valid {
		serviceCard.ServiceExpiresAt = &serviceExpiresAt.Time
	}
	if serviceCard.ServiceState(time.Now()) != "active" {
		return ErrCardServiceUnavailable
	}
	update := `UPDATE cards SET certificate_count = certificate_count + 1, updated_at = ? WHERE uuid = ?`
	args := []interface{}{time.Now(), c.CardUUID}
	if limit >= 0 {
		update += ` AND certificate_count < ?`
		args = append(args, limit)
	}
	result, err := tx.ExecContext(ctx, update, args...)
	if err != nil {
		return fmt.Errorf("预留卡片证书容量失败: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return ErrCardCertificateLimit
	}

	_, err = tx.ExecContext(ctx,
		`INSERT INTO certificates (uuid, card_uuid, user_uuid, cert_type, key_type, cert_content, private_data, remark,
		 order_no, ca_uuid, serial_number, serial_hex, subject_dn, issuer_dn, not_before, not_after,
		 key_usage, ext_key_usage, san_dns, san_ip, san_email, san_uris, certificate_policies,
		 issuance_tmpl_uuid, template_uuid, storage_policy, revocation_status, revoke_reason,
		 key_backend, key_ref, key_storage_tmpl_uuid, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.UUID, c.CardUUID, c.UserUUID, c.CertType, c.KeyType, c.CertContent, c.PrivateData, c.Remark,
		c.OrderNo, c.CAUUID, c.SerialNumber, c.SerialHex, c.SubjectDN, c.IssuerDN, c.NotBefore, c.NotAfter,
		c.KeyUsage, c.ExtKeyUsage, c.SANDNS, c.SANIP, c.SANEmail, c.SANURI, c.CertificatePolicies,
		c.IssuanceTmplUUID, c.TemplateUUID, c.StoragePolicy, c.RevocationStatus, c.RevokeReason,
		c.KeyBackend, c.KeyRef, c.KeyStorageTmplUUID, c.CreatedAt, c.UpdatedAt,
	)
	if err != nil {
		return err
	}
	return tx.Commit()
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
		 issuance_tmpl_uuid, template_uuid, storage_policy, revocation_status, revoke_reason, revoked_at,
		 key_backend, key_ref, key_storage_tmpl_uuid, created_at, updated_at
		 FROM certificates WHERE uuid = ?`, certUUID,
	).Scan(&c.UUID, &c.CardUUID, &c.UserUUID, &c.CertType, &c.KeyType, &c.CertContent, &c.PrivateData, &c.Remark,
		&c.OrderNo, &c.CAUUID, &c.SerialNumber, &c.SerialHex, &c.SubjectDN, &c.IssuerDN, &notBefore, &notAfter,
		&c.KeyUsage, &c.ExtKeyUsage, &c.SANDNS, &c.SANIP, &c.SANEmail, &c.SANURI, &c.CertificatePolicies,
		&c.IssuanceTmplUUID, &c.TemplateUUID, &c.StoragePolicy, &c.RevocationStatus, &c.RevokeReason, &revokedAt,
		&c.KeyBackend, &c.KeyRef, &c.KeyStorageTmplUUID, &c.CreatedAt, &c.UpdatedAt)
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
		 issuance_tmpl_uuid, template_uuid, storage_policy, revocation_status, revoke_reason, revoked_at,
		 key_backend, created_at, updated_at
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
			&c.IssuanceTmplUUID, &c.TemplateUUID, &c.StoragePolicy, &c.RevocationStatus, &c.RevokeReason, &revokedAt,
			&c.KeyBackend, &c.CreatedAt, &c.UpdatedAt); err != nil {
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
		 c.issuance_tmpl_uuid, c.template_uuid, c.storage_policy, c.revocation_status, c.revoke_reason, c.revoked_at,
		 c.key_backend, c.created_at, c.updated_at
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
			&c.IssuanceTmplUUID, &c.TemplateUUID, &c.StoragePolicy, &c.RevocationStatus, &c.RevokeReason, &revokedAt,
			&c.KeyBackend, &c.CreatedAt, &c.UpdatedAt); err != nil {
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

// AssignToCard 将证书分配到指定智能卡，并在同一事务内校验/调整容量计数。
func (r *CertRepo) AssignToCard(ctx context.Context, certUUID, targetCardUUID string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开启证书分配事务失败: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	var currentCardUUID string
	if err := tx.QueryRowContext(ctx, `SELECT card_uuid FROM certificates WHERE uuid = ?`, certUUID).Scan(&currentCardUUID); err != nil {
		return fmt.Errorf("读取证书记录失败: %w", err)
	}
	if currentCardUUID == targetCardUUID {
		return nil
	}
	var limit int
	var serviceStatus string
	var serviceExpiresAt sql.NullTime
	if err := tx.QueryRowContext(ctx,
		`SELECT certificate_limit, service_status, service_expires_at FROM cards WHERE uuid = ?`, targetCardUUID,
	).Scan(&limit, &serviceStatus, &serviceExpiresAt); err != nil {
		return fmt.Errorf("目标卡片不存在: %w", err)
	}
	target := &Card{ServiceStatus: serviceStatus}
	if serviceExpiresAt.Valid {
		target.ServiceExpiresAt = &serviceExpiresAt.Time
	}
	if target.ServiceState(time.Now()) != "active" {
		return ErrCardServiceUnavailable
	}
	update := `UPDATE cards SET certificate_count = certificate_count + 1, updated_at = ? WHERE uuid = ?`
	args := []interface{}{time.Now(), targetCardUUID}
	if limit >= 0 {
		update += ` AND certificate_count < ?`
		args = append(args, limit)
	}
	result, err := tx.ExecContext(ctx, update, args...)
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return ErrCardCertificateLimit
	}
	if _, err := tx.ExecContext(ctx, `UPDATE certificates SET card_uuid = ?, updated_at = ? WHERE uuid = ?`,
		targetCardUUID, time.Now(), certUUID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE cards SET certificate_count = CASE WHEN certificate_count > 0 THEN certificate_count - 1 ELSE 0 END, updated_at = ? WHERE uuid = ?`,
		time.Now(), currentCardUUID); err != nil {
		return err
	}
	return tx.Commit()
}

// Delete 删除证书并释放所属卡片的一个证书槽位。
func (r *CertRepo) Delete(ctx context.Context, certUUID string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开启证书删除事务失败: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck
	var cardUUID string
	if err := tx.QueryRowContext(ctx, `SELECT card_uuid FROM certificates WHERE uuid = ?`, certUUID).Scan(&cardUUID); err != nil {
		if err == sql.ErrNoRows {
			return nil
		}
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM certificates WHERE uuid = ?`, certUUID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE cards SET certificate_count = CASE WHEN certificate_count > 0 THEN certificate_count - 1 ELSE 0 END, updated_at = ? WHERE uuid = ?`,
		time.Now(), cardUUID); err != nil {
		return err
	}
	return tx.Commit()
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
