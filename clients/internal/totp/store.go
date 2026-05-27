// Package totp 提供 TOTP/HOTP 条目的加密存储和管理。
package totp

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Store 管理 TOTP/HOTP 条目的持久化存储。
type Store struct {
	db *sql.DB
}

// NewStore 创建 TOTP 存储实例。
func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// InitTable 创建 TOTP 条目表（如果不存在）。
func (s *Store) InitTable(ctx context.Context) error {
	query := `CREATE TABLE IF NOT EXISTS totp_entries (
		uuid TEXT PRIMARY KEY,
		card_uuid TEXT NOT NULL,
		otp_type TEXT NOT NULL DEFAULT 'totp',
		issuer TEXT NOT NULL DEFAULT '',
		account TEXT NOT NULL DEFAULT '',
		algorithm TEXT NOT NULL DEFAULT 'SHA1',
		digits INTEGER NOT NULL DEFAULT 6,
		period INTEGER NOT NULL DEFAULT 30,
		counter INTEGER NOT NULL DEFAULT 0,
		secret_enc TEXT NOT NULL,
		secret_salt TEXT NOT NULL,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`
	_, err := s.db.ExecContext(ctx, query)
	return err
}

// Create 创建一个新的 TOTP/HOTP 条目。
// secretEnc 是加密后的密钥，secretSalt 是加密盐值。
func (s *Store) Create(ctx context.Context, entry *Entry, secretEnc, secretSalt []byte) error {
	if entry.UUID == "" {
		entry.UUID = uuid.New().String()
	}
	now := time.Now()
	entry.CreatedAt = now
	entry.UpdatedAt = now

	query := `INSERT INTO totp_entries 
		(uuid, card_uuid, otp_type, issuer, account, algorithm, digits, period, counter, secret_enc, secret_salt, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := s.db.ExecContext(ctx, query,
		entry.UUID, entry.CardUUID, entry.OTPType, entry.Issuer, entry.Account,
		entry.Algorithm, entry.Digits, entry.Period, entry.Counter,
		base64.StdEncoding.EncodeToString(secretEnc),
		base64.StdEncoding.EncodeToString(secretSalt),
		entry.CreatedAt, entry.UpdatedAt,
	)
	return err
}

// GetByUUID 根据 UUID 获取 TOTP 条目。
func (s *Store) GetByUUID(ctx context.Context, id string) (*Entry, []byte, []byte, error) {
	query := `SELECT uuid, card_uuid, otp_type, issuer, account, algorithm, digits, period, counter, secret_enc, secret_salt, created_at, updated_at
		FROM totp_entries WHERE uuid = ?`
	row := s.db.QueryRowContext(ctx, query, id)

	var entry Entry
	var secretEncB64, secretSaltB64 string
	err := row.Scan(
		&entry.UUID, &entry.CardUUID, &entry.OTPType, &entry.Issuer, &entry.Account,
		&entry.Algorithm, &entry.Digits, &entry.Period, &entry.Counter,
		&secretEncB64, &secretSaltB64, &entry.CreatedAt, &entry.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil, nil, nil
	}
	if err != nil {
		return nil, nil, nil, fmt.Errorf("查询 TOTP 条目失败: %w", err)
	}
	secretEnc, err := base64.StdEncoding.DecodeString(secretEncB64)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("解码 secret_enc 失败: %w", err)
	}
	secretSalt, err := base64.StdEncoding.DecodeString(secretSaltB64)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("解码 secret_salt 失败: %w", err)
	}
	return &entry, secretEnc, secretSalt, nil
}

// ListByCard 列出指定卡片下的所有 TOTP 条目（不含密钥）。
func (s *Store) ListByCard(ctx context.Context, cardUUID string) ([]Entry, error) {
	query := `SELECT uuid, card_uuid, otp_type, issuer, account, algorithm, digits, period, counter, created_at, updated_at
		FROM totp_entries WHERE card_uuid = ? ORDER BY created_at DESC`
	rows, err := s.db.QueryContext(ctx, query, cardUUID)
	if err != nil {
		return nil, fmt.Errorf("查询 TOTP 列表失败: %w", err)
	}
	defer rows.Close()

	var entries []Entry
	for rows.Next() {
		var e Entry
		if err := rows.Scan(
			&e.UUID, &e.CardUUID, &e.OTPType, &e.Issuer, &e.Account,
			&e.Algorithm, &e.Digits, &e.Period, &e.Counter,
			&e.CreatedAt, &e.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("扫描 TOTP 条目失败: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// Delete 删除指定 TOTP 条目。
func (s *Store) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM totp_entries WHERE uuid = ?`
	result, err := s.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("删除 TOTP 条目失败: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("TOTP 条目 %s 不存在", id)
	}
	return nil
}

// IncrementCounter 递增 HOTP 计数器。
func (s *Store) IncrementCounter(ctx context.Context, id string) (uint64, error) {
	query := `UPDATE totp_entries SET counter = counter + 1, updated_at = ? WHERE uuid = ?`
	_, err := s.db.ExecContext(ctx, query, time.Now(), id)
	if err != nil {
		return 0, fmt.Errorf("递增 HOTP 计数器失败: %w", err)
	}

	// 读取新值
	var counter uint64
	err = s.db.QueryRowContext(ctx, `SELECT counter FROM totp_entries WHERE uuid = ?`, id).Scan(&counter)
	return counter, err
}
