// Package storage 提供审计日志的链式哈希完整性保护。
package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"
)

// AuditLog 是带链式哈希的审计日志记录。
type AuditLog struct {
	ID         int64     `json:"id"`
	LogType    string    `json:"log_type"` // operation / security / error
	SlotType   string    `json:"slot_type"`
	CardUUID   string    `json:"card_uuid"`
	UserUUID   string    `json:"user_uuid"`
	LogLevel   string    `json:"log_level"` // debug / info / warn / error
	RecordedAt time.Time `json:"recorded_at"`
	Title      string    `json:"title"`
	Content    string    `json:"content"`
	PrevHash   string    `json:"prev_hash"` // 前一条日志的哈希
	Hash       string    `json:"hash"`      // 当前记录的哈希（含 PrevHash）
}

// AuditRepo 提供审计日志的数据库操作。
type AuditRepo struct {
	db *sql.DB
}

// NewAuditRepo 创建审计日志仓库。
func NewAuditRepo(db *DB) *AuditRepo {
	return &AuditRepo{db: db.Conn()}
}

// InitTable 初始化审计日志表。
func (r *AuditRepo) InitTable(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS audit_logs (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			log_type    TEXT NOT NULL DEFAULT 'operation',
			slot_type   TEXT NOT NULL DEFAULT '',
			card_uuid   TEXT NOT NULL DEFAULT '',
			user_uuid   TEXT NOT NULL DEFAULT '',
			log_level   TEXT NOT NULL DEFAULT 'info',
			recorded_at DATETIME NOT NULL DEFAULT (datetime('now')),
			title       TEXT NOT NULL,
			content     TEXT NOT NULL DEFAULT '',
			prev_hash   TEXT NOT NULL DEFAULT '',
			hash        TEXT NOT NULL DEFAULT ''
		);
		CREATE INDEX IF NOT EXISTS idx_audit_logs_recorded_at ON audit_logs(recorded_at);
		CREATE INDEX IF NOT EXISTS idx_audit_logs_user_uuid ON audit_logs(user_uuid);
	`)
	return err
}

// computeHash 计算审计日志记录的 SHA-256 哈希。
// 哈希内容包含：prev_hash + log_type + slot_type + card_uuid + user_uuid + log_level + recorded_at + title + content
func computeHash(prevHash, logType, slotType, cardUUID, userUUID, logLevel, recordedAt, title, content string) string {
	data := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s|%s",
		prevHash, logType, slotType, cardUUID, userUUID, logLevel, recordedAt, title, content)
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

// getLastHash 获取最后一条审计日志的哈希值。
func (r *AuditRepo) getLastHash(ctx context.Context) (string, error) {
	var hash sql.NullString
	err := r.db.QueryRowContext(ctx,
		`SELECT hash FROM audit_logs ORDER BY id DESC LIMIT 1`,
	).Scan(&hash)
	if err == sql.ErrNoRows {
		return "", nil // 第一条记录，前一个哈希为空
	}
	if err != nil {
		return "", fmt.Errorf("查询最后一条审计日志哈希失败: %w", err)
	}
	return hash.String, nil
}

// Write 写入一条审计日志，自动计算链式哈希。
func (r *AuditRepo) Write(ctx context.Context, log *AuditLog) error {
	prevHash, err := r.getLastHash(ctx)
	if err != nil {
		return err
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	log.RecordedAt, _ = time.Parse(time.RFC3339Nano, now)
	log.PrevHash = prevHash
	log.Hash = computeHash(prevHash, log.LogType, log.SlotType, log.CardUUID,
		log.UserUUID, log.LogLevel, now, log.Title, log.Content)

	_, err = r.db.ExecContext(ctx, `
		INSERT INTO audit_logs (log_type, slot_type, card_uuid, user_uuid, log_level, recorded_at, title, content, prev_hash, hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		log.LogType, log.SlotType, log.CardUUID, log.UserUUID, log.LogLevel,
		now, log.Title, log.Content, log.PrevHash, log.Hash,
	)
	if err != nil {
		return fmt.Errorf("写入审计日志失败: %w", err)
	}
	return nil
}

// AuditListResult 是审计日志列表查询结果。
type AuditListResult struct {
	Logs            []AuditLog `json:"logs"`
	Total           int        `json:"total"`
	IntegrityBroken bool       `json:"integrity_broken"`
	BrokenAtID      int64      `json:"broken_at_id,omitempty"`
}

// List 查询审计日志列表，同时验证链式哈希完整性。
func (r *AuditRepo) List(ctx context.Context, offset, limit int) (*AuditListResult, error) {
	// 查询总数
	var total int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_logs`).Scan(&total); err != nil {
		return nil, fmt.Errorf("查询审计日志总数失败: %w", err)
	}

	// 查询日志列表
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, log_type, slot_type, card_uuid, user_uuid, log_level, recorded_at, title, content, prev_hash, hash
		FROM audit_logs ORDER BY id ASC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("查询审计日志失败: %w", err)
	}
	defer rows.Close()

	result := &AuditListResult{Total: total}
	var prevHash string

	// 如果 offset > 0，需要获取 offset 前一条的哈希
	if offset > 0 {
		err := r.db.QueryRowContext(ctx,
			`SELECT hash FROM audit_logs ORDER BY id ASC LIMIT 1 OFFSET ?`, offset-1,
		).Scan(&prevHash)
		if err != nil && err != sql.ErrNoRows {
			return nil, fmt.Errorf("查询前一条哈希失败: %w", err)
		}
	}

	for rows.Next() {
		var log AuditLog
		var recordedAt string
		if err := rows.Scan(&log.ID, &log.LogType, &log.SlotType, &log.CardUUID,
			&log.UserUUID, &log.LogLevel, &recordedAt, &log.Title, &log.Content,
			&log.PrevHash, &log.Hash); err != nil {
			return nil, fmt.Errorf("扫描审计日志行失败: %w", err)
		}
		log.RecordedAt, _ = time.Parse(time.RFC3339Nano, recordedAt)

		// 验证链式哈希完整性
		if !result.IntegrityBroken {
			// 验证 prev_hash 是否匹配
			if log.PrevHash != prevHash {
				result.IntegrityBroken = true
				result.BrokenAtID = log.ID
			}
			// 验证当前记录的哈希是否正确
			expectedHash := computeHash(log.PrevHash, log.LogType, log.SlotType, log.CardUUID,
				log.UserUUID, log.LogLevel, recordedAt, log.Title, log.Content)
			if log.Hash != expectedHash {
				result.IntegrityBroken = true
				result.BrokenAtID = log.ID
			}
			prevHash = log.Hash
		}

		result.Logs = append(result.Logs, log)
	}

	return result, rows.Err()
}

// VerifyIntegrity 验证整个审计日志链的完整性。
func (r *AuditRepo) VerifyIntegrity(ctx context.Context) (bool, int64, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, log_type, slot_type, card_uuid, user_uuid, log_level, recorded_at, title, content, prev_hash, hash
		FROM audit_logs ORDER BY id ASC`)
	if err != nil {
		return false, 0, fmt.Errorf("查询审计日志失败: %w", err)
	}
	defer rows.Close()

	var prevHash string
	for rows.Next() {
		var log AuditLog
		var recordedAt string
		if err := rows.Scan(&log.ID, &log.LogType, &log.SlotType, &log.CardUUID,
			&log.UserUUID, &log.LogLevel, &recordedAt, &log.Title, &log.Content,
			&log.PrevHash, &log.Hash); err != nil {
			return false, 0, fmt.Errorf("扫描审计日志行失败: %w", err)
		}

		// 验证 prev_hash
		if log.PrevHash != prevHash {
			return false, log.ID, nil
		}
		// 验证 hash
		expectedHash := computeHash(log.PrevHash, log.LogType, log.SlotType, log.CardUUID,
			log.UserUUID, log.LogLevel, recordedAt, log.Title, log.Content)
		if log.Hash != expectedHash {
			return false, log.ID, nil
		}
		prevHash = log.Hash
	}

	return true, 0, rows.Err()
}
