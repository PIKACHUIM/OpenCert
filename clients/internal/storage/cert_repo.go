package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// CertRepo 提供证书数据的 CRUD 操作。
type CertRepo struct {
	db *sql.DB
}

// NewCertRepo 创建 CertRepo 实例。
func NewCertRepo(db *DB) *CertRepo {
	return &CertRepo{db: db.Conn()}
}

// Create 创建新证书记录。
func (r *CertRepo) Create(ctx context.Context, c *Certificate) error {
	if c.UUID == "" {
		c.UUID = uuid.New().String()
	}
	now := time.Now()
	c.CreatedAt = now
	c.UpdatedAt = now

	_, err := r.db.ExecContext(ctx, `
		INSERT INTO certificates (
			uuid, slot_type, card_uuid, cert_type, key_type,
			cert_content, temp_key_salt, temp_key_enc, private_data,
			tpm_platform, tpm_key_handle, tpm_public_blob, tpm_private_blob,
			tpm_pcr_policy, tpm_auth_policy, tpm_wrapped_blob, tpm_cert_key_salt,
			remark, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.UUID, string(c.SlotType), c.CardUUID, string(c.CertType), c.KeyType,
		c.CertContent, c.TempKeySalt, c.TempKeyEnc, c.PrivateData,
		string(c.TPMPlatform), c.TPMKeyHandle, c.TPMPublicBlob, c.TPMPrivateBlob,
		c.TPMPCRPolicy, c.TPMAuthPolicy, c.TPMWrappedBlob, c.TPMCertKeySalt,
		c.Remark, c.CreatedAt, c.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("创建证书失败: %w", err)
	}
	return nil
}

// GetByUUID 根据 UUID 查询证书。
func (r *CertRepo) GetByUUID(ctx context.Context, certUUID string) (*Certificate, error) {
	c := &Certificate{}
	err := r.db.QueryRowContext(ctx, `
		SELECT uuid, slot_type, card_uuid, cert_type, key_type,
			cert_content, temp_key_salt, temp_key_enc, private_data,
			tpm_platform, tpm_key_handle, tpm_public_blob, tpm_private_blob,
			tpm_pcr_policy, tpm_auth_policy, tpm_wrapped_blob, tpm_cert_key_salt,
			remark, created_at, updated_at
		FROM certificates WHERE uuid=?`, certUUID).
		Scan(&c.UUID, &c.SlotType, &c.CardUUID, &c.CertType, &c.KeyType,
			&c.CertContent, &c.TempKeySalt, &c.TempKeyEnc, &c.PrivateData,
			&c.TPMPlatform, &c.TPMKeyHandle, &c.TPMPublicBlob, &c.TPMPrivateBlob,
			&c.TPMPCRPolicy, &c.TPMAuthPolicy, &c.TPMWrappedBlob, &c.TPMCertKeySalt,
			&c.Remark, &c.CreatedAt, &c.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("查询证书失败: %w", err)
	}
	return c, nil
}

// ListByCard 列出指定卡片的所有证书（含私钥相关字段，供登录后使用）。
func (r *CertRepo) ListByCard(ctx context.Context, cardUUID string) ([]*Certificate, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT uuid, slot_type, card_uuid, cert_type, key_type,
			cert_content, tpm_platform, remark, created_at, updated_at,
			CASE WHEN private_data IS NOT NULL AND length(private_data) > 0 THEN 1 ELSE 0 END as has_private,
			temp_key_salt, temp_key_enc, private_data,
			tpm_wrapped_blob, tpm_private_blob, tpm_cert_key_salt
		FROM certificates WHERE card_uuid=? ORDER BY created_at DESC`, cardUUID)
	if err != nil {
		return nil, fmt.Errorf("查询证书列表失败: %w", err)
	}
	defer rows.Close()

	var certs []*Certificate
	for rows.Next() {
		c := &Certificate{}
		var hasPrivate int
		if err := rows.Scan(&c.UUID, &c.SlotType, &c.CardUUID, &c.CertType, &c.KeyType,
			&c.CertContent, &c.TPMPlatform, &c.Remark, &c.CreatedAt, &c.UpdatedAt,
			&hasPrivate, &c.TempKeySalt, &c.TempKeyEnc, &c.PrivateData,
			&c.TPMWrappedBlob, &c.TPMPrivateBlob, &c.TPMCertKeySalt); err != nil {
			return nil, fmt.Errorf("扫描证书数据失败: %w", err)
		}
		_ = hasPrivate
		certs = append(certs, c)
	}
	return certs, rows.Err()
}

// ListByCardPublic 列出指定卡片的所有**用户可见**证书，过滤掉 internal 类型（如 TPM 保护密钥）。
// API handler 应使用此方法返回给前端。
func (r *CertRepo) ListByCardPublic(ctx context.Context, cardUUID string) ([]*Certificate, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT uuid, slot_type, card_uuid, cert_type, key_type,
			cert_content, tpm_platform, remark, created_at, updated_at,
			CASE WHEN private_data IS NOT NULL AND length(private_data) > 0 THEN 1 ELSE 0 END as has_private,
			temp_key_salt, temp_key_enc, private_data,
			tpm_wrapped_blob, tpm_private_blob, tpm_cert_key_salt
		FROM certificates WHERE card_uuid=? AND cert_type != 'internal' ORDER BY created_at DESC`, cardUUID)
	if err != nil {
		return nil, fmt.Errorf("查询证书列表失败: %w", err)
	}
	defer rows.Close()

	var certs []*Certificate
	for rows.Next() {
		c := &Certificate{}
		var hasPrivate int
		if err := rows.Scan(&c.UUID, &c.SlotType, &c.CardUUID, &c.CertType, &c.KeyType,
			&c.CertContent, &c.TPMPlatform, &c.Remark, &c.CreatedAt, &c.UpdatedAt,
			&hasPrivate, &c.TempKeySalt, &c.TempKeyEnc, &c.PrivateData,
			&c.TPMWrappedBlob, &c.TPMPrivateBlob, &c.TPMCertKeySalt); err != nil {
			return nil, fmt.Errorf("扫描证书数据失败: %w", err)
		}
		_ = hasPrivate
		certs = append(certs, c)
	}
	return certs, rows.Err()
}

// Update 更新证书信息（不含私钥数据）。
func (r *CertRepo) Update(ctx context.Context, c *Certificate) error {
	c.UpdatedAt = time.Now()
	_, err := r.db.ExecContext(ctx, `
		UPDATE certificates SET cert_type=?, key_type=?, cert_content=?, remark=?, updated_at=?
		WHERE uuid=?`,
		string(c.CertType), c.KeyType, c.CertContent, c.Remark, c.UpdatedAt, c.UUID,
	)
	if err != nil {
		return fmt.Errorf("更新证书失败: %w", err)
	}
	return nil
}

// Delete 删除证书。
func (r *CertRepo) Delete(ctx context.Context, certUUID string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM certificates WHERE uuid=?`, certUUID)
	if err != nil {
		return fmt.Errorf("删除证书失败: %w", err)
	}
	return nil
}

// CertStats 是每张卡片的证书类型统计。
type CertStats struct {
	X509  int `json:"x509"`
	FIDO  int `json:"fido"`
	TOTP  int `json:"totp"`
	Creds int `json:"creds"` // login/note/payment/text 等安全凭据
}

// CountGroupedByCard 查询所有卡片的证书类型统计，返回 map[cardUUID]*CertStats。
func (r *CertRepo) CountGroupedByCard(ctx context.Context) (map[string]*CertStats, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT card_uuid, cert_type, COUNT(*) as cnt
		FROM certificates
		GROUP BY card_uuid, cert_type`)
	if err != nil {
		return nil, fmt.Errorf("统计证书数量失败: %w", err)
	}
	defer rows.Close()

	result := make(map[string]*CertStats)
	for rows.Next() {
		var cardUUID, certType string
		var cnt int
		if err := rows.Scan(&cardUUID, &certType, &cnt); err != nil {
			return nil, fmt.Errorf("扫描统计数据失败: %w", err)
		}
		stats, ok := result[cardUUID]
		if !ok {
			stats = &CertStats{}
			result[cardUUID] = stats
		}
		switch CertType(certType) {
		case CertTypeX509, CertTypeSSH, CertTypeGPG:
			stats.X509 += cnt
		case CertTypeFIDO:
			stats.FIDO += cnt
		case CertTypeTOTP:
			stats.TOTP += cnt
		default:
			// login/note/payment/text 等归类为安全凭据
			stats.Creds += cnt
		}
	}
	return result, rows.Err()
}

// ListX509All 查询所有 X.509 类型的证书（用于证书传播）。
func (r *CertRepo) ListX509All(ctx context.Context) ([]*Certificate, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT uuid, slot_type, card_uuid, cert_type, key_type,
			cert_content, tpm_platform, remark, created_at, updated_at,
			CASE WHEN private_data IS NOT NULL AND length(private_data) > 0 THEN 1 ELSE 0 END as has_private,
			temp_key_salt, temp_key_enc, private_data
		FROM certificates WHERE cert_type=? AND cert_content IS NOT NULL AND length(cert_content) > 0
		ORDER BY created_at DESC`, string(CertTypeX509))
	if err != nil {
		return nil, fmt.Errorf("查询 X.509 证书列表失败: %w", err)
	}
	defer rows.Close()

	var certs []*Certificate
	for rows.Next() {
		c := &Certificate{}
		var hasPrivate int
		if err := rows.Scan(&c.UUID, &c.SlotType, &c.CardUUID, &c.CertType, &c.KeyType,
			&c.CertContent, &c.TPMPlatform, &c.Remark, &c.CreatedAt, &c.UpdatedAt,
			&hasPrivate, &c.TempKeySalt, &c.TempKeyEnc, &c.PrivateData); err != nil {
			return nil, fmt.Errorf("扫描证书数据失败: %w", err)
		}
		_ = hasPrivate
		certs = append(certs, c)
	}
	return certs, rows.Err()
}

// ---- LogRepo ----

// LogRepo 提供日志数据的写入和查询操作。
type LogRepo struct {
	db *sql.DB
}

// NewLogRepo 创建 LogRepo 实例。
func NewLogRepo(db *DB) *LogRepo {
	return &LogRepo{db: db.Conn()}
}

// Write 写入一条日志。
func (r *LogRepo) Write(ctx context.Context, l *Log) error {
	l.RecordedAt = time.Now()
	result, err := r.db.ExecContext(ctx, `
		INSERT INTO logs (log_type, slot_type, card_uuid, user_uuid, log_level, recorded_at, title, content)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		string(l.LogType), string(l.SlotType), l.CardUUID, l.UserUUID,
		string(l.LogLevel), l.RecordedAt, l.Title, l.Content,
	)
	if err != nil {
		return fmt.Errorf("写入日志失败: %w", err)
	}
	l.ID, _ = result.LastInsertId()
	return nil
}

// List 查询日志列表，支持分页。
func (r *LogRepo) List(ctx context.Context, limit, offset int) ([]*Log, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, log_type, slot_type, card_uuid, user_uuid, log_level, recorded_at, title, content
		FROM logs ORDER BY recorded_at DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("查询日志失败: %w", err)
	}
	defer rows.Close()

	var logs []*Log
	for rows.Next() {
		l := &Log{}
		if err := rows.Scan(&l.ID, &l.LogType, &l.SlotType, &l.CardUUID, &l.UserUUID,
			&l.LogLevel, &l.RecordedAt, &l.Title, &l.Content); err != nil {
			return nil, fmt.Errorf("扫描日志数据失败: %w", err)
		}
		logs = append(logs, l)
	}
	return logs, rows.Err()
}
