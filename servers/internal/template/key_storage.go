// Package template 提供密钥存储类型模板的管理服务。
package template

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/globaltrusts/server-card/internal/storage"
	"github.com/google/uuid"
)

// Service 是密钥存储类型模板服务。
type Service struct {
	db *storage.DB
}

// NewService 创建模板服务。
func NewService(db *storage.DB) *Service {
	return &Service{db: db}
}

// Create 创建密钥存储类型模板。
func (s *Service) Create(ctx context.Context, t *storage.KeyStorageTemplate) error {
	if err := Validate(t); err != nil {
		return fmt.Errorf("模板配置校验失败: %w", err)
	}

	t.UUID = uuid.New().String()
	t.CreatedAt = time.Now()
	t.UpdatedAt = time.Now()

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO key_storage_templates (uuid, name, storage_methods, security_level, allow_reimport, cloud_backup, allow_reissue, max_reissue_count, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.UUID, t.Name, t.StorageMethods, t.SecurityLevel, boolToInt(t.AllowReimport), boolToInt(t.CloudBackup),
		boolToInt(t.AllowReissue), t.MaxReissueCount, t.CreatedAt, t.UpdatedAt,
	)
	return err
}

// GetByUUID 按 UUID 查询模板。
func (s *Service) GetByUUID(ctx context.Context, templateUUID string) (*storage.KeyStorageTemplate, error) {
	t := &storage.KeyStorageTemplate{}
	var allowReimport, cloudBackup, allowReissue int
	err := s.db.QueryRowContext(ctx,
		`SELECT uuid, name, storage_methods, security_level, allow_reimport, cloud_backup, allow_reissue, max_reissue_count, created_at, updated_at
		 FROM key_storage_templates WHERE uuid = ?`, templateUUID,
	).Scan(&t.UUID, &t.Name, &t.StorageMethods, &t.SecurityLevel, &allowReimport, &cloudBackup, &allowReissue, &t.MaxReissueCount, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("模板不存在: %s", templateUUID)
	}
	t.AllowReimport = allowReimport == 1
	t.CloudBackup = cloudBackup == 1
	t.AllowReissue = allowReissue == 1
	return t, nil
}

// List 查询所有模板。
func (s *Service) List(ctx context.Context) ([]*storage.KeyStorageTemplate, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT uuid, name, storage_methods, security_level, allow_reimport, cloud_backup, allow_reissue, max_reissue_count, created_at, updated_at
		 FROM key_storage_templates ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var templates []*storage.KeyStorageTemplate
	for rows.Next() {
		t := &storage.KeyStorageTemplate{}
		var allowReimport, cloudBackup, allowReissue int
		if err := rows.Scan(&t.UUID, &t.Name, &t.StorageMethods, &t.SecurityLevel, &allowReimport, &cloudBackup, &allowReissue, &t.MaxReissueCount, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		t.AllowReimport = allowReimport == 1
		t.CloudBackup = cloudBackup == 1
		t.AllowReissue = allowReissue == 1
		templates = append(templates, t)
	}
	return templates, rows.Err()
}

// Update 更新模板（仅允许修改非安全属性：名称、下发次数等）。
func (s *Service) Update(ctx context.Context, templateUUID string, name string, maxReissueCount int) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE key_storage_templates SET name = ?, max_reissue_count = ?, updated_at = ? WHERE uuid = ?`,
		name, maxReissueCount, time.Now(), templateUUID,
	)
	return err
}

// Delete 删除模板（如果已关联证书则拒绝）。
func (s *Service) Delete(ctx context.Context, templateUUID string) error {
	// 检查是否有关联的下发记录
	var count int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM cert_reissue_counters WHERE template_uuid = ?`, templateUUID,
	).Scan(&count)
	if err != nil {
		return err
	}
	if count > 0 {
		return fmt.Errorf("模板已关联 %d 个证书，无法删除", count)
	}

	_, err = s.db.ExecContext(ctx, `DELETE FROM key_storage_templates WHERE uuid = ?`, templateUUID)
	return err
}

// isUnlimited 判断该模板的下发次数是否不受限制。
//
// 文件下载模式与 max_reissue_count = -1 都表示不限次数。
func isUnlimited(tmpl *storage.KeyStorageTemplate) bool {
	return tmpl.HasMethod(storage.StorageFileDownload) || tmpl.MaxReissueCount == -1
}

// ensureCounter 确保下发计数器存在（幂等）。
func ensureCounter(ctx context.Context, tx *sql.Tx, certUUID, templateUUID string, maxCount int) error {
	_, err := tx.ExecContext(ctx,
		`INSERT INTO cert_reissue_counters (cert_uuid, template_uuid, issued_count, max_count)
		 VALUES (?, ?, 0, ?)
		 ON CONFLICT(cert_uuid, template_uuid) DO NOTHING`,
		certUUID, templateUUID, maxCount)
	return err
}

// CheckReissue 检查证书是否可以重新下发，返回剩余次数（-1 表示不限）。
func (s *Service) CheckReissue(ctx context.Context, certUUID string, templateUUID string) (int, error) {
	tmpl, err := s.GetByUUID(ctx, templateUUID)
	if err != nil {
		return 0, err
	}
	if !tmpl.AllowReissue {
		return 0, fmt.Errorf("该证书的存储策略不允许重新下发")
	}
	if isUnlimited(tmpl) {
		return -1, nil
	}

	var issuedCount, maxCount int
	err = s.db.QueryRowContext(ctx,
		`SELECT issued_count, max_count FROM cert_reissue_counters WHERE cert_uuid = ? AND template_uuid = ?`,
		certUUID, templateUUID,
	).Scan(&issuedCount, &maxCount)
	if err == sql.ErrNoRows {
		// 首次下发：以模板配置作为上限
		return tmpl.MaxReissueCount, nil
	}
	if err != nil {
		return 0, fmt.Errorf("查询下发次数失败: %w", err)
	}
	if maxCount == -1 {
		return -1, nil
	}

	remaining := maxCount - issuedCount
	if remaining <= 0 {
		return 0, fmt.Errorf("已达最大下发次数 %d", maxCount)
	}
	return remaining, nil
}

// RecordReissue 记录一次证书下发（事务 + 条件更新，保证额度不被并发穿透）。
//
// 与早期实现的差异：不限次数的模板同样会创建计数器并记录下发流水，
// 不再出现"检查放行但记录时报已达上限"的矛盾。
func (s *Service) RecordReissue(ctx context.Context, certUUID, templateUUID, userUUID, method, deviceInfo string) error {
	tmpl, err := s.GetByUUID(ctx, templateUUID)
	if err != nil {
		return err
	}
	if !tmpl.AllowReissue {
		return fmt.Errorf("该证书的存储策略不允许重新下发")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开启事务失败: %w", err)
	}
	defer tx.Rollback()

	if err := ensureCounter(ctx, tx, certUUID, templateUUID, tmpl.MaxReissueCount); err != nil {
		return fmt.Errorf("初始化下发计数器失败: %w", err)
	}

	// 条件递增：max_count = -1 或仍有剩余额度时才允许
	res, err := tx.ExecContext(ctx,
		`UPDATE cert_reissue_counters SET issued_count = issued_count + 1
		 WHERE cert_uuid = ? AND template_uuid = ? AND (max_count = -1 OR issued_count < max_count)`,
		certUUID, templateUUID)
	if err != nil {
		return fmt.Errorf("更新下发计数失败: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("已达最大下发次数，无法继续下发")
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO cert_issuance_records (uuid, cert_uuid, user_uuid, issuance_method, device_info, issued_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		uuid.New().String(), certUUID, userUUID, method, deviceInfo, time.Now(),
	); err != nil {
		return fmt.Errorf("写入下发记录失败: %w", err)
	}

	return tx.Commit()
}

// ---- 工具函数 ----

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
