package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// StorageZoneRepo 提供私钥存储区域的数据访问。
//
// 驱动参数（库路径、令牌标签、PIN 等）以密文形式存放在 params_enc，
// 加解密由上层（card.Service）用服务端主密钥完成，仓储层只负责存取。
type StorageZoneRepo struct {
	db *DB
}

// NewStorageZoneRepo 创建 StorageZoneRepo。
func NewStorageZoneRepo(db *DB) *StorageZoneRepo {
	return &StorageZoneRepo{db: db}
}

// Create 创建存储区域。
func (r *StorageZoneRepo) Create(ctx context.Context, z *StorageZone) error {
	if z.UUID == "" {
		z.UUID = uuid.New().String()
	}
	now := time.Now()
	z.CreatedAt = now
	z.UpdatedAt = now
	if z.Status == "" {
		z.Status = "active"
	}
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO storage_zones (uuid, name, storage_type, hsm_driver, params_enc, capabilities, status, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		z.UUID, z.Name, z.StorageType, z.HSMDriver, z.ParamsEnc, z.Capabilities, z.Status, z.CreatedAt, z.UpdatedAt)
	if err != nil {
		return fmt.Errorf("创建存储区域失败: %w", err)
	}
	return nil
}

// Update 更新存储区域（名称、类型、驱动、参数、状态）。
func (r *StorageZoneRepo) Update(ctx context.Context, z *StorageZone) error {
	z.UpdatedAt = time.Now()
	_, err := r.db.ExecContext(ctx,
		`UPDATE storage_zones SET name = ?, storage_type = ?, hsm_driver = ?, params_enc = ?, capabilities = ?, status = ?, updated_at = ?
		 WHERE uuid = ?`,
		z.Name, z.StorageType, z.HSMDriver, z.ParamsEnc, z.Capabilities, z.Status, z.UpdatedAt, z.UUID)
	if err != nil {
		return fmt.Errorf("更新存储区域失败: %w", err)
	}
	return nil
}

// GetByUUID 按 UUID 查询存储区域。
func (r *StorageZoneRepo) GetByUUID(ctx context.Context, zoneUUID string) (*StorageZone, error) {
	z := &StorageZone{}
	var lastCheck sql.NullTime
	err := r.db.QueryRowContext(ctx,
		`SELECT uuid, name, storage_type, hsm_driver, params_enc, capabilities, status,
		        last_check_at, last_check_error, last_check_detail, created_at, updated_at
		 FROM storage_zones WHERE uuid = ?`, zoneUUID,
	).Scan(&z.UUID, &z.Name, &z.StorageType, &z.HSMDriver, &z.ParamsEnc, &z.Capabilities, &z.Status,
		&lastCheck, &z.LastCheckError, &z.LastCheckDetail, &z.CreatedAt, &z.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("存储区域不存在: %s", zoneUUID)
	}
	if err != nil {
		return nil, err
	}
	if lastCheck.Valid {
		z.LastCheckAt = &lastCheck.Time
	}
	return z, nil
}

// List 列出全部存储区域。
func (r *StorageZoneRepo) List(ctx context.Context) ([]*StorageZone, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT uuid, name, storage_type, hsm_driver, capabilities, status,
		        last_check_at, last_check_error, last_check_detail, created_at, updated_at
		 FROM storage_zones ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var zones []*StorageZone
	for rows.Next() {
		z := &StorageZone{}
		var lastCheck sql.NullTime
		if err := rows.Scan(&z.UUID, &z.Name, &z.StorageType, &z.HSMDriver, &z.Capabilities, &z.Status,
			&lastCheck, &z.LastCheckError, &z.LastCheckDetail, &z.CreatedAt, &z.UpdatedAt); err != nil {
			return nil, err
		}
		if lastCheck.Valid {
			z.LastCheckAt = &lastCheck.Time
		}
		zones = append(zones, z)
	}
	return zones, rows.Err()
}

// Delete 删除存储区域。
func (r *StorageZoneRepo) Delete(ctx context.Context, zoneUUID string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM storage_zones WHERE uuid = ?`, zoneUUID)
	return err
}

// CountCards 统计引用该存储区域的卡片数量（删除前安全检查）。
func (r *StorageZoneRepo) CountCards(ctx context.Context, zoneUUID string) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM cards WHERE storage_zone_uuid = ?`, zoneUUID).Scan(&n)
	return n, err
}

// SaveCheck 记录一次健康检查结果。
func (r *StorageZoneRepo) SaveCheck(ctx context.Context, zoneUUID string, detail string, checkErr error) error {
	now := time.Now()
	errMsg := ""
	if checkErr != nil {
		errMsg = checkErr.Error()
	}
	_, err := r.db.ExecContext(ctx,
		`UPDATE storage_zones SET last_check_at = ?, last_check_error = ?, last_check_detail = ?, updated_at = ? WHERE uuid = ?`,
		now, errMsg, detail, now, zoneUUID)
	return err
}
