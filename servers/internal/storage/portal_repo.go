// Package storage - 门户（官网/商城）数据访问。
package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// PortalRepo 提供门户商品、规格与站点配置的数据访问。
type PortalRepo struct {
	db *DB
}

// NewPortalRepo 创建 PortalRepo。
func NewPortalRepo(db *DB) *PortalRepo {
	return &PortalRepo{db: db}
}

// ---- 商品 ----

const portalProductColumns = `uuid, code, name, category, level, summary, description,
	features, highlights, badge, cover_image, sort_weight, visible, enabled, created_at, updated_at`

func scanPortalProduct(scan func(dest ...interface{}) error) (*PortalProduct, error) {
	p := &PortalProduct{}
	var visible, enabled int
	if err := scan(&p.UUID, &p.Code, &p.Name, &p.Category, &p.Level, &p.Summary, &p.Description,
		&p.Features, &p.Highlights, &p.Badge, &p.CoverImage, &p.SortWeight, &visible, &enabled,
		&p.CreatedAt, &p.UpdatedAt); err != nil {
		return nil, err
	}
	p.Visible = visible == 1
	p.Enabled = enabled == 1
	return p, nil
}

// ListProducts 查询商品列表。
// publicOnly 为 true 时仅返回前台可见且启用的商品。
func (r *PortalRepo) ListProducts(ctx context.Context, publicOnly bool, category string) ([]*PortalProduct, error) {
	query := `SELECT ` + portalProductColumns + ` FROM portal_products WHERE 1=1`
	args := []interface{}{}
	if publicOnly {
		query += ` AND visible = 1 AND enabled = 1`
	}
	if category != "" {
		query += ` AND category = ?`
		args = append(args, category)
	}
	query += ` ORDER BY sort_weight DESC, created_at DESC`

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("查询商品列表失败: %w", err)
	}
	defer rows.Close()

	products := []*PortalProduct{}
	for rows.Next() {
		p, err := scanPortalProduct(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("读取商品失败: %w", err)
		}
		products = append(products, p)
	}
	return products, rows.Err()
}

// GetProductByCode 按编码查询商品。
func (r *PortalRepo) GetProductByCode(ctx context.Context, code string) (*PortalProduct, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+portalProductColumns+` FROM portal_products WHERE code = ?`, code)
	p, err := scanPortalProduct(row.Scan)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("商品不存在: %s", code)
	}
	return p, err
}

// GetProductByUUID 按 UUID 查询商品。
func (r *PortalRepo) GetProductByUUID(ctx context.Context, productUUID string) (*PortalProduct, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+portalProductColumns+` FROM portal_products WHERE uuid = ?`, productUUID)
	p, err := scanPortalProduct(row.Scan)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("商品不存在: %s", productUUID)
	}
	return p, err
}

// CodeExists 判断商品编码是否已被占用（excludeUUID 为空时忽略自身）。
func (r *PortalRepo) CodeExists(ctx context.Context, code, excludeUUID string) (bool, error) {
	var count int
	err := r.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM portal_products WHERE code = ? AND uuid <> ?`, code, excludeUUID,
	).Scan(&count)
	return count > 0, err
}

// CreateProduct 创建商品。
func (r *PortalRepo) CreateProduct(ctx context.Context, p *PortalProduct) error {
	if p.UUID == "" {
		p.UUID = uuid.New().String()
	}
	now := time.Now()
	p.CreatedAt, p.UpdatedAt = now, now

	_, err := r.db.ExecContext(ctx,
		`INSERT INTO portal_products
		 (uuid, code, name, category, level, summary, description, features, highlights, badge,
		  cover_image, sort_weight, visible, enabled, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.UUID, p.Code, p.Name, p.Category, p.Level, p.Summary, p.Description, p.Features,
		p.Highlights, p.Badge, p.CoverImage, p.SortWeight, boolToInt(p.Visible), boolToInt(p.Enabled),
		p.CreatedAt, p.UpdatedAt,
	)
	return err
}

// UpdateProduct 更新商品（全字段覆盖）。
func (r *PortalRepo) UpdateProduct(ctx context.Context, p *PortalProduct) error {
	p.UpdatedAt = time.Now()
	_, err := r.db.ExecContext(ctx,
		`UPDATE portal_products SET code = ?, name = ?, category = ?, level = ?, summary = ?,
		 description = ?, features = ?, highlights = ?, badge = ?, cover_image = ?,
		 sort_weight = ?, visible = ?, enabled = ?, updated_at = ?
		 WHERE uuid = ?`,
		p.Code, p.Name, p.Category, p.Level, p.Summary, p.Description, p.Features, p.Highlights,
		p.Badge, p.CoverImage, p.SortWeight, boolToInt(p.Visible), boolToInt(p.Enabled),
		p.UpdatedAt, p.UUID,
	)
	return err
}

// DeleteProduct 删除商品及其规格（规格通过外键级联删除）。
func (r *PortalRepo) DeleteProduct(ctx context.Context, productUUID string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM portal_products WHERE uuid = ?`, productUUID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("商品不存在: %s", productUUID)
	}
	return nil
}

// ---- 商品规格 ----

const portalSKUColumns = `uuid, product_uuid, code, name, price_cents, currency, stock, min_qty, max_qty,
	duration_months, delivery_mode, key_types, san_included, cert_apply_tmpl_uuid, cloud_card_tmpl_uuid,
	san_policy, enabled, sort_weight, created_at, updated_at`

func scanPortalSKU(scan func(dest ...interface{}) error) (*PortalProductSKU, error) {
	s := &PortalProductSKU{}
	var enabled int
	if err := scan(&s.UUID, &s.ProductUUID, &s.Code, &s.Name, &s.PriceCents, &s.Currency, &s.Stock,
		&s.MinQty, &s.MaxQty, &s.DurationMonths, &s.DeliveryMode, &s.KeyTypes, &s.SANIncluded,
		&s.CertApplyTmplUUID, &s.CloudCardTmplUUID, &s.SANPolicy, &enabled, &s.SortWeight,
		&s.CreatedAt, &s.UpdatedAt); err != nil {
		return nil, err
	}
	s.Enabled = enabled == 1
	return s, nil
}

// ListSKUsByProduct 查询某商品下的规格。
func (r *PortalRepo) ListSKUsByProduct(ctx context.Context, productUUID string, publicOnly bool) ([]*PortalProductSKU, error) {
	query := `SELECT ` + portalSKUColumns + ` FROM portal_product_skus WHERE product_uuid = ?`
	if publicOnly {
		query += ` AND enabled = 1`
	}
	query += ` ORDER BY sort_weight DESC, price_cents ASC`
	return r.querySKUs(ctx, query, productUUID)
}

// ListSKUsByProducts 批量查询多个商品下的可用规格，避免 N+1。
func (r *PortalRepo) ListSKUsByProducts(ctx context.Context, productUUIDs []string, publicOnly bool) (map[string][]*PortalProductSKU, error) {
	result := map[string][]*PortalProductSKU{}
	if len(productUUIDs) == 0 {
		return result, nil
	}
	query := `SELECT ` + portalSKUColumns + ` FROM portal_product_skus WHERE product_uuid IN (`
	args := make([]interface{}, 0, len(productUUIDs))
	for i, id := range productUUIDs {
		if i > 0 {
			query += ", "
		}
		query += "?"
		args = append(args, id)
	}
	query += ")"
	if publicOnly {
		query += ` AND enabled = 1`
	}
	query += ` ORDER BY sort_weight DESC, price_cents ASC`

	skus, err := r.querySKUs(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	for _, s := range skus {
		result[s.ProductUUID] = append(result[s.ProductUUID], s)
	}
	return result, nil
}

func (r *PortalRepo) querySKUs(ctx context.Context, query string, args ...interface{}) ([]*PortalProductSKU, error) {
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("查询商品规格失败: %w", err)
	}
	defer rows.Close()

	skus := []*PortalProductSKU{}
	for rows.Next() {
		s, err := scanPortalSKU(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("读取商品规格失败: %w", err)
		}
		skus = append(skus, s)
	}
	return skus, rows.Err()
}

// GetSKUByCode 按编码查询规格。
// ReserveStock 预占库存：不限库存（stock<0）直接成功；否则仅在库存充足时扣减。
func (r *PortalRepo) ReserveStock(ctx context.Context, skuCode string, qty int) (bool, error) {
	if qty <= 0 {
		return true, nil
	}
	res, err := r.db.ExecContext(ctx,
		`UPDATE portal_product_skus SET stock = CASE WHEN stock < 0 THEN stock ELSE stock - ? END, updated_at = ?
		 WHERE code = ? AND (stock < 0 OR stock >= ?)`,
		qty, time.Now(), skuCode, qty)
	if err != nil {
		return false, fmt.Errorf("预占库存失败: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ReleaseStock 归还预占的库存（不限库存的规格不变）。
func (r *PortalRepo) ReleaseStock(ctx context.Context, skuCode string, qty int) error {
	if qty <= 0 || skuCode == "" {
		return nil
	}
	_, err := r.db.ExecContext(ctx,
		`UPDATE portal_product_skus SET stock = stock + ?, updated_at = ? WHERE code = ? AND stock >= 0`,
		qty, time.Now(), skuCode)
	return err
}

func (r *PortalRepo) GetSKUByCode(ctx context.Context, code string) (*PortalProductSKU, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+portalSKUColumns+` FROM portal_product_skus WHERE code = ?`, code)
	s, err := scanPortalSKU(row.Scan)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("商品规格不存在: %s", code)
	}
	return s, err
}

// GetSKUByUUID 按 UUID 查询规格。
func (r *PortalRepo) GetSKUByUUID(ctx context.Context, skuUUID string) (*PortalProductSKU, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+portalSKUColumns+` FROM portal_product_skus WHERE uuid = ?`, skuUUID)
	s, err := scanPortalSKU(row.Scan)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("商品规格不存在: %s", skuUUID)
	}
	return s, err
}

// CreateSKU 创建规格。
func (r *PortalRepo) CreateSKU(ctx context.Context, s *PortalProductSKU) error {
	if s.UUID == "" {
		s.UUID = uuid.New().String()
	}
	now := time.Now()
	s.CreatedAt, s.UpdatedAt = now, now

	_, err := r.db.ExecContext(ctx,
		`INSERT INTO portal_product_skus
		 (uuid, product_uuid, code, name, price_cents, currency, stock, min_qty, max_qty,
		  duration_months, delivery_mode, key_types, san_included, cert_apply_tmpl_uuid,
		  cloud_card_tmpl_uuid, san_policy, enabled, sort_weight, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.UUID, s.ProductUUID, s.Code, s.Name, s.PriceCents, s.Currency, s.Stock, s.MinQty, s.MaxQty,
		s.DurationMonths, s.DeliveryMode, s.KeyTypes, s.SANIncluded, s.CertApplyTmplUUID,
		s.CloudCardTmplUUID, normalizeJSONObject(s.SANPolicy), boolToInt(s.Enabled), s.SortWeight, s.CreatedAt, s.UpdatedAt,
	)
	return err
}

// normalizeJSONObject 空值统一为 "{}"，避免 NOT NULL 列写入空串后解析失败。
func normalizeJSONObject(v string) string {
	if v == "" {
		return "{}"
	}
	return v
}

// UpdateSKU 更新规格。
func (r *PortalRepo) UpdateSKU(ctx context.Context, s *PortalProductSKU) error {
	s.UpdatedAt = time.Now()
	_, err := r.db.ExecContext(ctx,
		`UPDATE portal_product_skus SET code = ?, name = ?, price_cents = ?, currency = ?, stock = ?,
		 min_qty = ?, max_qty = ?, duration_months = ?, delivery_mode = ?, key_types = ?,
		 san_included = ?, cert_apply_tmpl_uuid = ?, cloud_card_tmpl_uuid = ?, san_policy = ?, enabled = ?,
		 sort_weight = ?, updated_at = ?
		 WHERE uuid = ?`,
		s.Code, s.Name, s.PriceCents, s.Currency, s.Stock, s.MinQty, s.MaxQty, s.DurationMonths,
		s.DeliveryMode, s.KeyTypes, s.SANIncluded, s.CertApplyTmplUUID, s.CloudCardTmplUUID,
		normalizeJSONObject(s.SANPolicy), boolToInt(s.Enabled), s.SortWeight, s.UpdatedAt, s.UUID,
	)
	return err
}

// DeleteSKU 删除规格。
func (r *PortalRepo) DeleteSKU(ctx context.Context, skuUUID string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM portal_product_skus WHERE uuid = ?`, skuUUID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("商品规格不存在: %s", skuUUID)
	}
	return nil
}

// ---- 站点配置 ----

// GetSiteSettings 读取全部站点配置。
func (r *PortalRepo) GetSiteSettings(ctx context.Context) (map[string]string, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT key, value FROM site_settings`)
	if err != nil {
		return nil, fmt.Errorf("读取站点配置失败: %w", err)
	}
	defer rows.Close()

	settings := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, fmt.Errorf("读取站点配置失败: %w", err)
		}
		settings[k] = v
	}
	return settings, rows.Err()
}

// SetSiteSettings 以 UPSERT 方式批量写入站点配置。
func (r *PortalRepo) SetSiteSettings(ctx context.Context, settings map[string]string) error {
	if len(settings) == 0 {
		return nil
	}
	now := time.Now()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开启事务失败: %w", err)
	}
	defer tx.Rollback()

	for k, v := range settings {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO site_settings (key, value, updated_at) VALUES (?, ?, ?)
			 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
			k, v, now,
		); err != nil {
			return fmt.Errorf("写入站点配置失败 (%s): %w", k, err)
		}
	}
	return tx.Commit()
}
