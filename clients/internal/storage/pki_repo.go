package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ---- CSRRepo ----

// CSRRepo 提供 CSR 记录的 CRUD 操作。
type CSRRepo struct {
	db *sql.DB
}

// NewCSRRepo 创建 CSRRepo 实例。
func NewCSRRepo(db *DB) *CSRRepo {
	return &CSRRepo{db: db.Conn()}
}

// Create 创建 CSR 记录。
func (r *CSRRepo) Create(ctx context.Context, c *CSRRecord) error {
	if c.UUID == "" {
		c.UUID = uuid.New().String()
	}
	c.CreatedAt = time.Now()
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO pki_csrs (uuid, common_name, organization, org_unit, country, state, locality, email,
			key_type, key_storage, card_uuid, san_dns, san_ip, san_email, san_uri,
			key_usage, ext_key_usage, extra_subject, csr_pem, has_private_key, private_key_enc, remark, created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		c.UUID, c.CommonName, c.Organization, c.OrgUnit, c.Country, c.State, c.Locality, c.Email,
		c.KeyType, string(c.KeyStorage), c.CardUUID, c.SANDN, c.SANIP, c.SANEmail, c.SANURI,
		c.KeyUsage, c.ExtKeyUsage, c.ExtraSubject, c.CSRPEM, boolToInt(c.HasPrivateKey), c.PrivateKeyEnc, c.Remark, c.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("创建 CSR 失败: %w", err)
	}
	return nil
}

// GetByUUID 根据 UUID 查询 CSR。
func (r *CSRRepo) GetByUUID(ctx context.Context, id string) (*CSRRecord, error) {
	c := &CSRRecord{}
	var hasKey int
	err := r.db.QueryRowContext(ctx, `
		SELECT uuid, common_name, organization, org_unit, country, state, locality, email,
			key_type, key_storage, card_uuid, san_dns, san_ip, san_email, san_uri,
			key_usage, ext_key_usage, extra_subject, csr_pem, has_private_key, private_key_enc, remark, created_at
		FROM pki_csrs WHERE uuid=?`, id).
		Scan(&c.UUID, &c.CommonName, &c.Organization, &c.OrgUnit, &c.Country, &c.State, &c.Locality, &c.Email,
			&c.KeyType, &c.KeyStorage, &c.CardUUID, &c.SANDN, &c.SANIP, &c.SANEmail, &c.SANURI,
			&c.KeyUsage, &c.ExtKeyUsage, &c.ExtraSubject, &c.CSRPEM, &hasKey, &c.PrivateKeyEnc, &c.Remark, &c.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("查询 CSR 失败: %w", err)
	}
	c.HasPrivateKey = hasKey == 1
	return c, nil
}

// List 分页列出 CSR 记录（不含私钥数据）。
func (r *CSRRepo) List(ctx context.Context, page, pageSize int) ([]*CSRRecord, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	var total int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM pki_csrs`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("统计 CSR 数量失败: %w", err)
	}

	rows, err := r.db.QueryContext(ctx, `
		SELECT uuid, common_name, organization, org_unit, country, key_type, key_storage, card_uuid,
			san_dns, san_ip, san_email, san_uri, key_usage, ext_key_usage, csr_pem, has_private_key, remark, created_at
		FROM pki_csrs ORDER BY created_at DESC LIMIT ? OFFSET ?`, pageSize, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("查询 CSR 列表失败: %w", err)
	}
	defer rows.Close()

	var list []*CSRRecord
	for rows.Next() {
		c := &CSRRecord{}
		var hasKey int
		if err := rows.Scan(&c.UUID, &c.CommonName, &c.Organization, &c.OrgUnit, &c.Country,
			&c.KeyType, &c.KeyStorage, &c.CardUUID,
			&c.SANDN, &c.SANIP, &c.SANEmail, &c.SANURI,
			&c.KeyUsage, &c.ExtKeyUsage, &c.CSRPEM, &hasKey, &c.Remark, &c.CreatedAt); err != nil {
			return nil, 0, fmt.Errorf("扫描 CSR 数据失败: %w", err)
		}
		c.HasPrivateKey = hasKey == 1
		list = append(list, c)
	}
	return list, total, rows.Err()
}

// Delete 删除 CSR 记录。
func (r *CSRRepo) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM pki_csrs WHERE uuid=?`, id)
	if err != nil {
		return fmt.Errorf("删除 CSR 失败: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("CSR 不存在: %s", id)
	}
	return nil
}

// ---- CARepo ----

// CARepo 提供本地 CA 记录的 CRUD 操作。
type CARepo struct {
	db *sql.DB
}

// NewCARepo 创建 CARepo 实例。
func NewCARepo(db *DB) *CARepo {
	return &CARepo{db: db.Conn()}
}

// Create 创建 CA 记录。
func (r *CARepo) Create(ctx context.Context, ca *LocalCA) error {
	if ca.UUID == "" {
		ca.UUID = uuid.New().String()
	}
	ca.CreatedAt = time.Now()
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO pki_cas (uuid, name, common_name, organization, country, key_type,
			cert_pem, chain_pem, has_priv_key, priv_key_enc, card_uuid,
			not_before, not_after, issued_count, revoked, created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		ca.UUID, ca.Name, ca.CommonName, ca.Organization, ca.Country, ca.KeyType,
		ca.CertPEM, ca.ChainPEM, boolToInt(ca.HasPrivKey), ca.PrivKeyEnc, ca.CardUUID,
		ca.NotBefore, ca.NotAfter, ca.IssuedCount, boolToInt(ca.Revoked), ca.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("创建 CA 失败: %w", err)
	}
	return nil
}

// GetByUUID 根据 UUID 查询 CA（含私钥）。
func (r *CARepo) GetByUUID(ctx context.Context, id string) (*LocalCA, error) {
	ca := &LocalCA{}
	var hasKey, revoked int
	err := r.db.QueryRowContext(ctx, `
		SELECT uuid, name, common_name, organization, country, key_type,
			cert_pem, chain_pem, has_priv_key, priv_key_enc, card_uuid,
			not_before, not_after, issued_count, revoked, created_at
		FROM pki_cas WHERE uuid=?`, id).
		Scan(&ca.UUID, &ca.Name, &ca.CommonName, &ca.Organization, &ca.Country, &ca.KeyType,
			&ca.CertPEM, &ca.ChainPEM, &hasKey, &ca.PrivKeyEnc, &ca.CardUUID,
			&ca.NotBefore, &ca.NotAfter, &ca.IssuedCount, &revoked, &ca.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("查询 CA 失败: %w", err)
	}
	ca.HasPrivKey = hasKey == 1
	ca.Revoked = revoked == 1
	return ca, nil
}

// List 分页列出 CA 记录。
func (r *CARepo) List(ctx context.Context, page, pageSize int) ([]*LocalCA, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	var total int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM pki_cas`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("统计 CA 数量失败: %w", err)
	}

	rows, err := r.db.QueryContext(ctx, `
		SELECT uuid, name, common_name, organization, country, key_type,
			cert_pem, chain_pem, has_priv_key, card_uuid,
			not_before, not_after, issued_count, revoked, created_at
		FROM pki_cas ORDER BY created_at DESC LIMIT ? OFFSET ?`, pageSize, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("查询 CA 列表失败: %w", err)
	}
	defer rows.Close()

	var list []*LocalCA
	for rows.Next() {
		ca := &LocalCA{}
		var hasKey, revoked int
		if err := rows.Scan(&ca.UUID, &ca.Name, &ca.CommonName, &ca.Organization, &ca.Country, &ca.KeyType,
			&ca.CertPEM, &ca.ChainPEM, &hasKey, &ca.CardUUID,
			&ca.NotBefore, &ca.NotAfter, &ca.IssuedCount, &revoked, &ca.CreatedAt); err != nil {
			return nil, 0, fmt.Errorf("扫描 CA 数据失败: %w", err)
		}
		ca.HasPrivKey = hasKey == 1
		ca.Revoked = revoked == 1
		list = append(list, ca)
	}
	return list, total, rows.Err()
}

// Revoke 吊销 CA。
func (r *CARepo) Revoke(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, `UPDATE pki_cas SET revoked=1 WHERE uuid=?`, id)
	if err != nil {
		return fmt.Errorf("吊销 CA 失败: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("CA 不存在: %s", id)
	}
	return nil
}

// IncrIssuedCount 增加已签发数量。
func (r *CARepo) IncrIssuedCount(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE pki_cas SET issued_count=issued_count+1 WHERE uuid=?`, id)
	return err
}

// Delete 删除 CA 记录。
func (r *CARepo) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM pki_cas WHERE uuid=?`, id)
	if err != nil {
		return fmt.Errorf("删除 CA 失败: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("CA 不存在: %s", id)
	}
	return nil
}

// ---- PKICertRepo ----

// PKICertRepo 提供 PKI 证书记录的 CRUD 操作。
type PKICertRepo struct {
	db *sql.DB
}

// NewPKICertRepo 创建 PKICertRepo 实例。
func NewPKICertRepo(db *DB) *PKICertRepo {
	return &PKICertRepo{db: db.Conn()}
}

// Create 创建证书记录。
func (r *PKICertRepo) Create(ctx context.Context, c *PKICert) error {
	if c.UUID == "" {
		c.UUID = uuid.New().String()
	}
	c.CreatedAt = time.Now()
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO pki_certs (uuid, common_name, serial_number, ca_uuid, ca_name, csr_uuid,
			key_type, key_storage, card_uuid, cert_pem, has_private_key, private_key_enc,
			not_before, not_after, key_usage, ext_key_usage, san_dns, san_ip, san_email,
			revoked, remark, created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		c.UUID, c.CommonName, c.SerialNumber, c.CAUUID, c.CAName, c.CSRUUID,
		c.KeyType, string(c.KeyStorage), c.CardUUID, c.CertPEM, boolToInt(c.HasPrivateKey), c.PrivateKeyEnc,
		c.NotBefore, c.NotAfter, c.KeyUsage, c.ExtKeyUsage, c.SANDN, c.SANIP, c.SANEmail,
		boolToInt(c.Revoked), c.Remark, c.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("创建证书失败: %w", err)
	}
	return nil
}

// GetByUUID 根据 UUID 查询证书（含私钥）。
func (r *PKICertRepo) GetByUUID(ctx context.Context, id string) (*PKICert, error) {
	c := &PKICert{}
	var hasKey, revoked int
	err := r.db.QueryRowContext(ctx, `
		SELECT uuid, common_name, serial_number, ca_uuid, ca_name, csr_uuid,
			key_type, key_storage, card_uuid, cert_pem, has_private_key, private_key_enc,
			not_before, not_after, key_usage, ext_key_usage, san_dns, san_ip, san_email,
			revoked, remark, created_at
		FROM pki_certs WHERE uuid=?`, id).
		Scan(&c.UUID, &c.CommonName, &c.SerialNumber, &c.CAUUID, &c.CAName, &c.CSRUUID,
			&c.KeyType, &c.KeyStorage, &c.CardUUID, &c.CertPEM, &hasKey, &c.PrivateKeyEnc,
			&c.NotBefore, &c.NotAfter, &c.KeyUsage, &c.ExtKeyUsage, &c.SANDN, &c.SANIP, &c.SANEmail,
			&revoked, &c.Remark, &c.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("查询证书失败: %w", err)
	}
	c.HasPrivateKey = hasKey == 1
	c.Revoked = revoked == 1
	return c, nil
}

// List 分页列出证书记录。
func (r *PKICertRepo) List(ctx context.Context, page, pageSize int) ([]*PKICert, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	var total int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM pki_certs`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("统计证书数量失败: %w", err)
	}

	rows, err := r.db.QueryContext(ctx, `
		SELECT uuid, common_name, serial_number, ca_uuid, ca_name, csr_uuid,
			key_type, key_storage, card_uuid, cert_pem, has_private_key,
			not_before, not_after, key_usage, ext_key_usage, san_dns, san_ip, san_email,
			revoked, remark, created_at
		FROM pki_certs ORDER BY created_at DESC LIMIT ? OFFSET ?`, pageSize, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("查询证书列表失败: %w", err)
	}
	defer rows.Close()

	var list []*PKICert
	for rows.Next() {
		c := &PKICert{}
		var hasKey, revoked int
		if err := rows.Scan(&c.UUID, &c.CommonName, &c.SerialNumber, &c.CAUUID, &c.CAName, &c.CSRUUID,
			&c.KeyType, &c.KeyStorage, &c.CardUUID, &c.CertPEM, &hasKey,
			&c.NotBefore, &c.NotAfter, &c.KeyUsage, &c.ExtKeyUsage, &c.SANDN, &c.SANIP, &c.SANEmail,
			&revoked, &c.Remark, &c.CreatedAt); err != nil {
			return nil, 0, fmt.Errorf("扫描证书数据失败: %w", err)
		}
		c.HasPrivateKey = hasKey == 1
		c.Revoked = revoked == 1
		list = append(list, c)
	}
	return list, total, rows.Err()
}

// DeletePrivateKey 删除证书私钥（保留证书）。
func (r *PKICertRepo) DeletePrivateKey(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE pki_certs SET has_private_key=0, private_key_enc=NULL WHERE uuid=?`, id)
	if err != nil {
		return fmt.Errorf("删除证书私钥失败: %w", err)
	}
	return nil
}

// Revoke 吊销证书。
func (r *PKICertRepo) Revoke(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, `UPDATE pki_certs SET revoked=1 WHERE uuid=?`, id)
	if err != nil {
		return fmt.Errorf("吊销证书失败: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("证书不存在: %s", id)
	}
	return nil
}

// Delete 删除证书记录。
func (r *PKICertRepo) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM pki_certs WHERE uuid=?`, id)
	if err != nil {
		return fmt.Errorf("删除证书失败: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("证书不存在: %s", id)
	}
	return nil
}

// ListOrphanKeys 列出有私钥但无证书内容的记录（cert_pem 为空），用于自动匹配。
func (r *PKICertRepo) ListOrphanKeys(ctx context.Context) ([]*PKICert, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT uuid, common_name, key_type, key_storage, card_uuid, private_key_enc, created_at
		FROM pki_certs WHERE has_private_key=1 AND (cert_pem='' OR cert_pem IS NULL)`)
	if err != nil {
		return nil, fmt.Errorf("查询孤立私钥失败: %w", err)
	}
	defer rows.Close()

	var list []*PKICert
	for rows.Next() {
		c := &PKICert{HasPrivateKey: true}
		if err := rows.Scan(&c.UUID, &c.CommonName, &c.KeyType, &c.KeyStorage,
			&c.CardUUID, &c.PrivateKeyEnc, &c.CreatedAt); err != nil {
			return nil, fmt.Errorf("扫描孤立私钥失败: %w", err)
		}
		list = append(list, c)
	}
	return list, rows.Err()
}

// AssociateCert 将证书内容关联到已有私钥记录。
func (r *PKICertRepo) AssociateCert(ctx context.Context, id string, c *PKICert) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE pki_certs SET common_name=?, serial_number=?, ca_uuid=?, ca_name=?,
			cert_pem=?, not_before=?, not_after=?, key_usage=?, ext_key_usage=?,
			san_dns=?, san_ip=?, san_email=?, revoked=0, remark=?
		WHERE uuid=?`,
		c.CommonName, c.SerialNumber, c.CAUUID, c.CAName,
		c.CertPEM, c.NotBefore, c.NotAfter, c.KeyUsage, c.ExtKeyUsage,
		c.SANDN, c.SANIP, c.SANEmail, c.Remark, id,
	)
	if err != nil {
		return fmt.Errorf("关联证书失败: %w", err)
	}
	return nil
}
