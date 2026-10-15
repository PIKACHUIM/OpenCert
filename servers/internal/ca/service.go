// Package ca 提供 CA 证书颁发机构的管理服务。
package ca

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/globaltrusts/server-card/internal/storage"
	"github.com/google/uuid"
)

// Service 是 CA 管理服务。
type Service struct {
	db        *storage.DB
	masterKey []byte // 服务端主密钥，用于加密 CA 私钥
}

// NewService 创建 CA 管理服务。
func NewService(db *storage.DB, masterKey []byte) *Service {
	return &Service{db: db, masterKey: masterKey}
}

// Create 创建 CA（自签名根 CA 或由父 CA 签发的中间 CA）。
func (s *Service) Create(ctx context.Context, ca *storage.CA) error {
	ca.UUID = uuid.New().String()
	ca.CreatedAt = time.Now()
	ca.UpdatedAt = time.Now()
	if ca.Status == "" {
		ca.Status = "active"
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO cas (uuid, name, cert_pem, private_enc, parent_uuid, status, not_before, not_after, issued_count, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ca.UUID, ca.Name, ca.CertPEM, ca.PrivateEnc, ca.ParentUUID, ca.Status,
		ca.NotBefore, ca.NotAfter, ca.IssuedCount, ca.CreatedAt, ca.UpdatedAt,
	)
	return err
}

// GetByUUID 按 UUID 查询 CA。
func (s *Service) GetByUUID(ctx context.Context, caUUID string) (*storage.CA, error) {
	ca := &storage.CA{}
	err := s.db.QueryRowContext(ctx,
		`SELECT uuid, name, cert_pem, private_enc, parent_uuid, status, not_before, not_after, issued_count, created_at, updated_at
		 FROM cas WHERE uuid = ?`, caUUID,
	).Scan(&ca.UUID, &ca.Name, &ca.CertPEM, &ca.PrivateEnc, &ca.ParentUUID, &ca.Status,
		&ca.NotBefore, &ca.NotAfter, &ca.IssuedCount, &ca.CreatedAt, &ca.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("CA 不存在: %s", caUUID)
	}
	return ca, err
}

// List 查询所有 CA。
func (s *Service) List(ctx context.Context) ([]*storage.CA, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT uuid, name, cert_pem, parent_uuid, status, not_before, not_after, issued_count, created_at, updated_at
		 FROM cas ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cas []*storage.CA
	for rows.Next() {
		ca := &storage.CA{}
		if err := rows.Scan(&ca.UUID, &ca.Name, &ca.CertPEM, &ca.ParentUUID, &ca.Status,
			&ca.NotBefore, &ca.NotAfter, &ca.IssuedCount, &ca.CreatedAt, &ca.UpdatedAt); err != nil {
			return nil, err
		}
		cas = append(cas, ca)
	}
	return cas, rows.Err()
}

// Update 更新 CA 信息（仅名称和状态）。
func (s *Service) Update(ctx context.Context, caUUID, name, status string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE cas SET name = ?, status = ?, updated_at = ? WHERE uuid = ?`,
		name, status, time.Now(), caUUID,
	)
	return err
}

// Delete 删除 CA（仅允许删除无签发记录的 CA）。
func (s *Service) Delete(ctx context.Context, caUUID string) error {
	ca, err := s.GetByUUID(ctx, caUUID)
	if err != nil {
		return err
	}
	if ca.IssuedCount > 0 {
		return fmt.Errorf("CA 已签发 %d 个证书，无法删除", ca.IssuedCount)
	}

	// 检查是否有子 CA
	var childCount int
	err = s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM cas WHERE parent_uuid = ?`, caUUID,
	).Scan(&childCount)
	if err != nil {
		return err
	}
	if childCount > 0 {
		return fmt.Errorf("CA 有 %d 个子 CA，无法删除", childCount)
	}

	_, err = s.db.ExecContext(ctx, `DELETE FROM cas WHERE uuid = ?`, caUUID)
	return err
}

// RevokeCert 吊销证书（将序列号加入吊销列表）。
func (s *Service) RevokeCert(ctx context.Context, caUUID, serialNumber string, reason int) error {
	// 检查 CA 是否存在
	if _, err := s.GetByUUID(ctx, caUUID); err != nil {
		return err
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO revoked_certs (ca_uuid, serial_number, revoked_at, reason)
		 VALUES (?, ?, ?, ?)`,
		caUUID, serialNumber, time.Now(), reason,
	)
	return err
}

// ListRevokedCerts 查询 CA 的吊销证书列表。
func (s *Service) ListRevokedCerts(ctx context.Context, caUUID string) ([]*storage.RevokedCert, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, ca_uuid, serial_number, revoked_at, reason
		 FROM revoked_certs WHERE ca_uuid = ? ORDER BY revoked_at DESC`, caUUID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var certs []*storage.RevokedCert
	for rows.Next() {
		c := &storage.RevokedCert{}
		if err := rows.Scan(&c.ID, &c.CAUUID, &c.SerialNumber, &c.RevokedAt, &c.Reason); err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	return certs, rows.Err()
}

// GenerateCRL 生成 CRL（证书吊销列表）DER 格式。
func (s *Service) GenerateCRL(ctx context.Context, caUUID string) ([]byte, error) {
	ca, err := s.GetByUUID(ctx, caUUID)
	if err != nil {
		return nil, err
	}

	// 解析 CA 证书
	caCert, err := parseCertPEM(ca.CertPEM)
	if err != nil {
		return nil, fmt.Errorf("解析 CA 证书失败: %w", err)
	}

	// 解密 CA 私钥
	caKey, err := decryptPrivateKey(s.masterKey, ca.PrivateEnc)
	if err != nil {
		return nil, fmt.Errorf("解密 CA 私钥失败: %w", err)
	}

	// 获取吊销列表
	revokedCerts, err := s.ListRevokedCerts(ctx, caUUID)
	if err != nil {
		return nil, fmt.Errorf("获取吊销列表失败: %w", err)
	}

	// 构建 CRL 吊销条目
	revokedEntries := make([]pkix.RevokedCertificate, 0, len(revokedCerts))
	for _, rc := range revokedCerts {
		serial := new(big.Int)
		serial.SetString(rc.SerialNumber, 16)
		revokedEntries = append(revokedEntries, pkix.RevokedCertificate{
			SerialNumber:   serial,
			RevocationTime: rc.RevokedAt,
		})
	}

	// 生成 CRL
	now := time.Now()
	crlTemplate := &x509.RevocationList{
		RevokedCertificateEntries: make([]x509.RevocationListEntry, 0, len(revokedCerts)),
		Number:                    big.NewInt(now.Unix()),
		ThisUpdate:                now,
		NextUpdate:                now.Add(24 * time.Hour), // 默认 24 小时更新
	}

	for _, rc := range revokedCerts {
		serial := new(big.Int)
		serial.SetString(rc.SerialNumber, 16)
		crlTemplate.RevokedCertificateEntries = append(crlTemplate.RevokedCertificateEntries, x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: rc.RevokedAt,
			ReasonCode:     rc.Reason,
		})
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, caKey)
	if err != nil {
		return nil, fmt.Errorf("生成 CRL 失败: %w", err)
	}

	return crlDER, nil
}

// IncrementIssuedCount 递增 CA 的签发计数。
func (s *Service) IncrementIssuedCount(ctx context.Context, caUUID string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE cas SET issued_count = issued_count + 1, updated_at = ? WHERE uuid = ?`,
		time.Now(), caUUID,
	)
	return err
}

// ImportChain 导入证书链（PEM 格式，包含多个证书）。
//
// 实现方式：
//
//	为兼容 SQLite（`||`）、MySQL（`CONCAT`）、PostgreSQL（`||`）三种数据库的字符串拼接差异，
//	这里采用「应用层读 → 拼接 → 写」的方式实现，避免使用 SQL 方言特有的运算符。
//
// 幂等性：
//
//	如果输入的 chainPEM 已经完整包含在 ca.CertPEM 中，则不做任何修改，保证重复导入幂等。
func (s *Service) ImportChain(ctx context.Context, caUUID string, chainPEM string) error {
	// 1. 先读取 CA
	ca, err := s.GetByUUID(ctx, caUUID)
	if err != nil {
		return err
	}

	// 2. 解析证书链以验证格式
	rest := []byte(chainPEM)
	count := 0
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return fmt.Errorf("证书链中包含非证书类型: %s", block.Type)
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return fmt.Errorf("解析证书链中第 %d 个证书失败: %w", count+1, err)
		}
		count++
	}
	if count == 0 {
		return fmt.Errorf("证书链为空")
	}

	// 3. 幂等检查：如果要导入的链已经在现有 PEM 中，直接成功返回
	trimmed := strings.TrimSpace(chainPEM)
	if trimmed != "" && strings.Contains(ca.CertPEM, trimmed) {
		return nil
	}

	// 4. 应用层拼接：确保中间有换行分隔
	newCertPEM := ca.CertPEM
	if newCertPEM != "" && !strings.HasSuffix(newCertPEM, "\n") {
		newCertPEM += "\n"
	}
	newCertPEM += chainPEM

	// 5. 用标准 UPDATE 写回（跨数据库兼容）
	_, err = s.db.ExecContext(ctx,
		`UPDATE cas SET cert_pem = ?, updated_at = ? WHERE uuid = ?`,
		newCertPEM, time.Now(), caUUID,
	)
	return err
}

// ImportCAParams 是导入外部 CA 的参数。
type ImportCAParams struct {
	Name          string // CA 显示名称
	CertPEM       string // CA 证书 PEM（可包含多张：第一张为叶子 CA，后续为链）
	PrivateKeyPEM string // CA 私钥 PEM（支持 PKCS1/PKCS8/EC）
	ParentUUID    string // 父 CA UUID（可选；若导入中间 CA 可关联）
}

// ImportCA 导入外部 CA 证书和私钥。
// 校验：
//  1. PEM 解析成功，证书必须是 CA（BasicConstraints.IsCA=true）；
//  2. 私钥与证书公钥匹配；
//  3. 加密存储私钥。
func (s *Service) ImportCA(ctx context.Context, p *ImportCAParams) (*storage.CA, error) {
	if p.Name == "" {
		return nil, fmt.Errorf("CA 名称不能为空")
	}
	if p.CertPEM == "" || p.PrivateKeyPEM == "" {
		return nil, fmt.Errorf("证书 PEM 和私钥 PEM 不能为空")
	}

	// 1. 解析证书（取第一张）
	cert, err := parseCertPEM(p.CertPEM)
	if err != nil {
		return nil, fmt.Errorf("解析 CA 证书失败: %w", err)
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("导入的证书不是 CA 证书（BasicConstraints.IsCA=false）")
	}

	// 2. 解析私钥（尝试 PKCS8 / PKCS1 / EC 顺序）
	keyBlock, _ := pem.Decode([]byte(p.PrivateKeyPEM))
	if keyBlock == nil {
		return nil, fmt.Errorf("无效的私钥 PEM")
	}
	privKey, err := parsePrivateKeyAny(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析私钥失败: %w", err)
	}

	// 3. 校验公私钥匹配
	if err := verifyKeyPair(cert, privKey); err != nil {
		return nil, fmt.Errorf("公私钥不匹配: %w", err)
	}

	// 4. PKCS8 编码后加密
	privDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("序列化私钥失败: %w", err)
	}
	privEnc, err := encryptPrivateKey(s.masterKey, privDER)
	if err != nil {
		return nil, fmt.Errorf("加密私钥失败: %w", err)
	}

	// 5. 写入 CA 表（保留完整 PEM，便于后续读取证书链）
	ca := &storage.CA{
		Name:       p.Name,
		CertPEM:    p.CertPEM,
		PrivateEnc: privEnc,
		ParentUUID: p.ParentUUID,
		Status:     "active",
		NotBefore:  cert.NotBefore,
		NotAfter:   cert.NotAfter,
	}
	if err := s.Create(ctx, ca); err != nil {
		return nil, fmt.Errorf("保存导入的 CA 失败: %w", err)
	}
	return ca, nil
}

// GetCAKeypair 返回 CA 的 X.509 证书对象和解密后的私钥 Signer。
// 供 OCSP 响应签名、CRL 签发等场景使用。调用方应确保此方法仅在内部/受信任路径调用。
func (s *Service) GetCAKeypair(ctx context.Context, caUUID string) (*x509.Certificate, crypto.Signer, error) {
	caObj, err := s.GetByUUID(ctx, caUUID)
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode([]byte(caObj.CertPEM))
	if block == nil {
		return nil, nil, fmt.Errorf("CA 证书 PEM 解码失败")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("解析 CA 证书失败: %w", err)
	}
	signer, err := decryptPrivateKey(s.masterKey, caObj.PrivateEnc)
	if err != nil {
		return nil, nil, fmt.Errorf("解密 CA 私钥失败: %w", err)
	}
	return cert, signer, nil
}

// GetChain 返回指定 CA 及其所有父 CA 的 PEM 证书链（由下至上，即叶子 CA 在前、根 CA 在后）。
// 若 CA 的 CertPEM 字段本身已包含多张证书（如导入时含完整链），将整体原样拼接。
// 循环引用保护：最多递归 16 层。
func (s *Service) GetChain(ctx context.Context, caUUID string) (string, error) {
	var chain string
	visited := make(map[string]bool)
	currentUUID := caUUID
	for i := 0; i < 16; i++ {
		if currentUUID == "" || visited[currentUUID] {
			break
		}
		visited[currentUUID] = true
		ca, err := s.GetByUUID(ctx, currentUUID)
		if err != nil {
			return "", err
		}
		if chain != "" && chain[len(chain)-1] != '\n' {
			chain += "\n"
		}
		chain += ca.CertPEM
		currentUUID = ca.ParentUUID
	}
	if chain == "" {
		return "", fmt.Errorf("CA 链为空")
	}
	return chain, nil
}
