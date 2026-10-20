// Package ca 提供 CA 证书颁发机构的管理服务。
package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/globaltrusts/server-card/internal/storage"
	"github.com/google/uuid"
)

// SignerLoader 按 CA 记录加载托管在密钥后端（HSM/TPM）中的私钥签名器。
// 由上层注入，避免 ca 包直接依赖 keybackend。
type SignerLoader func(ctx context.Context, ca *storage.CA) (crypto.Signer, error)

// ErrUseLocalKeyGen 由 ZoneKeyGenerator 返回，表示该存储区域（通常是本地
// 数据库区域）应退回标准的本地内存生成路径（CreateCA 内部会据此生成密钥
// 并用主密钥加密入库，而不是把密钥留在某个"硬件区域"）。
var ErrUseLocalKeyGen = errors.New("该存储区域使用本地密钥生成路径")

// ZoneKeyGenerator 在指定存储区域内生成一对密钥。
//
// 本地数据库区域返回的 keyRef 为空（私钥随后由调用方加密落库）；
// 硬件区域（HSM/TPM）返回非空 keyRef，私钥留在设备内不出域，signer
// 直接基于该区域的 Provider 构造，可立即用于自签名。
type ZoneKeyGenerator func(ctx context.Context, zoneUUID, keyType string) (
	pub crypto.PublicKey, keyRef string, keyBackend string, signer crypto.Signer, err error)

// Service 是 CA 管理服务。
type Service struct {
	db           *storage.DB
	masterKey    []byte // 服务端主密钥，用于加密 CA 私钥
	signerLoader SignerLoader
	zoneKeyGen   ZoneKeyGenerator
	zoneKeyImp   ZoneKeyImporter
}

// NewService 创建 CA 管理服务。
func NewService(db *storage.DB, masterKey []byte) *Service {
	return &Service{db: db, masterKey: masterKey}
}

// SetSignerLoader 注入密钥后端签名器加载器（用于 HSM/TPM 托管的 CA 私钥）。
func (s *Service) SetSignerLoader(loader SignerLoader) {
	s.signerLoader = loader
}

// SetZoneKeyGenerator 注入存储区域密钥生成器（用于在 HSM/TPM 中生成 CA 密钥）。
func (s *Service) SetZoneKeyGenerator(gen ZoneKeyGenerator) {
	s.zoneKeyGen = gen
}

// Create 创建 CA 记录。
func (s *Service) Create(ctx context.Context, ca *storage.CA) error {
	ca.UUID = uuid.New().String()
	ca.CreatedAt = time.Now()
	ca.UpdatedAt = time.Now()
	if ca.Status == "" {
		ca.Status = "active"
	}
	if ca.KeyBackend == "" {
		ca.KeyBackend = "database"
	}
	// 仅证书 / 硬件托管的 CA 没有库内私钥；private_enc 列为 NOT NULL，需写入空值而非 NULL。
	if ca.PrivateEnc == nil {
		ca.PrivateEnc = []byte{}
	}
	// 未显式提供时，从证书内容回填算法与主体信息（读取兼容）。
	s.fillFromCert(ca)

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO cas (uuid, name, cert_pem, private_enc, parent_uuid, status, is_public,
		                  not_before, not_after, issued_count, key_type, sig_alg, subject_dn,
		                  key_source, key_backend, storage_zone_uuid, key_ref, issuance_tmpl_uuid,
		                  created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ca.UUID, ca.Name, ca.CertPEM, ca.PrivateEnc, ca.ParentUUID, ca.Status, boolToInt(ca.IsPublic),
		ca.NotBefore, ca.NotAfter, ca.IssuedCount, ca.KeyType, ca.SigAlg, ca.SubjectDN,
		ca.KeySource, ca.KeyBackend, ca.StorageZone, ca.KeyRef, ca.IssuanceTmplUUID,
		ca.CreatedAt, ca.UpdatedAt,
	)
	return err
}

// fillFromCert 在算法/主体字段缺失时，从证书内容解析回填（兼容历史数据）。
func (s *Service) fillFromCert(ca *storage.CA) {
	if ca.KeyType != "" && ca.SubjectDN != "" && ca.SigAlg != "" {
		return
	}
	cert, err := parseCertPEM(ca.CertPEM)
	if err != nil {
		return
	}
	if ca.SubjectDN == "" {
		ca.SubjectDN = cert.Subject.String()
	}
	if ca.SigAlg == "" {
		ca.SigAlg = signatureAlgorithmName(cert)
	}
	if ca.KeyType == "" {
		ca.KeyType = guessKeyType(cert)
	}
	if ca.NotBefore.IsZero() {
		ca.NotBefore = cert.NotBefore
	}
	if ca.NotAfter.IsZero() {
		ca.NotAfter = cert.NotAfter
	}
}

// guessKeyType 根据证书公钥推断密钥算法标识。
func guessKeyType(cert *x509.Certificate) string {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("rsa%d", pub.N.BitLen())
	case *ecdsa.PublicKey:
		switch pub.Curve.Params().BitSize {
		case 256:
			return "ec256"
		case 384:
			return "ec384"
		case 521:
			return "ec521"
		}
	case ed25519.PublicKey:
		return "ed25519"
	default:
		if isSM2PublicKey(cert.PublicKey) {
			return "sm2"
		}
	}
	return ""
}

// boolToInt 布尔转 0/1。
func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

const caColumns = `uuid, name, cert_pem, private_enc, parent_uuid, status, is_public,
	not_before, not_after, issued_count, key_type, sig_alg, subject_dn,
	key_source, key_backend, storage_zone_uuid, key_ref, issuance_tmpl_uuid, created_at, updated_at`

// scanCA 从行读取 CA 记录。
func scanCA(scan func(dest ...interface{}) error) (*storage.CA, error) {
	ca := &storage.CA{}
	var isPublic int
	if err := scan(&ca.UUID, &ca.Name, &ca.CertPEM, &ca.PrivateEnc, &ca.ParentUUID, &ca.Status, &isPublic,
		&ca.NotBefore, &ca.NotAfter, &ca.IssuedCount, &ca.KeyType, &ca.SigAlg, &ca.SubjectDN,
		&ca.KeySource, &ca.KeyBackend, &ca.StorageZone, &ca.KeyRef, &ca.IssuanceTmplUUID,
		&ca.CreatedAt, &ca.UpdatedAt); err != nil {
		return nil, err
	}
	ca.IsPublic = isPublic == 1
	return ca, nil
}

// GetByUUID 按 UUID 查询 CA。
func (s *Service) GetByUUID(ctx context.Context, caUUID string) (*storage.CA, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+caColumns+` FROM cas WHERE uuid = ?`, caUUID)
	ca, err := scanCA(row.Scan)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("CA 不存在: %s", caUUID)
	}
	if err != nil {
		return nil, err
	}
	// 历史数据回填：算法/主体为空时解析证书补齐并写回。
	if ca.KeyType == "" || ca.SubjectDN == "" || ca.SigAlg == "" {
		s.fillFromCert(ca)
		s.db.ExecContext(ctx, //nolint:errcheck
			`UPDATE cas SET key_type = ?, sig_alg = ?, subject_dn = ?, updated_at = ? WHERE uuid = ?`,
			ca.KeyType, ca.SigAlg, ca.SubjectDN, time.Now(), ca.UUID)
	}
	return ca, nil
}

// List 查询所有 CA，并一次性联表取出存储区域名称（避免逐条查询）。
func (s *Service) List(ctx context.Context) ([]*storage.CA, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT c.uuid, c.name, c.cert_pem, c.private_enc, c.parent_uuid, c.status, c.is_public,
		        c.not_before, c.not_after, c.issued_count, c.key_type, c.sig_alg, c.subject_dn,
		        c.key_source, c.key_backend, c.storage_zone_uuid, c.key_ref, c.issuance_tmpl_uuid,
		        c.created_at, c.updated_at, COALESCE(z.name, '')
		 FROM cas c LEFT JOIN storage_zones z ON z.uuid = c.storage_zone_uuid
		 ORDER BY c.created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cas := []*storage.CA{}
	for rows.Next() {
		ca := &storage.CA{}
		var isPublic int
		if err := rows.Scan(&ca.UUID, &ca.Name, &ca.CertPEM, &ca.PrivateEnc, &ca.ParentUUID, &ca.Status, &isPublic,
			&ca.NotBefore, &ca.NotAfter, &ca.IssuedCount, &ca.KeyType, &ca.SigAlg, &ca.SubjectDN,
			&ca.KeySource, &ca.KeyBackend, &ca.StorageZone, &ca.KeyRef, &ca.IssuanceTmplUUID,
			&ca.CreatedAt, &ca.UpdatedAt, &ca.StorageZoneName); err != nil {
			return nil, err
		}
		ca.IsPublic = isPublic == 1
		// 列表同样做历史数据回填，保证前端展示的算法与主体不为空。
		if ca.KeyType == "" || ca.SubjectDN == "" || ca.SigAlg == "" {
			s.fillFromCert(ca)
		}
		cas = append(cas, ca)
	}
	return cas, rows.Err()
}

// SetPublic 设置 CA 是否在门户公开。
func (s *Service) SetPublic(ctx context.Context, caUUID string, isPublic bool) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE cas SET is_public = ?, updated_at = ? WHERE uuid = ?`,
		boolToInt(isPublic), time.Now(), caUUID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("CA 不存在")
	}
	return nil
}

// CAKeySigner 返回 CA 私钥的签名器（SM2 会做签名选项适配）。
//
// 历史数据（private_enc + key_backend=database）解密后直接可用；
// 私钥托管在 HSM/TPM 时由 keybackend 提供 Signer。
func (s *Service) CAKeySigner(ctx context.Context, ca *storage.CA) (crypto.Signer, error) {
	if ca == nil {
		return nil, fmt.Errorf("CA 为空")
	}
	if ca.KeyBackend != "" && ca.KeyBackend != "database" && ca.KeyRef != "" {
		if s.signerLoader != nil {
			return s.signerLoader(ctx, ca)
		}
		return nil, fmt.Errorf("CA 私钥托管在 %s，但未配置密钥后端加载器", ca.KeyBackend)
	}
	if len(ca.PrivateEnc) == 0 {
		return nil, fmt.Errorf("CA 无私钥（仅证书导入），不能用于签发")
	}
	return decryptPrivateKey(s.masterKey, ca.PrivateEnc)
}

// Update 更新 CA 信息（名称、状态；isPublic 非 nil 时同时更新门户公开标记）。
func (s *Service) Update(ctx context.Context, caUUID, name, status string, isPublic *bool) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("CA 名称不能为空")
	}
	switch status {
	case "active", "disabled", "revoked":
	default:
		return fmt.Errorf("不支持的 CA 状态: %s", status)
	}
	var (
		res sql.Result
		err error
	)
	if isPublic != nil {
		res, err = s.db.ExecContext(ctx,
			`UPDATE cas SET name = ?, status = ?, is_public = ?, updated_at = ? WHERE uuid = ?`,
			name, status, boolToInt(*isPublic), time.Now(), caUUID)
	} else {
		res, err = s.db.ExecContext(ctx,
			`UPDATE cas SET name = ?, status = ?, updated_at = ? WHERE uuid = ?`,
			name, status, time.Now(), caUUID)
	}
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("CA 不存在")
	}
	return nil
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

	// 解密 CA 私钥（或从密钥后端加载签名器）
	caKey, err := s.CAKeySigner(ctx, ca)
	if err != nil {
		return nil, fmt.Errorf("加载 CA 私钥失败: %w", err)
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

	// CRL 签名：SM2 走国密库，其余走标准库（通过分派层）。
	crlDER, err := createRevocationListAny(rand.Reader, crlTemplate, caCert, caKey)
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
//
// 材料来源二选一：
//   - Bundle：已由 ParseImportBundle 解析好的材料（API 层使用，支持 PEM / DER / PKCS#7 / PKCS#12）；
//   - CertPEM + PrivateKeyPEM：兼容旧调用（仅 PEM）。
type ImportCAParams struct {
	Name          string        // CA 显示名称
	Bundle        *ImportBundle // 解析后的导入材料（优先）
	CertPEM       string        // CA 证书 PEM（可包含多张：第一张为本 CA，后续为链）
	PrivateKeyPEM string        // CA 私钥 PEM（支持 PKCS1/PKCS8/EC/SM2）
	ParentUUID    string        // 父 CA UUID（可选；若导入中间 CA 可关联）
	// CertOnly 为 true 时只导入证书，作为外部 CA 仅用于证书链，不具备签发能力。
	CertOnly bool
	// StorageZoneUUID 是私钥落地的存储区域；为空使用本地加密存储。
	StorageZoneUUID string
	// KeySource 记录私钥来源（imported / external），为空时按是否带私钥推断。
	KeySource string
}

// ImportCA 导入外部 CA 证书（可选私钥）。
//
// 校验：
//  1. 证书必须是 CA（BasicConstraints.IsCA=true）；
//  2. 带私钥时校验公私钥匹配、SM2 不与其它算法混用；
//  3. 私钥按所选存储区域落地：本地区域用主密钥加密入库，硬件区域导入设备（不支持时明确报错）；
//  4. 不带私钥时标记为仅证书（external），不能用于签发。
func (s *Service) ImportCA(ctx context.Context, p *ImportCAParams) (*storage.CA, error) {
	if strings.TrimSpace(p.Name) == "" {
		return nil, fmt.Errorf("CA 名称不能为空")
	}

	bundle := p.Bundle
	if bundle == nil {
		if strings.TrimSpace(p.CertPEM) == "" {
			return nil, fmt.Errorf("证书不能为空")
		}
		var err error
		bundle, err = ParseImportBundle([]byte(p.CertPEM), []byte(p.PrivateKeyPEM), nil, "")
		if err != nil {
			return nil, err
		}
	}
	if err := verifyBundle(bundle); err != nil {
		return nil, err
	}
	cert := bundle.Cert

	// 同一张证书重复导入没有意义，且会让签发时的 CA 选择产生歧义
	var dup int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM cas WHERE subject_dn = ? AND not_before = ? AND not_after = ?`,
		cert.Subject.String(), cert.NotBefore, cert.NotAfter).Scan(&dup); err == nil && dup > 0 {
		var samePEM int
		_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM cas WHERE cert_pem = ?`, bundle.CertPEM).Scan(&samePEM)
		if samePEM > 0 {
			return nil, fmt.Errorf("该 CA 证书已经导入过")
		}
	}

	ca := &storage.CA{
		Name:       p.Name,
		CertPEM:    bundle.CertPEM,
		ParentUUID: p.ParentUUID,
		Status:     "active",
		NotBefore:  cert.NotBefore,
		NotAfter:   cert.NotAfter,
		SubjectDN:  cert.Subject.String(),
		KeyType:    guessKeyType(cert),
		SigAlg:     signatureAlgorithmName(cert),
		KeySource:  p.KeySource,
		KeyBackend: "database",
	}

	// 仅证书导入：不涉及私钥，直接登记。
	if p.CertOnly || bundle.Key == nil {
		ca.KeySource = "external"
		if err := s.Create(ctx, ca); err != nil {
			return nil, fmt.Errorf("保存导入的 CA 失败: %w", err)
		}
		return ca, nil
	}

	// PKCS#8 编码（支持 SM2）
	privDER, err := marshalPrivateKeyAnyImpl(bundle.Key)
	if err != nil {
		return nil, fmt.Errorf("序列化私钥失败: %w", err)
	}

	// 按存储区域落地私钥
	landed := false
	if p.StorageZoneUUID != "" {
		ca.StorageZone = p.StorageZoneUUID
		if s.zoneKeyImp == nil {
			return nil, fmt.Errorf("当前部署未启用存储区域导入")
		}
		ref, backend, err := s.zoneKeyImp(ctx, p.StorageZoneUUID, ca.KeyType, privDER)
		switch {
		case err == nil:
			ca.KeyRef, ca.KeyBackend = ref, backend
			landed = true
		case errors.Is(err, ErrUseLocalKeyGen):
			// 本地加密存储：走下面的主密钥加密入库
		default:
			return nil, fmt.Errorf("导入私钥到存储区域失败: %w", err)
		}
	}
	if !landed {
		privEnc, err := encryptPrivateKey(s.masterKey, privDER)
		if err != nil {
			return nil, fmt.Errorf("加密私钥失败: %w", err)
		}
		ca.PrivateEnc = privEnc
	}
	if ca.KeySource == "" {
		ca.KeySource = "imported"
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
	cert, err := parseCertPEM(caObj.CertPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("解析 CA 证书失败: %w", err)
	}
	signer, err := s.CAKeySigner(ctx, caObj)
	if err != nil {
		return nil, nil, fmt.Errorf("加载 CA 私钥失败: %w", err)
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
