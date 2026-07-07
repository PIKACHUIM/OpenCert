package pki

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"
	"unicode/utf16"

	cryptoutil "github.com/globaltrusts/client-card/internal/crypto"
	"github.com/globaltrusts/client-card/internal/storage"
)

// ---- 自签名证书（基于 CSR）----

// CertExtensions 证书扩展选项（签发时可覆盖 CSR 中的设置）。
type CertExtensions struct {
	KeyUsage         []string `json:"key_usage,omitempty"`          // digitalSignature, keyEncipherment, ...
	ExtKeyUsage      []string `json:"ext_key_usage,omitempty"`      // serverAuth, clientAuth, ...
	IsCA             *bool    `json:"is_ca,omitempty"`              // 基本约束：是否 CA
	PathLenConstraint *int    `json:"path_len_constraint,omitempty"` // 基本约束：CA 链最大深度
	CRLURLs          []string `json:"crl_urls,omitempty"`           // CRL 分发点
	OCSPURLs         []string `json:"ocsp_urls,omitempty"`          // OCSP 响应者地址
	AIAURLs          []string `json:"aia_urls,omitempty"`           // AIA（颁发者信息访问）地址
	CSPName          string   `json:"csp_name,omitempty"`           // CSP（Cryptographic Service Provider）名称
}

// SelfSignFromCSRRequest 是通过已有 CSR 生成自签名证书的请求。
type SelfSignFromCSRRequest struct {
	CSRUUID      string          `json:"csr_uuid"`
	ValidityDays int             `json:"validity_days"`
	Remark       string          `json:"remark"`
	CardPassword string          `json:"card_password"`  // smartcard 模式下需要卡片密码解密私钥
	Extensions   *CertExtensions `json:"extensions,omitempty"` // 证书扩展选项
}

// SelfSignFromCSR 使用已有 CSR 的主体信息和密钥对生成自签名证书，并持久化。
// 支持 database 和 smartcard 两种密钥存储模式。
func SelfSignFromCSR(ctx context.Context,
	csrRepo *storage.CSRRepo,
	pkiCertRepo *storage.PKICertRepo,
	cardRepo *storage.CardRepo,
	scCertRepo *storage.CertRepo,
	req *SelfSignFromCSRRequest,
) (*storage.PKICert, error) {
	// 加载 CSR
	csrRecord, err := csrRepo.GetByUUID(ctx, req.CSRUUID)
	if err != nil {
		return nil, fmt.Errorf("加载 CSR 失败: %w", err)
	}
	if csrRecord == nil {
		return nil, fmt.Errorf("CSR 不存在: %s", req.CSRUUID)
	}
	if !csrRecord.HasPrivateKey || len(csrRecord.PrivateKeyEnc) == 0 {
		return nil, fmt.Errorf("该 CSR 没有存储私钥，请先生成一个包含私钥的 CSR")
	}

	// 解析 CSR
	csrBlock, _ := pem.Decode([]byte(csrRecord.CSRPEM))
	if csrBlock == nil {
		return nil, fmt.Errorf("解析 CSR PEM 失败")
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析 CSR 失败: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR 签名验证失败: %w", err)
	}

	// 根据密钥存储模式解析私钥
	var privKey crypto.PrivateKey
	switch csrRecord.KeyStorage {
	case storage.KeyStorageSmartcard:
		// 智能卡模式：PrivateKeyEnc 存储的是智能卡证书记录的 UUID
		if req.CardPassword == "" {
			return nil, fmt.Errorf("智能卡模式需要提供卡片密码")
		}
		if cardRepo == nil || scCertRepo == nil {
			return nil, fmt.Errorf("智能卡模式需要 cardRepo 和 certRepo")
		}
		privKey, err = decryptSmartcardPrivKey(ctx, cardRepo, scCertRepo, csrRecord, req.CardPassword)
		if err != nil {
			return nil, err
		}
	default:
		// database / imported 模式：PrivateKeyEnc 存储的是 PEM 格式私钥
		privKey, err = ParsePrivateKeyFromPEM(csrRecord.PrivateKeyEnc)
		if err != nil {
			return nil, fmt.Errorf("解析私钥失败: %w", err)
		}
	}

	if req.ValidityDays <= 0 {
		req.ValidityDays = 365
	}
	if req.ValidityDays > 3650 {
		req.ValidityDays = 3650
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("生成序列号失败: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.AddDate(0, 0, req.ValidityDays)

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               csr.Subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
		EmailAddresses:        csr.EmailAddresses,
	}

	// 应用证书扩展选项
	applyCertExtensions(template, req.Extensions)

	// 自签名：issuer = subject，用自身私钥签名
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, csr.PublicKey, privKey.(crypto.Signer))
	if err != nil {
		return nil, fmt.Errorf("生成自签名证书失败: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	pkiCert := &storage.PKICert{
		CommonName:    csr.Subject.CommonName,
		SerialNumber:  serialNumber.String(),
		CSRUUID:       csrRecord.UUID,
		KeyType:       csrRecord.KeyType,
		KeyStorage:    csrRecord.KeyStorage,
		CardUUID:      csrRecord.CardUUID,
		CertPEM:       string(certPEM),
		HasPrivateKey: true,
		PrivateKeyEnc: csrRecord.PrivateKeyEnc,
		NotBefore:     notBefore,
		NotAfter:      notAfter,
		KeyUsage:      csrRecord.KeyUsage,
		ExtKeyUsage:   csrRecord.ExtKeyUsage,
		SANDN:         csrRecord.SANDN,
		SANIP:         csrRecord.SANIP,
		SANEmail:      csrRecord.SANEmail,
		Remark:        req.Remark,
	}

	if err := pkiCertRepo.Create(ctx, pkiCert); err != nil {
		return nil, err
	}

	// 如果是智能卡模式，将签发的证书 PEM 写入智能卡证书记录的 CertContent
	if csrRecord.KeyStorage == storage.KeyStorageSmartcard && scCertRepo != nil {
		scCertUUID := string(csrRecord.PrivateKeyEnc)
		scCert, err := scCertRepo.GetByUUID(ctx, scCertUUID)
		if err == nil && scCert != nil {
			scCert.CertContent = certPEM
			_ = scCertRepo.Update(ctx, scCert)
		}
	}

	return pkiCert, nil
}

// decryptSmartcardPrivKey 从智能卡解密私钥。
// CSR 的 PrivateKeyEnc 存储的是智能卡证书记录的 UUID。
func decryptSmartcardPrivKey(ctx context.Context, cardRepo *storage.CardRepo, certRepo *storage.CertRepo, csrRecord *storage.CSRRecord, cardPassword string) (crypto.PrivateKey, error) {
	// 获取卡片
	card, err := cardRepo.GetByUUID(ctx, csrRecord.CardUUID)
	if err != nil || card == nil {
		return nil, fmt.Errorf("卡片不存在: %s", csrRecord.CardUUID)
	}

	// 用卡片密码解锁主密钥
	masterKey, err := unlockMasterKeyByPassword(card, cardPassword)
	if err != nil {
		return nil, fmt.Errorf("卡片密码错误: %w", err)
	}
	defer cryptoutil.ZeroBytes(masterKey)

	// PrivateKeyEnc 存储的是智能卡证书记录的 UUID
	scCertUUID := string(csrRecord.PrivateKeyEnc)
	scCert, err := certRepo.GetByUUID(ctx, scCertUUID)
	if err != nil || scCert == nil {
		return nil, fmt.Errorf("智能卡证书记录不存在: %s", scCertUUID)
	}

	// 解密私钥
	if len(scCert.TempKeySalt) == 0 || len(scCert.TempKeyEnc) == 0 || len(scCert.PrivateData) == 0 {
		return nil, fmt.Errorf("智能卡证书记录缺少加密私钥数据")
	}

	tempKeyAESKey := cryptoutil.HMACSHA256(masterKey, scCert.TempKeySalt)
	tempKey, err := cryptoutil.DecryptAES256GCM(tempKeyAESKey, scCert.TempKeyEnc)
	if err != nil {
		return nil, fmt.Errorf("解密临时密钥失败: %w", err)
	}
	defer cryptoutil.ZeroBytes(tempKey)

	privDER, err := cryptoutil.DecryptAES256GCM(tempKey, scCert.PrivateData)
	if err != nil {
		return nil, fmt.Errorf("解密私钥失败: %w", err)
	}

	// 解析 DER 格式私钥
	key, parseErr := x509.ParsePKCS8PrivateKey(privDER)
	if parseErr == nil {
		return key, nil
	}
	rsaKey, parseErr := x509.ParsePKCS1PrivateKey(privDER)
	if parseErr == nil {
		return rsaKey, nil
	}
	ecKey, parseErr := x509.ParseECPrivateKey(privDER)
	if parseErr == nil {
		return ecKey, nil
	}
	return nil, fmt.Errorf("无法解析智能卡私钥格式")
}

// ---- CSR 服务（持久化版本）----

// CreateCSRRequest 是创建并持久化 CSR 的请求。
type CreateCSRRequest struct {
	CommonName   string            `json:"common_name"`
	Organization string            `json:"organization"`
	OrgUnit      string            `json:"org_unit"`
	Country      string            `json:"country"`
	State        string            `json:"state"`
	Locality     string            `json:"locality"`
	Email        string            `json:"email"`
	KeyType      string            `json:"key_type"`
	DigestType   string            `json:"digest_type"`  // sha256/sha384/sha512；空值则按密钥类型取默认值
	KeyStorage   storage.KeyStorage `json:"key_storage"` // database / smartcard
	CardUUID     string            `json:"card_uuid"`
	CardPassword string            `json:"card_password"` // smartcard 模式下需要卡片密码
	SANDN        string            `json:"san_dns"`
	SANIP        string            `json:"san_ip"`
	SANEmail     string            `json:"san_email"`
	SANURI       string            `json:"san_uri"`
	KeyUsage     []string          `json:"key_usage"`
	ExtKeyUsage  []string          `json:"ext_key_usage"`
	ExtraSubject map[string]string `json:"extra_subject"` // 额外 DN 字段（serialNumber/givenName 等）
	Remark       string            `json:"remark"`
}

// CreateAndSaveCSR 生成 CSR 并持久化到数据库。
// 若 KeyStorage=database，同时保存加密私钥；
// 若 KeyStorage=smartcard，私钥加密后存储到智能卡 certificates 表。
func CreateAndSaveCSR(ctx context.Context, repo *storage.CSRRepo, certRepo *storage.CertRepo, cardRepo *storage.CardRepo, req *CreateCSRRequest) (*storage.CSRRecord, error) {
	if req.KeyType == "" {
		req.KeyType = "ec256"
	}
	if req.KeyStorage == "" {
		req.KeyStorage = storage.KeyStorageDatabase
	}

	// 构建 CSR 请求
	csrReq := &CSRRequest{
		CommonName:   req.CommonName,
		Organization: req.Organization,
		OrgUnit:      req.OrgUnit,
		Country:      req.Country,
		Province:     req.State,
		Locality:     req.Locality,
		KeyType:      req.KeyType,
		DigestType:   req.DigestType,
		ExtraSubject: req.ExtraSubject,
	}

	// 解析 SAN
	if req.SANDN != "" {
		csrReq.DNSNames = splitTrim(req.SANDN)
	}
	if req.SANIP != "" {
		csrReq.IPAddresses = splitTrim(req.SANIP)
	}
	if req.SANEmail != "" {
		csrReq.Emails = splitTrim(req.SANEmail)
	}

	result, err := GenerateCSR(csrReq)
	if err != nil {
		return nil, fmt.Errorf("生成 CSR 失败: %w", err)
	}

	record := &storage.CSRRecord{
		CommonName:   req.CommonName,
		Organization: req.Organization,
		OrgUnit:      req.OrgUnit,
		Country:      req.Country,
		State:        req.State,
		Locality:     req.Locality,
		Email:        req.Email,
		KeyType:      req.KeyType,
		DigestType:   req.DigestType,
		KeyStorage:   req.KeyStorage,
		CardUUID:     req.CardUUID,
		SANDN:        req.SANDN,
		SANIP:        req.SANIP,
		SANEmail:     req.SANEmail,
		SANURI:       req.SANURI,
		KeyUsage:     joinStrings(req.KeyUsage),
		ExtKeyUsage:  joinStrings(req.ExtKeyUsage),
		ExtraSubject: marshalExtraSubject(req.ExtraSubject),
		CSRPEM:       string(result.CSRPEM),
		Remark:       req.Remark,
	}

	switch req.KeyStorage {
	case storage.KeyStorageDatabase:
		// 存储明文私钥（生产环境应加密，此处为 MVP）
		record.HasPrivateKey = true
		record.PrivateKeyEnc = result.KeyPEM

	case storage.KeyStorageSmartcard:
		// 智能卡模式：将密钥加密后存储到 certificates 表
		if req.CardUUID == "" {
			return nil, fmt.Errorf("smartcard 模式需要指定 card_uuid")
		}
		if req.CardPassword == "" {
			return nil, fmt.Errorf("smartcard 模式需要提供卡片密码")
		}
		if certRepo == nil || cardRepo == nil {
			return nil, fmt.Errorf("smartcard 模式需要 certRepo 和 cardRepo")
		}

		// 获取卡片并解锁主密钥
		card, err := cardRepo.GetByUUID(ctx, req.CardUUID)
		if err != nil || card == nil {
			return nil, fmt.Errorf("卡片不存在: %s", req.CardUUID)
		}

		// 用卡片密码解锁主密钥
		masterKey, err := unlockMasterKeyByPassword(card, req.CardPassword)
		if err != nil {
			return nil, fmt.Errorf("卡片密码错误: %w", err)
		}
		defer cryptoutil.ZeroBytes(masterKey)

		// 解析私钥 DER
		privDER, err := parsePrivateKeyDER(result.KeyPEM)
		if err != nil {
			return nil, fmt.Errorf("解析私钥失败: %w", err)
		}

		// 加密私钥并存储到 certificates 表（创建空证书记录，只存储密钥）
		certRecord, err := encryptAndStoreKeyOnly(ctx, certRepo, card, masterKey, privDER, req)
		if err != nil {
			return nil, fmt.Errorf("存储密钥到智能卡失败: %w", err)
		}

		record.HasPrivateKey = true
		record.CardUUID = req.CardUUID
		// 在 CSR 记录中关联智能卡证书 UUID（不存储明文密钥）
		record.PrivateKeyEnc = []byte(certRecord.UUID)
	}

	if err := repo.Create(ctx, record); err != nil {
		return nil, err
	}
	return record, nil
}

// unlockMasterKeyByPassword 用密码解锁卡片主密钥。
func unlockMasterKeyByPassword(card *storage.Card, password string) ([]byte, error) {
	pinBytes := []byte(password)
	for _, entry := range card.CardKeys {
		if entry.Locked {
			continue
		}
		aesKey := cryptoutil.HMACSHA256(pinBytes, entry.Salt)
		masterKey, err := cryptoutil.DecryptAES256GCM(aesKey, entry.EncMasterKey)
		if err == nil {
			return masterKey, nil
		}
	}
	return nil, fmt.Errorf("密码错误，无法解锁卡片")
}

// parsePrivateKeyDER 从 PEM 私钥中提取 DER 字节。
func parsePrivateKeyDER(keyPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("无法解码私钥 PEM")
	}
	return block.Bytes, nil
}

// encryptAndStoreKeyOnly 加密私钥并存储到 certificates 表（创建空证书记录）。
func encryptAndStoreKeyOnly(ctx context.Context, certRepo *storage.CertRepo, card *storage.Card, masterKey, privDER []byte, req *CreateCSRRequest) (*storage.Certificate, error) {
	// 1. 生成临时密钥
	tempKey, err := cryptoutil.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("生成临时密钥失败: %w", err)
	}
	defer cryptoutil.ZeroBytes(tempKey)

	// 2. 生成盐值
	tempKeySalt, err := cryptoutil.GenerateSalt()
	if err != nil {
		return nil, fmt.Errorf("生成盐值失败: %w", err)
	}

	// 3. 用 HMAC(masterKey, salt) 加密临时密钥
	tempKeyAESKey := cryptoutil.HMACSHA256(masterKey, tempKeySalt)
	tempKeyEnc, err := cryptoutil.EncryptAES256GCM(tempKeyAESKey, tempKey)
	if err != nil {
		return nil, fmt.Errorf("加密临时密钥失败: %w", err)
	}

	// 4. 用临时密钥加密私钥
	privateData, err := cryptoutil.EncryptAES256GCM(tempKey, privDER)
	if err != nil {
		return nil, fmt.Errorf("加密私钥失败: %w", err)
	}

	// 5. 创建空证书记录（只存储密钥，CertContent 为空）
	cert := &storage.Certificate{
		SlotType:    storage.SlotTypeLocal,
		CardUUID:    card.UUID,
		CertType:    storage.CertTypeX509,
		KeyType:     req.KeyType,
		CertContent: nil, // 空证书，等待后续签发后填充
		TempKeySalt: tempKeySalt,
		TempKeyEnc:  tempKeyEnc,
		PrivateData: privateData,
	}

	if err := certRepo.Create(ctx, cert); err != nil {
		return nil, fmt.Errorf("保存密钥记录失败: %w", err)
	}
	return cert, nil
}

// ---- CA 服务 ----

// CreateCARequest 是创建本地 CA 的请求。
type CreateCARequest struct {
	Name         string `json:"name"`
	CommonName   string `json:"common_name"`
	Organization string `json:"organization"`
	Country      string `json:"country"`
	KeyType      string `json:"key_type"`
	ValidityYears int   `json:"validity_years"`
	CardUUID     string `json:"card_uuid"`
}

// CreateAndSaveCA 生成自签名 CA 并持久化。
func CreateAndSaveCA(ctx context.Context, repo *storage.CARepo, req *CreateCARequest) (*storage.LocalCA, error) {
	if req.KeyType == "" {
		req.KeyType = "ec256"
	}
	if req.ValidityYears <= 0 {
		req.ValidityYears = 10
	}

	result, err := GenerateSelfSigned(&SelfSignRequest{
		CommonName:        req.CommonName,
		Organization:      req.Organization,
		Country:           req.Country,
		KeyType:           req.KeyType,
		ValidDays:         req.ValidityYears * 365,
		IsCA:              true,
		PathLenConstraint: 1,
	})
	if err != nil {
		return nil, fmt.Errorf("生成 CA 证书失败: %w", err)
	}

	// 解析证书获取有效期
	cert, err := ParseCertificateFromPEM(result.CertPEM)
	if err != nil {
		return nil, fmt.Errorf("解析 CA 证书失败: %w", err)
	}

	ca := &storage.LocalCA{
		Name:         req.Name,
		CommonName:   req.CommonName,
		Organization: req.Organization,
		Country:      req.Country,
		KeyType:      req.KeyType,
		CertPEM:      string(result.CertPEM),
		HasPrivKey:   true,
		PrivKeyEnc:   result.KeyPEM, // MVP：明文存储，生产应加密
		CardUUID:     req.CardUUID,
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
	}

	if err := repo.Create(ctx, ca); err != nil {
		return nil, err
	}
	return ca, nil
}

// ImportCARequest 是导入外部 CA 的请求。
type ImportCARequest struct {
	Name     string `json:"name"`
	CertPEM  string `json:"cert_pem"`
	KeyPEM   string `json:"key_pem"`   // 可选
	ChainPEM string `json:"chain_pem"` // 可选
	CardUUID string `json:"card_uuid"` // 可选
}

// ImportAndSaveCA 导入外部 CA 证书并持久化。
func ImportAndSaveCA(ctx context.Context, repo *storage.CARepo, req *ImportCARequest) (*storage.LocalCA, error) {
	if req.CertPEM == "" {
		return nil, fmt.Errorf("CA 证书 PEM 不能为空")
	}

	cert, err := ParseCertificateFromPEM([]byte(req.CertPEM))
	if err != nil {
		return nil, fmt.Errorf("解析 CA 证书失败: %w", err)
	}

	// CA 名称默认使用证书的 CN
	name := req.Name
	if name == "" {
		name = cert.Subject.CommonName
	}

	ca := &storage.LocalCA{
		Name:       name,
		CommonName: cert.Subject.CommonName,
		CertPEM:    req.CertPEM,
		ChainPEM:   req.ChainPEM,
		CardUUID:   req.CardUUID,
		NotBefore:  cert.NotBefore,
		NotAfter:   cert.NotAfter,
	}

	if len(cert.Subject.Organization) > 0 {
		ca.Organization = cert.Subject.Organization[0]
	}
	if len(cert.Subject.Country) > 0 {
		ca.Country = cert.Subject.Country[0]
	}

	// 推断密钥类型
	ca.KeyType = inferKeyType(cert)

	if req.KeyPEM != "" {
		ca.HasPrivKey = true
		ca.PrivKeyEnc = []byte(req.KeyPEM) // MVP：明文存储
	}

	if err := repo.Create(ctx, ca); err != nil {
		return nil, err
	}
	return ca, nil
}

// ---- 证书签发服务 ----

// IssueCertFromCSRRequest 是通过 CSR 签发证书的请求。
type IssueCertFromCSRRequest struct {
	CSRUUID      string          `json:"csr_uuid"`
	CAUUID       string          `json:"ca_uuid"`
	ValidityDays int             `json:"validity_days"`
	Remark       string          `json:"remark"`
	NotBefore    string          `json:"not_before,omitempty"`  // ISO8601
	NotAfter     string          `json:"not_after,omitempty"`   // ISO8601
	Extensions   *CertExtensions `json:"extensions,omitempty"`  // 证书扩展选项
}

// IssueCertFromCSR 通过已有 CSR 和 CA 签发证书并持久化。
func IssueCertFromCSR(ctx context.Context,
	csrRepo *storage.CSRRepo,
	caRepo *storage.CARepo,
	certRepo *storage.PKICertRepo,
	scCertRepo *storage.CertRepo,
	req *IssueCertFromCSRRequest,
) (*storage.PKICert, error) {
	// 加载 CSR
	csrRecord, err := csrRepo.GetByUUID(ctx, req.CSRUUID)
	if err != nil {
		return nil, fmt.Errorf("加载 CSR 失败: %w", err)
	}
	if csrRecord == nil {
		return nil, fmt.Errorf("CSR 不存在: %s", req.CSRUUID)
	}

	// 加载 CA
	caRecord, err := caRepo.GetByUUID(ctx, req.CAUUID)
	if err != nil {
		return nil, fmt.Errorf("加载 CA 失败: %w", err)
	}
	if caRecord == nil {
		return nil, fmt.Errorf("CA 不存在: %s", req.CAUUID)
	}
	if caRecord.Revoked {
		return nil, fmt.Errorf("CA 已被吊销，无法签发证书")
	}
	if !caRecord.HasPrivKey {
		return nil, fmt.Errorf("CA 没有私钥，无法签发证书")
	}

	// 解析 CA 证书和私钥
	caCert, err := ParseCertificateFromPEM([]byte(caRecord.CertPEM))
	if err != nil {
		return nil, fmt.Errorf("解析 CA 证书失败: %w", err)
	}
	caKey, err := ParsePrivateKeyFromPEM(caRecord.PrivKeyEnc)
	if err != nil {
		return nil, fmt.Errorf("解析 CA 私钥失败: %w", err)
	}

	// 解析 CSR
	csrBlock, _ := pem.Decode([]byte(csrRecord.CSRPEM))
	if csrBlock == nil {
		return nil, fmt.Errorf("解析 CSR PEM 失败")
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析 CSR 失败: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR 签名验证失败: %w", err)
	}

	if req.ValidityDays <= 0 {
		req.ValidityDays = 365
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("生成序列号失败: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.AddDate(0, 0, req.ValidityDays)
	// 如果前端传了明确的起止时间，优先使用
	if req.NotBefore != "" {
		if t, e := time.Parse(time.RFC3339, req.NotBefore); e == nil {
			notBefore = t
		}
	}
	if req.NotAfter != "" {
		if t, e := time.Parse(time.RFC3339, req.NotAfter); e == nil {
			notAfter = t
		}
	}
	if notAfter.After(caCert.NotAfter) {
		notAfter = caCert.NotAfter
	}

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               csr.Subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
		EmailAddresses:        csr.EmailAddresses,
	}

	// 应用证书扩展选项
	applyCertExtensions(template, req.Extensions)

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, csr.PublicKey, caKey.(crypto.Signer))
	if err != nil {
		return nil, fmt.Errorf("签发证书失败: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// 构建证书记录
	pkiCert := &storage.PKICert{
		CommonName:   csr.Subject.CommonName,
		SerialNumber: serialNumber.String(),
		CAUUID:       caRecord.UUID,
		CAName:       caRecord.Name,
		CSRUUID:      csrRecord.UUID,
		KeyType:      csrRecord.KeyType,
		KeyStorage:   csrRecord.KeyStorage,
		CardUUID:     csrRecord.CardUUID,
		CertPEM:      string(certPEM),
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     csrRecord.KeyUsage,
		ExtKeyUsage:  csrRecord.ExtKeyUsage,
		SANDN:        csrRecord.SANDN,
		SANIP:        csrRecord.SANIP,
		SANEmail:     csrRecord.SANEmail,
		Remark:       req.Remark,
	}

	// 若 CSR 有私钥，关联到证书
	if csrRecord.HasPrivateKey {
		pkiCert.HasPrivateKey = true
		pkiCert.PrivateKeyEnc = csrRecord.PrivateKeyEnc
	}

	if err := certRepo.Create(ctx, pkiCert); err != nil {
		return nil, err
	}

	// 如果是智能卡模式，将签发的证书 PEM 写入智能卡证书记录的 CertContent
	if csrRecord.KeyStorage == storage.KeyStorageSmartcard && scCertRepo != nil {
		scCertUUID := string(csrRecord.PrivateKeyEnc)
		scCert, err := scCertRepo.GetByUUID(ctx, scCertUUID)
		if err == nil && scCert != nil {
			scCert.CertContent = certPEM
			_ = scCertRepo.Update(ctx, scCert)
		}
	}

	// 更新 CA 签发计数
	_ = caRepo.IncrIssuedCount(ctx, caRecord.UUID)

	return pkiCert, nil
}

// ---- 证书导入服务 ----

// ImportCertMode 是证书导入模式。
type ImportCertMode string

const (
	ImportModeCertOnly  ImportCertMode = "cert_only"  // 仅证书，自动匹配私钥
	ImportModeCertKey   ImportCertMode = "cert_key"   // 证书 + 私钥
	ImportModePKCS12    ImportCertMode = "pkcs12"     // PKCS#12
	ImportModeKeyOnly   ImportCertMode = "key_only"   // 仅私钥
)

// ImportCertRequest 是导入证书的请求。
type ImportCertRequest struct {
	Mode           ImportCertMode `json:"mode"`
	CertPEM        string         `json:"cert_pem"`
	KeyPEM         string         `json:"key_pem"`
	PKCS12B64      string         `json:"pkcs12_b64"`
	PKCS12Password string         `json:"pkcs12_password"`
	CardUUID       string         `json:"card_uuid"`
	Remark         string         `json:"remark"`
}

// ImportCertResult 是导入证书的结果。
type ImportCertResult struct {
	Cert          *storage.PKICert `json:"cert"`
	KeyMatched    bool             `json:"key_matched"`    // 是否自动匹配到私钥
	KeyMatchedID  string           `json:"key_matched_id"` // 匹配到的私钥记录 UUID
	MatchedSource string           `json:"matched_source"` // "database" / "card:<uuid>" / ""
}

// ImportCert 导入证书（支持四种模式）。
func ImportCert(ctx context.Context, certRepo *storage.PKICertRepo, req *ImportCertRequest) (*ImportCertResult, error) {
	switch req.Mode {
	case ImportModeCertOnly:
		return importCertOnly(ctx, certRepo, req)
	case ImportModeCertKey:
		return importCertWithKey(ctx, certRepo, req)
	case ImportModePKCS12:
		return importFromPKCS12(ctx, certRepo, req)
	case ImportModeKeyOnly:
		return importKeyOnly(ctx, certRepo, req)
	default:
		return nil, fmt.Errorf("不支持的导入模式: %s", req.Mode)
	}
}

// importCertOnly 导入仅证书，自动匹配已有私钥。
func importCertOnly(ctx context.Context, certRepo *storage.PKICertRepo, req *ImportCertRequest) (*ImportCertResult, error) {
	if req.CertPEM == "" {
		return nil, fmt.Errorf("证书 PEM 不能为空")
	}

	cert, err := ParseCertificateFromPEM([]byte(req.CertPEM))
	if err != nil {
		return nil, fmt.Errorf("解析证书失败: %w", err)
	}

	pkiCert := buildPKICertFromX509(cert, req)

	// 尝试自动匹配孤立私钥
	result := &ImportCertResult{Cert: pkiCert}
	orphans, _ := certRepo.ListOrphanKeys(ctx)
	for _, orphan := range orphans {
		if matchKeyToCert(orphan.PrivateKeyEnc, cert) {
			pkiCert.HasPrivateKey = true
			pkiCert.PrivateKeyEnc = orphan.PrivateKeyEnc
			pkiCert.KeyStorage = orphan.KeyStorage
			result.KeyMatched = true
			result.KeyMatchedID = orphan.UUID
			result.MatchedSource = "database"
			// 删除孤立私钥记录
			_ = certRepo.Delete(ctx, orphan.UUID)
			break
		}
	}

	if err := certRepo.Create(ctx, pkiCert); err != nil {
		return nil, err
	}
	return result, nil
}

// importCertWithKey 导入证书 + 私钥。
func importCertWithKey(ctx context.Context, certRepo *storage.PKICertRepo, req *ImportCertRequest) (*ImportCertResult, error) {
	if req.CertPEM == "" || req.KeyPEM == "" {
		return nil, fmt.Errorf("证书和私钥 PEM 均不能为空")
	}

	cert, err := ParseCertificateFromPEM([]byte(req.CertPEM))
	if err != nil {
		return nil, fmt.Errorf("解析证书失败: %w", err)
	}

	pkiCert := buildPKICertFromX509(cert, req)
	pkiCert.HasPrivateKey = true
	pkiCert.PrivateKeyEnc = []byte(req.KeyPEM)

	if err := certRepo.Create(ctx, pkiCert); err != nil {
		return nil, err
	}
	return &ImportCertResult{Cert: pkiCert}, nil
}

// importFromPKCS12 从 PKCS#12 导入。
func importFromPKCS12(ctx context.Context, certRepo *storage.PKICertRepo, req *ImportCertRequest) (*ImportCertResult, error) {
	if req.PKCS12B64 == "" {
		return nil, fmt.Errorf("PKCS#12 数据不能为空")
	}

	// 去除换行后 base64 解码
	cleaned := strings.ReplaceAll(req.PKCS12B64, "\n", "")
	cleaned = strings.ReplaceAll(cleaned, "\r", "")
	cleaned = strings.ReplaceAll(cleaned, " ", "")

	import64 := cleaned
	_ = import64 // 避免未使用警告

	// 使用 encoding/base64 解码
	p12Data := make([]byte, len(cleaned))
	n, err := decodeBase64(cleaned, p12Data)
	if err != nil {
		return nil, fmt.Errorf("PKCS#12 base64 解码失败: %w", err)
	}
	p12Data = p12Data[:n]

	// 使用 pki 包的 ImportPKCS12
	certPEM, keyPEM, err := ImportPKCS12(p12Data, req.PKCS12Password)
	if err != nil {
		return nil, fmt.Errorf("解析 PKCS#12 失败: %w", err)
	}

	cert, err := ParseCertificateFromPEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("解析证书失败: %w", err)
	}

	pkiCert := buildPKICertFromX509(cert, req)
	pkiCert.CertPEM = string(certPEM)
	pkiCert.HasPrivateKey = true
	pkiCert.PrivateKeyEnc = keyPEM

	if err := certRepo.Create(ctx, pkiCert); err != nil {
		return nil, err
	}
	return &ImportCertResult{Cert: pkiCert}, nil
}

// importKeyOnly 仅导入私钥（等待未来关联证书）。
func importKeyOnly(ctx context.Context, certRepo *storage.PKICertRepo, req *ImportCertRequest) (*ImportCertResult, error) {
	if req.KeyPEM == "" {
		return nil, fmt.Errorf("私钥 PEM 不能为空")
	}

	pkiCert := &storage.PKICert{
		CommonName:    "(待关联)",
		KeyStorage:    storage.KeyStorageDatabase,
		HasPrivateKey: true,
		PrivateKeyEnc: []byte(req.KeyPEM),
		NotBefore:     time.Now(),
		NotAfter:      time.Now().AddDate(10, 0, 0),
		Remark:        req.Remark,
	}

	if err := certRepo.Create(ctx, pkiCert); err != nil {
		return nil, err
	}
	return &ImportCertResult{Cert: pkiCert}, nil
}

// ---- 证书导出服务 ----

// ExportCertFormat 是证书导出格式。
type ExportCertFormat string

const (
	ExportFormatPEM    ExportCertFormat = "pem"
	ExportFormatDER    ExportCertFormat = "der"
	ExportFormatPKCS12 ExportCertFormat = "pkcs12"
	ExportFormatKeyPEM ExportCertFormat = "key_pem"
)

// ExportCert 导出证书（支持多种格式）。
func ExportCert(cert *storage.PKICert, format ExportCertFormat, password string) ([]byte, string, error) {
	switch format {
	case ExportFormatPEM:
		return []byte(cert.CertPEM), "application/x-pem-file", nil

	case ExportFormatDER:
		der, err := ConvertPEMToDER([]byte(cert.CertPEM))
		if err != nil {
			return nil, "", fmt.Errorf("转换 DER 失败: %w", err)
		}
		return der, "application/x-x509-ca-cert", nil

	case ExportFormatPKCS12:
		if !cert.HasPrivateKey || len(cert.PrivateKeyEnc) == 0 {
			return nil, "", fmt.Errorf("证书没有私钥，无法导出 PKCS#12")
		}
		if password == "" {
			password = "changeit"
		}
		p12, err := ExportPKCS12([]byte(cert.CertPEM), cert.PrivateKeyEnc, password)
		if err != nil {
			return nil, "", fmt.Errorf("导出 PKCS#12 失败: %w", err)
		}
		return p12, "application/x-pkcs12", nil

	case ExportFormatKeyPEM:
		if !cert.HasPrivateKey || len(cert.PrivateKeyEnc) == 0 {
			return nil, "", fmt.Errorf("证书没有私钥，无法导出私钥")
		}
		return cert.PrivateKeyEnc, "application/x-pem-file", nil

	default:
		return nil, "", fmt.Errorf("不支持的导出格式: %s", format)
	}
}

// ---- 工具函数 ----

// buildPKICertFromX509 从 x509.Certificate 构建 PKICert 记录。
func buildPKICertFromX509(cert *x509.Certificate, req *ImportCertRequest) *storage.PKICert {
	c := &storage.PKICert{
		CommonName:   cert.Subject.CommonName,
		SerialNumber: cert.SerialNumber.String(),
		KeyType:      inferKeyType(cert),
		KeyStorage:   storage.KeyStorageImported,
		CardUUID:     req.CardUUID,
		CertPEM:      req.CertPEM,
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		Remark:       req.Remark,
	}

	// SAN
	c.SANDN = strings.Join(cert.DNSNames, ",")
	var ips []string
	for _, ip := range cert.IPAddresses {
		ips = append(ips, ip.String())
	}
	c.SANIP = strings.Join(ips, ",")
	c.SANEmail = strings.Join(cert.EmailAddresses, ",")

	return c
}

// matchKeyToCert 检查私钥是否与证书匹配（通过公钥比较）。
func matchKeyToCert(keyPEM []byte, cert *x509.Certificate) bool {
	if len(keyPEM) == 0 {
		return false
	}
	privKey, err := ParsePrivateKeyFromPEM(keyPEM)
	if err != nil {
		return false
	}
	signer, ok := privKey.(crypto.Signer)
	if !ok {
		return false
	}
	// 比较公钥
	pubKeyDER1, err1 := x509.MarshalPKIXPublicKey(signer.Public())
	pubKeyDER2, err2 := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err1 != nil || err2 != nil {
		return false
	}
	return string(pubKeyDER1) == string(pubKeyDER2)
}

// inferKeyType 从证书推断密钥类型字符串。
func inferKeyType(cert *x509.Certificate) string {
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		if key, ok := cert.PublicKey.(interface{ Size() int }); ok {
			bits := key.Size() * 8
			return fmt.Sprintf("rsa%d", bits)
		}
		return "rsa2048"
	case x509.ECDSA:
		return "ec256"
	case x509.Ed25519:
		return "ed25519"
	default:
		return "unknown"
	}
}

// marshalExtraSubject 将 map[string]string 序列化为 JSON 字符串，用于存储额外 DN 字段。
func marshalExtraSubject(extra map[string]string) string {
	if len(extra) == 0 {
		return "{}"
	}
	// 过滤空值
	filtered := make(map[string]string)
	for k, v := range extra {
		if strings.TrimSpace(v) != "" {
			filtered[k] = v
		}
	}
	if len(filtered) == 0 {
		return "{}"
	}
	b, err := json.Marshal(filtered)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// splitTrim 按逗号分割并去除空白。
func splitTrim(s string) []string {
	parts := strings.Split(s, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// joinStrings 将字符串切片序列化为逗号分隔字符串。
func joinStrings(ss []string) string {
	return strings.Join(ss, ",")
}

// ParseIPAddresses 解析 IP 地址字符串列表。
func ParseIPAddresses(ipStrs []string) []net.IP {
	var ips []net.IP
	for _, s := range ipStrs {
		if ip := net.ParseIP(strings.TrimSpace(s)); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips
}

// decodeBase64 解码 base64 字符串到 dst，返回写入字节数。
func decodeBase64(src string, dst []byte) (int, error) {
	n, err := base64.StdEncoding.Decode(dst, []byte(src))
	if err != nil {
		// 尝试 URL 编码
		n, err = base64.URLEncoding.Decode(dst, []byte(src))
		if err != nil {
			// 尝试 RawStd 编码
			n, err = base64.RawStdEncoding.Decode(dst, []byte(src))
		}
	}
	return n, err
}

// applyCertExtensions 将 CertExtensions 中的选项应用到 x509.Certificate 模板上。
// 如果 ext 为 nil 则不做任何修改。
func applyCertExtensions(tmpl *x509.Certificate, ext *CertExtensions) {
	if ext == nil {
		return
	}

	// 密钥用途
	if len(ext.KeyUsage) > 0 {
		tmpl.KeyUsage = parseKeyUsage(ext.KeyUsage)
	}

	// 扩展密钥用途
	if len(ext.ExtKeyUsage) > 0 {
		tmpl.ExtKeyUsage = parseExtKeyUsage(ext.ExtKeyUsage)
	}

	// 基本约束
	if ext.IsCA != nil {
		tmpl.IsCA = *ext.IsCA
		tmpl.BasicConstraintsValid = true
		if *ext.IsCA && ext.PathLenConstraint != nil {
			pl := *ext.PathLenConstraint
			if pl >= 0 {
				tmpl.MaxPathLen = pl
				tmpl.MaxPathLenZero = pl == 0
			} else {
				tmpl.MaxPathLen = -1
				tmpl.MaxPathLenZero = false
			}
		}
	}

	// CRL 分发点
	if len(ext.CRLURLs) > 0 {
		tmpl.CRLDistributionPoints = ext.CRLURLs
	}

	// OCSP 响应者
	if len(ext.OCSPURLs) > 0 {
		tmpl.OCSPServer = ext.OCSPURLs
	}

	// AIA（颁发者信息访问）
	if len(ext.AIAURLs) > 0 {
		for _, rawURL := range ext.AIAURLs {
			if u, err := url.Parse(rawURL); err == nil {
				tmpl.IssuingCertificateURL = append(tmpl.IssuingCertificateURL, u.String())
			}
		}
	}

	// CSP 信息：写入 Microsoft szOID_ENROLLMENT_CSP_PROVIDER 扩展 (1.3.6.1.4.1.311.13.2.2)
	if ext.CSPName != "" {
		cspExt, err := buildCSPProviderExtension(ext.CSPName)
		if err == nil {
			tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, cspExt)
		}
	}
}

// parseKeyUsage 将字符串列表转换为 x509.KeyUsage 位掩码。
func parseKeyUsage(usages []string) x509.KeyUsage {
	var ku x509.KeyUsage
	for _, u := range usages {
		switch u {
		case "digitalSignature":
			ku |= x509.KeyUsageDigitalSignature
		case "contentCommitment":
			ku |= x509.KeyUsageContentCommitment
		case "keyEncipherment":
			ku |= x509.KeyUsageKeyEncipherment
		case "dataEncipherment":
			ku |= x509.KeyUsageDataEncipherment
		case "keyAgreement":
			ku |= x509.KeyUsageKeyAgreement
		case "certSign":
			ku |= x509.KeyUsageCertSign
		case "crlSign":
			ku |= x509.KeyUsageCRLSign
		case "encipherOnly":
			ku |= x509.KeyUsageEncipherOnly
		case "decipherOnly":
			ku |= x509.KeyUsageDecipherOnly
		}
	}
	return ku
}

// parseExtKeyUsage 将字符串列表转换为 []x509.ExtKeyUsage。
func parseExtKeyUsage(usages []string) []x509.ExtKeyUsage {
	var eku []x509.ExtKeyUsage
	for _, u := range usages {
		switch u {
		case "serverAuth":
			eku = append(eku, x509.ExtKeyUsageServerAuth)
		case "clientAuth":
			eku = append(eku, x509.ExtKeyUsageClientAuth)
		case "codeSigning":
			eku = append(eku, x509.ExtKeyUsageCodeSigning)
		case "emailProtection":
			eku = append(eku, x509.ExtKeyUsageEmailProtection)
		case "timeStamping":
			eku = append(eku, x509.ExtKeyUsageTimeStamping)
		case "ocspSigning":
			eku = append(eku, x509.ExtKeyUsageOCSPSigning)
		}
	}
	return eku
}

// szOID_ENROLLMENT_CSP_PROVIDER (1.3.6.1.4.1.311.13.2.2)
// Microsoft CSP Provider 扩展，用于指定证书关联的 Cryptographic Service Provider。
// ASN.1 结构：
//
//	SEQUENCE {
//	    INTEGER keySpec,       -- 1=AT_KEYEXCHANGE, 2=AT_SIGNATURE
//	    BMPString cspName,     -- UTF-16LE 编码的 CSP 名称
//	    BIT STRING signature   -- 空（0 字节）
//	}
var oidCSPProvider = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 13, 2, 2}

// cspProviderInfo 是 Microsoft CSP Provider 扩展的 ASN.1 结构。
type cspProviderInfo struct {
	KeySpec   int              `asn1:""`
	CSPName   asn1.RawValue   `asn1:""`
	Signature asn1.BitString  `asn1:""`
}

// buildCSPProviderExtension 构建 Microsoft CSP Provider 扩展。
func buildCSPProviderExtension(cspName string) (pkix.Extension, error) {
	// 将 CSP 名称编码为 BMPString（UTF-16BE）
	bmpBytes := stringToBMPString(cspName)

	info := cspProviderInfo{
		KeySpec: 1, // AT_KEYEXCHANGE（默认）
		CSPName: asn1.RawValue{
			Tag:   asn1.TagBMPString,
			Class: asn1.ClassUniversal,
			Bytes: bmpBytes,
		},
		Signature: asn1.BitString{Bytes: []byte{}, BitLength: 0},
	}

	val, err := asn1.Marshal(info)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("编码 CSP 扩展失败: %w", err)
	}

	return pkix.Extension{
		Id:       oidCSPProvider,
		Critical: false,
		Value:    val,
	}, nil
}

// stringToBMPString 将 Go 字符串转换为 BMPString（UTF-16BE 编码，无 BOM）。
func stringToBMPString(s string) []byte {
	runes := []rune(s)
	u16 := utf16.Encode(runes)
	buf := make([]byte, len(u16)*2)
	for i, v := range u16 {
		// BMPString 使用大端序
		buf[i*2] = byte(v >> 8)
		buf[i*2+1] = byte(v)
	}
	return buf
}
