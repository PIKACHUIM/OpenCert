// Package ca - 证书签发逻辑。
package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/globaltrusts/server-card/internal/storage"
)

// IssueRequest 是证书签发请求。
type IssueRequest struct {
	CAUUID      string             // 签发 CA 的 UUID
	Subject     pkix.Name          // 证书主体
	KeyType     string             // 密钥类型（rsa2048/rsa4096/ec256/ec384/ec521/sm2）
	ValidDays   int                // 有效期（天，当 NotAfter 为空时生效）
	NotBefore   *time.Time         // 显式生效时间（为空时取当前时间）
	NotAfter    *time.Time         // 显式失效时间（为空时按 ValidDays 计算）
	IsCA        bool               // 是否为 CA 证书
	PathLen     int                // CA 路径长度（仅 IsCA=true 时有效）
	KeyUsage    x509.KeyUsage      // 密钥用途
	ExtKeyUsage []x509.ExtKeyUsage // 扩展密钥用途
	// UnknownExtKeyUsage 是标准库没有常量的扩展密钥用途 OID（自定义 OID、国密专用用途等），
	// 与 ExtKeyUsage 一起写入证书的 Extended Key Usage 扩展，不会被静默丢弃。
	UnknownExtKeyUsage []asn1.ObjectIdentifier
	DNSNames           []string // SAN DNS 名称
	IPAddresses        []net.IP // SAN IP 地址
	EmailAddrs         []string // SAN 邮箱
	URIs               []string // SAN URI （写入证书的 Subject Alternative Name - uniformResourceIdentifier）
	PolicyOIDs         []string // 证书策略 OID 列表（Certificate Policies 扩展，与 EVPolicyOID 合并写入）

	// 模板约束（可选，签发前验证）
	IssuanceTmplUUID string // 颁发模板 UUID（用于约束验证）

	// 证书拓展模板（可选，签发时写入扩展）
	CRLDistPoints []string // CRL 分发点
	OCSPServers   []string // OCSP 服务器
	AIAIssuers    []string // AIA 颁发者
	CTServers     []string // CT 服务器
	EVPolicyOID   string   // EV 策略 OID

	// Netscape 扩展（对应 CertExtTemplate.NetscapeConfig）。
	// JSON 形如 {"cert_type":176,"comment":"Issued by XCA","base_url":"https://ca.example.com"}。
	// 保留原始 JSON 以便在签发引擎内解析并以对应 OID 写入 ExtraExtensions。
	NetscapeConfigJSON string

	// Microsoft CSP 扩展（对应 CertExtTemplate.CSPConfig）。
	// JSON 形如 {"template_name":"User","template_oid":"1.3.6.1.4.1.311.20.2","ca_version":"V1.0"}。
	CSPConfigJSON string

	// 自定义 ASN.1 扩展（对应 CertExtTemplate.ASN1Extensions）。
	// JSON 数组，每项 {"oid":"1.2.3.4","critical":false,"value_hex":"0403..."} 或 {"oid":"1.2.3.4","value_str":"..."}。
	ASN1ExtensionsJSON string

	// SignatureAlgorithm 可选：显式指定签名摘要算法（对应 x509.SignatureAlgorithm）。
	// 支持值（大小写不敏感）：
	//   MD5_RSA / SHA1_RSA / SHA256_RSA / SHA384_RSA / SHA512_RSA
	//   SHA3_256_RSA / SHA3_384_RSA / SHA3_512_RSA
	//   SHA256_RSA_PSS / SHA384_RSA_PSS / SHA512_RSA_PSS
	//   ECDSA_SHA1 / ECDSA_SHA256 / ECDSA_SHA384 / ECDSA_SHA512
	//   ECDSA_SHA3_256 / ECDSA_SHA3_384 / ECDSA_SHA3_512
	//   Ed25519
	// 为空时由 Go 标准库根据 CA 私钥类型自动选择（通常是 SHA256WithRSA 或 ECDSAWithSHA256）。
	SignatureAlgorithm string

	// CSRPublicKey 可选：直接使用申请者 CSR 中的公钥进行签发（ACME / 自带密钥场景）。
	// 非 nil 时 IssueCert 不生成新密钥对，返回的 IssueResponse.PrivateEnc 为空。
	CSRPublicKey interface{}

	// KeyZoneUUID 可选：用户私钥在哪个存储区域生成。
	//   - 为空，或区域为本地加密存储：在内存生成后用主密钥加密，随 IssueResponse.PrivateEnc 返回；
	//   - 区域为硬件（HSM / TPM）：在设备内生成，私钥不出域，IssueResponse 返回 KeyRef / KeyBackend。
	// CSRPublicKey 非空时忽略（私钥不在平台）。
	KeyZoneUUID string

	// ParentSigner 可选：指定签发者私钥（用于创建中间 CA，父 CA 不落库的场景）。
	// 为空时按 CAUUID 从数据库读取并解密。
	ParentSigner crypto.Signer

	// ParentCert 可选：与 ParentSigner 配套的签发者证书。
	ParentCert *x509.Certificate
}

// IssueResponse 是证书签发响应。
type IssueResponse struct {
	CertPEM      string    // 签发的证书 PEM
	CertDER      []byte    // 签发的证书 DER
	PrivateEnc   []byte    // 加密的私钥（本地存储时）
	KeyBackend   string    // 私钥所在后端驱动（硬件区域时为 pkcs11 / tpm2；本地为空）
	KeyRef       string    // 硬件后端内的私钥引用
	SerialNumber string    // 证书序列号（十六进制）
	SubjectDN    string    // 主体 DN
	IssuerDN     string    // 颁发者 DN
	NotBefore    time.Time // 生效时间
	NotAfter     time.Time // 失效时间
}

// IssueCert 使用 CA 签发证书。
func (s *Service) IssueCert(ctx context.Context, req *IssueRequest) (*IssueResponse, error) {
	// 若指定了颁发模板 UUID，从 issuance_templates 取出 cert_ext_tmpl_uuid，
	// 再从 cert_ext_templates 读取扩展信息（CRL/OCSP/AIA/EV），回填到 req 中尚未填充的字段。
	// 只有当 req 中对应字段为空时才会覆盖，以允许 handler 显式指定。
	if req.IssuanceTmplUUID != "" {
		if err := s.applyCertExtTemplate(ctx, req); err != nil {
			return nil, fmt.Errorf("加载证书扩展模板失败: %w", err)
		}
		// 从 KeyUsageTemplate 回填 KU/EKU（仅当 req 未显式设置时）
		if err := s.applyKeyUsageTemplate(ctx, req); err != nil {
			return nil, fmt.Errorf("加载密钥用途模板失败: %w", err)
		}
		// 对请求参数进行模板约束验证（有效期、密钥类型、CA 白名单）
		if err := s.validateAgainstTemplate(ctx, req); err != nil {
			return nil, err
		}
	}

	// 获取 CA（证书 + 签发者私钥）。允许调用方直接传入父 Signer（创建中间 CA 时避免私钥二次落库）。
	ca, err := s.GetByUUID(ctx, req.CAUUID)
	if err != nil {
		return nil, fmt.Errorf("获取 CA 失败: %w", err)
	}
	if ca.Status != "active" {
		return nil, fmt.Errorf("CA 状态不可用: %s", ca.Status)
	}

	// 解析 CA 证书
	caCert, err := parseCertPEM(ca.CertPEM)
	if err != nil {
		return nil, fmt.Errorf("解析 CA 证书失败: %w", err)
	}

	// CA 私钥：优先使用调用方传入的 Signer，否则解密库内私钥。
	caKey := req.ParentSigner
	if caKey == nil {
		caKey, err = s.CAKeySigner(ctx, ca)
		if err != nil {
			return nil, fmt.Errorf("解密 CA 私钥失败: %w", err)
		}
	}
	if req.ParentCert != nil {
		caCert = req.ParentCert
	}

	// 生成密钥对（若请求中直接带 CSRPublicKey，则跳过生成，使用申请者公钥）
	var privKey crypto.PrivateKey
	var pubKey crypto.PublicKey
	var userKeyRef, userKeyBackend string
	if req.CSRPublicKey != nil {
		pubKey = req.CSRPublicKey
	} else if req.KeyZoneUUID != "" && s.zoneKeyGen != nil {
		// 指定了存储区域：硬件区域在设备内生成（私钥不出域）；本地区域退回内存生成路径。
		pub, ref, backend, _, genErr := s.zoneKeyGen(ctx, req.KeyZoneUUID, req.KeyType)
		switch {
		case genErr == nil:
			pubKey, userKeyRef, userKeyBackend = pub, ref, backend
		case errors.Is(genErr, ErrUseLocalKeyGen):
			pk, err := generateKey(req.KeyType)
			if err != nil {
				return nil, fmt.Errorf("生成密钥对失败: %w", err)
			}
			privKey = pk
			pubKey = publicKey(pk)
		default:
			return nil, fmt.Errorf("在存储区域内生成密钥失败: %w", genErr)
		}
	} else {
		pk, err := generateKey(req.KeyType)
		if err != nil {
			return nil, fmt.Errorf("生成密钥对失败: %w", err)
		}
		privKey = pk
		pubKey = publicKey(pk)
	}

	// 生成随机序列号（128 位）
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("生成序列号失败: %w", err)
	}

	now := time.Now()
	// 生效时间：显式指定优先，未指定时取当前时间。
	notBefore := now
	if req.NotBefore != nil {
		notBefore = *req.NotBefore
	}
	// 失效时间：显式指定优先，否则按 ValidDays 计算；两者都受 CA 有效期上限约束。
	var notAfter time.Time
	if req.NotAfter != nil {
		notAfter = *req.NotAfter
	} else {
		days := req.ValidDays
		if days <= 0 {
			days = 365
		}
		notAfter = notBefore.AddDate(0, 0, days)
	}
	if notAfter.After(ca.NotAfter) {
		notAfter = ca.NotAfter
	}
	if !notAfter.After(notBefore) {
		return nil, fmt.Errorf("失效时间必须晚于生效时间（且不超过 CA 有效期 %s）", ca.NotAfter.Format(time.RFC3339))
	}

	// 构建证书模板
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               req.Subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              req.KeyUsage,
		ExtKeyUsage:           req.ExtKeyUsage,
		UnknownExtKeyUsage:    req.UnknownExtKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  req.IsCA,
		DNSNames:              req.DNSNames,
		IPAddresses:           req.IPAddresses,
		EmailAddresses:        req.EmailAddrs,
	}

	if req.IsCA {
		template.MaxPathLen = req.PathLen
		template.MaxPathLenZero = req.PathLen == 0
	}

	// 写入证书拓展模板的扩展信息
	if len(req.CRLDistPoints) > 0 {
		template.CRLDistributionPoints = req.CRLDistPoints
	}
	if len(req.OCSPServers) > 0 {
		template.OCSPServer = req.OCSPServers
	}
	if len(req.AIAIssuers) > 0 {
		template.IssuingCertificateURL = req.AIAIssuers
	}
	// EV 策略 OID（如 2.23.140.1.1）
	if req.EVPolicyOID != "" {
		if oid, err := parseOID(req.EVPolicyOID); err == nil {
			template.PolicyIdentifiers = append(template.PolicyIdentifiers, oid)
		}
	}

	// 证书策略 OID 列表（certificate_policies 扩展）
	for _, p := range req.PolicyOIDs {
		if p == "" {
			continue
		}
		if oid, err := parseOID(p); err == nil {
			template.PolicyIdentifiers = append(template.PolicyIdentifiers, oid)
		}
	}

	// SAN URIs（x509.Certificate.URIs 接受 *url.URL）
	for _, u := range req.URIs {
		if u == "" {
			continue
		}
		if parsed, err := url.Parse(u); err == nil && parsed != nil && parsed.IsAbs() {
			template.URIs = append(template.URIs, parsed)
		}
	}

	// Netscape 扩展（RFC 2459 历史扩展，部分 OEM/浏览器仍使用）
	if req.NetscapeConfigJSON != "" {
		if nsExts, err := buildNetscapeExtensions(req.NetscapeConfigJSON); err == nil {
			template.ExtraExtensions = append(template.ExtraExtensions, nsExts...)
		}
	}

	// Microsoft CSP / 证书模板扩展（Windows 域场景）
	if req.CSPConfigJSON != "" {
		if cspExts, err := buildCSPExtensions(req.CSPConfigJSON); err == nil {
			template.ExtraExtensions = append(template.ExtraExtensions, cspExts...)
		}
	}

	// 自定义 ASN.1 扩展（任意 OID）
	if req.ASN1ExtensionsJSON != "" {
		if customExts, err := buildCustomASN1Extensions(req.ASN1ExtensionsJSON); err == nil {
			template.ExtraExtensions = append(template.ExtraExtensions, customExts...)
		}
	}

	// 显式指定签名摘要算法（可选，为空时由 Go 自动选择）
	if req.SignatureAlgorithm != "" {
		if algo, ok := parseSignatureAlgorithm(req.SignatureAlgorithm); ok {
			template.SignatureAlgorithm = algo
		}
	}

	// 签发证书（pubKey 已在前面根据 CSR/生成分支获取）
	// 使用分派层：SM2 参与方走国密库 smx509，其余走标准库。
	certDER, err := createCertificate(rand.Reader, template, caCert, pubKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("签发证书失败: %w", err)
	}

	// 解析签发后的证书获取完整元数据（兼容 SM2 证书）
	issuedCert, _, err := parseCertificateAny(certDER)
	if err != nil {
		return nil, fmt.Errorf("解析签发证书失败: %w", err)
	}

	// 编码为 PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// 加密私钥（仅在本次签发自行生成了密钥时执行；CSRPublicKey 场景下 privKey 为 nil，不返回私钥）
	var privEnc []byte
	if privKey != nil {
		privDER, err := marshalPrivateKeyAnyImpl(privKey)
		if err != nil {
			return nil, fmt.Errorf("序列化私钥失败: %w", err)
		}
		privEnc, err = encryptPrivateKey(s.masterKey, privDER)
		if err != nil {
			return nil, fmt.Errorf("加密私钥失败: %w", err)
		}
	}

	// 递增 CA 签发计数
	if err := s.IncrementIssuedCount(ctx, req.CAUUID); err != nil {
		return nil, fmt.Errorf("更新签发计数失败: %w", err)
	}

	return &IssueResponse{
		CertPEM:      string(certPEM),
		CertDER:      certDER,
		PrivateEnc:   privEnc,
		KeyBackend:   userKeyBackend,
		KeyRef:       userKeyRef,
		SerialNumber: fmt.Sprintf("%x", serialNumber),
		SubjectDN:    issuedCert.Subject.String(),
		IssuerDN:     issuedCert.Issuer.String(),
		NotBefore:    issuedCert.NotBefore,
		NotAfter:     issuedCert.NotAfter,
	}, nil
}

// CACreateParams 是创建 CA（根 CA 或中间 CA）的参数。
type CACreateParams struct {
	Name        string            // CA 显示名称
	Subject     pkix.Name         // 主体
	KeyType     string            // 密钥算法（rsa2048/ec256/.../sm2）
	NotBefore   *time.Time        // 生效时间（为空取当前时间）
	NotAfter    *time.Time        // 失效时间（为空时按 ValidDays 计算）
	ValidDays   int               // 有效期（天），NotAfter 为空时使用
	PathLen     int               // 路径长度限制
	PathLenZero bool              // 路径长度是否固定为 0（签发的中间 CA 不能再签发下级）
	KeyUsage    x509.KeyUsage     // 密钥用途（为空时默认 CertSign|CRLSign）
	ParentUUID  string            // 上级 CA UUID（为空表示自签根 CA）
	ParentCert  *x509.Certificate // 上级 CA 证书（自签时为空）
	ParentKey   crypto.Signer     // 上级 CA 私钥（自签时为空）

	IssuanceTmplUUID string // 创建时使用的颁发模板（记录来源，便于审计）
	StorageZoneUUID  string // 私钥所在存储区域（当前为本地加密库）
}

// CreateCA 创建 CA 证书（自签根 CA 或由上级 CA 签发的中间 CA）。
//
// 与普通签发共用同一套密钥生成、扩展构造与签名分派逻辑，区别仅在于
// 主体由调用方直接给出、BasicConstraints 为 CA、私钥需要落库保管。
func (s *Service) CreateCA(ctx context.Context, p *CACreateParams) (*storage.CA, error) {
	if strings.TrimSpace(p.Name) == "" {
		return nil, fmt.Errorf("CA 名称不能为空")
	}

	// 生成密钥对：指定了存储区域（且注入了区域密钥生成器）时在该区域内生成
	// （硬件区域私钥不出域，signer 直接可用）；否则在本地内存生成后加密入库。
	var (
		pubKey     crypto.PublicKey
		localPriv  crypto.PrivateKey
		keySigner  crypto.Signer
		keyRef     string
		keyBackend = "database"
	)
	if p.StorageZoneUUID != "" && s.zoneKeyGen != nil {
		pub, ref, backend, signer, err := s.zoneKeyGen(ctx, p.StorageZoneUUID, p.KeyType)
		switch {
		case err == nil:
			pubKey, keyRef, keyBackend, keySigner = pub, ref, backend, signer
		case errors.Is(err, ErrUseLocalKeyGen):
			// 调用方表示该区域（如本地加密存储）应走本地生成路径。
			priv, genErr := generateKey(p.KeyType)
			if genErr != nil {
				return nil, fmt.Errorf("生成密钥对失败: %w", genErr)
			}
			localPriv = priv
			pubKey = publicKey(priv)
			keySigner = asSigner(priv)
			keyBackend = "database"
		default:
			return nil, fmt.Errorf("在存储区域内生成密钥失败: %w", err)
		}
	} else {
		priv, err := generateKey(p.KeyType)
		if err != nil {
			return nil, fmt.Errorf("生成密钥对失败: %w", err)
		}
		localPriv = priv
		pubKey = publicKey(priv)
		keySigner = asSigner(priv)
	}
	if pubKey == nil {
		return nil, fmt.Errorf("不支持的密钥算法: %s", p.KeyType)
	}

	// 生成随机序列号
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("生成序列号失败: %w", err)
	}

	// 生效/失效时间
	notBefore := time.Now()
	if p.NotBefore != nil {
		notBefore = *p.NotBefore
	}
	notAfter := notBefore.AddDate(0, 0, 3650)
	if p.ValidDays > 0 {
		notAfter = notBefore.AddDate(0, 0, p.ValidDays)
	}
	if p.NotAfter != nil {
		notAfter = *p.NotAfter
	}

	keyUsage := p.KeyUsage
	if keyUsage == 0 {
		keyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               p.Subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            p.PathLen,
		MaxPathLenZero:        p.PathLenZero,
	}

	// 自签：父证书就是自己，签名者是自己；中间 CA：父证书与签名者来自上级 CA。
	parentCert := template
	signerKey := keySigner
	if p.ParentUUID != "" {
		parent, err := s.GetByUUID(ctx, p.ParentUUID)
		if err != nil {
			return nil, fmt.Errorf("上级 CA 不存在: %w", err)
		}
		if parent.Status != "active" {
			return nil, fmt.Errorf("上级 CA 状态不可用: %s", parent.Status)
		}
		pc := p.ParentCert
		if pc == nil {
			pc, err = parseCertPEM(parent.CertPEM)
			if err != nil {
				return nil, fmt.Errorf("解析上级 CA 证书失败: %w", err)
			}
		}
		pk := p.ParentKey
		if pk == nil {
			pk, err = s.CAKeySigner(ctx, parent)
			if err != nil {
				return nil, fmt.Errorf("解密上级 CA 私钥失败: %w", err)
			}
		}
		parentCert = pc
		signerKey = pk
		// 不能签发超过上级 CA 有效期的证书
		if notAfter.After(parent.NotAfter) {
			notAfter = parent.NotAfter
			template.NotAfter = notAfter
		}
		// SM2 与标准算法不能混用：SM2 上级 CA 只能签发 SM2 下级 CA
		if isSM2Signature(parentCert) && !isSM2PublicKey(pubKey) {
			return nil, fmt.Errorf("SM2 CA 只能签发 SM2 证书，请将密钥算法改为 SM2")
		}
		if !isSM2Signature(parentCert) && isSM2PublicKey(pubKey) {
			return nil, fmt.Errorf("SM2 证书必须由 SM2 CA 签发，请更换上级 CA")
		}
	}
	if !notAfter.After(notBefore) {
		return nil, fmt.Errorf("失效时间必须晚于生效时间")
	}

	certDER, err := createCertificate(rand.Reader, template, parentCert, pubKey, signerKey)
	if err != nil {
		return nil, fmt.Errorf("创建 CA 证书失败: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// 本地生成的密钥需要加密入库；存储区域生成的密钥只记录引用，私钥不出域。
	var privEnc []byte
	if localPriv != nil {
		privDER, err := marshalPrivateKeyAnyImpl(localPriv)
		if err != nil {
			return nil, fmt.Errorf("序列化私钥失败: %w", err)
		}
		privEnc, err = encryptPrivateKey(s.masterKey, privDER)
		if err != nil {
			return nil, fmt.Errorf("加密私钥失败: %w", err)
		}
	}

	parsed, _, err := parseCertificateAny(certDER)
	if err != nil {
		return nil, fmt.Errorf("解析新建 CA 证书失败: %w", err)
	}

	keySource := "generated"
	ca := &storage.CA{
		Name:             p.Name,
		CertPEM:          string(certPEM),
		PrivateEnc:       privEnc,
		ParentUUID:       p.ParentUUID,
		Status:           "active",
		NotBefore:        parsed.NotBefore,
		NotAfter:         parsed.NotAfter,
		KeyType:          p.KeyType,
		SigAlg:           signatureAlgorithmName(parsed),
		SubjectDN:        parsed.Subject.String(),
		KeySource:        keySource,
		KeyBackend:       keyBackend,
		StorageZone:      p.StorageZoneUUID,
		KeyRef:           keyRef,
		IssuanceTmplUUID: p.IssuanceTmplUUID,
	}

	if err := s.Create(ctx, ca); err != nil {
		return nil, fmt.Errorf("保存 CA 失败: %w", err)
	}

	return ca, nil
}

// CreateSelfSignedCA 创建自签名根 CA（兼容旧调用方的简化入口）。
//
// 等价于调用 CreateCA 且不指定上级 CA、不指定颁发模板约束；有效期按年换算为天。
// 新代码应直接使用 CreateCA 以获得颁发模板约束、生效/失效时间与存储区域支持。
func (s *Service) CreateSelfSignedCA(ctx context.Context, name string, subject pkix.Name, keyType string, validYears int) (*storage.CA, error) {
	if validYears <= 0 {
		validYears = 10
	}
	return s.CreateCA(ctx, &CACreateParams{
		Name:      name,
		Subject:   subject,
		KeyType:   keyType,
		ValidDays: validYears * 365,
	})
}

// asSigner 将私钥转换为 crypto.Signer（SM2 需要包装以适配签名选项）。
func asSigner(priv crypto.PrivateKey) crypto.Signer {
	if k, ok := priv.(*sm2.PrivateKey); ok {
		return asSM2Signer(k)
	}
	if k, ok := priv.(crypto.Signer); ok {
		return k
	}
	return nil
}

// signatureAlgorithmName 返回证书签名算法的可读名称（SM2 会显示为 SM2WithSM3）。
func signatureAlgorithmName(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	if isSM2Signature(cert) {
		return "SM2WithSM3"
	}
	return cert.SignatureAlgorithm.String()
}

// ---- 内部工具函数 ----

// generateKey 生成密钥对。
//
// 支持的密钥类型：
//   - rsa2048 / rsa4096：标准 RSA
//   - ec256 / ec384 / ec521：NIST 椭圆曲线
//   - sm2 / sm2p256v1：国密 SM2（需 `-tags gmsm` 构建以启用真实实现，
//     否则返回明确错误提示）
//
// generateKey 根据 keyType 生成私钥。
// 支持的 keyType：
//   - RSA：rsa1024, rsa2048, rsa3072, rsa4096, rsa8192
//   - ECDSA：ec256(P-256), ec384(P-384), ec521(P-521)
//   - EdDSA：ed25519
//   - 国密：sm2, sm2p256v1
//
// Brainpool 曲线（brainpoolP256r1/P384r1/P512r1）与 X25519 在 Go 标准库中无直接支持：
// Brainpool 需要引入第三方包（如 crypto/brainpool）；
// X25519 主要用于密钥协商（ECDH），不用于证书签名，因此不列入签发密钥类型。
// 如需启用 Brainpool，在此分支返回相应的 ecdsa.GenerateKey（elliptic.Curve 需第三方实现）。
func generateKey(keyType string) (crypto.PrivateKey, error) {
	switch keyType {
	case "rsa1024":
		// 弱密钥，仅用于兼容遗留系统；正常签发不应使用。
		return rsa.GenerateKey(rand.Reader, 1024)
	case "rsa2048":
		return rsa.GenerateKey(rand.Reader, 2048)
	case "rsa3072":
		return rsa.GenerateKey(rand.Reader, 3072)
	case "rsa4096":
		return rsa.GenerateKey(rand.Reader, 4096)
	case "rsa8192":
		return rsa.GenerateKey(rand.Reader, 8192)
	case "ec256", "p256":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ec384", "p384":
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "ec521", "p521":
		return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case "ed25519":
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	case "sm2", "sm2p256v1":
		return generateSM2Key()
	default:
		return nil, fmt.Errorf("不支持的密钥类型: %s（支持：rsa1024/2048/3072/4096/8192、ec256/384/521、ed25519、sm2）", keyType)
	}
}

// publicKey 从私钥提取公钥。
func publicKey(priv crypto.PrivateKey) crypto.PublicKey {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case *sm2.PrivateKey:
		return sm2PublicKeyOf(k)
	case ed25519.PrivateKey:
		return k.Public()
	default:
		return nil
	}
}

// applyCertExtTemplate 根据 IssuanceTmplUUID 查询 cert_ext_templates，
// 将扩展模板的 CRL/OCSP/AIA/CT/EV 字段回填到 req 中（只回填未显式设置的字段）。
func (s *Service) applyCertExtTemplate(ctx context.Context, req *IssueRequest) error {
	// 1. 从颁发模板取出 cert_ext_tmpl_uuid
	var certExtTmplUUID string
	err := s.db.QueryRowContext(ctx,
		`SELECT cert_ext_tmpl_uuid FROM issuance_templates WHERE uuid = ?`,
		req.IssuanceTmplUUID,
	).Scan(&certExtTmplUUID)
	if err == sql.ErrNoRows {
		return fmt.Errorf("颁发模板不存在: %s", req.IssuanceTmplUUID)
	}
	if err != nil {
		return fmt.Errorf("读取颁发模板失败: %w", err)
	}
	if certExtTmplUUID == "" {
		return nil
	}

	// 2. 从 cert_ext_templates 读取扩展配置
	var crlJSON, ocspJSON, aiaJSON, ctJSON, evOID string
	var netscapeJSON, cspJSON, asn1JSON string
	err = s.db.QueryRowContext(ctx,
		`SELECT crl_dist_points, ocsp_servers, aia_issuers, ct_servers, ev_policy_oid,
		        netscape_config, csp_config, asn1_extensions
		 FROM cert_ext_templates WHERE uuid = ?`, certExtTmplUUID,
	).Scan(&crlJSON, &ocspJSON, &aiaJSON, &ctJSON, &evOID,
		&netscapeJSON, &cspJSON, &asn1JSON)
	if err == sql.ErrNoRows {
		return fmt.Errorf("颁发模板关联的证书扩展模板不存在")
	}
	if err != nil {
		return fmt.Errorf("读取证书扩展模板失败: %w", err)
	}

	// 3. 解析 JSON 数组并回填（只在 req 未设置时）
	if len(req.CRLDistPoints) == 0 {
		req.CRLDistPoints = parseJSONStringArray(crlJSON)
	}
	if len(req.OCSPServers) == 0 {
		req.OCSPServers = parseJSONStringArray(ocspJSON)
	}
	if len(req.AIAIssuers) == 0 {
		req.AIAIssuers = parseJSONStringArray(aiaJSON)
	}
	if len(req.CTServers) == 0 {
		req.CTServers = parseJSONStringArray(ctJSON)
	}
	if req.EVPolicyOID == "" {
		req.EVPolicyOID = evOID
	}
	// Netscape/CSP/ASN.1 扩展直接保留原始 JSON，由 IssueCert 构造证书时解析
	if req.NetscapeConfigJSON == "" {
		req.NetscapeConfigJSON = netscapeJSON
	}
	if req.CSPConfigJSON == "" {
		req.CSPConfigJSON = cspJSON
	}
	if req.ASN1ExtensionsJSON == "" {
		req.ASN1ExtensionsJSON = asn1JSON
	}
	return nil
}

// parseJSONStringArray 将 JSON 字符串数组（如 "[\"a\",\"b\"]"）解析为 []string。
// 解析失败时返回 nil，不报错。
func parseJSONStringArray(s string) []string {
	if s == "" || s == "[]" {
		return nil
	}
	var arr []string
	if err := json.Unmarshal([]byte(s), &arr); err != nil {
		return nil
	}
	return arr
}

// parseOID 将字符串 "1.2.3.4" 解析为 asn1.ObjectIdentifier。
func parseOID(s string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(s, ".")
	oid := make(asn1.ObjectIdentifier, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			return nil, fmt.Errorf("无效的 OID 片段 %q: %w", p, err)
		}
		oid = append(oid, n)
	}
	if len(oid) == 0 {
		return nil, fmt.Errorf("OID 为空")
	}
	return oid, nil
}

// validateAgainstTemplate 根据 IssuanceTmplUUID 读取颁发模板，对签发请求进行约束校验：
//   - ValidDays 是否在 tmpl.ValidDays 列表中（若列表非空）
//   - KeyType 是否在 tmpl.AllowedKeyTypes 列表中（若列表非空）
//   - CAUUID 是否在 tmpl.AllowedCAUUIDs 列表中（若列表非空）
//   - IsCA 是否与 tmpl.IsCA 一致（若模板明确要求）
//
// 模板不存在或字段为空（表示无限制）时均放行。
func (s *Service) validateAgainstTemplate(ctx context.Context, req *IssueRequest) error {
	var validDaysJSON, allowedKeyTypesJSON, allowedCAsJSON string
	var isCA int
	err := s.db.QueryRowContext(ctx,
		`SELECT valid_days, allowed_key_types, allowed_ca_uuids, is_ca
		 FROM issuance_templates WHERE uuid = ?`, req.IssuanceTmplUUID,
	).Scan(&validDaysJSON, &allowedKeyTypesJSON, &allowedCAsJSON, &isCA)
	if err != nil {
		// 模板不存在时静默跳过
		return nil
	}

	// 1. 有效期白名单
	if allowed := parseJSONIntArray(validDaysJSON); len(allowed) > 0 {
		if !containsInt(allowed, req.ValidDays) {
			return fmt.Errorf("有效期 %d 天不在模板允许列表 %v 中", req.ValidDays, allowed)
		}
	}

	// 2. 密钥类型白名单
	if allowed := parseJSONStringArray(allowedKeyTypesJSON); len(allowed) > 0 {
		if !containsString(allowed, req.KeyType) {
			return fmt.Errorf("密钥类型 %s 不在模板允许列表 %v 中", req.KeyType, allowed)
		}
	}

	// 3. CA 白名单
	if allowed := parseJSONStringArray(allowedCAsJSON); len(allowed) > 0 {
		if !containsString(allowed, req.CAUUID) {
			return fmt.Errorf("CA %s 不在模板允许列表中", req.CAUUID)
		}
	}

	// 4. IsCA 一致性：模板声明 IsCA=1 时必须签发 CA；声明 IsCA=0 时不得签发 CA
	if isCA == 1 && !req.IsCA {
		return fmt.Errorf("模板要求签发 CA 证书，但请求 is_ca=false")
	}
	if isCA == 0 && req.IsCA {
		return fmt.Errorf("模板不允许签发 CA 证书")
	}
	return nil
}

// parseJSONIntArray 解析 JSON 整数数组（如 "[30,90,365]"）。
func parseJSONIntArray(s string) []int {
	if s == "" || s == "[]" {
		return nil
	}
	var arr []int
	if err := json.Unmarshal([]byte(s), &arr); err != nil {
		return nil
	}
	return arr
}

// containsInt 判断整数是否在切片中。
func containsInt(arr []int, v int) bool {
	for _, x := range arr {
		if x == v {
			return true
		}
	}
	return false
}

// containsString 判断字符串是否在切片中。
func containsString(arr []string, v string) bool {
	for _, x := range arr {
		if x == v {
			return true
		}
	}
	return false
}

// applyKeyUsageTemplate 根据 IssuanceTmplUUID 查询 KeyUsageTemplate，
// 将 KU 和 EKU 回填到 req（仅当 req 中相应字段未显式设置时）。
func (s *Service) applyKeyUsageTemplate(ctx context.Context, req *IssueRequest) error {
	var keyUsageTmplUUID string
	err := s.db.QueryRowContext(ctx,
		`SELECT key_usage_tmpl_uuid FROM issuance_templates WHERE uuid = ?`,
		req.IssuanceTmplUUID,
	).Scan(&keyUsageTmplUUID)
	if err == sql.ErrNoRows {
		return fmt.Errorf("颁发模板不存在: %s", req.IssuanceTmplUUID)
	}
	if err != nil {
		return fmt.Errorf("读取颁发模板失败: %w", err)
	}
	if keyUsageTmplUUID == "" {
		return nil
	}

	var keyUsage int
	var extKeyUsagesJSON string
	err = s.db.QueryRowContext(ctx,
		`SELECT key_usage, ext_key_usages FROM key_usage_templates WHERE uuid = ?`,
		keyUsageTmplUUID,
	).Scan(&keyUsage, &extKeyUsagesJSON)
	if err == sql.ErrNoRows {
		// 模板配置断链时拒绝签发，避免签出缺少用途限制的证书
		return fmt.Errorf("颁发模板关联的密钥用途模板不存在")
	}
	if err != nil {
		return fmt.Errorf("读取密钥用途模板失败: %w", err)
	}

	// 只在 req 未显式设置 KU 时覆盖（0 表示未设置）
	if req.KeyUsage == 0 {
		req.KeyUsage = x509.KeyUsage(keyUsage)
	}

	// EKU：只在 req 为空时回填；已有常量的走标准字段，其余 OID 写入 UnknownExtKeyUsage
	if len(req.ExtKeyUsage) == 0 && len(req.UnknownExtKeyUsage) == 0 {
		for _, oidStr := range parseJSONStringArray(extKeyUsagesJSON) {
			if eku, ok := ekuOIDToConstant(oidStr); ok {
				req.ExtKeyUsage = append(req.ExtKeyUsage, eku)
				continue
			}
			oid, err := parseOIDString(oidStr)
			if err != nil {
				return fmt.Errorf("密钥用途模板中的扩展密钥用途 %q 不是合法 OID", oidStr)
			}
			req.UnknownExtKeyUsage = append(req.UnknownExtKeyUsage, oid)
		}
	}
	return nil
}

// parseOIDString 解析点分十进制 OID。
func parseOIDString(s string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(strings.TrimSpace(s), ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("OID 至少需要两段")
	}
	oid := make(asn1.ObjectIdentifier, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("OID 第 %d 段不是非负整数", i+1)
		}
		oid[i] = n
	}
	return oid, nil
}

// ekuOIDToConstant 将字符串 OID 映射到 x509.ExtKeyUsage 常量。
// 覆盖最常用的 EKU；未覆盖的返回 false。
func ekuOIDToConstant(oid string) (x509.ExtKeyUsage, bool) {
	switch oid {
	case "1.3.6.1.5.5.7.3.1":
		return x509.ExtKeyUsageServerAuth, true
	case "1.3.6.1.5.5.7.3.2":
		return x509.ExtKeyUsageClientAuth, true
	case "1.3.6.1.5.5.7.3.3":
		return x509.ExtKeyUsageCodeSigning, true
	case "1.3.6.1.5.5.7.3.4":
		return x509.ExtKeyUsageEmailProtection, true
	case "1.3.6.1.5.5.7.3.5":
		return x509.ExtKeyUsageIPSECEndSystem, true
	case "1.3.6.1.5.5.7.3.6":
		return x509.ExtKeyUsageIPSECTunnel, true
	case "1.3.6.1.5.5.7.3.7":
		return x509.ExtKeyUsageIPSECUser, true
	case "1.3.6.1.5.5.7.3.8":
		return x509.ExtKeyUsageTimeStamping, true
	case "1.3.6.1.5.5.7.3.9":
		return x509.ExtKeyUsageOCSPSigning, true
	case "1.3.6.1.4.1.311.10.3.3":
		return x509.ExtKeyUsageMicrosoftServerGatedCrypto, true
	case "2.16.840.1.113730.4.1":
		return x509.ExtKeyUsageNetscapeServerGatedCrypto, true
	case "1.3.6.1.4.1.311.20.2.2":
		return x509.ExtKeyUsageMicrosoftCommercialCodeSigning, true
	case "1.3.6.1.4.1.311.10.3.12":
		return x509.ExtKeyUsageMicrosoftKernelCodeSigning, true
	}
	return x509.ExtKeyUsageAny, false
}

// parseSignatureAlgorithm 将字符串映射到 x509.SignatureAlgorithm。
// 大小写不敏感；下划线、连字符均可作分隔符。
// 未识别时返回 (0, false)，调用方应让 Go 自动选择签名算法。
func parseSignatureAlgorithm(name string) (x509.SignatureAlgorithm, bool) {
	// 归一化：去除分隔符并转大写
	n := strings.ToUpper(name)
	n = strings.ReplaceAll(n, "-", "")
	n = strings.ReplaceAll(n, "_", "")
	switch n {
	case "MD5RSA", "MD5WITHRSA":
		return x509.MD5WithRSA, true
	case "SHA1RSA", "SHA1WITHRSA":
		return x509.SHA1WithRSA, true
	case "SHA256RSA", "SHA256WITHRSA":
		return x509.SHA256WithRSA, true
	case "SHA384RSA", "SHA384WITHRSA":
		return x509.SHA384WithRSA, true
	case "SHA512RSA", "SHA512WITHRSA":
		return x509.SHA512WithRSA, true
	case "SHA256RSAPSS":
		return x509.SHA256WithRSAPSS, true
	case "SHA384RSAPSS":
		return x509.SHA384WithRSAPSS, true
	case "SHA512RSAPSS":
		return x509.SHA512WithRSAPSS, true
	case "ECDSASHA1":
		return x509.ECDSAWithSHA1, true
	case "ECDSASHA256":
		return x509.ECDSAWithSHA256, true
	case "ECDSASHA384":
		return x509.ECDSAWithSHA384, true
	case "ECDSASHA512":
		return x509.ECDSAWithSHA512, true
	case "ED25519", "PUREED25519":
		return x509.PureEd25519, true
	}
	return 0, false
}
