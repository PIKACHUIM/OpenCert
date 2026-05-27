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
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/globaltrusts/server-card/internal/storage"
)

// IssueRequest 是证书签发请求。
type IssueRequest struct {
	CAUUID      string            // 签发 CA 的 UUID
	Subject     pkix.Name         // 证书主体
	KeyType     string            // 密钥类型（rsa2048/rsa4096/ec256/ec384/ec521）
	ValidDays   int               // 有效期（天）
	IsCA        bool              // 是否为 CA 证书
	PathLen     int               // CA 路径长度（仅 IsCA=true 时有效）
	KeyUsage    x509.KeyUsage     // 密钥用途
	ExtKeyUsage []x509.ExtKeyUsage // 扩展密钥用途
	DNSNames    []string          // SAN DNS 名称
	IPAddresses []net.IP          // SAN IP 地址
	EmailAddrs  []string          // SAN 邮箱
	URIs        []string          // SAN URI （写入证书的 Subject Alternative Name - uniformResourceIdentifier）
	PolicyOIDs  []string          // 证书策略 OID 列表（Certificate Policies 扩展，与 EVPolicyOID 合并写入）

	// 模板约束（可选，签发前验证）
	IssuanceTmplUUID string // 颁发模板 UUID（用于约束验证）

	// 证书拓展模板（可选，签发时写入扩展）
	CRLDistPoints  []string // CRL 分发点
	OCSPServers    []string // OCSP 服务器
	AIAIssuers     []string // AIA 颁发者
	CTServers      []string // CT 服务器
	EVPolicyOID    string   // EV 策略 OID

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
}

// IssueResponse 是证书签发响应。
type IssueResponse struct {
	CertPEM      string    // 签发的证书 PEM
	CertDER      []byte    // 签发的证书 DER
	PrivateEnc   []byte    // 加密的私钥
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

	// 获取 CA
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

	// 解密 CA 私钥
	caKey, err := decryptPrivateKey(s.masterKey, ca.PrivateEnc)
	if err != nil {
		return nil, fmt.Errorf("解密 CA 私钥失败: %w", err)
	}

	// 生成密钥对（若请求中直接带 CSRPublicKey，则跳过生成，使用申请者公钥）
	var privKey crypto.PrivateKey
	var pubKey crypto.PublicKey
	if req.CSRPublicKey != nil {
		pubKey = req.CSRPublicKey
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
	notAfter := now.AddDate(0, 0, req.ValidDays)

	// 限制有效期不超过 CA 有效期
	if notAfter.After(ca.NotAfter) {
		notAfter = ca.NotAfter
	}

	// 构建证书模板
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               req.Subject,
		NotBefore:             now,
		NotAfter:              notAfter,
		KeyUsage:              req.KeyUsage,
		ExtKeyUsage:           req.ExtKeyUsage,
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
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, pubKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("签发证书失败: %w", err)
	}

	// 解析签发后的证书获取完整元数据
	issuedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("解析签发证书失败: %w", err)
	}

	// 编码为 PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// 加密私钥（仅在本次签发自行生成了密钥时执行；CSRPublicKey 场景下 privKey 为 nil，不返回私钥）
	var privEnc []byte
	if privKey != nil {
		privDER, err := x509.MarshalPKCS8PrivateKey(privKey)
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
		SerialNumber: fmt.Sprintf("%x", serialNumber),
		SubjectDN:    issuedCert.Subject.String(),
		IssuerDN:     issuedCert.Issuer.String(),
		NotBefore:    issuedCert.NotBefore,
		NotAfter:     issuedCert.NotAfter,
	}, nil
}

// CreateSelfSignedCA 创建自签名根 CA。
func (s *Service) CreateSelfSignedCA(ctx context.Context, name string, subject pkix.Name, keyType string, validYears int) (*storage.CA, error) {
	// 生成密钥对
	privKey, err := generateKey(keyType)
	if err != nil {
		return nil, fmt.Errorf("生成密钥对失败: %w", err)
	}

	// 生成随机序列号
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("生成序列号失败: %w", err)
	}

	now := time.Now()
	notAfter := now.AddDate(validYears, 0, 0)

	// 构建自签名 CA 证书模板
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             now,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        false,
		MaxPathLen:            -1,
	}

	pubKey := publicKey(privKey)

	// 自签名
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("创建自签名证书失败: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// 加密私钥
	privDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("序列化私钥失败: %w", err)
	}
	privEnc, err := encryptPrivateKey(s.masterKey, privDER)
	if err != nil {
		return nil, fmt.Errorf("加密私钥失败: %w", err)
	}

	ca := &storage.CA{
		Name:       name,
		CertPEM:    string(certPEM),
		PrivateEnc: privEnc,
		Status:     "active",
		NotBefore:  now,
		NotAfter:   notAfter,
	}

	if err := s.Create(ctx, ca); err != nil {
		return nil, fmt.Errorf("保存 CA 失败: %w", err)
	}

	return ca, nil
}

// ---- 内部工具函数 ----

// generateKey 生成密钥对。
//
// 支持的密钥类型：
//   - rsa2048 / rsa4096：标准 RSA
//   - ec256 / ec384 / ec521：NIST 椭圆曲线
//   - sm2 / sm2p256v1：国密 SM2（需 `-tags gmsm` 构建以启用真实实现，
//     否则返回明确错误提示）
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
	if err != nil {
		// 模板不存在或读取失败时静默跳过，不阻塞签发
		return nil
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
	if err != nil {
		return nil
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
	if err != nil || keyUsageTmplUUID == "" {
		return nil
	}

	var keyUsage int
	var extKeyUsagesJSON string
	err = s.db.QueryRowContext(ctx,
		`SELECT key_usage, ext_key_usages FROM key_usage_templates WHERE uuid = ?`,
		keyUsageTmplUUID,
	).Scan(&keyUsage, &extKeyUsagesJSON)
	if err != nil {
		return nil
	}

	// 只在 req 未显式设置 KU 时覆盖（0 表示未设置）
	if req.KeyUsage == 0 {
		req.KeyUsage = x509.KeyUsage(keyUsage)
	}

	// EKU：只在 req 为空时回填
	if len(req.ExtKeyUsage) == 0 {
		oidList := parseJSONStringArray(extKeyUsagesJSON)
		for _, oidStr := range oidList {
			if eku, ok := ekuOIDToConstant(oidStr); ok {
				req.ExtKeyUsage = append(req.ExtKeyUsage, eku)
			}
			// 对于未知 OID，当前版本忽略（避免引入 UnknownExtKeyUsage 复杂性）；
			// T14 中补充 ExtraExtensions 写入支持任意 EKU OID。
		}
	}
	return nil
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
