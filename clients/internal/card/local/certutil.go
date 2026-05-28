package local

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"

	cryptoutil "github.com/globaltrusts/client-card/internal/crypto"
	"github.com/globaltrusts/client-card/internal/storage"
	zcryptox509 "github.com/zmap/zcrypto/x509"
)

// CertPolicy 表示一个证书策略条目。
type CertPolicy struct {
	OID         string `json:"oid"`
	Description string `json:"description,omitempty"` // EV/OV/DV 等描述
}

// CertDetail 是解析后的 X.509 证书详细信息。
type CertDetail struct {
	CommonName        string   `json:"common_name"`
	Organization      string   `json:"organization,omitempty"`
	OrgUnit           string   `json:"org_unit,omitempty"`
	Country           string   `json:"country,omitempty"`
	State             string   `json:"state,omitempty"`
	Locality          string   `json:"locality,omitempty"`
	IssuerCN          string   `json:"issuer_cn"`
	IssuerOrg         string   `json:"issuer_org,omitempty"`
	IssuerOU          string   `json:"issuer_ou,omitempty"`
	IssuerCountry     string   `json:"issuer_country,omitempty"`
	NotBefore         string   `json:"not_before"`
	NotAfter          string   `json:"not_after"`
	SerialNumber      string   `json:"serial_number"`
	SHA1Fingerprint   string   `json:"sha1_fingerprint"`
	SHA256Fingerprint string   `json:"sha256_fingerprint"`
	KeyUsage          []string `json:"key_usage"`
	ExtKeyUsage       []string `json:"ext_key_usage"`
	IsCA              bool     `json:"is_ca"`
	MaxPathLen        int      `json:"max_path_len"`
	MaxPathLenZero    bool     `json:"max_path_len_zero"` // 区分 pathLen=0 和未设置
	KeyBits           int      `json:"key_bits,omitempty"`           // 密钥长度（位）
	SANDNSNames       []string `json:"san_dns,omitempty"`
	SANIPAddresses    []string `json:"san_ip,omitempty"`
	SANEmailAddresses []string `json:"san_email,omitempty"`
	SANURIs           []string `json:"san_uri,omitempty"`
	CRLDistPoints     []string `json:"crl_dist_points,omitempty"`
	OCSPServers       []string `json:"ocsp_servers,omitempty"`
	IssuingCertURL    []string `json:"issuing_cert_url,omitempty"` // AIA
	CPSURLs           []string `json:"cps_urls,omitempty"`
	CertPolicies      []CertPolicy `json:"cert_policies,omitempty"` // 证书策略 OID
	SignatureAlgo     string   `json:"signature_algo"`
	PublicKeyAlgo     string   `json:"public_key_algo"`
	IsSelfSigned      bool     `json:"is_self_signed"`
}

// ParseCertLenient 宽松解析 X.509 证书（导出版本）。
// 使用 zcrypto/x509 库进行解析，该库对 Certificate Policies 等扩展
// 采用了更宽松的处理方式，可以解析标准库 crypto/x509 无法处理的证书。
func ParseCertLenient(derData []byte) (*x509.Certificate, error) {
	return parseCertLenient(derData)
}

func parseCertLenient(derData []byte) (*x509.Certificate, error) {
	// 优先使用标准库解析
	cert, err := x509.ParseCertificate(derData)
	if err == nil {
		return cert, nil
	}

	// 标准库解析失败，使用 zcrypto 宽松解析
	zcert, zerr := zcryptox509.ParseCertificate(derData)
	if zerr != nil {
		return nil, fmt.Errorf("标准库解析失败: %w; zcrypto 解析也失败: %v", err, zerr)
	}

	// 将 zcrypto 证书转换为标准库证书
	return zcertToStdCert(zcert), nil
}

// zcertToStdCert 将 zcrypto/x509.Certificate 转换为 crypto/x509.Certificate。
// zcrypto 的 Certificate 结构与标准库兼容，但类型不同，需要逐字段转换。
func zcertToStdCert(z *zcryptox509.Certificate) *x509.Certificate {
	c := &x509.Certificate{
		Raw:                         z.Raw,
		RawTBSCertificate:           z.RawTBSCertificate,
		RawSubjectPublicKeyInfo:     z.RawSubjectPublicKeyInfo,
		RawSubject:                  z.RawSubject,
		RawIssuer:                   z.RawIssuer,
		Signature:                   z.Signature,
		SignatureAlgorithm:          x509.SignatureAlgorithm(z.SignatureAlgorithm),
		PublicKeyAlgorithm:          x509.PublicKeyAlgorithm(z.PublicKeyAlgorithm),
		SerialNumber:                z.SerialNumber,
		Issuer:                      z.Issuer,
		Subject:                     z.Subject,
		NotBefore:                   z.NotBefore,
		NotAfter:                    z.NotAfter,
		KeyUsage:                    x509.KeyUsage(z.KeyUsage),
		Extensions:                  z.Extensions,
		ExtraExtensions:             z.ExtraExtensions,
		UnhandledCriticalExtensions: z.UnhandledCriticalExtensions,
		ExtKeyUsage:                 convertExtKeyUsages(z.ExtKeyUsage),
		UnknownExtKeyUsage:          z.UnknownExtKeyUsage,
		BasicConstraintsValid:       z.BasicConstraintsValid,
		IsCA:                        z.IsCA,
		MaxPathLen:                  z.MaxPathLen,
		MaxPathLenZero:              z.MaxPathLenZero,
		SubjectKeyId:                z.SubjectKeyId,
		AuthorityKeyId:              z.AuthorityKeyId,
		OCSPServer:                  z.OCSPServer,
		IssuingCertificateURL:       z.IssuingCertificateURL,
		DNSNames:                    z.DNSNames,
		EmailAddresses:              z.EmailAddresses,
		IPAddresses:                 z.IPAddresses,
		URIs:                        z.URIs,
		CRLDistributionPoints:       z.CRLDistributionPoints,
		PolicyIdentifiers:           z.PolicyIdentifiers,
	}

	// 转换公钥
	if z.PublicKey != nil {
		c.PublicKey = z.PublicKey
	}

	return c
}

// convertExtKeyUsages 将 zcrypto 的 ExtKeyUsage 切片转换为标准库的 ExtKeyUsage 切片。
func convertExtKeyUsages(ekus []zcryptox509.ExtKeyUsage) []x509.ExtKeyUsage {
	result := make([]x509.ExtKeyUsage, len(ekus))
	for i, eku := range ekus {
		result[i] = x509.ExtKeyUsage(eku)
	}
	return result
}

// ParseCertDetail 解析 X.509 证书 DER 或 PEM 数据，返回结构化详情。
func ParseCertDetail(certData []byte) (*CertDetail, error) {
	var cert *x509.Certificate
	var err error

	// 尝试 PEM 解码
	block, _ := pem.Decode(certData)
	if block != nil {
		if block.Type != "CERTIFICATE" && block.Type != "X509 CERTIFICATE" {
			return nil, fmt.Errorf("PEM 类型不是证书: %s", block.Type)
		}
		cert, err = parseCertLenient(block.Bytes)
	} else {
		// 尝试 DER 解码
		cert, err = parseCertLenient(certData)
	}
	if err != nil {
		return nil, fmt.Errorf("解析 X.509 证书失败: %w", err)
	}

	// 计算 SHA1 指纹
	sha1Hash := sha1.Sum(cert.Raw)
	sha1Hex := strings.ToUpper(hex.EncodeToString(sha1Hash[:]))
	// 每两个字符插入冒号
	var sha1Parts []string
	for i := 0; i < len(sha1Hex); i += 2 {
		sha1Parts = append(sha1Parts, sha1Hex[i:i+2])
	}

	serialStr := ""
	if cert.SerialNumber != nil {
		serialStr = cert.SerialNumber.String()
	}

	// 签名算法
	sigAlgo := cert.SignatureAlgorithm.String()
	if sigAlgo == "" || sigAlgo == "0" {
		sigAlgo = "Unknown"
	}
	pubKeyAlgo := cert.PublicKeyAlgorithm.String()
	if pubKeyAlgo == "" || pubKeyAlgo == "0" {
		pubKeyAlgo = "Unknown"
	}

	detail := &CertDetail{
		CommonName:      cert.Subject.CommonName,
		IssuerCN:        cert.Issuer.CommonName,
		NotBefore:       cert.NotBefore.Format("2006-01-02T15:04:05Z07:00"),
		NotAfter:        cert.NotAfter.Format("2006-01-02T15:04:05Z07:00"),
		SerialNumber:    serialStr,
		SHA1Fingerprint: strings.Join(sha1Parts, ":"),
		SignatureAlgo:   sigAlgo,
		PublicKeyAlgo:   pubKeyAlgo,
		CRLDistPoints:   cert.CRLDistributionPoints,
		OCSPServers:     cert.OCSPServer,
		IssuingCertURL:  cert.IssuingCertificateURL,
		IsSelfSigned:    cert.Subject.CommonName == cert.Issuer.CommonName,
		IsCA:            cert.IsCA,
		MaxPathLen:      cert.MaxPathLen,
		MaxPathLenZero:  cert.MaxPathLenZero,
	}

	// Subject 主体信息
	if len(cert.Subject.Organization) > 0 {
		detail.Organization = strings.Join(cert.Subject.Organization, ", ")
	}
	if len(cert.Subject.OrganizationalUnit) > 0 {
		detail.OrgUnit = strings.Join(cert.Subject.OrganizationalUnit, ", ")
	}
	if len(cert.Subject.Country) > 0 {
		detail.Country = strings.Join(cert.Subject.Country, ", ")
	}
	if len(cert.Subject.Province) > 0 {
		detail.State = strings.Join(cert.Subject.Province, ", ")
	}

	// Issuer 信息
	if len(cert.Issuer.Organization) > 0 {
		detail.IssuerOrg = strings.Join(cert.Issuer.Organization, ", ")
	}

	// Key Usage
	detail.KeyUsage = parseKeyUsage(cert.KeyUsage)

	// Extended Key Usage
	for _, eku := range cert.ExtKeyUsage {
		detail.ExtKeyUsage = append(detail.ExtKeyUsage, extKeyUsageName(eku))
	}
	// 未知的扩展密钥用途直接显示 OID
	for _, oid := range cert.UnknownExtKeyUsage {
		detail.ExtKeyUsage = append(detail.ExtKeyUsage, oid.String())
	}

	// SAN
	for _, dns := range cert.DNSNames {
		detail.SANDNSNames = append(detail.SANDNSNames, dns)
	}
	for _, ip := range cert.IPAddresses {
		detail.SANIPAddresses = append(detail.SANIPAddresses, ip.String())
	}
	for _, email := range cert.EmailAddresses {
		detail.SANEmailAddresses = append(detail.SANEmailAddresses, email)
	}
	for _, uri := range cert.URIs {
		detail.SANURIs = append(detail.SANURIs, uri.String())
	}

	// CPS URLs 和证书策略 OID（从证书策略扩展中提取）
	detail.CPSURLs = extractCPSURLs(cert)
	detail.CertPolicies = extractCertPolicies(cert)

	// Issuer 扩展信息
	if len(cert.Issuer.OrganizationalUnit) > 0 {
		detail.IssuerOU = strings.Join(cert.Issuer.OrganizationalUnit, ", ")
	}
	if len(cert.Issuer.Country) > 0 {
		detail.IssuerCountry = strings.Join(cert.Issuer.Country, ", ")
	}

	// Locality
	if len(cert.Subject.Locality) > 0 {
		detail.Locality = strings.Join(cert.Subject.Locality, ", ")
	}

	// 密钥长度
	detail.KeyBits = getKeyBits(cert)

	// SHA256 指纹
	sha256Hash := sha256.Sum256(cert.Raw)
	sha256Hex := strings.ToUpper(hex.EncodeToString(sha256Hash[:]))
	var sha256Parts []string
	for i := 0; i < len(sha256Hex); i += 2 {
		sha256Parts = append(sha256Parts, sha256Hex[i:i+2])
	}
	detail.SHA256Fingerprint = strings.Join(sha256Parts, ":")

	return detail, nil
}

// DecryptPrivateKey 使用主密钥解密证书的私钥。
func DecryptPrivateKey(masterKey []byte, cert *storage.Certificate) ([]byte, error) {
	if len(cert.TempKeySalt) == 0 || len(cert.TempKeyEnc) == 0 || len(cert.PrivateData) == 0 {
		return nil, fmt.Errorf("证书缺少加密私钥数据")
	}

	// 1. 用主密钥解密临时密钥
	tempKeyAESKey := cryptoutil.HMACSHA256(masterKey, cert.TempKeySalt)
	tempKey, err := cryptoutil.DecryptAES256GCM(tempKeyAESKey, cert.TempKeyEnc)
	if err != nil {
		return nil, fmt.Errorf("解密临时密钥失败: %w", err)
	}
	defer zeroBytes(tempKey)

	// 2. 用临时密钥解密私钥
	privDER, err := cryptoutil.DecryptAES256GCM(tempKey, cert.PrivateData)
	if err != nil {
		return nil, fmt.Errorf("解密私钥失败: %w", err)
	}

	return privDER, nil
}

// parseKeyUsage 将 x509.KeyUsage 位掩码转为字符串列表。
func parseKeyUsage(ku x509.KeyUsage) []string {
	var usages []string
	if ku&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "DigitalSignature")
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "ContentCommitment")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "KeyEncipherment")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "DataEncipherment")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "KeyAgreement")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "CertSign")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRLSign")
	}
	if ku&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "EncipherOnly")
	}
	if ku&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "DecipherOnly")
	}
	return usages
}

// extKeyUsageName 返回 ExtKeyUsage 的可读名称。
func extKeyUsageName(eku x509.ExtKeyUsage) string {
	switch eku {
	case x509.ExtKeyUsageAny:
		return "Any"
	case x509.ExtKeyUsageServerAuth:
		return "ServerAuth"
	case x509.ExtKeyUsageClientAuth:
		return "ClientAuth"
	case x509.ExtKeyUsageCodeSigning:
		return "CodeSigning"
	case x509.ExtKeyUsageEmailProtection:
		return "EmailProtection"
	case x509.ExtKeyUsageTimeStamping:
		return "TimeStamping"
	case x509.ExtKeyUsageOCSPSigning:
		return "OCSPSigning"
	default:
		return fmt.Sprintf("Unknown(%d)", eku)
	}
}

// extractCPSURLs 从证书扩展中提取 CPS URL。
func extractCPSURLs(cert *x509.Certificate) []string {
	var urls []string
	// 证书策略扩展 OID: 2.5.29.32
	for _, ext := range cert.Extensions {
		if ext.Id.String() == "2.5.29.32" {
			// 使用 zcrypto 解析证书策略来提取 CPS URL
			cpsURLs := extractCPSFromCertPoliciesExt(ext.Value)
			urls = append(urls, cpsURLs...)
		}
	}
	return urls
}

// extractCPSFromCertPoliciesExt 从 certificatePolicies 扩展值中提取 CPS URL。
func extractCPSFromCertPoliciesExt(value []byte) []string {
	var urls []string
	// 简单提取：查找 http:// 或 https:// 开头的字符串
	data := string(value)
	for _, part := range strings.Split(data, "http") {
		if strings.HasPrefix(part, "s://") || strings.HasPrefix(part, "://") {
			u := "http" + part
			// 截断到第一个不可打印字符
			end := len(u)
			for i, c := range u {
				if c < 0x20 || c > 0x7e {
					end = i
					break
				}
			}
			u = u[:end]
			if len(u) > 7 { // http://x 最少 8 字符
				urls = append(urls, u)
			}
		}
	}
	return urls
}

// 常见证书策略 OID 映射
var knownPolicyOIDs = map[string]string{
	// CA/Browser Forum 基线要求
	"2.23.140.1.2.1": "DV (Domain Validated)",
	"2.23.140.1.2.2": "OV (Organization Validated)",
	"2.23.140.1.1":   "EV (Extended Validation)",
	"2.23.140.1.2.3": "IV (Individual Validated)",
	// 常见 CA 的 EV OID
	"1.3.6.1.4.1.44947.1.1.1":     "ISRG EV",
	"2.16.840.1.114412.2.1":       "DigiCert EV",
	"2.16.840.1.113733.1.7.23.6":  "VeriSign EV",
	"1.3.6.1.4.1.6449.1.2.1.5.1":  "Comodo EV",
	"2.16.840.1.114028.10.1.2":    "Entrust EV",
	"1.2.616.1.113527.2.5.1.1":    "Certum EV",
}

// extractCertPolicies 从证书策略扩展中提取策略 OID 列表。
func extractCertPolicies(cert *x509.Certificate) []CertPolicy {
	var policies []CertPolicy
	for _, oid := range cert.PolicyIdentifiers {
		oidStr := oid.String()
		desc := knownPolicyOIDs[oidStr]
		if desc == "" {
			desc = classifyPolicyOID(oidStr)
		}
		policies = append(policies, CertPolicy{
			OID:         oidStr,
			Description: desc,
		})
	}
	return policies
}

// classifyPolicyOID 根据 OID 前缀推断策略类型。
func classifyPolicyOID(oid string) string {
	// 2.23.140.1.x 是 CA/Browser Forum 定义的
	if strings.HasPrefix(oid, "2.23.140.1.") {
		return "CA/Browser Forum Policy"
	}
	return ""
}

// getKeyBits 获取证书公钥的位数。
func getKeyBits(cert *x509.Certificate) int {
	if cert.PublicKey == nil {
		return 0
	}
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return pub.N.BitLen()
	case *ecdsa.PublicKey:
		return pub.Curve.Params().BitSize
	case ed25519.PublicKey:
		return 256
	default:
		return 0
	}
}

// ParsePEMCert 解析 PEM 格式的证书，返回 DER 字节。
func ParsePEMCert(pemData []byte) ([]byte, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("无法解码 PEM 数据")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("PEM 类型不是 CERTIFICATE，而是 %s", block.Type)
	}
	// 验证是否为合法 X.509 证书（宽松模式）
	if _, err := parseCertLenient(block.Bytes); err != nil {
		return nil, fmt.Errorf("解析 X.509 证书失败: %w", err)
	}
	return block.Bytes, nil
}

// ParsePEMKey 解析 PEM 格式的私钥，返回 PKCS8 DER 字节。
func ParsePEMKey(pemData []byte) ([]byte, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("无法解码 PEM 私钥数据")
	}

	// 尝试 PKCS8
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("序列化 PKCS8 私钥失败: %w", err)
		}
		return der, nil
	}

	// 尝试 PKCS1 (RSA)
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("序列化 RSA 私钥失败: %w", err)
		}
		return der, nil
	}

	// 尝试 EC
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("序列化 EC 私钥失败: %w", err)
		}
		return der, nil
	}

	return nil, fmt.Errorf("无法解析私钥（支持 PKCS8/PKCS1/EC 格式）")
}

// ParsePFX 解析 PKCS12/PFX 文件，返回证书 DER 和私钥 PKCS8 DER。
func ParsePFX(pfxData []byte, password string) (certDER, privDER []byte, err error) {
	return nil, nil, fmt.Errorf("PFX/PKCS12 解析需要 go-pkcs12 库支持，请使用 PEM 格式导入")
}
