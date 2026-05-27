package local

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"

	cryptoutil "github.com/globaltrusts/client-card/internal/crypto"
	"github.com/globaltrusts/client-card/internal/storage"
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
// Go 1.22+ 对 Certificate Policies 扩展的解析更严格，某些合法证书会报
// "x509: invalid certificate policies" 错误。此函数在标准解析失败时，
// 尝试使用 ASN.1 手动提取基本字段。
func ParseCertLenient(derData []byte) (*x509.Certificate, error) {
	return parseCertLenient(derData)
}

func parseCertLenient(derData []byte) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(derData)
	if err == nil {
		return cert, nil
	}
	// 仅对 certificate policies 相关错误做宽松处理
	if !strings.Contains(err.Error(), "certificate policies") {
		return nil, err
	}
	// 使用 ASN.1 手动解析基本结构
	return parseCertASN1Fallback(derData)
}

// ---- ASN.1 辅助类型 ----

type asn1TBSCert struct {
	Raw       asn1.RawContent
	Version   asn1.RawValue   `asn1:"optional,explicit,default:0,tag:0"`
	Serial    *big.Int
	SigAlgo   asn1.RawValue
	Issuer    asn1.RawValue
	Validity  asn1.RawValue
	Subject   asn1.RawValue
	PublicKey asn1.RawValue
	// 后续字段可选，不解析
}

type asn1Certificate struct {
	Raw       asn1.RawContent
	TBS       asn1TBSCert
	SigAlgo   asn1.RawValue
	Signature asn1.BitString
}

type asn1Validity struct {
	NotBefore asn1.RawValue
	NotAfter  asn1.RawValue
}

type rdnSequence []rdnSet
type rdnSet []attributeTypeAndValue
type attributeTypeAndValue struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue
}

// parseCertASN1Fallback 当标准解析因 certificate policies 失败时，
// 手动从 ASN.1 结构中提取基本证书信息。
func parseCertASN1Fallback(derData []byte) (*x509.Certificate, error) {
	// 方式一：尝试结构体解析
	var rawCert asn1Certificate
	if _, err := asn1.Unmarshal(derData, &rawCert); err == nil {
		return buildCertFromASN1(derData, &rawCert), nil
	}

	// 方式二：手动逐步解析（处理含大量扩展的复杂证书）
	return parseCertManual(derData)
}

// buildCertFromASN1 从已解析的 ASN.1 结构构建 x509.Certificate。
func buildCertFromASN1(derData []byte, rawCert *asn1Certificate) *x509.Certificate {
	cert := &x509.Certificate{
		Raw:          derData,
		SerialNumber: rawCert.TBS.Serial,
	}
	if cert.SerialNumber == nil {
		cert.SerialNumber = big.NewInt(0)
	}

	// 解析 Subject
	var subjectRDN pkix.RDNSequence
	if len(rawCert.TBS.Subject.FullBytes) > 0 {
		if _, err := asn1.Unmarshal(rawCert.TBS.Subject.FullBytes, &subjectRDN); err == nil {
			var name pkix.Name
			name.FillFromRDNSequence(&subjectRDN)
			cert.Subject = name
		}
	}

	// 解析 Issuer
	var issuerRDN pkix.RDNSequence
	if len(rawCert.TBS.Issuer.FullBytes) > 0 {
		if _, err := asn1.Unmarshal(rawCert.TBS.Issuer.FullBytes, &issuerRDN); err == nil {
			var name pkix.Name
			name.FillFromRDNSequence(&issuerRDN)
			cert.Issuer = name
		}
	}

	// 解析有效期
	var val asn1Validity
	if _, err := asn1.Unmarshal(rawCert.TBS.Validity.FullBytes, &val); err == nil {
		cert.NotBefore = parseASN1Time(val.NotBefore)
		cert.NotAfter = parseASN1Time(val.NotAfter)
	}

	return cert
}

// parseCertManual 手动逐步解析 X.509 证书的 TBSCertificate 字段。
// 不依赖结构体映射，直接按 ASN.1 SEQUENCE 顺序逐个读取元素。
func parseCertManual(derData []byte) (*x509.Certificate, error) {
	// 外层 Certificate SEQUENCE
	var certSeq asn1.RawValue
	if _, err := asn1.Unmarshal(derData, &certSeq); err != nil {
		return nil, fmt.Errorf("解析证书外层 SEQUENCE 失败: %w", err)
	}
	if certSeq.Tag != 16 || !certSeq.IsCompound { // SEQUENCE
		return nil, fmt.Errorf("证书外层不是 SEQUENCE")
	}

	// TBSCertificate SEQUENCE（Certificate 的第一个元素）
	var tbsRaw asn1.RawValue
	rest, err := asn1.Unmarshal(certSeq.Bytes, &tbsRaw)
	if err != nil {
		return nil, fmt.Errorf("解析 TBSCertificate 失败: %w", err)
	}
	_ = rest

	if tbsRaw.Tag != 16 || !tbsRaw.IsCompound {
		return nil, fmt.Errorf("TBSCertificate 不是 SEQUENCE")
	}

	cert := &x509.Certificate{
		Raw:          derData,
		SerialNumber: big.NewInt(0),
	}

	// 逐步解析 TBSCertificate 内部字段
	tbsBytes := tbsRaw.Bytes
	var elem asn1.RawValue

	// 1. version [0] EXPLICIT INTEGER (optional)
	tbsBytes, err = asn1.Unmarshal(tbsBytes, &elem)
	if err != nil {
		return cert, nil // 返回部分结果
	}
	// 如果是 context-specific tag 0，说明有 version 字段，跳过
	if elem.Class == 2 && elem.Tag == 0 {
		// version 字段，继续读下一个
		tbsBytes, err = asn1.Unmarshal(tbsBytes, &elem)
		if err != nil {
			return cert, nil
		}
	}

	// 2. serialNumber INTEGER
	var serial *big.Int
	if _, err2 := asn1.Unmarshal(elem.FullBytes, &serial); err2 == nil && serial != nil {
		cert.SerialNumber = serial
	}

	// 3. signature AlgorithmIdentifier (SEQUENCE) - 提取签名算法 OID
	tbsBytes, err = asn1.Unmarshal(tbsBytes, &elem)
	if err != nil {
		return cert, nil
	}
	// 尝试从 AlgorithmIdentifier 中提取 OID
	if elem.IsCompound {
		var sigOID asn1.ObjectIdentifier
		if _, err2 := asn1.Unmarshal(elem.Bytes, &sigOID); err2 == nil {
			cert.SignatureAlgorithm = oidToSignatureAlgorithm(sigOID)
		}
	}

	// 4. issuer Name (SEQUENCE)
	tbsBytes, err = asn1.Unmarshal(tbsBytes, &elem)
	if err != nil {
		return cert, nil
	}
	var issuerRDN pkix.RDNSequence
	if _, err2 := asn1.Unmarshal(elem.FullBytes, &issuerRDN); err2 == nil {
		var name pkix.Name
		name.FillFromRDNSequence(&issuerRDN)
		cert.Issuer = name
	}

	// 5. validity Validity (SEQUENCE)
	tbsBytes, err = asn1.Unmarshal(tbsBytes, &elem)
	if err != nil {
		return cert, nil
	}
	var val asn1Validity
	if _, err2 := asn1.Unmarshal(elem.FullBytes, &val); err2 == nil {
		cert.NotBefore = parseASN1Time(val.NotBefore)
		cert.NotAfter = parseASN1Time(val.NotAfter)
	}

	// 6. subject Name (SEQUENCE)
	tbsBytes, err = asn1.Unmarshal(tbsBytes, &elem)
	if err != nil {
		return cert, nil
	}
	var subjectRDN pkix.RDNSequence
	if _, err2 := asn1.Unmarshal(elem.FullBytes, &subjectRDN); err2 == nil {
		var name pkix.Name
		name.FillFromRDNSequence(&subjectRDN)
		cert.Subject = name
	}

	// 7. subjectPublicKeyInfo (SEQUENCE) - 跳过
	tbsBytes, err = asn1.Unmarshal(tbsBytes, &elem)
	if err != nil {
		return cert, nil
	}

	// 8. 继续读取可选字段，寻找 extensions [3] EXPLICIT
	for len(tbsBytes) > 0 {
		tbsBytes, err = asn1.Unmarshal(tbsBytes, &elem)
		if err != nil {
			break
		}
		// extensions 是 context-specific tag 3, EXPLICIT
		if elem.Class == 2 && elem.Tag == 3 {
			parseExtensionsInto(cert, elem.Bytes)
			break
		}
	}

	return cert, nil
}

// parseExtensionsInto 从 extensions 原始字节中提取 SAN、CRL、OCSP、AIA 等扩展到 cert 中。
func parseExtensionsInto(cert *x509.Certificate, extBytes []byte) {
	// extensions 是 SEQUENCE OF Extension
	var extensions []asn1.RawValue
	var extSeq asn1.RawValue
	if _, err := asn1.Unmarshal(extBytes, &extSeq); err != nil {
		return
	}
	rest := extSeq.Bytes
	for len(rest) > 0 {
		var ext asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &ext)
		if err != nil {
			break
		}
		extensions = append(extensions, ext)
	}

	for _, extRaw := range extensions {
		if !extRaw.IsCompound {
			continue
		}
		// Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }
		var oid asn1.ObjectIdentifier
		extInner := extRaw.Bytes
		extInner, err := asn1.Unmarshal(extInner, &oid)
		if err != nil {
			continue
		}
		// 跳过 critical (BOOLEAN, optional)
		var val asn1.RawValue
		extInner, err = asn1.Unmarshal(extInner, &val)
		if err != nil {
			continue
		}
		var extnValue []byte
		if val.Tag == 1 { // BOOLEAN
			// critical, 读取下一个 (OCTET STRING)
			_, err = asn1.Unmarshal(extInner, &val)
			if err != nil {
				continue
			}
		}
		if val.Tag == 4 { // OCTET STRING
			extnValue = val.Bytes
		} else {
			continue
		}

		oidStr := oid.String()
		switch oidStr {
		case "2.5.29.17": // SAN
			parseSANInto(cert, extnValue)
		case "2.5.29.31": // CRL Distribution Points
			cert.CRLDistributionPoints = extractURLsFromDistPoints(extnValue)
		case "1.3.6.1.5.5.7.1.1": // Authority Information Access (AIA)
			ocsp, caIssuers := parseAIA(extnValue)
			cert.OCSPServer = ocsp
			cert.IssuingCertificateURL = caIssuers
		case "2.5.29.15": // Key Usage
			parseKeyUsageInto(cert, extnValue)
		case "2.5.29.37": // Extended Key Usage
			parseExtKeyUsageInto(cert, extnValue)
		case "2.5.29.19": // Basic Constraints
			parseBasicConstraintsInto(cert, extnValue)
		}
		// 保存到 Extensions 列表（供 extractCPSURLs 等使用）
		cert.Extensions = append(cert.Extensions, pkix.Extension{
			Id:    oid,
			Value: extnValue,
		})
	}
}

// parseSANInto 从 SAN 扩展值中提取 DNS、IP、Email、URI。
func parseSANInto(cert *x509.Certificate, value []byte) {
	// SubjectAltName ::= GeneralNames ::= SEQUENCE OF GeneralName
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(value, &seq); err != nil {
		return
	}
	rest := seq.Bytes
	for len(rest) > 0 {
		var gn asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &gn)
		if err != nil {
			break
		}
		// GeneralName 是 context-specific:
		// [2] dNSName IA5String
		// [6] uniformResourceIdentifier IA5String
		// [1] rfc822Name IA5String
		// [7] iPAddress OCTET STRING
		switch gn.Tag {
		case 1: // rfc822Name (email)
			cert.EmailAddresses = append(cert.EmailAddresses, string(gn.Bytes))
		case 2: // dNSName
			cert.DNSNames = append(cert.DNSNames, string(gn.Bytes))
		case 6: // URI
			if u, err := url.Parse(string(gn.Bytes)); err == nil {
				cert.URIs = append(cert.URIs, u)
			}
		case 7: // iPAddress
			if len(gn.Bytes) == 4 || len(gn.Bytes) == 16 {
				cert.IPAddresses = append(cert.IPAddresses, gn.Bytes)
			}
		}
	}
}

// extractURLsFromDistPoints 从 CRL Distribution Points 扩展值中提取 URL。
func extractURLsFromDistPoints(value []byte) []string {
	var urls []string
	// 简单提取：查找 http:// 或 https:// 字符串
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
			if parsed, err := url.Parse(u); err == nil && parsed.Host != "" {
				urls = append(urls, parsed.String())
			}
		}
	}
	return urls
}

// parseAIA 从 Authority Information Access 扩展值中提取 OCSP 和 CA Issuers URL。
func parseAIA(value []byte) (ocsp []string, caIssuers []string) {
	// 简单提取：查找 http:// 或 https:// 字符串，根据前面的 OID 区分
	// OID 1.3.6.1.5.5.7.48.1 = OCSP
	// OID 1.3.6.1.5.5.7.48.2 = CA Issuers
	data := string(value)
	for _, part := range strings.Split(data, "http") {
		if strings.HasPrefix(part, "s://") || strings.HasPrefix(part, "://") {
			u := "http" + part
			end := len(u)
			for i, c := range u {
				if c < 0x20 || c > 0x7e {
					end = i
					break
				}
			}
			u = u[:end]
			if parsed, err := url.Parse(u); err == nil && parsed.Host != "" {
				urlStr := parsed.String()
				if strings.Contains(urlStr, "ocsp") {
					ocsp = append(ocsp, urlStr)
				} else {
					caIssuers = append(caIssuers, urlStr)
				}
			}
		}
	}
	return
}

// parseKeyUsageInto 从 Key Usage 扩展值中解析密钥用途。
func parseKeyUsageInto(cert *x509.Certificate, value []byte) {
	var bs asn1.BitString
	if _, err := asn1.Unmarshal(value, &bs); err != nil {
		return
	}
	if bs.BitLength > 0 {
		usage := x509.KeyUsage(0)
		for i := 0; i < bs.BitLength && i < 9; i++ {
			if bs.At(i) != 0 {
				usage |= x509.KeyUsage(1 << uint(i))
			}
		}
		cert.KeyUsage = usage
	}
}

// parseExtKeyUsageInto 从 Extended Key Usage 扩展值中解析扩展密钥用途。
func parseExtKeyUsageInto(cert *x509.Certificate, value []byte) {
	// ExtKeyUsageSyntax ::= SEQUENCE OF OBJECT IDENTIFIER
	var oids []asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(value, &oids); err != nil {
		return
	}
	for _, oid := range oids {
		eku := oidToExtKeyUsage(oid)
		if eku >= 0 {
			cert.ExtKeyUsage = append(cert.ExtKeyUsage, x509.ExtKeyUsage(eku))
		} else {
			cert.UnknownExtKeyUsage = append(cert.UnknownExtKeyUsage, oid)
		}
	}
}

// oidToExtKeyUsage 将 OID 转换为 x509.ExtKeyUsage 常量。
func oidToExtKeyUsage(oid asn1.ObjectIdentifier) int {
	switch oid.String() {
	case "2.5.29.37.0":
		return int(x509.ExtKeyUsageAny)
	case "1.3.6.1.5.5.7.3.1":
		return int(x509.ExtKeyUsageServerAuth)
	case "1.3.6.1.5.5.7.3.2":
		return int(x509.ExtKeyUsageClientAuth)
	case "1.3.6.1.5.5.7.3.3":
		return int(x509.ExtKeyUsageCodeSigning)
	case "1.3.6.1.5.5.7.3.4":
		return int(x509.ExtKeyUsageEmailProtection)
	case "1.3.6.1.5.5.7.3.8":
		return int(x509.ExtKeyUsageTimeStamping)
	case "1.3.6.1.5.5.7.3.9":
		return int(x509.ExtKeyUsageOCSPSigning)
	default:
		return -1
	}
}

// parseBasicConstraintsInto 从 Basic Constraints 扩展值中解析基本约束。
func parseBasicConstraintsInto(cert *x509.Certificate, value []byte) {
	type basicConstraints struct {
		IsCA       bool `asn1:"optional"`
		MaxPathLen int  `asn1:"optional,default:-1"`
	}
	var bc basicConstraints
	if _, err := asn1.Unmarshal(value, &bc); err != nil {
		return
	}
	cert.IsCA = bc.IsCA
	if bc.MaxPathLen >= 0 {
		cert.MaxPathLen = bc.MaxPathLen
		cert.MaxPathLenZero = bc.MaxPathLen == 0
	}
}

// oidToSignatureAlgorithm 将签名算法 OID 转换为 x509.SignatureAlgorithm。
func oidToSignatureAlgorithm(oid asn1.ObjectIdentifier) x509.SignatureAlgorithm {
	switch oid.String() {
	case "1.2.840.113549.1.1.5":
		return x509.SHA1WithRSA
	case "1.2.840.113549.1.1.11":
		return x509.SHA256WithRSA
	case "1.2.840.113549.1.1.12":
		return x509.SHA384WithRSA
	case "1.2.840.113549.1.1.13":
		return x509.SHA512WithRSA
	case "1.2.840.113549.1.1.10":
		return x509.SHA256WithRSAPSS // RSAPSS (simplified)
	case "1.2.840.10045.4.3.2":
		return x509.ECDSAWithSHA256
	case "1.2.840.10045.4.3.3":
		return x509.ECDSAWithSHA384
	case "1.2.840.10045.4.3.4":
		return x509.ECDSAWithSHA512
	case "1.3.101.112":
		return x509.PureEd25519
	default:
		return x509.UnknownSignatureAlgorithm
	}
}

// parseASN1Time 解析 ASN.1 时间值（UTCTime 或 GeneralizedTime）
func parseASN1Time(raw asn1.RawValue) time.Time {
	s := string(raw.Bytes)
	// UTCTime: tag 23, 格式 YYMMDDHHMMSSZ
	if raw.Tag == 23 {
		if t, err := time.Parse("060102150405Z", s); err == nil {
			return t
		}
		if t, err := time.Parse("0601021504Z", s); err == nil {
			return t
		}
	}
	// GeneralizedTime: tag 24, 格式 YYYYMMDDHHMMSSZ
	if raw.Tag == 24 {
		if t, err := time.Parse("20060102150405Z", s); err == nil {
			return t
		}
	}
	return time.Time{}
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

	// 签名算法：如果标准解析返回 Unknown，尝试从 OID 推断
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
			// 简单提取：查找 http:// 或 https:// 开头的字符串
			data := string(ext.Value)
			for _, part := range strings.Split(data, "http") {
				if strings.HasPrefix(part, "s://") || strings.HasPrefix(part, "://") {
					u := "http" + part
					if parsed, err := url.Parse(u); err == nil && parsed.Host != "" {
						urls = append(urls, parsed.String())
					}
				}
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
	"1.3.6.1.4.1.44947.1.1.1": "ISRG EV",
	"2.16.840.1.114412.2.1":   "DigiCert EV",
	"2.16.840.1.113733.1.7.23.6": "VeriSign EV",
	"1.3.6.1.4.1.6449.1.2.1.5.1": "Comodo EV",
	"2.16.840.1.114028.10.1.2":   "Entrust EV",
	"1.2.616.1.113527.2.5.1.1":   "Certum EV",
}

// extractCertPolicies 从证书策略扩展中提取策略 OID 列表。
func extractCertPolicies(cert *x509.Certificate) []CertPolicy {
	var policies []CertPolicy
	for _, ext := range cert.Extensions {
		if ext.Id.String() != "2.5.29.32" {
			continue
		}
		// 解析 certificatePolicies SEQUENCE OF PolicyInformation
		var rawPolicies []asn1.RawValue
		rest, err := asn1.Unmarshal(ext.Value, &rawPolicies)
		if err != nil || len(rest) > 0 {
			// 尝试外层 SEQUENCE 解析
			var outer asn1.RawValue
			if _, err2 := asn1.Unmarshal(ext.Value, &outer); err2 == nil && outer.IsCompound {
				asn1.Unmarshal(outer.Bytes, &rawPolicies)
			}
		}
		for _, raw := range rawPolicies {
			if !raw.IsCompound {
				continue
			}
			// PolicyInformation ::= SEQUENCE { policyIdentifier OID, ... }
			var policyOID asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(raw.Bytes, &policyOID); err == nil {
				oidStr := policyOID.String()
				desc := knownPolicyOIDs[oidStr]
				if desc == "" {
					desc = classifyPolicyOID(oidStr)
				}
				policies = append(policies, CertPolicy{
					OID:         oidStr,
					Description: desc,
				})
			}
		}
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
// 对于包含非标准 Certificate Policies 的证书，使用宽松解析。
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
