package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"net"
)

// CSRRequest 是 CSR 生成请求参数。
type CSRRequest struct {
	CommonName   string            `json:"common_name"`
	Organization string            `json:"organization"`
	OrgUnit      string            `json:"org_unit"`
	Country      string            `json:"country"`
	Province     string            `json:"province"`
	Locality     string            `json:"locality"`
	KeyType      string            `json:"key_type"`    // rsa2048/rsa4096/ec256/ec384/ec521
	DigestType   string            `json:"digest_type"` // sha256/sha384/sha512；空值则按密钥类型选默认值
	DNSNames     []string          `json:"dns_names"`
	IPAddresses  []string          `json:"ip_addresses"`
	Emails       []string          `json:"emails"`
	ExtraSubject map[string]string `json:"extra_subject"` // 额外 DN 字段（serialNumber/givenName/surname 等）
}

// CSRResult 是 CSR 生成结果。
type CSRResult struct {
	CSRPEM  []byte `json:"csr_pem"`
	CSRDER  []byte `json:"csr_der"`
	KeyPEM  []byte `json:"key_pem"`
	KeyDER  []byte `json:"key_der"`
}

// GenerateCSR 生成 CSR（证书签名请求）。
// 密钥对在本地生成，CSR 使用私钥签名，确保片上生成的可信性。
func GenerateCSR(req *CSRRequest) (*CSRResult, error) {
	// 生成密钥对
	privKey, _, err := generateKeyPair(req.KeyType)
	if err != nil {
		return nil, fmt.Errorf("生成密钥对失败: %w", err)
	}

	// 构建主体
	subject := pkix.Name{CommonName: req.CommonName}
	if req.Organization != "" {
		subject.Organization = []string{req.Organization}
	}
	if req.OrgUnit != "" {
		subject.OrganizationalUnit = []string{req.OrgUnit}
	}
	if req.Country != "" {
		subject.Country = []string{req.Country}
	}
	if req.Province != "" {
		subject.Province = []string{req.Province}
	}
	if req.Locality != "" {
		subject.Locality = []string{req.Locality}
	}

	// 写入额外 DN 字段（serialNumber/givenName/surname 等 25 个标准字段）
	if len(req.ExtraSubject) > 0 {
		subject.ExtraNames = buildExtraNames(req.ExtraSubject)
	}

	// 构建 CSR 模板
	template := &x509.CertificateRequest{
		Subject:            subject,
		SignatureAlgorithm: resolveSignatureAlgorithm(req.KeyType, req.DigestType),
		DNSNames:           req.DNSNames,
		EmailAddresses:     req.Emails,
	}

	// 解析 IP 地址
	for _, ipStr := range req.IPAddresses {
		if ip := net.ParseIP(ipStr); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		}
	}

	// 使用私钥签名 CSR
	signer, ok := privKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("私钥不支持签名操作")
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, signer)
	if err != nil {
		return nil, fmt.Errorf("创建 CSR 失败: %w", err)
	}

	// 验证 CSR 签名
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("解析 CSR 失败: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR 签名验证失败: %w", err)
	}

	// 编码 PEM
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	keyDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("编码私钥失败: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	return &CSRResult{
		CSRPEM: csrPEM,
		CSRDER: csrDER,
		KeyPEM: keyPEM,
		KeyDER: keyDER,
	}, nil
}

// resolveSignatureAlgorithm 根据密钥类型和摘要类型返回签名算法。
// digestType 可为 "sha1"/"sha256"/"sha384"/"sha512"，空值则按密钥类型取默认值（sha256）。
// Ed25519 忽略 digestType，始终返回 x509.PureEd25519。
func resolveSignatureAlgorithm(keyType, digestType string) x509.SignatureAlgorithm {
	switch keyType {
	case "rsa2048", "rsa4096", "rsa8192":
		switch digestType {
		case "sha1":
			return x509.SHA1WithRSA
		case "sha384":
			return x509.SHA384WithRSA
		case "sha512":
			return x509.SHA512WithRSA
		default: // sha256 及空值
			return x509.SHA256WithRSA
		}
	case "ec256":
		switch digestType {
		case "sha384":
			return x509.ECDSAWithSHA384
		case "sha512":
			return x509.ECDSAWithSHA512
		default:
			return x509.ECDSAWithSHA256
		}
	case "ec384":
		switch digestType {
		case "sha256":
			return x509.ECDSAWithSHA256
		case "sha512":
			return x509.ECDSAWithSHA512
		default:
			return x509.ECDSAWithSHA384
		}
	case "ec521":
		switch digestType {
		case "sha256":
			return x509.ECDSAWithSHA256
		case "sha384":
			return x509.ECDSAWithSHA384
		default:
			return x509.ECDSAWithSHA512
		}
	case "ed25519":
		return x509.PureEd25519
	default:
		return x509.SHA256WithRSA
	}
}

// extraNameOIDs 是额外 DN 字段名到 OID 的映射表（对齐 dn.txt 25 个标准字段）。
// 其中 C/ST/L/O/OU/CN 已由 pkix.Name 原生字段处理，此处仅包含需要通过 ExtraNames 写入的字段。
var extraNameOIDs = map[string]asn1.ObjectIdentifier{
	"emailAddress":            {1, 2, 840, 113549, 1, 9, 1},
	"serialNumber":            {2, 5, 4, 5},
	"givenName":               {2, 5, 4, 42},
	"surname":                 {2, 5, 4, 4},
	"title":                   {2, 5, 4, 12},
	"initials":                {2, 5, 4, 43},
	"description":             {2, 5, 4, 13},
	"role":                    {2, 5, 4, 72},
	"pseudonym":               {2, 5, 4, 65},
	"name":                    {2, 5, 4, 41},
	"dnQualifier":             {2, 5, 4, 46},
	"generationQualifier":     {2, 5, 4, 44},
	"x500UniqueIdentifier":    {2, 5, 4, 45},
	"businessCategory":        {2, 5, 4, 15},
	"streetAddress":           {2, 5, 4, 9},
	"postalCode":              {2, 5, 4, 17},
	"IncLocalityName":         {1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 1},
	"IncStateOrProvinceName":  {1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 2},
	"IncCountryName":          {1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 3},
}

// buildExtraNames 将 map[string]string 转换为 pkix.AttributeTypeAndValue 切片。
func buildExtraNames(extra map[string]string) []pkix.AttributeTypeAndValue {
	var names []pkix.AttributeTypeAndValue
	for key, val := range extra {
		if val == "" {
			continue
		}
		oid, ok := extraNameOIDs[key]
		if !ok {
			continue
		}
		names = append(names, pkix.AttributeTypeAndValue{
			Type:  oid,
			Value: val,
		})
	}
	return names
}
