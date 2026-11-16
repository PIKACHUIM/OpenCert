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
	// KeyUsage 是请求写入 CSR 的密钥用法，可选值：
	// digital_signature / content_commitment / key_encipherment / data_encipherment /
	// key_agreement / cert_sign / crl_sign / encipher_only / decipher_only。
	KeyUsage []string `json:"key_usage"`
	// ExtKeyUsage 是请求写入 CSR 的扩展密钥用法，可选值：
	// server_auth / client_auth / code_signing / email_protection / ocsp_signing / timestamping。
	ExtKeyUsage []string `json:"ext_key_usage"`
}

// CSRResult 是 CSR 生成结果。
type CSRResult struct {
	CSRPEM []byte `json:"csr_pem"`
	CSRDER []byte `json:"csr_der"`
	KeyPEM []byte `json:"key_pem"`
	KeyDER []byte `json:"key_der"`
}

// GenerateCSR 使用客户端本地软件密钥生成并签名 CSR；此函数不调用 TPM/智能卡 Provider。
func GenerateCSR(req *CSRRequest) (*CSRResult, error) {
	if req == nil {
		return nil, fmt.Errorf("CSR 请求不能为空")
	}
	privKey, _, err := generateKeyPair(req.KeyType)
	if err != nil {
		return nil, fmt.Errorf("生成密钥对失败: %w", err)
	}
	signer, ok := privKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("私钥不支持签名操作")
	}
	result, err := GenerateCSRWithSigner(req, signer)
	if err != nil {
		return nil, err
	}
	keyDER, err := marshalPKCS8Any(privKey)
	if err != nil {
		return nil, fmt.Errorf("编码私钥失败: %w", err)
	}
	result.KeyDER = keyDER
	result.KeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return result, nil
}

// GenerateCSRWithSigner builds and signs a CSR using the supplied signer without exporting its private key.
func GenerateCSRWithSigner(req *CSRRequest, signer crypto.Signer) (*CSRResult, error) {
	if req == nil {
		return nil, fmt.Errorf("CSR 请求不能为空")
	}
	if signer == nil {
		return nil, fmt.Errorf("CSR 签名器不能为空")
	}

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
	if len(req.ExtraSubject) > 0 {
		subject.ExtraNames = buildExtraNames(req.ExtraSubject)
	}

	template := &x509.CertificateRequest{
		Subject:            subject,
		SignatureAlgorithm: resolveSignatureAlgorithm(req.KeyType, req.DigestType),
		DNSNames:           req.DNSNames,
		EmailAddresses:     req.Emails,
	}
	for _, ipStr := range req.IPAddresses {
		if ip := net.ParseIP(ipStr); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		}
	}
	if err := appendCSRExtensions(template, req); err != nil {
		return nil, err
	}

	csrDER, err := createCSRAny(rand.Reader, template, signer)
	if err != nil {
		return nil, fmt.Errorf("创建 CSR 失败: %w", err)
	}
	if err := checkCSRSignatureAny(csrDER); err != nil {
		return nil, fmt.Errorf("CSR 签名验证失败: %w", err)
	}
	return &CSRResult{
		CSRPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}),
		CSRDER: csrDER,
	}, nil
}

// appendCSRExtensions 把请求的 KeyUsage / ExtKeyUsage 写入 CSR 扩展请求。
// 证书最终是否采纳由 CA 决定；这里只表达申请方的意图。
func appendCSRExtensions(template *x509.CertificateRequest, req *CSRRequest) error {
	usageBits := map[string]int{
		"digital_signature":  0,
		"content_commitment": 1,
		"key_encipherment":   2,
		"data_encipherment":  3,
		"key_agreement":      4,
		"cert_sign":          5,
		"crl_sign":           6,
		"encipher_only":      7,
		"decipher_only":      8,
	}
	if len(req.KeyUsage) > 0 {
		var mask int
		for _, name := range req.KeyUsage {
			bit, ok := usageBits[name]
			if !ok {
				return fmt.Errorf("未知的 key_usage: %s", name)
			}
			mask |= 1 << bit
		}
		highest := 0
		for i := 0; i < 16; i++ {
			if mask&(1<<i) != 0 {
				highest = i
			}
		}
		bits := make([]byte, highest/8+1)
		for i := 0; i <= highest; i++ {
			if mask&(1<<i) != 0 {
				bits[i/8] |= 0x80 >> (uint(i) % 8)
			}
		}
		value, err := asn1.Marshal(asn1.BitString{Bytes: bits, BitLength: highest + 1})
		if err != nil {
			return fmt.Errorf("编码 key_usage 扩展失败: %w", err)
		}
		template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 15},
			Value: value,
		})
	}

	extOIDs := map[string]asn1.ObjectIdentifier{
		"server_auth":      {1, 3, 6, 1, 5, 5, 7, 3, 1},
		"client_auth":      {1, 3, 6, 1, 5, 5, 7, 3, 2},
		"code_signing":     {1, 3, 6, 1, 5, 5, 7, 3, 3},
		"email_protection": {1, 3, 6, 1, 5, 5, 7, 3, 4},
		"ocsp_signing":     {1, 3, 6, 1, 5, 5, 7, 3, 9},
		"timestamping":     {1, 3, 6, 1, 5, 5, 7, 3, 8},
	}
	if len(req.ExtKeyUsage) > 0 {
		oids := make([]asn1.ObjectIdentifier, 0, len(req.ExtKeyUsage))
		for _, name := range req.ExtKeyUsage {
			oid, ok := extOIDs[name]
			if !ok {
				return fmt.Errorf("未知的 ext_key_usage: %s", name)
			}
			oids = append(oids, oid)
		}
		value, err := asn1.Marshal(oids)
		if err != nil {
			return fmt.Errorf("编码 ext_key_usage 扩展失败: %w", err)
		}
		template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 37},
			Value: value,
		})
	}
	return nil
}

// resolveSignatureAlgorithm 根据密钥类型和摘要类型返回签名算法。// digestType 可为 "sha1"/"sha256"/"sha384"/"sha512"，空值则按密钥类型取默认值（sha256）。
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
	case "sm2":
		// SM2 只配 SM3：标准库没有该算法枚举，交由 smx509 依据私钥类型决定（SM2WithSM3）
		return x509.UnknownSignatureAlgorithm
	default:
		return x509.SHA256WithRSA
	}
}

// extraNameOIDs 是额外 DN 字段名到 OID 的映射表（对齐 dn.txt 25 个标准字段）。
// 其中 C/ST/L/O/OU/CN 已由 pkix.Name 原生字段处理，此处仅包含需要通过 ExtraNames 写入的字段。
var extraNameOIDs = map[string]asn1.ObjectIdentifier{
	"emailAddress":           {1, 2, 840, 113549, 1, 9, 1},
	"serialNumber":           {2, 5, 4, 5},
	"givenName":              {2, 5, 4, 42},
	"surname":                {2, 5, 4, 4},
	"title":                  {2, 5, 4, 12},
	"initials":               {2, 5, 4, 43},
	"description":            {2, 5, 4, 13},
	"role":                   {2, 5, 4, 72},
	"pseudonym":              {2, 5, 4, 65},
	"name":                   {2, 5, 4, 41},
	"dnQualifier":            {2, 5, 4, 46},
	"generationQualifier":    {2, 5, 4, 44},
	"x500UniqueIdentifier":   {2, 5, 4, 45},
	"businessCategory":       {2, 5, 4, 15},
	"streetAddress":          {2, 5, 4, 9},
	"postalCode":             {2, 5, 4, 17},
	"IncLocalityName":        {1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 1},
	"IncStateOrProvinceName": {1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 2},
	"IncCountryName":         {1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 3},
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
