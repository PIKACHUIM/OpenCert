package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

// CAInfo 是本地 CA 信息。
type CAInfo struct {
	UUID        string    `json:"uuid"`
	Name        string    `json:"name"`
	CertPEM     []byte    `json:"cert_pem"`
	IssuedCount int       `json:"issued_count"`
	CRLCount    int       `json:"crl_count"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
}

// IssueCertRequest 是 CA 签发子证书的请求参数。
type IssueCertRequest struct {
	// 主体信息
	CommonName   string `json:"common_name"`
	Organization string `json:"organization"`
	OrgUnit      string `json:"org_unit"`
	Country      string `json:"country"`
	// 有效期（天）
	ValidDays int `json:"valid_days"`
	// 密钥类型
	KeyType string `json:"key_type"`
	// SAN
	DNSNames    []string `json:"dns_names"`
	IPAddresses []string `json:"ip_addresses"`
	Emails      []string `json:"emails"`
	// 基本约束
	IsCA              bool `json:"is_ca"`
	PathLenConstraint int  `json:"path_len_constraint"`
	// 密钥用途
	KeyUsage    x509.KeyUsage      `json:"-"`
	ExtKeyUsage []x509.ExtKeyUsage `json:"-"`
}

// IssueCertResult 是 CA 签发证书的结果。
type IssueCertResult struct {
	CertPEM []byte `json:"cert_pem"`
	KeyPEM  []byte `json:"key_pem"`
	CertDER []byte `json:"cert_der"`
}

// IssueCertificate 使用 CA 签发子证书。
func IssueCertificate(caCert *x509.Certificate, caKey crypto.PrivateKey, req *IssueCertRequest) (*IssueCertResult, error) {
	// 生成子证书密钥对
	privKey, pubKey, err := generateKeyPair(req.KeyType)
	if err != nil {
		return nil, fmt.Errorf("生成密钥对失败: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("生成序列号失败: %w", err)
	}

	if req.ValidDays <= 0 {
		req.ValidDays = 365
	}
	if req.ValidDays > 3650 {
		req.ValidDays = 3650
	}

	notBefore := time.Now()
	notAfter := notBefore.AddDate(0, 0, req.ValidDays)

	// 子证书有效期不能超过 CA 有效期
	if notAfter.After(caCert.NotAfter) {
		notAfter = caCert.NotAfter
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

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		IsCA:                  req.IsCA,
	}

	if req.IsCA {
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature
		template.MaxPathLen = req.PathLenConstraint
		template.MaxPathLenZero = req.PathLenConstraint == 0
	} else {
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}

	if req.KeyUsage != 0 {
		template.KeyUsage = req.KeyUsage
	}
	if len(req.ExtKeyUsage) > 0 {
		template.ExtKeyUsage = req.ExtKeyUsage
	}

	// SAN
	template.DNSNames = req.DNSNames
	template.EmailAddresses = req.Emails
	for _, ipStr := range req.IPAddresses {
		if ip := net.ParseIP(ipStr); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		}
	}

	// 使用 CA 签发
	// 国密分派：SM2 CA / SM2 用户密钥走 smx509
	certDER, err := createCertificateAny(rand.Reader, template, caCert, pubKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("签发证书失败: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := marshalPKCS8Any(privKey)
	if err != nil {
		return nil, fmt.Errorf("编码私钥失败: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	return &IssueCertResult{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
		CertDER: certDER,
	}, nil
}

// RevokeCertificate 将证书加入 CRL 吊销列表。
func RevokeCertificate(caCert *x509.Certificate, caKey crypto.PrivateKey, revokedCerts []pkix.RevokedCertificate) ([]byte, error) {
	now := time.Now()
	nextUpdate := now.AddDate(0, 0, 7) // CRL 有效期 7 天

	crlBytes, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		RevokedCertificateEntries: toRevocationEntries(revokedCerts),
		Number:                    big.NewInt(now.Unix()),
		ThisUpdate:                now,
		NextUpdate:                nextUpdate,
	}, caCert, caKey.(crypto.Signer))
	if err != nil {
		return nil, fmt.Errorf("生成 CRL 失败: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlBytes}), nil
}

// toRevocationEntries 将 pkix.RevokedCertificate 转换为 x509.RevocationListEntry。
func toRevocationEntries(revoked []pkix.RevokedCertificate) []x509.RevocationListEntry {
	entries := make([]x509.RevocationListEntry, len(revoked))
	for i, r := range revoked {
		entries[i] = x509.RevocationListEntry{
			SerialNumber:   r.SerialNumber,
			RevocationTime: r.RevocationTime,
		}
	}
	return entries
}
