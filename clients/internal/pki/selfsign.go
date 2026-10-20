// Package pki 提供本地 PKI 操作：自签名证书、CA 管理、CSR 生成、证书格式转换。
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/emmansun/gmsm/sm2"
)

// SelfSignRequest 是自签名证书请求参数。
type SelfSignRequest struct {
	// 主体信息
	CommonName   string `json:"common_name"`
	Organization string `json:"organization"`
	OrgUnit      string `json:"org_unit"`
	Country      string `json:"country"`
	Province     string `json:"province"`
	Locality     string `json:"locality"`
	// 密钥类型
	KeyType string `json:"key_type"` // rsa2048/rsa4096/ec256/ec384/ec521
	// 有效期（天）
	ValidDays int `json:"valid_days"`
	// SAN
	DNSNames    []string `json:"dns_names"`
	IPAddresses []string `json:"ip_addresses"`
	Emails      []string `json:"emails"`
	// 密钥用途
	IsCA              bool               `json:"is_ca"`
	KeyUsage          x509.KeyUsage      `json:"-"`
	ExtKeyUsage       []x509.ExtKeyUsage `json:"-"`
	PathLenConstraint int                `json:"path_len_constraint"`
}

// SelfSignResult 是自签名证书生成结果。
type SelfSignResult struct {
	CertPEM []byte `json:"cert_pem"`
	KeyPEM  []byte `json:"key_pem"`
	CertDER []byte `json:"cert_der"`
	KeyDER  []byte `json:"key_der"`
}

// GenerateSelfSigned 生成自签名证书。
func GenerateSelfSigned(req *SelfSignRequest) (*SelfSignResult, error) {
	// 生成密钥对
	privKey, pubKey, err := generateKeyPair(req.KeyType)
	if err != nil {
		return nil, fmt.Errorf("生成密钥对失败: %w", err)
	}

	// 构建证书模板
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("生成序列号失败: %w", err)
	}

	if req.ValidDays <= 0 {
		req.ValidDays = 365
	}
	// 有效期上限 10 年
	if req.ValidDays > 3650 {
		req.ValidDays = 3650
	}

	notBefore := time.Now()
	notAfter := notBefore.AddDate(0, 0, req.ValidDays)

	subject := pkix.Name{
		CommonName: req.CommonName,
	}
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

	// 覆盖自定义密钥用途
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

	// 自签名
	// 国密分派：SM2 自签走 smx509
	certDER, err := createCertificateAny(rand.Reader, template, template, pubKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("创建证书失败: %w", err)
	}

	// 编码 PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := marshalPKCS8Any(privKey)
	if err != nil {
		return nil, fmt.Errorf("编码私钥失败: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	return &SelfSignResult{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
		CertDER: certDER,
		KeyDER:  keyDER,
	}, nil
}

// generateKeyPair 根据类型生成密钥对，返回 (私钥, 公钥)。
func generateKeyPair(keyType string) (crypto.PrivateKey, crypto.PublicKey, error) {
	switch keyType {
	case "rsa2048":
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, err
		}
		return key, &key.PublicKey, nil
	case "rsa4096":
		key, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, nil, err
		}
		return key, &key.PublicKey, nil
	case "rsa8192":
		key, err := rsa.GenerateKey(rand.Reader, 8192)
		if err != nil {
			return nil, nil, err
		}
		return key, &key.PublicKey, nil
	case "ec256":
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return key, &key.PublicKey, nil
	case "ec384":
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return key, &key.PublicKey, nil
	case "ec521":
		key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return key, &key.PublicKey, nil
	case "sm2":
		key, err := sm2.GenerateKey(rand.Reader) //nolint:staticcheck // 需要 SM2 私钥类型
		if err != nil {
			return nil, nil, err
		}
		return key, &key.PublicKey, nil
	default:
		return nil, nil, fmt.Errorf("不支持的密钥类型: %s", keyType)
	}
}

// ParsePrivateKeyFromPEM 从 PEM 数据解析私钥。
func ParsePrivateKeyFromPEM(pemData []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("无法解码私钥 PEM 数据")
	}

	// 尝试 PKCS8
	key, err := parsePKCS8Any(block.Bytes)
	if err == nil {
		return key, nil
	}

	// 尝试 PKCS1 RSA
	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return rsaKey, nil
	}

	// 尝试 EC
	ecKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err == nil {
		return ecKey, nil
	}

	return nil, fmt.Errorf("无法解析私钥（尝试了 PKCS8/PKCS1/EC 格式）")
}
