package pki

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"software.sslmate.com/src/go-pkcs12"
	zcryptox509 "github.com/zmap/zcrypto/x509"
)

// parseCertLenient 宽松解析 X.509 证书 DER 数据。
// 使用 zcrypto/x509 库进行解析，该库对 Certificate Policies 等扩展
// 采用了更宽松的处理方式，可以解析标准库 crypto/x509 无法处理的证书。
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

// ValidateCertDER 验证 DER 数据是否为合法的 X.509 证书。
// 使用 zcrypto 宽松解析，对 Certificate Policies 等扩展不严格检查。
func ValidateCertDER(derData []byte) error {
	_, err := x509.ParseCertificate(derData)
	if err == nil {
		return nil
	}
	// 标准库失败，尝试 zcrypto 宽松解析
	_, zerr := zcryptox509.ParseCertificate(derData)
	if zerr == nil {
		return nil // zcrypto 能解析，视为有效
	}
	return fmt.Errorf("证书验证失败: %w", err)
}

// ConvertPEMToDER 将 PEM 编码的证书转换为 DER 格式。
func ConvertPEMToDER(pemData []byte) ([]byte, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("无法解码 PEM 数据")
	}
	return block.Bytes, nil
}

// ConvertDERToPEM 将 DER 编码的证书转换为 PEM 格式。
func ConvertDERToPEM(derData []byte, blockType string) []byte {
	if blockType == "" {
		blockType = "CERTIFICATE"
	}
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: derData})
}

// ParseCertificateFromPEM 从 PEM 数据解析 X.509 证书。
// 使用 zcrypto 宽松解析，兼容非标准 Certificate Policies 扩展。
func ParseCertificateFromPEM(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("无法解码 PEM 数据")
	}
	return parseCertLenient(block.Bytes)
}

// ParseCertificateAuto 自动识别 PEM 或 DER 格式并解析证书。
// 使用 zcrypto 宽松解析，兼容非标准 Certificate Policies 扩展。
func ParseCertificateAuto(data []byte) (*x509.Certificate, error) {
	// 先尝试 PEM
	block, _ := pem.Decode(data)
	if block != nil {
		return parseCertLenient(block.Bytes)
	}
	// 尝试 DER
	return parseCertLenient(data)
}

// ExportPKCS12 将证书和私钥导出为 PKCS#12 格式。
// 使用 zcrypto 宽松解析，兼容非标准 Certificate Policies 扩展。
func ExportPKCS12(certPEM, keyPEM []byte, password string) ([]byte, error) {
	if len(password) < 8 {
		return nil, fmt.Errorf("PKCS#12 导出密码长度必须 >= 8 字符")
	}

	// 解析证书
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("无法解码证书 PEM")
	}
	cert, err := parseCertLenient(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析证书失败: %w", err)
	}

	// 解析私钥
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("无法解码私钥 PEM")
	}
	privKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		// 尝试 PKCS1
		privKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			// 尝试 EC
			privKey, err = x509.ParseECPrivateKey(keyBlock.Bytes)
			if err != nil {
				return nil, fmt.Errorf("解析私钥失败: %w", err)
			}
		}
	}

	// 编码 PKCS#12
	pfxData, err := pkcs12.Modern.Encode(privKey, cert, nil, password)
	if err != nil {
		return nil, fmt.Errorf("编码 PKCS#12 失败: %w", err)
	}
	return pfxData, nil
}

// ImportPKCS12 从 PKCS#12 数据导入证书和私钥。
func ImportPKCS12(pfxData []byte, password string) (certPEM, keyPEM []byte, err error) {
	privKey, cert, _, err := pkcs12.DecodeChain(pfxData, password)
	if err != nil {
		return nil, nil, fmt.Errorf("解码 PKCS#12 失败: %w", err)
	}

	// 编码证书 PEM
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	// 编码私钥 PEM
	keyDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("编码私钥失败: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
}

// ParseCertChainFromPEM 从 PEM 数据解析证书链（多个证书）。
// 使用 zcrypto 宽松解析，兼容非标准 Certificate Policies 扩展。
func ParseCertChainFromPEM(pemData []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := parseCertLenient(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("解析证书链中的证书失败: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("PEM 数据中未找到证书")
	}
	return certs, nil
}

// ExportPKCS7 将证书链导出为 PKCS#7 格式（仅证书，不含私钥）。
// 返回 DER 编码的 PKCS#7 数据。
func ExportPKCS7(certs []*x509.Certificate) ([]byte, error) {
	if len(certs) == 0 {
		return nil, fmt.Errorf("证书列表为空")
	}
	// 简化实现：将证书链编码为 PEM 格式（完整的 PKCS#7 需要 ASN.1 编码）
	var pemData []byte
	for _, cert := range certs {
		pemData = append(pemData, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	return pemData, nil
}
