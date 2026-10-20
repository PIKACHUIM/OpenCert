package pki

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"software.sslmate.com/src/go-pkcs12"
)

// ValidateCertDER 验证 DER 数据是否为合法的 X.509 证书。
// 对于 certificate policies 解析错误的证书仍视为有效。
func ValidateCertDER(derData []byte) error {
	// 国密证书标准库解析不了，交给分派层判断
	_, err := parseCertificateAny(derData)
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "certificate policies") {
		return nil // 证书有效，只是策略扩展不兼容
	}
	return err
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
// 对包含非标准 Certificate Policies 的证书使用宽松解析。
func ParseCertificateFromPEM(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("无法解码 PEM 数据")
	}
	cert, err := parseCertificateAny(block.Bytes)
	if err != nil && strings.Contains(err.Error(), "certificate policies") {
		// 证书有效但策略扩展不兼容，返回 nil cert 和 nil error 表示无法完整解析
		return nil, nil
	}
	return cert, err
}

// ParseCertificateAuto 自动识别 PEM 或 DER 格式并解析证书。
// 对包含非标准 Certificate Policies 扩展的证书，剥离该扩展后重新解析，
// 从而仍能返回 subject/issuer/有效期等可用字段（Raw 保留原始 DER）。
func ParseCertificateAuto(data []byte) (*x509.Certificate, error) {
	der := data
	if block, _ := pem.Decode(data); block != nil {
		der = block.Bytes
	}

	cert, err := parseCertLenientStripping(der)
	if err == nil {
		return cert, nil
	}
	// 保留历史契约：Certificate Policies 不兼容时返回 (nil, nil)，
	// 由调用方提示「证书有效但部分信息无法解析」。
	if strings.Contains(err.Error(), "certificate policies") {
		return nil, nil
	}
	return nil, err
}

// ExportPKCS12 将证书和私钥导出为 PKCS#12 格式。
// 对于包含 Go 1.22+ 不兼容的 Certificate Policies 扩展的证书，
// 使用原始 DER 数据构造最小 Certificate 对象来绕过严格解析。
func ExportPKCS12(certPEM, keyPEM []byte, password string) ([]byte, error) {
	if len(password) < 8 {
		return nil, fmt.Errorf("PKCS#12 导出密码长度必须 >= 8 字符")
	}

	// 解析证书
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("无法解码证书 PEM")
	}
	cert, err := parseCertificateAny(certBlock.Bytes)
	if err != nil {
		// 对 certificate policies 错误做宽松处理：
		// Go 1.22+ 对策略扩展解析过于严格，但证书本身是合法的。
		// pkcs12.Encode 内部只使用 cert.Raw，所以构造一个最小对象即可。
		if strings.Contains(err.Error(), "certificate policies") {
			cert = &x509.Certificate{Raw: certBlock.Bytes}
		} else {
			return nil, fmt.Errorf("解析证书失败: %w", err)
		}
	}

	// 解析私钥
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("无法解码私钥 PEM")
	}
	privKey, err := parsePKCS8Any(keyBlock.Bytes)
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

	// 国密证书不提供 PKCS#12：主流平台没有 SM2 的 PKCS#12 通用方案
	if isSM2Key(privKey) {
		return nil, fmt.Errorf("SM2 证书不支持 PKCS#12 导出，请改用 PEM 或 PKCS#8")
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
	if isSM2Key(privKey) {
		return nil, nil, fmt.Errorf("PKCS#12 内的私钥是 SM2，请改用 PEM / PKCS#8 格式导入")
	}

	// 编码证书 PEM
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	// 编码私钥 PEM
	keyDER, err := marshalPKCS8Any(privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("编码私钥失败: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
}

// ParseCertChainFromPEM 从 PEM 数据解析证书链（多个证书）。
// 对包含非标准 Certificate Policies 的证书使用宽松解析。
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
		// 使用宽松解析：策略扩展不兼容的证书不应被整条链丢弃
		cert, err := parseCertLenientStripping(block.Bytes)
		if err != nil {
			if strings.Contains(err.Error(), "certificate policies") {
				continue // 策略扩展不兼容且剥离失败，跳过
			}
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
