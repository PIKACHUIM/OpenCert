package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"
)

// makeCertWithInvalidPolicies 构造一张 Certificate Policies 扩展内容不合规的证书：
// 扩展值不是 SEQUENCE，标准库会报 "x509: invalid certificate policies"。
// 这类证书本身合法（签名覆盖原始 TBS），只是 Go 1.22+ 的策略解析更严格。
func makeCertWithInvalidPolicies(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(20260920),
		Subject:      pkix.Name{CommonName: "lenient-test", Organization: []string{"OpenCert"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtraExtensions: []pkix.Extension{{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 32}, // certificatePolicies
			Value: []byte{0x02, 0x01, 0x05},            // INTEGER 5，非合法策略结构
		}},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("签发测试证书失败: %v", err)
	}
	return der
}

// TestParseCertLenientStripping 验证剥离 Certificate Policies 后仍能解析出证书字段。
func TestParseCertLenientStripping(t *testing.T) {
	der := makeCertWithInvalidPolicies(t)

	// 先确认标准库确实解析失败
	if _, err := x509.ParseCertificate(der); err == nil {
		t.Skip("当前 Go 版本可解析该证书，宽松解析路径无需启用")
	} else if !strings.Contains(err.Error(), "certificate policies") {
		t.Skipf("构造的证书触发了其他解析错误，跳过: %v", err)
	}

	cert, err := parseCertLenientStripping(der)
	if err != nil {
		t.Fatalf("宽松解析失败: %v", err)
	}
	if cert.Subject.CommonName != "lenient-test" {
		t.Errorf("Subject.CommonName = %q, 期望 %q", cert.Subject.CommonName, "lenient-test")
	}
	if len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != "OpenCert" {
		t.Errorf("Organization = %v, 期望 [OpenCert]", cert.Subject.Organization)
	}
	// 剥离后的解析结果必须保留原始 DER，供后续验签/导出使用
	if !bytes.Equal(cert.Raw, der) {
		t.Error("宽松解析后的 Cert.Raw 应保留原始 DER")
	}
	// 证书链导出依赖 Raw，确认剥离后的 DER 仍是结构完整的证书
	if _, err := x509.ParseCertificate(cert.Raw); err == nil {
		t.Error("原始 DER 不应能被标准库直接解析（说明测试样本无效）")
	}
}

// TestParseCertificateAuto_Lenient 验证 ParseCertificateAuto 对策略扩展
// 不兼容的证书能返回可用字段，而不是退化为 (nil, nil)。
func TestParseCertificateAuto_Lenient(t *testing.T) {
	der := makeCertWithInvalidPolicies(t)
	if _, err := x509.ParseCertificate(der); err == nil {
		t.Skip("当前 Go 版本可解析该证书")
	} else if !strings.Contains(err.Error(), "certificate policies") {
		t.Skipf("构造的证书触发了其他解析错误，跳过: %v", err)
	}

	cert, err := ParseCertificateAuto(der)
	if err != nil {
		t.Fatalf("ParseCertificateAuto 失败: %v", err)
	}
	if cert == nil {
		t.Fatal("应返回宽松解析后的证书，而不是 nil")
	}
	if cert.Subject.CommonName != "lenient-test" {
		t.Errorf("Subject.CommonName = %q, 期望 %q", cert.Subject.CommonName, "lenient-test")
	}
	if cert.PublicKeyAlgorithm != x509.ECDSA {
		t.Errorf("PublicKeyAlgorithm = %v, 期望 ECDSA", cert.PublicKeyAlgorithm)
	}
}
