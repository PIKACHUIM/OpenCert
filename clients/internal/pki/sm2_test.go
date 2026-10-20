package pki

import (
	"crypto/ecdsa"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

// TestGenerateCSR_SM2 验证 SM2 CSR 的生成、解析与自校验。
func TestGenerateCSR_SM2(t *testing.T) {
	res, err := GenerateCSR(&CSRRequest{
		CommonName: "sm2.example.com",
		OrgUnit:    "国密测试",
		KeyType:    "sm2",
		DNSNames:   []string{"sm2.example.com"},
	})
	if err != nil {
		t.Fatalf("GenerateCSR: %v", err)
	}

	// CSR 必须能被国密库解析并通过自校验（SM2WithSM3）
	csr, err := smx509.ParseCertificateRequest(res.CSRDER)
	if err != nil {
		t.Fatalf("解析 SM2 CSR: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("SM2 CSR 签名校验失败: %v", err)
	}
	if csr.Subject.CommonName != "sm2.example.com" {
		t.Fatalf("CSR CN 不正确: %s", csr.Subject.CommonName)
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != sm2.P256() {
		t.Fatalf("CSR 公钥不是 SM2: %T", csr.PublicKey)
	}

	// 私钥 PEM 应为 PKCS#8，可被通用解析路径识别
	block, _ := pem.Decode(res.KeyPEM)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("私钥 PEM 块不正确: %v", block)
	}
	key, err := parsePKCS8Any(block.Bytes)
	if err != nil {
		t.Fatalf("解析 SM2 私钥: %v", err)
	}
	if _, ok := key.(*sm2.PrivateKey); !ok {
		t.Fatalf("私钥类型不是 SM2: %T", key)
	}
}

// TestSelfSignSM2 验证 SM2 自签证书的生成与解析。
func TestSelfSignSM2(t *testing.T) {
	res, err := GenerateSelfSigned(&SelfSignRequest{
		CommonName: "SM2 Test Root",
		KeyType:    "sm2",
		ValidDays:  30,
	})
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}

	cert, err := smx509.ParseCertificate(res.CertDER)
	if err != nil {
		t.Fatalf("解析 SM2 自签证书: %v", err)
	}
	if cert.Subject.CommonName != "SM2 Test Root" {
		t.Fatalf("证书 CN 不正确: %s", cert.Subject.CommonName)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != sm2.P256() {
		t.Fatalf("证书公钥不是 SM2: %T", cert.PublicKey)
	}
	// 自签证书用自身公钥验签
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		t.Fatalf("SM2 自签证书验签失败: %v", err)
	}

	// 通用解析层也应识别（业务代码统一走 parseCertificateAny）
	if _, err := parseCertificateAny(res.CertDER); err != nil {
		t.Fatalf("parseCertificateAny 解析 SM2 证书失败: %v", err)
	}
}

// TestSM2CertRejectsPKCS12 验证 SM2 证书不会导出 PKCS#12。
func TestSM2CertRejectsPKCS12(t *testing.T) {
	res, err := GenerateSelfSigned(&SelfSignRequest{CommonName: "SM2 PFX", KeyType: "sm2", ValidDays: 1})
	if err != nil {
		t.Fatalf("生成 SM2 自签证书: %v", err)
	}

	_, err = ExportPKCS12(res.CertPEM, res.KeyPEM, "password123")
	if err == nil {
		t.Fatal("SM2 证书导出 PKCS#12 应返回错误")
	}
	if !strings.Contains(err.Error(), "SM2") {
		t.Fatalf("错误信息应提示 SM2 限制，实际: %v", err)
	}
}

// TestSM2CAIssueSM2Cert 验证 SM2 CA 签发 SM2 终端证书。
func TestSM2CAIssueSM2Cert(t *testing.T) {
	caRes, err := GenerateSelfSigned(&SelfSignRequest{
		CommonName:        "SM2 Test CA",
		KeyType:           "sm2",
		ValidDays:         365,
		IsCA:              true,
		PathLenConstraint: 0,
	})
	if err != nil {
		t.Fatalf("生成 SM2 CA: %v", err)
	}

	caCert, err := parseCertificateAny(caRes.CertDER)
	if err != nil {
		t.Fatalf("解析 SM2 CA 证书: %v", err)
	}
	caKey, err := ParsePrivateKeyFromPEM(caRes.KeyPEM)
	if err != nil {
		t.Fatalf("解析 SM2 CA 私钥: %v", err)
	}

	issued, err := IssueCertificate(caCert, caKey, &IssueCertRequest{
		CommonName: "leaf.example.com",
		KeyType:    "sm2",
		ValidDays:  30,
		DNSNames:   []string{"leaf.example.com"},
	})
	if err != nil {
		t.Fatalf("SM2 CA 签发失败: %v", err)
	}

	leaf, err := smx509.ParseCertificate(issued.CertDER)
	if err != nil {
		t.Fatalf("解析签发的 SM2 证书: %v", err)
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != sm2.P256() {
		t.Fatalf("终端证书公钥不是 SM2: %T", leaf.PublicKey)
	}
	// 用 CA 公钥校验证书链签名
	gmCACert, err := smx509.ParseCertificate(caRes.CertDER)
	if err != nil {
		t.Fatalf("解析 SM2 CA: %v", err)
	}
	if err := gmCACert.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature); err != nil {
		t.Fatalf("SM2 CA 签发的证书验签失败: %v", err)
	}
}
