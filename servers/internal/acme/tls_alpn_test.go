// Package acme - TLS-ALPN-01 单元测试。
package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// buildTLSALPNCert 生成符合 RFC 8737 §3 的自签名证书（含 critical id-pe-acmeIdentifier 扩展）。
func buildTLSALPNCert(t *testing.T, domain, keyAuth string, critical bool, badExt bool) *x509.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(keyAuth))
	extVal, _ := asn1.Marshal(asn1.RawValue{Tag: asn1.TagOctetString, Bytes: hash[:]})
	if badExt {
		// 篡改第一个字节
		extVal[len(extVal)-1] ^= 0xFF
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{
				Id:       oidACMEIdentifier,
				Critical: critical,
				Value:    extVal,
			},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestVerifyTLSALPN01Cert_OK(t *testing.T) {
	t.Parallel()
	cert := buildTLSALPNCert(t, "example.com", "token.thumbprint", true, false)
	if err := verifyTLSALPN01Cert(cert, "example.com", "token.thumbprint"); err != nil {
		t.Errorf("应通过，实际: %v", err)
	}
}

func TestVerifyTLSALPN01Cert_DomainMismatch(t *testing.T) {
	t.Parallel()
	cert := buildTLSALPNCert(t, "example.com", "ka", true, false)
	if err := verifyTLSALPN01Cert(cert, "other.com", "ka"); err == nil {
		t.Error("SAN 不含 other.com 应失败")
	}
}

func TestVerifyTLSALPN01Cert_NotCritical(t *testing.T) {
	t.Parallel()
	cert := buildTLSALPNCert(t, "example.com", "ka", false, false)
	if err := verifyTLSALPN01Cert(cert, "example.com", "ka"); err == nil {
		t.Error("非 critical 扩展应失败")
	}
}

func TestVerifyTLSALPN01Cert_BadExtensionValue(t *testing.T) {
	t.Parallel()
	cert := buildTLSALPNCert(t, "example.com", "ka", true, true)
	if err := verifyTLSALPN01Cert(cert, "example.com", "ka"); err == nil {
		t.Error("篡改扩展值应失败")
	}
}

func TestVerifyTLSALPN01Cert_KeyAuthMismatch(t *testing.T) {
	t.Parallel()
	cert := buildTLSALPNCert(t, "example.com", "ka-original", true, false)
	if err := verifyTLSALPN01Cert(cert, "example.com", "ka-different"); err == nil {
		t.Error("keyAuth 不一致应失败")
	}
}

func TestVerifyTLSALPN01Cert_MissingExtension(t *testing.T) {
	t.Parallel()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	if err := verifyTLSALPN01Cert(cert, "example.com", "ka"); err == nil {
		t.Error("缺少扩展应失败")
	}
}

func TestBytesEqualConstantTime(t *testing.T) {
	t.Parallel()
	if !bytesEqualConstantTime([]byte{1, 2, 3}, []byte{1, 2, 3}) {
		t.Error("相同应返回 true")
	}
	if bytesEqualConstantTime([]byte{1, 2, 3}, []byte{1, 2, 4}) {
		t.Error("不同应返回 false")
	}
	if bytesEqualConstantTime([]byte{1, 2}, []byte{1, 2, 3}) {
		t.Error("长度不同应返回 false")
	}
}
