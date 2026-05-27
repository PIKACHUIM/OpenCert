// Package card - attestation_test.go：EK 认证服务端校验测试。
package card

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// makeAtt 构造一个最小可用的 Attestation。
func makeAtt(t *testing.T, nonce, keyFP string, withCert bool, software bool) *Attestation {
	t.Helper()
	blob, _ := json.Marshal(map[string]string{
		"key_fp":   keyFP,
		"nonce":    nonce,
		"platform": "tpm2",
	})
	att := &Attestation{
		Platform:          "tpm2",
		EKPubFingerprint:  "deadbeef",
		CertifyBlob:       blob,
		CertifySignature:  []byte{1, 2, 3, 4},
		KeyPubFingerprint: keyFP,
		SoftwareEK:        software,
		Nonce:             nonce,
	}
	if withCert {
		att.EKCertificate = makeSelfSignedCert(t)
	}
	return att
}

// makeSelfSignedCert 生成一个自签名证书 DER（用于厂商根模拟）。
func makeSelfSignedCert(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test TPM Vendor Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestEKTrustStore_RegisterRoot_PEM(t *testing.T) {
	s := NewEKTrustStore()
	der := makeSelfSignedCert(t)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	if err := s.RegisterEKTrustRoot(pemBytes); err != nil {
		t.Fatalf("PEM 注册失败: %v", err)
	}
	if s.Count() != 1 {
		t.Errorf("count 期望 1，实际 %d", s.Count())
	}
}

func TestEKTrustStore_RegisterRoot_DER(t *testing.T) {
	s := NewEKTrustStore()
	der := makeSelfSignedCert(t)
	if err := s.RegisterEKTrustRoot(der); err != nil {
		t.Fatalf("DER 注册失败: %v", err)
	}
	if s.Count() != 1 {
		t.Errorf("count 期望 1，实际 %d", s.Count())
	}
}

func TestEKTrustStore_RegisterRoot_Empty(t *testing.T) {
	s := NewEKTrustStore()
	if err := s.RegisterEKTrustRoot(nil); err == nil {
		t.Errorf("空字节应返回错误")
	}
}

func TestVerifyEKAttestation_NonceMismatch(t *testing.T) {
	s := NewEKTrustStore()
	att := makeAtt(t, "nonce-A", "keyfp", false, true)
	if err := s.VerifyEKAttestation(att, "nonce-B", SecurityLow); err == nil {
		t.Errorf("nonce 不一致应失败")
	}
}

func TestVerifyEKAttestation_HighSecurityRejectsSoftware(t *testing.T) {
	s := NewEKTrustStore()
	att := makeAtt(t, "n1", "keyfp", false, true)
	if err := s.VerifyEKAttestation(att, "n1", SecurityHigh); err == nil {
		t.Errorf("高安全等级应拒绝软件 EK")
	}
}

func TestVerifyEKAttestation_HighSecurityRequiresCert(t *testing.T) {
	s := NewEKTrustStore()
	att := makeAtt(t, "n1", "keyfp", false, false)
	if err := s.VerifyEKAttestation(att, "n1", SecurityHigh); err == nil {
		t.Errorf("高安全等级应要求 EK 证书")
	}
}

func TestVerifyEKAttestation_HighSecurityChainOK(t *testing.T) {
	s := NewEKTrustStore()
	der := makeSelfSignedCert(t)
	if err := s.RegisterEKTrustRoot(der); err != nil {
		t.Fatal(err)
	}
	// 自签名同时充当 EK 证书与厂商根
	att := &Attestation{
		Platform:          "tpm2",
		EKPubFingerprint:  "fp",
		EKCertificate:     der,
		CertifyBlob:       mustJSON(map[string]string{"key_fp": "k", "nonce": "n1", "platform": "tpm2"}),
		CertifySignature:  []byte{1},
		KeyPubFingerprint: "k",
		SoftwareEK:        false,
		Nonce:             "n1",
	}
	if err := s.VerifyEKAttestation(att, "n1", SecurityHigh); err != nil {
		t.Errorf("链校验应通过: %v", err)
	}
}

func TestVerifyEKAttestation_HighSecurityChainNoRoot(t *testing.T) {
	s := NewEKTrustStore() // 未注册任何根
	der := makeSelfSignedCert(t)
	att := &Attestation{
		EKCertificate:     der,
		CertifyBlob:       mustJSON(map[string]string{"key_fp": "k", "nonce": "n1"}),
		CertifySignature:  []byte{1},
		KeyPubFingerprint: "k",
		Nonce:             "n1",
	}
	if err := s.VerifyEKAttestation(att, "n1", SecurityHigh); err == nil {
		t.Errorf("无厂商根应拒绝")
	}
}

func TestVerifyEKAttestation_LowSecurityAcceptsSoftware(t *testing.T) {
	s := NewEKTrustStore()
	att := makeAtt(t, "n1", "k", false, true)
	if err := s.VerifyEKAttestation(att, "n1", SecurityLow); err != nil {
		t.Errorf("低安全等级应接受软件 EK: %v", err)
	}
}

func TestVerifyEKAttestation_NilOrMissingFields(t *testing.T) {
	s := NewEKTrustStore()
	if err := s.VerifyEKAttestation(nil, "n", SecurityLow); err == nil {
		t.Error("nil 应返回错误")
	}
	att := &Attestation{Nonce: "n"}
	if err := s.VerifyEKAttestation(att, "n", SecurityLow); err == nil {
		t.Error("缺少 key_fp 应失败")
	}
}

func mustJSON(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}
