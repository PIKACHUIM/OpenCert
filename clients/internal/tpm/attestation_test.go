// Package tpm - attestation_test.go：EK 认证单元测试。
package tpm

import (
	"strings"
	"testing"
)

func TestAttestor_AttestKey_Mock(t *testing.T) {
	p := NewMock()
	att, err := NewAttestor(p)
	if err != nil {
		t.Fatalf("NewAttestor 失败: %v", err)
	}

	keyFp := strings.Repeat("a", 64)
	a, err := att.AttestKey(keyFp, "nonce-123")
	if err != nil {
		t.Fatalf("AttestKey 失败: %v", err)
	}

	if a.Platform != "mock" {
		t.Errorf("Platform 期望 mock，实际 %s", a.Platform)
	}
	if !a.SoftwareEK {
		t.Errorf("Mock 应被标记为 SoftwareEK")
	}
	if a.KeyPubFingerprint != keyFp {
		t.Errorf("KeyPubFingerprint 不一致")
	}
	if len(a.EKPubFingerprint) != 64 {
		t.Errorf("EKPubFingerprint 应为 hex(SHA256) 即 64 字符，实际 %d", len(a.EKPubFingerprint))
	}
	if len(a.CertifyBlob) == 0 || len(a.CertifySignature) == 0 {
		t.Errorf("CertifyBlob/Signature 不能为空")
	}

	// 自验签名
	if err := VerifyAttestationSignature(p, a); err != nil {
		t.Errorf("VerifyAttestationSignature 失败: %v", err)
	}
}

func TestAttestor_StableEKAcrossCalls(t *testing.T) {
	// 同一 Provider 实例多次调用应得到相同 EKPubFingerprint
	p := NewMock()
	att, _ := NewAttestor(p)

	a1, err := att.AttestKey("fp1", "n1")
	if err != nil {
		t.Fatal(err)
	}
	a2, err := att.AttestKey("fp2", "n2")
	if err != nil {
		t.Fatal(err)
	}
	if a1.EKPubFingerprint != a2.EKPubFingerprint {
		t.Errorf("同一 TPM 的 EK 指纹应稳定: %s vs %s", a1.EKPubFingerprint, a2.EKPubFingerprint)
	}
}

func TestAttestor_TamperDetection(t *testing.T) {
	p := NewMock()
	att, _ := NewAttestor(p)

	a, err := att.AttestKey("fp", "nonce")
	if err != nil {
		t.Fatal(err)
	}

	// 篡改签名
	a.CertifySignature[0] ^= 0xff
	if err := VerifyAttestationSignature(p, a); err == nil {
		t.Errorf("篡改签名后应校验失败")
	}
}

func TestAttestor_RequiresKeyFingerprint(t *testing.T) {
	p := NewMock()
	att, _ := NewAttestor(p)
	if _, err := att.AttestKey("", "n"); err == nil {
		t.Errorf("空 keyPubFingerprint 应返回错误")
	}
}

func TestNewAttestor_NilProvider(t *testing.T) {
	if _, err := NewAttestor(nil); err == nil {
		t.Errorf("nil provider 应返回错误")
	}
}
