package keybackend

import (
	"crypto"
	"crypto/ecdsa"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/emmansun/gmsm/sm2"
)

func TestSM2SignerUsesRawMessageMechanism(t *testing.T) {
	pub := &ecdsa.PublicKey{Curve: sm2.P256(), X: big.NewInt(1), Y: big.NewInt(2)}
	mechanism, err := mechanismFor(pub, sm2.DefaultSM2SignerOpts)
	if err != nil {
		t.Fatal(err)
	}
	if mechanism != "SM2_SM3" {
		t.Fatalf("机制 = %q，期望 SM2_SM3", mechanism)
	}
	if _, err := mechanismFor(pub, crypto.SHA256); err == nil {
		t.Fatal("SM2 不应接受预先摘要的签名选项")
	}
}

func TestNormalizeSM2SignatureAcceptsRawAndDER(t *testing.T) {
	raw := make([]byte, 64)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	der, err := normalizeSM2Signature(raw)
	if err != nil {
		t.Fatal(err)
	}
	var parsed ecdsaSig
	rest, err := asn1.Unmarshal(der, &parsed)
	if err != nil || len(rest) != 0 || parsed.R == nil || parsed.S == nil {
		t.Fatalf("转换后的签名不是完整 ASN.1 DER: rest=%d err=%v", len(rest), err)
	}

	derAgain, err := normalizeSM2Signature(der)
	if err != nil {
		t.Fatal(err)
	}
	if string(derAgain) != string(der) {
		t.Fatal("DER 签名不应被二次转换")
	}
	if _, err := normalizeSM2Signature([]byte{1, 2, 3}); err == nil {
		t.Fatal("非法签名格式必须返回错误")
	}
}
