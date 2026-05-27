// Package storage_test - PKCS#11 层 SSH / GPG 公钥属性映射测试。
package storage_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"
	"time"

	"github.com/globaltrusts/client-card/internal/pki"
	"golang.org/x/crypto/ssh"
)

func TestSSH_PKIXRoundTrip_RSA(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	authLine, err := pki.SSHPublicKeyFromPKIX(der, "user@host")
	if err != nil {
		t.Fatalf("PKIX -> SSH 失败: %v", err)
	}
	if len(authLine) == 0 {
		t.Fatalf("SSH 公钥行不应为空")
	}

	derBack, err := pki.SSHPublicKeyToPKIX(authLine)
	if err != nil {
		t.Fatalf("SSH -> PKIX 失败: %v", err)
	}
	pubBack, err := x509.ParsePKIXPublicKey(derBack)
	if err != nil {
		t.Fatalf("解析回程 PKIX 失败: %v", err)
	}
	rsaBack, ok := pubBack.(*rsa.PublicKey)
	if !ok || rsaBack.N.Cmp(priv.PublicKey.N) != 0 || rsaBack.E != priv.PublicKey.E {
		t.Fatalf("回程公钥不一致")
	}
}

func TestSSH_PKIXRoundTrip_ECDSA(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	line, err := pki.SSHPublicKeyFromPKIX(der, "")
	if err != nil {
		t.Fatal(err)
	}
	derBack, err := pki.SSHPublicKeyToPKIX(line)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.ParsePKIXPublicKey(derBack)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pub.(*ecdsa.PublicKey); !ok {
		t.Fatalf("应回到 ECDSA")
	}
}

func TestSSH_FingerprintMatchesUpstream(t *testing.T) {
	// 与 x/crypto/ssh.FingerprintSHA256 输出对比
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	sshPub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	want := ssh.FingerprintSHA256(sshPub)

	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	line, _ := pki.SSHPublicKeyFromPKIX(der, "")
	got, raw, err := pki.SSHFingerprintSHA256(line)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("指纹不匹配:\n want=%s\n got =%s", want, got)
	}
	if len(raw) != 32 {
		t.Errorf("raw 指纹应为 32 字节，实际 %d", len(raw))
	}
}

func TestGPG_FingerprintAndKeyID_Ed25519(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	createdAt := time.Unix(1700000000, 0)

	fp, err := pki.GPGFingerprint(pub, createdAt)
	if err != nil {
		t.Fatalf("GPGFingerprint 失败: %v", err)
	}
	if len(fp) != 20 {
		t.Errorf("V4 fingerprint 应为 20 字节，实际 %d", len(fp))
	}

	keyID := pki.GPGKeyIDFromFingerprint(fp)
	if len(keyID) != 8 {
		t.Errorf("keyid 应为 8 字节，实际 %d", len(keyID))
	}

	// fingerprint hex 渲染长度（20 字节 -> 40 十六进制 + 19 空格 = 59）
	hexs := pki.GPGFingerprintHex(fp)
	if len(hexs) == 0 {
		t.Errorf("fingerprint hex 不应为空")
	}
}

func TestGPG_FingerprintStable(t *testing.T) {
	// 同一公钥 + 同一时间 -> 同一 fingerprint
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	t1, _ := pki.GPGFingerprint(pub, time.Unix(1, 0))
	t2, _ := pki.GPGFingerprint(pub, time.Unix(1, 0))
	if string(t1) != string(t2) {
		t.Errorf("同输入应得到相同 fingerprint")
	}
	// 不同时间 -> 不同 fingerprint
	t3, _ := pki.GPGFingerprint(pub, time.Unix(2, 0))
	if string(t1) == string(t3) {
		t.Errorf("不同时间应得到不同 fingerprint")
	}
}

func TestGPG_PKIXRoundTrip_RSA(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	body, err := pki.GPGPublicKeyFromPKIX(der, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	derBack, err := pki.GPGPublicKeyToPKIX(body)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.ParsePKIXPublicKey(derBack)
	if err != nil {
		t.Fatal(err)
	}
	rsaBack, ok := pub.(*rsa.PublicKey)
	if !ok || rsaBack.N.Cmp(priv.PublicKey.N) != 0 || rsaBack.E != priv.PublicKey.E {
		t.Fatalf("RSA 回程不一致")
	}
}

func TestGPG_PKIXRoundTrip_ECDSA(t *testing.T) {
	for _, c := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		priv, _ := ecdsa.GenerateKey(c, rand.Reader)
		der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
		body, err := pki.GPGPublicKeyFromPKIX(der, time.Unix(0, 0))
		if err != nil {
			t.Fatalf("%s: %v", c.Params().Name, err)
		}
		derBack, err := pki.GPGPublicKeyToPKIX(body)
		if err != nil {
			t.Fatalf("%s: %v", c.Params().Name, err)
		}
		pub, _ := x509.ParsePKIXPublicKey(derBack)
		ecBack, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("%s: 应回到 ECDSA", c.Params().Name)
		}
		if ecBack.Curve.Params().Name != c.Params().Name {
			t.Errorf("曲线不一致: %s vs %s", ecBack.Curve.Params().Name, c.Params().Name)
		}
	}
}

func TestGPG_UnsupportedAlgoRejected(t *testing.T) {
	_, err := pki.GPGV4PacketBody("not-a-key", time.Now())
	if err == nil {
		t.Errorf("非法公钥应返回错误")
	}
	_, err = pki.GPGPublicKeyToPKIX([]byte{0x05, 0, 0, 0, 0, 0x99}) // 非 V4
	if err == nil {
		t.Errorf("非 V4 应返回错误")
	}
}
