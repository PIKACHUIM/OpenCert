// Package test - server-card 端 CreateCard + EK Attestation 集成测试。
//
// 这是三组件 E2E 联调链路在服务端侧的端到端验证：模拟 client-card 经
// HTTP 上送 attestation 到 servers，验证服务端 EK 校验策略：
//
//   1. 高安全等级 + 缺 attestation        → 拒绝
//   2. 高安全等级 + 软件 EK              → 拒绝
//   3. 高安全等级 + 真实 EK 证书 + 厂商根 → 通过
//   4. 中/低安全等级 + 软件 EK             → 通过
//   5. nonce 不一致                       → 拒绝（防重放）
package test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/globaltrusts/server-card/internal/card"
	"github.com/globaltrusts/server-card/internal/storage"
)

// setupCardSvc 构造一个带 EK 信任库的 cardSvc，并预置一个用户。
func setupCardSvc(t *testing.T) (*card.Service, string, []byte, func()) {
	t.Helper()
	db, cleanup := setupServerDB(t)

	userRepo := storage.NewUserRepo(db)
	cardRepo := storage.NewCardRepo(db)
	certRepo := storage.NewCertRepo(db)

	user := &storage.User{
		UserType:    storage.UserTypeLocal,
		DisplayName: "EK 测试用户",
		Email:       "ek@test.com",
		Enabled:     true,
	}
	if err := userRepo.Create(context.Background(), user); err != nil {
		cleanup()
		t.Fatal(err)
	}

	// 厂商根证书 DER（用于注入 EKTrustStore + 模拟 EK 证书）
	rootDER := makeTestRootCert(t)

	svc := card.NewService(cardRepo, certRepo, testMasterKey)
	if err := svc.EKTrust().RegisterEKTrustRoot(rootDER); err != nil {
		cleanup()
		t.Fatal(err)
	}

	return svc, user.UUID, rootDER, cleanup
}

// makeTestRootCert 生成一个自签名 ECDSA 证书 DER（同时充当厂商根与 EK 证书）。
func makeTestRootCert(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
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

// makeAtt 构造一份带 nonce 的 Attestation；withCert=true 时附带真实 EK 证书 DER。
func makeAtt(t *testing.T, nonce, keyFP string, withCert bool, software bool, ekCertDER []byte) *card.Attestation {
	t.Helper()
	blob, _ := json.Marshal(map[string]string{
		"key_fp":   keyFP,
		"nonce":    nonce,
		"platform": "tpm2",
	})
	att := &card.Attestation{
		Platform:          "tpm2",
		EKPubFingerprint:  "deadbeef",
		CertifyBlob:       blob,
		CertifySignature:  []byte{1, 2, 3, 4},
		KeyPubFingerprint: keyFP,
		SoftwareEK:        software,
		Nonce:             nonce,
	}
	if withCert {
		att.EKCertificate = ekCertDER
	}
	return att
}

// ---- 1) 高安全等级缺 attestation ----

func TestE2E_CreateCard_HighSecurity_MissingAttestation(t *testing.T) {
	t.Parallel()
	svc, userUUID, _, cleanup := setupCardSvc(t)
	defer cleanup()

	_, err := svc.CreateCard(context.Background(), &card.CreateCardRequest{
		UserUUID:      userUUID,
		CardName:      "高安全卡片",
		PIN:           "123456",
		SlotType:      card.SlotTPMv2,
		SecurityLevel: card.SecurityHigh,
		// 缺 Attestation
	})
	if err == nil {
		t.Fatal("高安全等级缺 attestation 应被拒绝")
	}
	t.Logf("✓ 高安全 + 无 attestation 被正确拒绝: %v", err)
}

// ---- 2) 高安全等级 + 软件 EK 被拒绝 ----

func TestE2E_CreateCard_HighSecurity_RejectsSoftwareEK(t *testing.T) {
	t.Parallel()
	svc, userUUID, _, cleanup := setupCardSvc(t)
	defer cleanup()

	att := makeAtt(t, "nonce-A", "keyfp-1", false, true, nil) // 软件 EK
	_, err := svc.CreateCard(context.Background(), &card.CreateCardRequest{
		UserUUID:         userUUID,
		CardName:         "高安全软件 EK 卡片",
		PIN:              "123456",
		SlotType:         card.SlotTPMv2,
		SecurityLevel:    card.SecurityHigh,
		Attestation:      att,
		AttestationNonce: "nonce-A",
	})
	if err == nil {
		t.Fatal("高安全等级应拒绝软件 EK")
	}
	t.Logf("✓ 高安全 + 软件 EK 被正确拒绝: %v", err)
}

// ---- 3) 高安全等级 + 真实 EK 证书通过 ----

func TestE2E_CreateCard_HighSecurity_AcceptValidEK(t *testing.T) {
	t.Parallel()
	svc, userUUID, rootDER, cleanup := setupCardSvc(t)
	defer cleanup()

	// 自签名同时充当厂商根与 EK 证书
	att := makeAtt(t, "nonce-B", "keyfp-2", true, false, rootDER)
	c, err := svc.CreateCard(context.Background(), &card.CreateCardRequest{
		UserUUID:         userUUID,
		CardName:         "高安全合法 EK 卡片",
		PIN:              "123456",
		SlotType:         card.SlotTPMv2,
		SecurityLevel:    card.SecurityHigh,
		Attestation:      att,
		AttestationNonce: "nonce-B",
	})
	if err != nil {
		t.Fatalf("高安全合法 EK 应通过，实际: %v", err)
	}
	if c == nil || c.UUID == "" {
		t.Fatal("CreateCard 返回了空卡片")
	}
	t.Logf("✓ 高安全 + 真实 EK + 厂商根 创建成功: %s", c.UUID)
}

// ---- 4) 中/低安全等级 + 软件 EK 通过 ----

func TestE2E_CreateCard_MediumSecurity_AcceptsSoftwareEK(t *testing.T) {
	t.Parallel()
	svc, userUUID, _, cleanup := setupCardSvc(t)
	defer cleanup()

	att := makeAtt(t, "nonce-C", "keyfp-3", false, true, nil)
	c, err := svc.CreateCard(context.Background(), &card.CreateCardRequest{
		UserUUID:         userUUID,
		CardName:         "中安全软件 EK 卡片",
		PIN:              "123456",
		SlotType:         card.SlotTPMv2,
		SecurityLevel:    card.SecurityMedium,
		Attestation:      att,
		AttestationNonce: "nonce-C",
	})
	if err != nil {
		t.Fatalf("中安全等级应接受软件 EK: %v", err)
	}
	if c.UUID == "" {
		t.Fatal("应返回有效卡片")
	}
	t.Logf("✓ 中安全 + 软件 EK 创建成功: %s", c.UUID)
}

func TestE2E_CreateCard_LowSecurity_NoAttestationRequired(t *testing.T) {
	t.Parallel()
	svc, userUUID, _, cleanup := setupCardSvc(t)
	defer cleanup()

	c, err := svc.CreateCard(context.Background(), &card.CreateCardRequest{
		UserUUID:      userUUID,
		CardName:      "低安全软件卡片",
		PIN:           "123456",
		SlotType:      card.SlotSoftware,
		SecurityLevel: card.SecurityLow,
		// 无 attestation
	})
	if err != nil {
		t.Fatalf("低安全等级无 attestation 应通过: %v", err)
	}
	if c.UUID == "" {
		t.Fatal("应返回有效卡片")
	}
	t.Logf("✓ 低安全 + 无 attestation 创建成功: %s", c.UUID)
}

// ---- 5) nonce 不一致（防重放） ----

func TestE2E_CreateCard_HighSecurity_NonceReplayBlocked(t *testing.T) {
	t.Parallel()
	svc, userUUID, rootDER, cleanup := setupCardSvc(t)
	defer cleanup()

	// attestation 内 nonce 与 server 期望不一致 → 应拒绝
	att := makeAtt(t, "nonce-OLD", "keyfp", true, false, rootDER)
	_, err := svc.CreateCard(context.Background(), &card.CreateCardRequest{
		UserUUID:         userUUID,
		CardName:         "重放攻击卡片",
		PIN:              "123456",
		SlotType:         card.SlotTPMv2,
		SecurityLevel:    card.SecurityHigh,
		Attestation:      att,
		AttestationNonce: "nonce-NEW",
	})
	if err == nil {
		t.Fatal("nonce 不一致应被拒绝")
	}
	t.Logf("✓ nonce 不一致被正确拒绝: %v", err)
}

// ---- 6) 高安全等级 + 无厂商根注册 ----

func TestE2E_CreateCard_HighSecurity_NoTrustRoot(t *testing.T) {
	t.Parallel()
	db, cleanup := setupServerDB(t)
	defer cleanup()

	userRepo := storage.NewUserRepo(db)
	user := &storage.User{
		UserType: storage.UserTypeLocal, DisplayName: "u", Email: "u@t", Enabled: true,
	}
	userRepo.Create(context.Background(), user)

	cardRepo := storage.NewCardRepo(db)
	certRepo := storage.NewCertRepo(db)
	svc := card.NewService(cardRepo, certRepo, testMasterKey)
	// 故意不注册任何厂商根

	rootDER := makeTestRootCert(t)
	att := makeAtt(t, "nonce-X", "kfp", true, false, rootDER)

	_, err := svc.CreateCard(context.Background(), &card.CreateCardRequest{
		UserUUID:         user.UUID,
		CardName:         "无信任根",
		PIN:              "123456",
		SlotType:         card.SlotTPMv2,
		SecurityLevel:    card.SecurityHigh,
		Attestation:      att,
		AttestationNonce: "nonce-X",
	})
	if err == nil {
		t.Fatal("未注册厂商根时应拒绝")
	}
	t.Logf("✓ 无厂商根被正确拒绝: %v", err)
}
