// Package test - 交付与申请校验测试。
//
// 覆盖：真实 PKCS#12 编码/解码、私钥 PEM 规范化、申请前置校验（未支付、
// 算法不允许、非法 CSR）以及自带 CSR 的申请受理。
package test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"

	"github.com/globaltrusts/server-card/internal/card"
	"github.com/globaltrusts/server-card/internal/issuance"
	"github.com/globaltrusts/server-card/internal/storage"
	"github.com/globaltrusts/server-card/internal/workflow"
)

// newCertificateFixture 生成一张带私钥的证书记录，返回证书服务与证书对象。
func newCertificateFixture(t *testing.T, db *storage.DB) (*card.Service, *storage.Certificate) {
	t.Helper()
	ctx := context.Background()

	userUUID := createTestUser(t, db, "deliver@test.com")

	cardRepo := storage.NewCardRepo(db)
	c := &storage.Card{CardName: "交付测试卡", UserUUID: userUUID}
	if err := cardRepo.Create(ctx, c); err != nil {
		t.Fatalf("创建卡片失败: %v", err)
	}

	// 生成私钥与自签证书
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(20260923),
		Subject:      pkix.Name{CommonName: "deliver.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("签发测试证书失败: %v", err)
	}

	cardSvc := card.NewService(cardRepo, storage.NewCertRepo(db), testMasterKey)
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("序列化私钥失败: %v", err)
	}
	encPriv, err := cardSvc.EncryptData(privDER)
	if err != nil {
		t.Fatalf("加密私钥失败: %v", err)
	}

	cert := &storage.Certificate{
		UUID:             "cert-deliver-1",
		CardUUID:         c.UUID,
		UserUUID:         userUUID,
		CertType:         "x509",
		KeyType:          "rsa2048",
		CertContent:      der, // 故意使用 DER，验证交付时会被规范化为 PEM
		PrivateData:      encPriv,
		SubjectDN:        "CN=deliver.example.com",
		SerialNumber:     "20260923",
		SANDNS:           `["deliver.example.com"]`,
		RevocationStatus: "active",
	}
	if err := storage.NewCertRepo(db).Create(ctx, cert); err != nil {
		t.Fatalf("创建证书失败: %v", err)
	}
	return cardSvc, cert
}

func TestExportPKCS12RoundTrip(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)
	cardSvc, cert := newCertificateFixture(t, db)
	ctx := context.Background()

	// 短口令必须被拒绝：导出私钥不接受弱保护
	if _, err := cardSvc.ExportPKCS12(ctx, cert, "123", nil); err == nil {
		t.Fatal("过短的 PFX 口令应被拒绝")
	}

	pfx, err := cardSvc.ExportPKCS12(ctx, cert, "strong-password", nil)
	if err != nil {
		t.Fatalf("导出 PKCS#12 失败: %v", err)
	}

	// 必须能被标准库解析（验证不是 PEM 拼接的伪实现）
	priv, leaf, _, err := pkcs12.DecodeChain(pfx, "strong-password")
	if err != nil {
		t.Fatalf("解析 PKCS#12 失败（说明并非真实 PFX）: %v", err)
	}
	if leaf.Subject.CommonName != "deliver.example.com" {
		t.Errorf("PFX 中的证书主体不符: %s", leaf.Subject.CommonName)
	}
	rsaKey, ok := priv.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("PFX 中的私钥类型不符: %T", priv)
	}
	if rsaKey.N.Cmp(leaf.PublicKey.(*rsa.PublicKey).N) != 0 {
		t.Error("PFX 中的私钥与证书公钥不匹配")
	}

	// 错误口令必须解密失败
	if _, _, _, err := pkcs12.DecodeChain(pfx, "wrong-password"); err == nil {
		t.Error("错误口令不应能解开 PFX")
	}
}

func TestExportPrivateKeyPEMNormalizesToPKCS8(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)
	cardSvc, cert := newCertificateFixture(t, db)

	keyPEM, err := cardSvc.ExportPrivateKeyPEM(context.Background(), cert)
	if err != nil {
		t.Fatalf("导出私钥 PEM 失败: %v", err)
	}
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		t.Fatal("导出的私钥不是有效 PEM")
	}
	if block.Type != "PRIVATE KEY" {
		t.Errorf("私钥应为 PKCS#8（PRIVATE KEY），实际 %q", block.Type)
	}
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		t.Errorf("PKCS#8 解析失败: %v", err)
	}
}

func TestApplicationRequiresPaidOrder(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)
	svc := workflow.NewService(db, nil, nil)
	ctx := context.Background()

	userUUID := createTestUser(t, db, "applycheck@test.com")
	order := &storage.CertOrder{UserUUID: userUUID, AmountCents: 100}
	if err := svc.CreateOrder(ctx, order); err != nil {
		t.Fatalf("创建订单失败: %v", err)
	}

	// 未支付：拒绝
	err := svc.CreateApplication(ctx, &storage.CertApplication{
		OrderUUID: order.UUID, UserUUID: userUUID,
		SubjectJSON: `{"CN":"a.example.com"}`, SANJSON: `{"dns":["a.example.com"]}`, KeyType: "ec256",
	})
	if err == nil {
		t.Fatal("未支付订单不应允许提交申请")
	}
	if !strings.Contains(err.Error(), "尚未支付") {
		t.Errorf("错误信息应提示先支付，实际: %v", err)
	}

	// 他人订单：拒绝
	markOrderPaid(t, db, order.UUID)
	otherUser := createTestUser(t, db, "other@test.com")
	err = svc.CreateApplication(ctx, &storage.CertApplication{
		OrderUUID: order.UUID, UserUUID: otherUser,
		SubjectJSON: `{}`, SANJSON: `{}`, KeyType: "ec256",
	})
	if err == nil {
		t.Fatal("不应允许为他人订单提交申请")
	}

	// 支付后：通过
	if err := svc.CreateApplication(ctx, &storage.CertApplication{
		OrderUUID: order.UUID, UserUUID: userUUID,
		SubjectJSON: `{"CN":"a.example.com"}`, SANJSON: `{"dns":["a.example.com"]}`, KeyType: "ec256",
	}); err != nil {
		t.Fatalf("已支付订单应允许提交申请: %v", err)
	}

	// 订单应进入申请中状态
	got, err := svc.GetOrderByNo(ctx, order.OrderNo)
	if err != nil {
		t.Fatalf("查询订单失败: %v", err)
	}
	if got.Status != storage.CertOrderApplying {
		t.Errorf("订单状态应为 applying，实际 %q", got.Status)
	}
}

func TestApplicationRejectsInvalidCSRAndKeyType(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)
	issSvc := issuance.NewService(db)
	svc := workflow.NewService(db, nil, issSvc)
	ctx := context.Background()

	userUUID := createTestUser(t, db, "csrcheck@test.com")

	// 商品只允许 ec256
	insertApplyTemplateWithKeyTypes(t, db, issSvc, "tmpl-ec256", "仅 ec256", `["ec256"]`)
	order := &storage.CertOrder{UserUUID: userUUID, CertApplyTmplUUID: "tmpl-ec256"}
	if err := svc.CreateOrder(ctx, order); err != nil {
		t.Fatalf("创建订单失败: %v", err)
	}
	markOrderPaid(t, db, order.UUID)

	// 算法不在允许范围
	err := svc.CreateApplication(ctx, &storage.CertApplication{
		OrderUUID: order.UUID, UserUUID: userUUID,
		SubjectJSON: `{}`, SANJSON: `{}`, KeyType: "rsa4096",
	})
	if err == nil || !strings.Contains(err.Error(), "密钥算法") {
		t.Errorf("不允许的算法应被拒绝，实际: %v", err)
	}

	// 非法 CSR
	err = svc.CreateApplication(ctx, &storage.CertApplication{
		OrderUUID: order.UUID, UserUUID: userUUID,
		SubjectJSON: `{}`, SANJSON: `{}`, KeyType: "ec256",
		CSRPEM: "-----BEGIN CERTIFICATE REQUEST-----\nnot-base64\n-----END CERTIFICATE REQUEST-----\n",
	})
	if err == nil {
		t.Error("非法 CSR 应被拒绝")
	}

	// 合法 CSR（ec256）应被受理
	csrPEM := generateECDSACSRPEM(t, "csr.example.com")
	if err := svc.CreateApplication(ctx, &storage.CertApplication{
		OrderUUID: order.UUID, UserUUID: userUUID,
		SubjectJSON: `{}`, SANJSON: `{}`, KeyType: "ec256",
		CSRPEM: csrPEM,
	}); err != nil {
		t.Fatalf("合法 CSR 应被受理: %v", err)
	}
}

// generateECDSACSRPEM 生成一份 ECDSA P-256 的 CSR（PEM），用于验证自带 CSR 流程。
func generateECDSACSRPEM(t *testing.T, commonName string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成 EC 密钥失败: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: commonName},
		DNSNames: []string{commonName},
	}, key)
	if err != nil {
		t.Fatalf("生成 CSR 失败: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
}

// insertApplyTemplateWithKeyTypes 插入开通模板，并在其关联的颁发模板上设置算法白名单
// （算法范围属于颁发模板，开通模板不再配置）。
func insertApplyTemplateWithKeyTypes(t *testing.T, db *storage.DB, issSvc *issuance.Service, uuid, name, keyTypes string) {
	t.Helper()
	ctx := context.Background()
	it := &storage.IssuanceTemplate{
		Name: name + " 颁发模板", ValidDays: `[365]`, AllowedKeyTypes: keyTypes, AllowedCAUUIDs: `[]`,
		Category: "ssl", Enabled: true,
	}
	if err := issSvc.CreateIssuanceTemplate(ctx, it); err != nil {
		t.Fatalf("创建颁发模板失败: %v", err)
	}
	_, err := db.ExecContext(ctx,
		`INSERT INTO cert_apply_templates
		 (uuid, name, issuance_tmpl_uuid, enabled, require_approval, allow_renewal, description, created_at, updated_at)
		 VALUES (?, ?, ?, 1, 0, 1, '', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
		uuid, name, it.UUID)
	if err != nil {
		t.Fatalf("插入开通模板失败: %v", err)
	}
}
