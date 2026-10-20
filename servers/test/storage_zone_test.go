// Package test - 私钥存储区域（本地 / TPM / HSM）功能测试。
//
// 覆盖：存储区域驱动路由、参数加解密与回显脱敏、按区域生成/签名/解密、
// 私钥导出策略、区域与证书不匹配时的报错，以及不可导出私钥的明确提示。
package test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"runtime"
	"strings"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"

	"github.com/globaltrusts/server-card/internal/card"
	"github.com/globaltrusts/server-card/internal/keybackend"
	_ "github.com/globaltrusts/server-card/internal/keybackend/pkcs11"
	_ "github.com/globaltrusts/server-card/internal/keybackend/tpm"
	"github.com/globaltrusts/server-card/internal/storage"
)

// zoneFixture 是一套「存储区域 + 用户 + 卡片」的测试环境。
type zoneFixture struct {
	svc      *card.Service
	zoneRepo *storage.StorageZoneRepo
	cardRepo *storage.CardRepo
	zone     *storage.StorageZone
	card     *storage.Card
	userUUID string
}

// newZoneFixture 创建存储区域并绑定一张卡片。
func newZoneFixture(t *testing.T, db *storage.DB, driver, storageType string, label string, params map[string]string) *zoneFixture {
	t.Helper()
	ctx := context.Background()

	userUUID := createTestUser(t, db, fmt.Sprintf("zone-%s-%s@test.com", driver, strings.ReplaceAll(label, " ", "")))
	cardSvc := card.NewService(storage.NewCardRepo(db), storage.NewCertRepo(db), testMasterKey)
	zoneRepo := storage.NewStorageZoneRepo(db)
	cardSvc.AttachStorageZones(zoneRepo)

	enc, err := cardSvc.EncryptZoneParams(keybackend.Params(params))
	if err != nil {
		t.Fatalf("加密存储区域参数失败: %v", err)
	}
	zone := &storage.StorageZone{
		Name:        label,
		StorageType: storageType,
		HSMDriver:   driver,
		ParamsEnc:   enc,
		Status:      "active",
	}
	if err := zoneRepo.Create(ctx, zone); err != nil {
		t.Fatalf("创建存储区域失败: %v", err)
	}

	cardRepo := storage.NewCardRepo(db)
	c := &storage.Card{CardName: "区域测试卡", UserUUID: userUUID, StorageZoneUUID: zone.UUID}
	if err := cardRepo.Create(ctx, c); err != nil {
		t.Fatalf("创建卡片失败: %v", err)
	}

	return &zoneFixture{
		svc: cardSvc, zoneRepo: zoneRepo, cardRepo: cardRepo,
		zone: zone, card: c, userUUID: userUUID,
	}
}

// TestLocalZoneKeyLifecycle 本地加密存储区域：生成 → 签名 → 解密 → 导出 → 删除。
func TestLocalZoneKeyLifecycle(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)
	fx := newZoneFixture(t, db, storage.DriverDatabase, "database", "本地加密存储", nil)
	ctx := context.Background()

	// 生成 RSA 密钥对
	cert, err := fx.svc.GenerateKeyPair(ctx, fx.card.UUID, fx.userUUID, "rsa2048", "区域测试")
	if err != nil {
		t.Fatalf("生成密钥对失败: %v", err)
	}
	if cert.KeyBackend != storage.DriverDatabase {
		t.Errorf("证书应记录私有后端 database，实际 %q", cert.KeyBackend)
	}
	if len(cert.PrivateData) != 0 || cert.KeyRef != "" {
		t.Errorf("返回给调用方的证书不应包含私钥材料")
	}

	// 重新读取应能看到加密私钥与后端标记
	stored, err := storage.NewCertRepo(db).GetByUUID(ctx, cert.UUID)
	if err != nil {
		t.Fatalf("读取证书失败: %v", err)
	}
	if len(stored.PrivateData) == 0 {
		t.Fatal("本地存储区域的私钥应加密入库")
	}
	if stored.KeyRef != "" {
		t.Errorf("本地存储区域不应产生硬件引用，实际 %q", stored.KeyRef)
	}

	// 签名并验签
	msg := []byte("storage-zone-signature")
	sig, err := fx.svc.Sign(ctx, cert.UUID, fx.card.UUID, fx.userUUID, "SHA256_RSA_PKCS", msg)
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	pub, err := x509.ParsePKIXPublicKey(stored.CertContent)
	if err != nil {
		t.Fatalf("解析公钥失败: %v", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("公钥类型应为 RSA，实际 %T", pub)
	}
	digest := sha256.Sum256(msg)
	if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("签名验签失败: %v", err)
	}

	// RSA-PSS 机制
	pssSig, err := fx.svc.Sign(ctx, cert.UUID, fx.card.UUID, fx.userUUID, "SHA256_RSA_PSS", msg)
	if err != nil {
		t.Fatalf("RSA-PSS 签名失败: %v", err)
	}
	if err := rsa.VerifyPSS(rsaPub, crypto.SHA256, digest[:], pssSig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto}); err != nil {
		t.Fatalf("RSA-PSS 验签失败: %v", err)
	}

	// 解密：用公钥加密，服务端用存储区域中的私钥解密
	plaintext := []byte("storage-zone-decrypt")
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPub, plaintext)
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}
	out, err := fx.svc.Decrypt(ctx, cert.UUID, fx.card.UUID, fx.userUUID, "RSA_PKCS", ciphertext)
	if err != nil {
		t.Fatalf("解密失败: %v", err)
	}
	if string(out) != string(plaintext) {
		t.Fatalf("解密结果不一致: %q", out)
	}

	// 导出私钥 PEM（私钥在本地加密存储区域时允许导出）
	keyPEM, err := fx.svc.ExportPrivateKeyPEM(ctx, stored)
	if err != nil {
		t.Fatalf("导出私钥 PEM 失败: %v", err)
	}
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("导出的私钥应为 PKCS#8 PEM，实际 %v", block)
	}

	// 删除后证书与私钥记录一并消失
	if err := fx.svc.DeleteCert(ctx, cert.UUID, fx.card.UUID, fx.userUUID); err != nil {
		t.Fatalf("删除证书失败: %v", err)
	}
	if _, err := storage.NewCertRepo(db).GetByUUID(ctx, cert.UUID); err == nil {
		t.Fatal("删除后证书仍可读")
	}
}

// TestECDSASignatureFormatMatchesSoftware 本地存储区域的 ECDSA 签名与软件实现格式一致（r||s）。
func TestECDSASignatureFormatMatchesSoftware(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)
	fx := newZoneFixture(t, db, storage.DriverDatabase, "database", "EC 本地存储", nil)
	ctx := context.Background()

	cert, err := fx.svc.GenerateKeyPair(ctx, fx.card.UUID, fx.userUUID, "ec256", "EC 测试")
	if err != nil {
		t.Fatalf("生成 EC 密钥对失败: %v", err)
	}
	msg := []byte("ecdsa-message")
	sig, err := fx.svc.Sign(ctx, cert.UUID, fx.card.UUID, fx.userUUID, "ECDSA_SHA256", msg)
	if err != nil {
		t.Fatalf("ECDSA 签名失败: %v", err)
	}
	// 现有实现输出定长 r||s（64 字节，P-256），与 PKCS#11 设备返回格式一致
	if len(sig) != 64 {
		t.Fatalf("P-256 的 ECDSA 签名应为 64 字节 r||s，实际 %d", len(sig))
	}
	stored, err := storage.NewCertRepo(db).GetByUUID(ctx, cert.UUID)
	if err != nil {
		t.Fatalf("读取证书失败: %v", err)
	}
	pub, err := x509.ParsePKIXPublicKey(stored.CertContent)
	if err != nil {
		t.Fatalf("解析公钥失败: %v", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("公钥类型应为 ECDSA，实际 %T", pub)
	}
	digest := sha256.Sum256(msg)
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(ecPub, digest[:], r, s) {
		t.Fatal("ECDSA r||s 签名验签失败")
	}
}

// TestImportCertWithKeyToLocalZone 带私钥导入：私钥按存储区域存放。
func TestImportCertWithKeyToLocalZone(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)
	fx := newZoneFixture(t, db, storage.DriverDatabase, "database", "导入本地存储", nil)
	ctx := context.Background()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成私钥失败: %v", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("序列化私钥失败: %v", err)
	}
	// 自签证书（模拟已有证书场景）
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(20261016),
		Subject:      pkix.Name{CommonName: "import.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("自签证书失败: %v", err)
	}

	cert, err := fx.svc.ImportCertWithKey(ctx, fx.card.UUID, fx.userUUID, "x509", "rsa2048", "导入测试", certDER, privDER)
	if err != nil {
		t.Fatalf("导入带私钥的证书失败: %v", err)
	}
	if cert.KeyBackend != storage.DriverDatabase {
		t.Errorf("导入后的私钥后端应记录为 database，实际 %q", cert.KeyBackend)
	}
	stored, err := storage.NewCertRepo(db).GetByUUID(ctx, cert.UUID)
	if err != nil {
		t.Fatalf("读取证书失败: %v", err)
	}
	if len(stored.PrivateData) == 0 {
		t.Fatal("导入的私钥应加密入库")
	}
	// 导入的私钥可直接用于签名
	if _, err := fx.svc.Sign(ctx, cert.UUID, fx.card.UUID, fx.userUUID, "SHA256_RSA_PKCS", []byte("x")); err != nil {
		t.Fatalf("导入后签名失败: %v", err)
	}
	// 有真实证书时可以导出 PKCS#12
	pfx, err := fx.svc.ExportPKCS12(ctx, stored, "strong-password", nil)
	if err != nil {
		t.Fatalf("导出 PKCS#12 失败: %v", err)
	}
	if _, _, _, err := pkcs12.DecodeChain(pfx, "strong-password"); err != nil {
		t.Fatalf("导出的 PKCS#12 无法解析: %v", err)
	}
}

// TestZoneParamsEncryptionAndRedaction 存储区域参数加密保存、回显脱敏。
func TestZoneParamsEncryptionAndRedaction(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)
	fx := newZoneFixture(t, db, storage.DriverPKCS11, "hsm", "HSM 参数测试", map[string]string{
		"library": "/tmp/libsofthsm2.so",
		"pin":     "1234",
	})

	// 密文中不应出现明文参数
	enc := string(fx.zone.ParamsEnc)
	if strings.Contains(enc, "1234") || strings.Contains(enc, "libsofthsm2") {
		t.Fatal("存储区域参数未加密")
	}

	params, err := fx.svc.DecryptZoneParams(fx.zone)
	if err != nil {
		t.Fatalf("解密存储区域参数失败: %v", err)
	}
	if params.Get("pin") != "1234" || params.Get("library") != "/tmp/libsofthsm2.so" {
		t.Fatalf("解密后的参数不正确: %+v", params)
	}

	view := fx.svc.ParamsForView(fx.zone)
	if view["pin"] != "" {
		t.Errorf("PIN 属于敏感项，回显时必须抹除，实际 %q", view["pin"])
	}
	if view["library"] != "/tmp/libsofthsm2.so" {
		t.Errorf("非敏感参数应正常回显，实际 %q", view["library"])
	}
}

// TestZoneMissingModuleFailsClearly 存储区域指向不存在的 PKCS#11 模块时给出明确错误。
func TestZoneMissingModuleFailsClearly(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)
	missing := "/nonexistent/libnosuchhsm.so"
	if runtime.GOOS == "windows" {
		missing = `C:\nonexistent\nosuchhsm.dll`
	}
	fx := newZoneFixture(t, db, storage.DriverPKCS11, "hsm", "缺失模块", map[string]string{
		"library": missing,
		"pin":     "1234",
	})
	ctx := context.Background()

	_, err := fx.svc.GenerateKeyPair(ctx, fx.card.UUID, fx.userUUID, "rsa2048", "x")
	if err == nil {
		t.Fatal("模块不存在时应返回错误")
	}
	msg := err.Error()
	if !strings.Contains(msg, "存储区域") && !strings.Contains(msg, "模块不存在") {
		t.Errorf("错误信息应指出存储区域/模块问题，实际: %v", msg)
	}
}

// TestCertBackendMismatchRejected 证书私钥位于硬件区域但卡片绑定了本地区域时拒绝操作。
func TestCertBackendMismatchRejected(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)
	fx := newZoneFixture(t, db, storage.DriverDatabase, "database", "本地区域", nil)
	ctx := context.Background()

	// 伪造一条「私钥在 HSM 内」的证书记录
	ref, err := keybackend.EncodeRef(storage.DriverPKCS11, map[string]string{"cka_id": "aabbcc"})
	if err != nil {
		t.Fatalf("构造私钥引用失败: %v", err)
	}
	cert := &storage.Certificate{
		CardUUID:         fx.card.UUID,
		UserUUID:         fx.userUUID,
		CertType:         "x509",
		KeyType:          "rsa2048",
		RevocationStatus: "active",
		KeyBackend:       storage.DriverPKCS11,
		KeyRef:           ref,
	}
	if err := storage.NewCertRepo(db).Create(ctx, cert); err != nil {
		t.Fatalf("创建证书失败: %v", err)
	}

	_, err = fx.svc.Sign(ctx, cert.UUID, fx.card.UUID, fx.userUUID, "SHA256_RSA_PKCS", []byte("x"))
	if err == nil {
		t.Fatal("存储区域不匹配时应拒绝签名")
	}
	if !strings.Contains(err.Error(), "存储区域") {
		t.Errorf("错误信息应说明存储区域不匹配，实际: %v", err)
	}

	// 导出私钥时同样应给出「硬件保护不可导出」的明确提示
	_, err = fx.svc.ExportPrivateKeyPEM(ctx, cert)
	if err == nil {
		t.Fatal("硬件私钥不应被导出")
	}
	if !strings.Contains(err.Error(), "不可导出") && !strings.Contains(err.Error(), "存储区域") {
		t.Errorf("导出错误信息不友好: %v", err)
	}
}

// TestProbeRejectsUnknownDriver 连接测试对未注册驱动给出明确错误。
func TestProbeRejectsUnknownDriver(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)
	cardSvc := card.NewService(storage.NewCardRepo(db), storage.NewCertRepo(db), testMasterKey)

	_, err := cardSvc.ProbeZone(context.Background(), "no-such-driver", keybackend.KindHSM, nil)
	if err == nil {
		t.Fatal("未注册的驱动应返回错误")
	}
	if !strings.Contains(err.Error(), "驱动") {
		t.Errorf("错误信息应提到驱动，实际: %v", err)
	}
}

// TestDriverRegistryBuiltins 内置驱动（本地 / TPM / PKCS#11）均已注册。
func TestDriverRegistryBuiltins(t *testing.T) {
	t.Parallel()
	want := map[string]keybackend.Kind{
		storage.DriverDatabase: keybackend.KindDatabase,
		storage.DriverTPM:      keybackend.KindTPM,
		storage.DriverPKCS11:   keybackend.KindHSM,
	}
	for driver, kind := range want {
		d, ok := keybackend.Lookup(driver)
		if !ok {
			t.Errorf("驱动 %s 未注册", driver)
			continue
		}
		if d.Kind != kind {
			t.Errorf("驱动 %s 的类型应为 %s，实际 %s", driver, kind, d.Kind)
		}
		if !d.Capabilities.Sign {
			t.Errorf("驱动 %s 应支持签名", driver)
		}
	}
	// PKCS#11 驱动应带有厂商预设，便于「扫描本机模块」
	d, _ := keybackend.Lookup(storage.DriverPKCS11)
	if len(d.Presets) == 0 {
		t.Error("PKCS#11 驱动应内置厂商预设")
	}
	// 扫描接口在无设备时也不应报错
	_ = keybackend.ScanPresets()
}
