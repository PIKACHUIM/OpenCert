package storage_test

import (
	"context"
	"os"
	"testing"

	"github.com/globaltrusts/client-card/internal/card/local"
	"github.com/globaltrusts/client-card/internal/storage"
	"github.com/globaltrusts/client-card/pkg/pkcs11types"
)

func setupDB(t *testing.T) (*storage.DB, func()) {
	t.Helper()
	f, err := os.CreateTemp("", "local-slot-test-*.db")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	db, err := storage.Open(f.Name())
	if err != nil {
		os.Remove(f.Name())
		t.Fatal(err)
	}
	return db, func() {
		db.Close()
		os.Remove(f.Name())
	}
}

func TestCreateCardAndLogin(t *testing.T) {
	db, cleanup := setupDB(t)
	defer cleanup()

	ctx := context.Background()
	cardRepo := storage.NewCardRepo(db)
	certRepo := storage.NewCertRepo(db)
	userRepo := storage.NewUserRepo(db)

	// 创建用户
	user := &storage.User{
		UserType:    storage.UserTypeLocal,
		DisplayName: "测试用户",
		Email:       "test@example.com",
		Enabled:     true,
	}
	if err := userRepo.Create(ctx, user); err != nil {
		t.Fatal(err)
	}

	// 创建本地卡片
	card, err := local.CreateCard(ctx, cardRepo, user.UUID, "测试卡片", "mypassword123", "", "测试")
	if err != nil {
		t.Fatalf("创建卡片失败: %v", err)
	}
	if card.UUID == "" {
		t.Fatal("卡片 UUID 为空")
	}
	if len(card.CardKeys) != 1 {
		t.Fatalf("CardKeys 数量错误: got %d, want 1", len(card.CardKeys))
	}

	// 创建 Slot 并登录
	slot := local.New(pkcs11types.SlotID(1), card, certRepo)

	// 错误密码应该失败
	if err := slot.Login(ctx, pkcs11types.CKU_USER, "wrongpassword"); err == nil {
		t.Fatal("错误密码应该登录失败")
	}

	// 正确密码应该成功
	if err := slot.Login(ctx, pkcs11types.CKU_USER, "mypassword123"); err != nil {
		t.Fatalf("正确密码登录失败: %v", err)
	}

	if !slot.IsLoggedIn() {
		t.Fatal("登录后 IsLoggedIn 应为 true")
	}

	masterKey := slot.MasterKey()
	if len(masterKey) != 32 {
		t.Fatalf("主密钥长度错误: got %d, want 32", len(masterKey))
	}

	// 登出
	if err := slot.Logout(ctx); err != nil {
		t.Fatalf("登出失败: %v", err)
	}
	if slot.IsLoggedIn() {
		t.Fatal("登出后 IsLoggedIn 应为 false")
	}
}

func TestGenerateKeyPairAndSign(t *testing.T) {
	db, cleanup := setupDB(t)
	defer cleanup()

	ctx := context.Background()
	cardRepo := storage.NewCardRepo(db)
	certRepo := storage.NewCertRepo(db)
	userRepo := storage.NewUserRepo(db)

	// 创建用户和卡片
	user := &storage.User{
		UserType:    storage.UserTypeLocal,
		DisplayName: "密钥测试用户",
		Email:       "key@example.com",
		Enabled:     true,
	}
	userRepo.Create(ctx, user)

	card, err := local.CreateCard(ctx, cardRepo, user.UUID, "密钥卡片", "keypass456", "", "")
	if err != nil {
		t.Fatal(err)
	}

	// 登录获取主密钥
	slot := local.New(pkcs11types.SlotID(1), card, certRepo)
	if err := slot.Login(ctx, pkcs11types.CKU_USER, "keypass456"); err != nil {
		t.Fatalf("登录失败: %v", err)
	}
	defer slot.Logout(ctx)

	masterKey := slot.MasterKey()

	// 生成 EC-256 密钥对
	km := local.NewKeyManager(certRepo, cardRepo)
	result, err := km.GenerateKeyPair(ctx, local.KeyGenRequest{
		CardUUID: card.UUID,
		CertType: storage.CertTypeX509,
		KeyType:  "ec256",
		Remark:   "测试 EC 密钥",
	}, masterKey, card)
	if err != nil {
		t.Fatalf("生成密钥对失败: %v", err)
	}
	if result.CertUUID == "" {
		t.Fatal("证书 UUID 为空")
	}
	if len(result.PublicKeyDER) == 0 {
		t.Fatal("公钥为空")
	}

	// 重新加载 Slot（模拟重启后从数据库加载）
	slot2 := local.New(pkcs11types.SlotID(1), card, certRepo)
	if err := slot2.Login(ctx, pkcs11types.CKU_USER, "keypass456"); err != nil {
		t.Fatalf("重新登录失败: %v", err)
	}
	defer slot2.Logout(ctx)

	// 查找私钥对象
	handles, err := slot2.FindObjects(ctx, []pkcs11types.Attribute{
		{Type: pkcs11types.CKA_CLASS, Value: uint32BE(uint32(pkcs11types.CKO_PRIVATE_KEY))},
	})
	if err != nil {
		t.Fatalf("查找对象失败: %v", err)
	}
	if len(handles) == 0 {
		t.Fatal("未找到私钥对象")
	}

	// 签名测试
	testData := []byte("hello, pkcs11 signing test")
	sig, err := slot2.Sign(ctx, handles[0], pkcs11types.Mechanism{
		Type: pkcs11types.CKM_ECDSA_SHA256,
	}, testData)
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("签名结果为空")
	}
	t.Logf("EC-256 签名成功，签名长度: %d 字节", len(sig))
}

func TestGenerateRSAKeyPair(t *testing.T) {
	db, cleanup := setupDB(t)
	defer cleanup()

	ctx := context.Background()
	cardRepo := storage.NewCardRepo(db)
	certRepo := storage.NewCertRepo(db)
	userRepo := storage.NewUserRepo(db)

	user := &storage.User{UserType: storage.UserTypeLocal, DisplayName: "RSA 测试", Email: "rsa@test.com", Enabled: true}
	userRepo.Create(ctx, user)

	card, _ := local.CreateCard(ctx, cardRepo, user.UUID, "RSA 卡片", "rsapass", "", "")
	slot := local.New(pkcs11types.SlotID(1), card, certRepo)
	slot.Login(ctx, pkcs11types.CKU_USER, "rsapass")
	defer slot.Logout(ctx)

	km := local.NewKeyManager(certRepo, cardRepo)
	result, err := km.GenerateKeyPair(ctx, local.KeyGenRequest{
		CardUUID: card.UUID,
		CertType: storage.CertTypeX509,
		KeyType:  "rsa2048",
		Remark:   "RSA-2048 测试",
	}, slot.MasterKey(), card)
	if err != nil {
		t.Fatalf("生成 RSA 密钥对失败: %v", err)
	}
	t.Logf("RSA-2048 密钥对生成成功，证书 UUID: %s", result.CertUUID)
}

// uint32BE 将 uint32 转为大端字节序。
func uint32BE(v uint32) []byte {
	return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}
