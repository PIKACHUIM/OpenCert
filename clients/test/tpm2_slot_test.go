// Package storage_test - TPM2 Slot 集成测试。
// 使用 Mock TPM Provider 测试 TPM2 Slot 的完整流程。
package storage_test

import (
	"context"
	"testing"

	"github.com/globaltrusts/client-card/internal/card/local"
	tpm2card "github.com/globaltrusts/client-card/internal/card/tpm2"
	"github.com/globaltrusts/client-card/internal/storage"
	"github.com/globaltrusts/client-card/internal/tpm"
	"github.com/globaltrusts/client-card/pkg/pkcs11types"
)

// TestTPM2CreateCardAndLogin 测试 TPM2 卡片创建和登录。
func TestTPM2CreateCardAndLogin(t *testing.T) {
	db, cleanup := setupDB(t)
	defer cleanup()
	ctx := context.Background()

	cardRepo := storage.NewCardRepo(db)
	certRepo := storage.NewCertRepo(db)
	userRepo := storage.NewUserRepo(db)

	user := &storage.User{
		UserType:    storage.UserTypeLocal,
		DisplayName: "TPM2 测试用户",
		Email:       "tpm2@test.com",
		Enabled:     true,
	}
	if err := userRepo.Create(ctx, user); err != nil {
		t.Fatalf("创建用户失败: %v", err)
	}

	mockTPM := tpm.NewMock()
	keyMgr := tpm2card.NewKeyManager(certRepo, cardRepo, mockTPM)

	// 创建 TPM2 卡片
	card, err := keyMgr.CreateCard(ctx, user.UUID, "TPM2测试卡", "user-password-123", "", "TPM2测试")
	if err != nil {
		t.Fatalf("创建 TPM2 卡片失败: %v", err)
	}

	if card.SlotType != storage.SlotTypeTPM2 {
		t.Errorf("期望 SlotType=tpm2，实际=%s", card.SlotType)
	}
	t.Logf("TPM2 卡片已创建: UUID=%s", card.UUID)

	// 创建 TPM2 Slot 并登录
	slot := tpm2card.New(pkcs11types.SlotID(10), card, certRepo, mockTPM)

	// 错误密码应该失败
	if err := slot.Login(ctx, pkcs11types.CKU_USER, "wrong-password"); err == nil {
		t.Error("错误密码应该登录失败")
	}

	// 正确密码应该成功
	if err := slot.Login(ctx, pkcs11types.CKU_USER, "user-password-123"); err != nil {
		t.Fatalf("TPM2 Slot 登录失败: %v", err)
	}
	if !slot.IsLoggedIn() {
		t.Error("登录后 IsLoggedIn 应为 true")
	}
	t.Log("TPM2 Slot 登录成功")

	// 注销
	if err := slot.Logout(ctx); err != nil {
		t.Fatalf("注销失败: %v", err)
	}
	if slot.IsLoggedIn() {
		t.Error("注销后 IsLoggedIn 应为 false")
	}
}

// TestTPM2KeyGenAndSign 测试 TPM2 卡片密钥生成和签名。
func TestTPM2KeyGenAndSign(t *testing.T) {
	db, cleanup := setupDB(t)
	defer cleanup()
	ctx := context.Background()

	cardRepo := storage.NewCardRepo(db)
	certRepo := storage.NewCertRepo(db)
	userRepo := storage.NewUserRepo(db)

	user := &storage.User{
		UserType:    storage.UserTypeLocal,
		DisplayName: "TPM2 签名测试用户",
		Email:       "tpm2sign@test.com",
		Enabled:     true,
	}
	userRepo.Create(ctx, user)

	mockTPM := tpm.NewMock()
	keyMgr := tpm2card.NewKeyManager(certRepo, cardRepo, mockTPM)

	card, err := keyMgr.CreateCard(ctx, user.UUID, "TPM2签名卡", "sign-pass-456", "", "")
	if err != nil {
		t.Fatalf("创建 TPM2 卡片失败: %v", err)
	}

	// 登录获取主密钥
	slot := tpm2card.New(pkcs11types.SlotID(20), card, certRepo, mockTPM)
	if err := slot.Login(ctx, pkcs11types.CKU_USER, "sign-pass-456"); err != nil {
		t.Fatalf("登录失败: %v", err)
	}
	defer slot.Logout(ctx)

	masterKey := slot.MasterKey()
	if len(masterKey) != 32 {
		t.Fatalf("主密钥长度错误: got %d, want 32", len(masterKey))
	}

	// 生成 EC-256 密钥对
	result, err := keyMgr.GenerateKeyPair(ctx, local.KeyGenRequest{
		CardUUID: card.UUID,
		CertType: storage.CertTypeX509,
		KeyType:  "ec256",
		Remark:   "TPM2 EC 密钥",
	}, masterKey, card)
	if err != nil {
		t.Fatalf("生成 EC 密钥对失败: %v", err)
	}
	t.Logf("EC 密钥对已生成: CertUUID=%s", result.CertUUID)

	// 重新登录（模拟重启后加载）
	slot2 := tpm2card.New(pkcs11types.SlotID(21), card, certRepo, mockTPM)
	if err := slot2.Login(ctx, pkcs11types.CKU_USER, "sign-pass-456"); err != nil {
		t.Fatalf("重新登录失败: %v", err)
	}
	defer slot2.Logout(ctx)

	// 查找私钥对象
	handles, err := slot2.FindObjects(ctx, []pkcs11types.Attribute{
		{Type: pkcs11types.CKA_CLASS, Value: uint32BE(uint32(pkcs11types.CKO_PRIVATE_KEY))},
	})
	if err != nil {
		t.Fatalf("查找私钥对象失败: %v", err)
	}
	if len(handles) == 0 {
		t.Fatal("未找到私钥对象")
	}

	// 签名
	testData := []byte("TPM2 签名测试数据")
	sig, err := slot2.Sign(ctx, handles[0], pkcs11types.Mechanism{Type: pkcs11types.CKM_ECDSA_SHA256}, testData)
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	t.Logf("TPM2 签名成功，签名长度: %d 字节", len(sig))
}

// TestTPM2DeviceBinding 测试 TPM 设备绑定（不同 TPM 无法解封）。
func TestTPM2DeviceBinding(t *testing.T) {
	db, cleanup := setupDB(t)
	defer cleanup()
	ctx := context.Background()

	cardRepo := storage.NewCardRepo(db)
	certRepo := storage.NewCertRepo(db)
	userRepo := storage.NewUserRepo(db)

	user := &storage.User{
		UserType:    storage.UserTypeLocal,
		DisplayName: "TPM2 绑定测试用户",
		Email:       "tpm2bind@test.com",
		Enabled:     true,
	}
	userRepo.Create(ctx, user)

	// 用 TPM1 创建卡片
	tpm1 := tpm.NewMock()
	keyMgr := tpm2card.NewKeyManager(certRepo, cardRepo, tpm1)
	card, err := keyMgr.CreateCard(ctx, user.UUID, "绑定测试卡", "bind-pass-789", "", "")
	if err != nil {
		t.Fatalf("创建卡片失败: %v", err)
	}

	// 用 TPM1 可以登录
	slot1 := tpm2card.New(pkcs11types.SlotID(30), card, certRepo, tpm1)
	if err := slot1.Login(ctx, pkcs11types.CKU_USER, "bind-pass-789"); err != nil {
		t.Fatalf("TPM1 登录应该成功: %v", err)
	}
	t.Log("TPM1 登录成功（符合预期）")

	// 用 TPM2（不同设备）无法登录
	tpm2 := tpm.NewMock() // 不同的随机密钥 = 不同设备
	slot2 := tpm2card.New(pkcs11types.SlotID(31), card, certRepo, tpm2)
	if err := slot2.Login(ctx, pkcs11types.CKU_USER, "bind-pass-789"); err == nil {
		t.Error("不同 TPM 设备应该无法登录（设备绑定失败）")
	} else {
		t.Logf("不同 TPM 设备登录被拒绝（符合预期）: %v", err)
	}
}

// ---- 测试辅助函数 ----

// getMasterKeyForTest 通过 TPM Unseal 获取测试用主密钥。
func getMasterKeyForTest(t *testing.T, card *storage.Card, tpmProv tpm.Provider, pin string) []byte {
	t.Helper()
	_ = card
	_ = tpmProv
	_ = pin
	// 直接通过 slot 登录获取主密钥，此处为占位实现
	return nil
}

// zeroTestKey 清零测试密钥。
func zeroTestKey(key []byte) {
	for i := range key {
		key[i] = 0
	}
}
