// Package storage_test - E2E 联调测试。
// 覆盖完整的 PKCS#11 操作序列：
// C_Initialize → C_GetSlotList → C_OpenSession → C_Login → C_FindObjects → C_Sign → C_Logout → C_CloseSession → C_Finalize
package storage_test

import (
	"context"
	"os"
	"testing"

	"github.com/globaltrusts/client-card/internal/card"
	"github.com/globaltrusts/client-card/internal/card/local"
	"github.com/globaltrusts/client-card/internal/storage"
	"github.com/globaltrusts/client-card/pkg/pkcs11types"
)

// TestE2EFullPKCS11Sequence 测试完整的 PKCS#11 操作序列。
// 模拟 pkcs11-mock DLL 通过 IPC 调用 client-card 的完整流程。
func TestE2EFullPKCS11Sequence(t *testing.T) {
	// 创建临时数据库
	f, err := os.CreateTemp("", "e2e-test-*.db")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	defer os.Remove(f.Name())

	db, err := storage.Open(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	userRepo := storage.NewUserRepo(db)
	cardRepo := storage.NewCardRepo(db)
	certRepo := storage.NewCertRepo(db)

	// 1. 创建测试用户
	user := &storage.User{
		UserType:    storage.UserTypeLocal,
		DisplayName: "E2E 测试用户",
		Email:       "e2e@test.com",
		Enabled:     true,
	}
	if err := userRepo.Create(ctx, user); err != nil {
		t.Fatalf("创建用户失败: %v", err)
	}

	// 2. 创建本地卡片（模拟 C_Initialize 阶段的卡片初始化）
	testCard, err := local.CreateCard(ctx, cardRepo, user.UUID, "E2E 测试卡片", "e2epin123", "", "E2E 测试")
	if err != nil {
		t.Fatalf("创建卡片失败: %v", err)
	}
	t.Logf("✓ 卡片创建成功: %s", testCard.UUID)

	// 3. C_Initialize：创建 Manager（模拟 PKCS#11 初始化）
	mgr := card.NewManager()

	// 4. 注册 Slot（模拟 C_GetSlotList 返回的 Slot）
	slot := local.New(pkcs11types.SlotID(1), testCard, certRepo)
	mgr.RegisterSlot(slot)

	// 5. C_GetSlotList：获取 Slot 列表
	slots := mgr.GetSlotList(true)
	if len(slots) == 0 {
		t.Fatal("C_GetSlotList 返回空列表")
	}
	t.Logf("✓ C_GetSlotList 成功，Slot 数量: %d", len(slots))

	// 6. C_OpenSession：打开会话
	sessionHandle, err := mgr.OpenSession(pkcs11types.SlotID(1), pkcs11types.CKF_SERIAL_SESSION|pkcs11types.CKF_RW_SESSION)
	if err != nil {
		t.Fatalf("C_OpenSession 失败: %v", err)
	}
	t.Logf("✓ C_OpenSession 成功，SessionHandle: %d", sessionHandle)

	// 7. C_Login（错误 PIN 应该失败）
	if err := mgr.Login(ctx, sessionHandle, pkcs11types.CKU_USER, "wrongpin"); err == nil {
		t.Fatal("错误 PIN 应该登录失败")
	}
	t.Logf("✓ 错误 PIN 正确拒绝")

	// 8. C_Login（正确 PIN）
	if err := mgr.Login(ctx, sessionHandle, pkcs11types.CKU_USER, "e2epin123"); err != nil {
		t.Fatalf("C_Login 失败: %v", err)
	}
	t.Logf("✓ C_Login 成功")

	// 9. 生成密钥对（模拟 C_GenerateKeyPair）
	km := local.NewKeyManager(certRepo, cardRepo)
	keyResult, err := km.GenerateKeyPair(ctx, local.KeyGenRequest{
		CardUUID: testCard.UUID,
		CertType: storage.CertTypeX509,
		KeyType:  "ec256",
		Remark:   "E2E 测试密钥",
	}, slot.MasterKey(), testCard)
	if err != nil {
		t.Fatalf("C_GenerateKeyPair 失败: %v", err)
	}
	t.Logf("✓ C_GenerateKeyPair 成功，证书 UUID: %s", keyResult.CertUUID)

	// 重新登出并登录，使新生成的密钥对被加载到 Slot 对象缓存
	mgr.Logout(ctx, sessionHandle)
	if err := mgr.Login(ctx, sessionHandle, pkcs11types.CKU_USER, "e2epin123"); err != nil {
		t.Fatalf("重新 C_Login 失败: %v", err)
	}
	t.Logf("✓ 重新 C_Login 成功（加载新密钥对）")

	// 10. C_FindObjects：查找私钥对象
	handles, err := slot.FindObjects(ctx, []pkcs11types.Attribute{
		{Type: pkcs11types.CKA_CLASS, Value: uint32BE(uint32(pkcs11types.CKO_PRIVATE_KEY))},
	})
	if err != nil {
		t.Fatalf("C_FindObjects 失败: %v", err)
	}
	if len(handles) == 0 {
		t.Fatal("C_FindObjects 未找到私钥对象")
	}
	t.Logf("✓ C_FindObjects 成功，找到 %d 个私钥对象", len(handles))

	// 11. C_Sign：使用私钥签名
	testData := []byte("E2E PKCS#11 签名测试数据 - Hello World!")
	sig, err := slot.Sign(ctx, handles[0], pkcs11types.Mechanism{
		Type: pkcs11types.CKM_ECDSA_SHA256,
	}, testData)
	if err != nil {
		t.Fatalf("C_Sign 失败: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("C_Sign 返回空签名")
	}
	t.Logf("✓ C_Sign 成功，签名长度: %d 字节", len(sig))

	// 12. C_Logout
	if err := mgr.Logout(ctx, sessionHandle); err != nil {
		t.Fatalf("C_Logout 失败: %v", err)
	}
	t.Logf("✓ C_Logout 成功")

	// 13. C_CloseSession
	if err := mgr.CloseSession(sessionHandle); err != nil {
		t.Fatalf("C_CloseSession 失败: %v", err)
	}
	t.Logf("✓ C_CloseSession 成功")

	// 14. C_Finalize：验证所有会话已关闭
	remainingSessions := mgr.GetSlotList(false)
	t.Logf("✓ C_Finalize 完成，剩余 Slot 数量: %d", len(remainingSessions))

	t.Log("✓ 完整 PKCS#11 操作序列测试通过！")
}

// TestE2EPINLockout 测试 PIN 锁定机制。
func TestE2EPINLockout(t *testing.T) {
	f, err := os.CreateTemp("", "e2e-pin-test-*.db")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	defer os.Remove(f.Name())

	db, err := storage.Open(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	userRepo := storage.NewUserRepo(db)
	cardRepo := storage.NewCardRepo(db)
	certRepo := storage.NewCertRepo(db)

	user := &storage.User{UserType: storage.UserTypeLocal, DisplayName: "PIN 锁定测试", Email: "pin@test.com", Enabled: true}
	userRepo.Create(ctx, user)

	testCard, err := local.CreateCard(ctx, cardRepo, user.UUID, "PIN 测试卡片", "correctpin", "", "")
	if err != nil {
		t.Fatal(err)
	}
	// 设置 PIN 重试次数为 3
	testCard.PINRetries = 3
	cardRepo.Update(ctx, testCard)

	// 创建带 CardRepo 的 Slot（支持 PIN 锁定）
	slot := local.NewWithCardRepo(pkcs11types.SlotID(1), testCard, certRepo, cardRepo)

	// 连续错误 3 次
	for i := 0; i < 3; i++ {
		err := slot.Login(ctx, pkcs11types.CKU_USER, "wrongpin")
		if err == nil {
			t.Fatalf("第 %d 次错误 PIN 应该失败", i+1)
		}
		t.Logf("第 %d 次错误 PIN: %v", i+1, err)
	}

	// 第 4 次应该返回 PIN_LOCKED
	err = slot.Login(ctx, pkcs11types.CKU_USER, "correctpin")
	if err == nil {
		t.Fatal("PIN 锁定后正确 PIN 也应该失败")
	}
	t.Logf("✓ PIN 锁定机制正常工作: %v", err)
}

// TestE2EMultipleSlots 测试多 Slot 并发操作。
func TestE2EMultipleSlots(t *testing.T) {
	f, err := os.CreateTemp("", "e2e-multi-*.db")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	defer os.Remove(f.Name())

	db, err := storage.Open(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	userRepo := storage.NewUserRepo(db)
	cardRepo := storage.NewCardRepo(db)
	certRepo := storage.NewCertRepo(db)

	user := &storage.User{UserType: storage.UserTypeLocal, DisplayName: "多 Slot 测试", Email: "multi@test.com", Enabled: true}
	userRepo.Create(ctx, user)

	// 创建两张卡片
	card1, _ := local.CreateCard(ctx, cardRepo, user.UUID, "卡片 1", "pin1", "", "")
	card2, _ := local.CreateCard(ctx, cardRepo, user.UUID, "卡片 2", "pin2", "", "")

	mgr := card.NewManager()
	slot1 := local.New(pkcs11types.SlotID(1), card1, certRepo)
	slot2 := local.New(pkcs11types.SlotID(2), card2, certRepo)
	mgr.RegisterSlot(slot1)
	mgr.RegisterSlot(slot2)

	slots := mgr.GetSlotList(true)
	if len(slots) != 2 {
		t.Fatalf("期望 2 个 Slot，实际 %d 个", len(slots))
	}

	// 分别打开两个会话
	h1, _ := mgr.OpenSession(pkcs11types.SlotID(1), pkcs11types.CKF_SERIAL_SESSION|pkcs11types.CKF_RW_SESSION)
	h2, _ := mgr.OpenSession(pkcs11types.SlotID(2), pkcs11types.CKF_SERIAL_SESSION|pkcs11types.CKF_RW_SESSION)

	// 分别登录
	if err := mgr.Login(ctx, h1, pkcs11types.CKU_USER, "pin1"); err != nil {
		t.Fatalf("Slot 1 登录失败: %v", err)
	}
	if err := mgr.Login(ctx, h2, pkcs11types.CKU_USER, "pin2"); err != nil {
		t.Fatalf("Slot 2 登录失败: %v", err)
	}

	t.Log("✓ 多 Slot 并发操作测试通过！")

	mgr.Logout(ctx, h1)
	mgr.Logout(ctx, h2)
	mgr.CloseSession(h1)
	mgr.CloseSession(h2)
}
