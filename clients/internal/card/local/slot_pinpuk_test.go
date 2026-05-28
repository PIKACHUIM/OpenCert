// Package local 的三级凭据单元测试：验证 PIN/PUK/AdminKey 能独立解锁同一主密钥、
// PUK 可重置 PIN、Admin 可重置 PUK 与 PIN、以及凭据锁定逻辑。
package local

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/globaltrusts/client-card/internal/storage"
)

// newTestRepos 创建临时 SQLite 数据库，返回 CardRepo。
func newTestRepos(t *testing.T) (*storage.DB, *storage.CardRepo) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "pinpuk.db")
	db, err := storage.Open(dbPath)
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db, storage.NewCardRepo(db)
}

// TestCreateCardWithCreds_GeneratesPUKAndAdmin 验证：未提供 PUK/AdminKey 时自动生成并返回。
func TestCreateCardWithCreds_GeneratesPUKAndAdmin(t *testing.T) {
	_, cardRepo := newTestRepos(t)
	ctx := context.Background()

	res, err := CreateCardWithCreds(ctx, cardRepo, CreateCardArgs{
		UserUUID:      "user-1",
		CardName:      "test-card",
		PIN:           "123456",
		GeneratePUK:   true,
		GenerateAdmin: true,
	})
	if err != nil {
		t.Fatalf("创建卡片失败: %v", err)
	}
	if res.PUK == "" {
		t.Fatalf("应自动生成 PUK")
	}
	if res.AdminKey == "" {
		t.Fatalf("应自动生成 AdminKey")
	}
	if res.PUK == res.AdminKey {
		t.Fatalf("PUK 与 AdminKey 不应相同")
	}

	// 校验卡片被正确持久化
	card, err := cardRepo.GetByUUID(ctx, res.Card.UUID)
	if err != nil || card == nil {
		t.Fatalf("卡片未落库: %v", err)
	}
	// 至少 3 条 CardKey 条目：pin / puk / admin
	countByType := map[string]int{}
	for _, e := range card.CardKeys {
		countByType[e.KeyType]++
	}
	for _, kt := range []string{"pin", "puk", "admin"} {
		if countByType[kt] != 1 {
			t.Fatalf("期望 %s 条目 1 条, 实际 %d (all=%v)", kt, countByType[kt], countByType)
		}
	}
}

// TestResetPIN_WithPUK 验证 PUK 可以用来重置 PIN。
func TestResetPIN_WithPUK(t *testing.T) {
	_, cardRepo := newTestRepos(t)
	ctx := context.Background()

	res, err := CreateCardWithCreds(ctx, cardRepo, CreateCardArgs{
		UserUUID:      "u1",
		CardName:      "c",
		PIN:           "111111",
		GeneratePUK:   true,
		GenerateAdmin: true,
	})
	if err != nil {
		t.Fatalf("创建失败: %v", err)
	}
	card := res.Card

	// 用 PUK 重置 PIN
	if err := ResetPIN(ctx, cardRepo, card, "puk", res.PUK, "222222"); err != nil {
		t.Fatalf("PUK 重置 PIN 失败: %v", err)
	}

	// 重新加载卡片，验证新 PIN 可解锁主密钥
	reloaded, err := cardRepo.GetByUUID(ctx, card.UUID)
	if err != nil || reloaded == nil {
		t.Fatalf("reload 卡片失败: %v", err)
	}
	mk, err := tryUnlockByType(reloaded, "pin", "222222")
	if err != nil {
		t.Fatalf("新 PIN 无法解锁: %v", err)
	}
	if len(mk) != 32 {
		t.Fatalf("主密钥长度应为 32, 实际 %d", len(mk))
	}
	// 旧 PIN 应失效
	if _, err := tryUnlockByType(reloaded, "pin", "111111"); err == nil {
		t.Fatalf("旧 PIN 不应再有效")
	}
}

// TestResetPUK_WithAdmin 验证 AdminKey 可以用来重置 PUK。
func TestResetPUK_WithAdmin(t *testing.T) {
	_, cardRepo := newTestRepos(t)
	ctx := context.Background()

	res, err := CreateCardWithCreds(ctx, cardRepo, CreateCardArgs{
		UserUUID:      "u1",
		CardName:      "c",
		PIN:           "mypin",
		GeneratePUK:   true,
		GenerateAdmin: true,
	})
	if err != nil {
		t.Fatalf("创建失败: %v", err)
	}
	card := res.Card

	if err := ResetPUK(ctx, cardRepo, card, res.AdminKey, "mypin", "new-puk-value"); err != nil {
		t.Fatalf("Admin 重置 PUK 失败: %v", err)
	}

	reloaded, err := cardRepo.GetByUUID(ctx, card.UUID)
	if err != nil || reloaded == nil {
		t.Fatalf("reload 失败: %v", err)
	}
	// 新 PUK 应能直接解锁主密钥（PUK 现在直接加密主密钥）
	mk, err := tryUnlockByType(reloaded, "puk", "new-puk-value")
	if err != nil {
		t.Fatalf("新 PUK 无法解锁主密钥: %v", err)
	}
	if len(mk) != 32 {
		t.Fatalf("主密钥长度应为 32, 实际 %d", len(mk))
	}
	// 旧 PUK 失效
	if _, err := tryUnlockByType(reloaded, "puk", res.PUK); err == nil {
		t.Fatalf("旧 PUK 不应再有效")
	}
}

// TestResetPIN_WrongSecret 验证错误的 PUK/AdminKey 会递增失败计数并拒绝。
func TestResetPIN_WrongSecret(t *testing.T) {
	_, cardRepo := newTestRepos(t)
	ctx := context.Background()
	res, err := CreateCardWithCreds(ctx, cardRepo, CreateCardArgs{
		UserUUID:      "u1",
		CardName:      "c",
		PIN:           "testpin",
		GeneratePUK:   true,
		GenerateAdmin: true,
	})
	if err != nil {
		t.Fatalf("创建失败: %v", err)
	}

	if err := ResetPIN(ctx, cardRepo, res.Card, "puk", "wrong-puk", "new-pin"); err == nil {
		t.Fatalf("错误 PUK 应返回失败")
	}

	reloaded, _ := cardRepo.GetByUUID(ctx, res.Card.UUID)
	var pukEntry *storage.CardKeyEntry
	for i := range reloaded.CardKeys {
		if reloaded.CardKeys[i].KeyType == "puk" {
			pukEntry = &reloaded.CardKeys[i]
			break
		}
	}
	if pukEntry == nil || pukEntry.Attempts < 1 {
		t.Fatalf("PUK 失败计数未递增: entry=%+v", pukEntry)
	}
}

// TestPUKLockoutAfter10Failures 验证连续 10 次失败后 PUK 被锁定。
func TestPUKLockoutAfter10Failures(t *testing.T) {
	_, cardRepo := newTestRepos(t)
	ctx := context.Background()
	res, err := CreateCardWithCreds(ctx, cardRepo, CreateCardArgs{
		UserUUID:      "u1",
		CardName:      "c",
		PIN:           "lockpin",
		GeneratePUK:   true,
		GenerateAdmin: true,
	})
	if err != nil {
		t.Fatalf("创建失败: %v", err)
	}

	for i := 0; i < 10; i++ {
		_ = ResetPIN(ctx, cardRepo, res.Card, "puk", "bad", "x")
		// 每次重载以模拟真实请求
		reloaded, _ := cardRepo.GetByUUID(ctx, res.Card.UUID)
		res.Card = reloaded
	}

	// 第 11 次：即使给正确 PUK 也应被拒绝（已锁定）
	if err := ResetPIN(ctx, cardRepo, res.Card, "puk", res.PUK, "newpin"); err == nil {
		t.Fatalf("锁定后应拒绝重置")
	}

	// AdminKey 仍可用于重置 PIN
	if err := ResetPIN(ctx, cardRepo, res.Card, "admin", res.AdminKey, "recoverpin"); err != nil {
		t.Fatalf("AdminKey 应能绕过 PUK 锁定: %v", err)
	}
	reloaded, _ := cardRepo.GetByUUID(ctx, res.Card.UUID)
	if _, err := tryUnlockByType(reloaded, "pin", "recoverpin"); err != nil {
		t.Fatalf("AdminKey 重置后的新 PIN 应可解锁: %v", err)
	}
}

// TestTryUnlockByType_SkipsOtherTypes 验证 tryUnlockByType 只匹配对应类型。
// 这是安全性关键测试：防止凭据类型误用。
func TestTryUnlockByType_SkipsOtherTypes(t *testing.T) {
	_, cardRepo := newTestRepos(t)
	ctx := context.Background()

	res, err := CreateCardWithCreds(ctx, cardRepo, CreateCardArgs{
		UserUUID:      "u1",
		CardName:      "c",
		PIN:           "secret-shared", // 故意让 PIN 与 AdminKey 不同
		AdminKey:      "admin-key-123",
		GeneratePUK:   true,
	})
	if err != nil {
		t.Fatalf("创建失败: %v", err)
	}

	// 用 "pin" 凭据类型 + "secret-shared" 应解锁 pin 条目（ok）
	mk, err := tryUnlockByType(res.Card, "pin", "secret-shared")
	if err != nil {
		t.Fatalf("pin 解锁失败: %v", err)
	}
	if len(mk) != 32 {
		t.Fatalf("解出的主密钥长度错误")
	}

	// 用 "admin" 类型 + PIN 值应失败（类型隔离）
	if _, err := tryUnlockByType(res.Card, "admin", "secret-shared"); err == nil {
		t.Fatalf("跨类型解锁不应成功")
	}

	// PUK 现在直接加密主密钥，可以通过 tryUnlockByType 解锁
	pukMK, err := tryUnlockByType(res.Card, "puk", res.PUK)
	if err != nil {
		t.Fatalf("PUK 直接解锁主密钥应成功: %v", err)
	}
	if len(pukMK) != 32 {
		t.Fatalf("PUK 解出的主密钥长度错误")
	}

	// 用错误的 PUK 值应失败
	if _, err := tryUnlockByType(res.Card, "puk", "wrong-puk"); err == nil {
		t.Fatalf("错误 PUK 不应解锁成功")
	}
}
