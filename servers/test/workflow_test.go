// Package test 提供 servers 的集成测试。
package test

import (
	"context"
	"strings"
	"testing"

	"github.com/globaltrusts/server-card/internal/storage"
	"github.com/globaltrusts/server-card/internal/workflow"
)

// createTestUser 在测试数据库中创建一个测试用户，返回 UUID。
// email 同时作为 Username（唯一），确保并行测试不冲突。
func createTestUser(t *testing.T, db *storage.DB, email string) string {
	t.Helper()
	ctx := context.Background()
	repo := storage.NewUserRepo(db)
	u := &storage.User{
		Username:     email, // servers users 表 username 有 UNIQUE 约束
		DisplayName:  "测试用户",
		Email:        email,
		PasswordHash: "$2a$12$testhashabcdefghijklmno",
		Role:         "user",
		Enabled:      true,
	}
	if err := repo.Create(ctx, u); err != nil {
		t.Fatalf("创建测试用户失败 (email=%s): %v", email, err)
	}
	return u.UUID
}

// seedBalance 为用户初始化可用余额。
//
// 自门户改造起，下单（CreateOrder）不再预扣或冻结余额：
// 待支付订单允许任何已登录用户创建，实际扣款发生在支付阶段。
// 此处保留该辅助函数，供后续支付相关测试使用。
func seedBalance(t *testing.T, db *storage.DB, userUUID string, cents int64) {
	t.Helper()
	_, err := db.ExecContext(context.Background(),
		`INSERT INTO user_balances (user_uuid, available_cents, frozen_cents, total_recharge, total_consume)
		 VALUES (?, ?, 0, ?, 0)
		 ON CONFLICT(user_uuid) DO UPDATE SET available_cents = excluded.available_cents`,
		userUUID, cents, cents)
	if err != nil {
		t.Fatalf("初始化测试余额失败: %v", err)
	}
}

func TestWorkflowCreateOrder(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)

	svc := workflow.NewService(db, nil, nil)
	ctx := context.Background()
	userUUID := createTestUser(t, db, "order@test.com")

	order := &storage.CertOrder{
		UserUUID:           userUUID,
		IssuanceTmplUUID:   "tmpl-uuid-1",
		KeyStorageTmplUUID: "ks-tmpl-uuid-1",
		AmountCents:        100,
	}
	if err := svc.CreateOrder(ctx, order); err != nil {
		t.Fatalf("CreateOrder() 失败: %v", err)
	}

	if order.UUID == "" {
		t.Error("CreateOrder() 未生成 UUID")
	}
	if order.OrderNo == "" {
		t.Error("CreateOrder() 未生成对外订单号")
	}
	if !strings.HasPrefix(order.OrderNo, "CO") {
		t.Errorf("对外订单号应以 CO 开头，实际 %q", order.OrderNo)
	}
	if order.Status != storage.CertOrderPendingPayment {
		t.Errorf("初始状态应为 pending_payment，got %q", order.Status)
	}
	// 下单阶段不预冻结金额，扣款在支付阶段完成
	if order.FrozenCents != 0 {
		t.Errorf("下单不应冻结金额，FrozenCents = %d", order.FrozenCents)
	}

	// 空用户不应被接受（避免产生无归属订单）
	if err := svc.CreateOrder(ctx, &storage.CertOrder{AmountCents: 1}); err == nil {
		t.Error("缺少归属用户的订单应被拒绝")
	}
}

// TestWorkflowCreateOrder_NoBalanceRecord 验证从未充值的用户也可以下单。
//
// 门户流程允许「先下单、再支付」，因此下单不应要求账户已有余额记录，
// 也不应因余额为 0 而失败。
func TestWorkflowCreateOrder_NoBalanceRecord(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)
	svc := workflow.NewService(db, nil, nil)
	userUUID := createTestUser(t, db, "nobalance@test.com")

	order := &storage.CertOrder{
		UserUUID:         userUUID,
		IssuanceTmplUUID: "tmpl",
		AmountCents:      100,
	}
	if err := svc.CreateOrder(context.Background(), order); err != nil {
		t.Fatalf("无余额记录的用户应能创建待支付订单，实际错误: %v", err)
	}
	if order.Status != storage.CertOrderPendingPayment {
		t.Errorf("状态应为 pending_payment，got %q", order.Status)
	}
}

// insertApplyTemplate 插入一条证书申请模板，用于验证服务端权威定价。
func insertApplyTemplate(t *testing.T, db *storage.DB, uuid, name string, priceCents int64, enabled bool) {
	t.Helper()
	enabledInt := 0
	if enabled {
		enabledInt = 1
	}
	_, err := db.ExecContext(context.Background(),
		`INSERT INTO cert_apply_templates
		 (uuid, name, issuance_tmpl_uuid, valid_days, ca_uuid, enabled, require_approval,
		  allow_renewal, allowed_key_types, price_cents, description, created_at, updated_at)
		 VALUES (?, ?, 'issuance-tmpl-1', 365, 'ca-1', ?, 0, 1, '["ec256"]', ?, '', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
		uuid, name, enabledInt, priceCents)
	if err != nil {
		t.Fatalf("插入证书申请模板失败: %v", err)
	}
}

// TestWorkflowCreateOrder_TemplatePricing 验证订单定价以服务端模板为准：
// 未传金额时按模板定价回填，模板下架时拒绝下单。
func TestWorkflowCreateOrder_TemplatePricing(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)
	svc := workflow.NewService(db, nil, nil)
	ctx := context.Background()
	userUUID := createTestUser(t, db, "pricing@test.com")

	insertApplyTemplate(t, db, "tmpl-priced", "标准证书", 12345, true)

	order := &storage.CertOrder{UserUUID: userUUID, CertApplyTmplUUID: "tmpl-priced"}
	if err := svc.CreateOrder(ctx, order); err != nil {
		t.Fatalf("CreateOrder() 失败: %v", err)
	}
	if order.AmountCents != 12345 {
		t.Errorf("金额应由模板定价回填，期望 12345，实际 %d", order.AmountCents)
	}
	if order.IssuanceTmplUUID != "issuance-tmpl-1" {
		t.Errorf("应自动关联颁发模板，实际 %q", order.IssuanceTmplUUID)
	}

	// 已下架模板必须拒绝下单
	insertApplyTemplate(t, db, "tmpl-disabled", "已下架证书", 100, false)
	err := svc.CreateOrder(ctx, &storage.CertOrder{UserUUID: userUUID, CertApplyTmplUUID: "tmpl-disabled"})
	if err == nil {
		t.Fatal("已下架模板应拒绝下单")
	}
	if !strings.Contains(err.Error(), "下架") {
		t.Errorf("错误信息应提示商品已下架，实际: %v", err)
	}
}

func TestWorkflowGetOrder(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)

	svc := workflow.NewService(db, nil, nil)
	ctx := context.Background()
	userUUID := createTestUser(t, db, "getorder@test.com")
	seedBalance(t, db, userUUID, 1000)

	order := &storage.CertOrder{
		UserUUID:         userUUID,
		IssuanceTmplUUID: "tmpl-uuid",
		AmountCents:      200,
	}
	if err := svc.CreateOrder(ctx, order); err != nil {
		t.Fatalf("创建订单失败: %v", err)
	}

	// 查询存在的订单
	got, err := svc.GetOrder(ctx, order.UUID)
	if err != nil {
		t.Fatalf("GetOrder() 失败: %v", err)
	}
	if got.AmountCents != 200 {
		t.Errorf("AmountCents = %d，期望 200", got.AmountCents)
	}

	// 查询不存在的订单
	if _, err := svc.GetOrder(ctx, "non-existent"); err == nil {
		t.Error("查询不存在的订单应返回错误")
	}
}

func TestWorkflowListOrders(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)

	svc := workflow.NewService(db, nil, nil)
	ctx := context.Background()
	userUUID := createTestUser(t, db, "listorder@test.com")
	seedBalance(t, db, userUUID, 1000)

	// 创建 3 个订单
	for i := 0; i < 3; i++ {
		o := &storage.CertOrder{
			UserUUID:         userUUID,
			IssuanceTmplUUID: "tmpl",
			AmountCents:      int64(100 * (i + 1)),
		}
		if err := svc.CreateOrder(ctx, o); err != nil {
			t.Fatalf("创建订单失败: %v", err)
		}
	}

	orders, total, err := svc.ListOrders(ctx, userUUID, 1, 10)
	if err != nil {
		t.Fatalf("ListOrders() 失败: %v", err)
	}
	if total != 3 {
		t.Errorf("total = %d，期望 3", total)
	}
	if len(orders) != 3 {
		t.Errorf("len(orders) = %d，期望 3", len(orders))
	}
}

// markOrderPaid 把订单置为已支付。
// 新流程要求"先支付、后提交申请"，因此提交申请前必须先完成支付。
func markOrderPaid(t *testing.T, db *storage.DB, orderUUID string) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(),
		`UPDATE cert_orders SET status = 'paid', paid_at = CURRENT_TIMESTAMP WHERE uuid = ?`, orderUUID); err != nil {
		t.Fatalf("标记订单已支付失败: %v", err)
	}
}

func TestWorkflowApplicationApprove(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)

	svc := workflow.NewService(db, nil, nil)
	ctx := context.Background()
	userUUID := createTestUser(t, db, "approve@test.com")
	seedBalance(t, db, userUUID, 1000)
	adminUUID := createTestUser(t, db, "admin@test.com")

	// 创建订单
	order := &storage.CertOrder{
		UserUUID:         userUUID,
		IssuanceTmplUUID: "tmpl",
		AmountCents:      100,
	}
	if err := svc.CreateOrder(ctx, order); err != nil {
		t.Fatalf("创建订单失败: %v", err)
	}
	markOrderPaid(t, db, order.UUID)

	// 提交申请
	app := &storage.CertApplication{
		OrderUUID:   order.UUID,
		UserUUID:    userUUID,
		SubjectJSON: `{"CN":"test.example.com"}`,
		SANJSON:     `{"dns":["test.example.com"]}`,
		KeyType:     "ec256",
	}
	if err := svc.CreateApplication(ctx, app); err != nil {
		t.Fatalf("CreateApplication() 失败: %v", err)
	}
	if app.UUID == "" {
		t.Fatal("申请 UUID 未生成")
	}
	if app.Status != "pending" {
		t.Errorf("初始状态应为 pending，got %q", app.Status)
	}

	// 管理员审批通过
	if err := svc.ApproveApplication(ctx, app.UUID, adminUUID); err != nil {
		t.Fatalf("ApproveApplication() 失败: %v", err)
	}

	// 验证状态已更新
	apps, _, err := svc.ListApplications(ctx, userUUID, "approved", 1, 10)
	if err != nil {
		t.Fatalf("ListApplications() 失败: %v", err)
	}
	if len(apps) != 1 {
		t.Errorf("审批后 approved 申请数量 = %d，期望 1", len(apps))
	}
	if apps[0].ApprovedBy != adminUUID {
		t.Errorf("ApprovedBy = %q，期望 %q", apps[0].ApprovedBy, adminUUID)
	}
}

func TestWorkflowApplicationReject(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)

	svc := workflow.NewService(db, nil, nil)
	ctx := context.Background()
	userUUID := createTestUser(t, db, "reject@test.com")
	seedBalance(t, db, userUUID, 1000)
	adminUUID := createTestUser(t, db, "admin2@test.com")

	order := &storage.CertOrder{
		UserUUID:         userUUID,
		IssuanceTmplUUID: "tmpl",
		AmountCents:      100,
	}
	if err := svc.CreateOrder(ctx, order); err != nil {
		t.Fatalf("创建订单失败: %v", err)
	}
	markOrderPaid(t, db, order.UUID)

	app := &storage.CertApplication{
		OrderUUID:   order.UUID,
		UserUUID:    userUUID,
		SubjectJSON: `{"CN":"bad.example.com"}`,
		SANJSON:     `{}`,
		KeyType:     "ec256",
	}
	if err := svc.CreateApplication(ctx, app); err != nil {
		t.Fatalf("CreateApplication() 失败: %v", err)
	}

	// 管理员拒绝
	rejectReason := "主体信息不符合要求"
	if err := svc.RejectApplication(ctx, app.UUID, adminUUID, rejectReason); err != nil {
		t.Fatalf("RejectApplication() 失败: %v", err)
	}

	// 验证状态
	apps, _, err := svc.ListApplications(ctx, userUUID, "rejected", 1, 10)
	if err != nil {
		t.Fatalf("ListApplications() 失败: %v", err)
	}
	if len(apps) != 1 {
		t.Errorf("拒绝后 rejected 申请数量 = %d，期望 1", len(apps))
	}
	if apps[0].RejectReason != rejectReason {
		t.Errorf("RejectReason = %q，期望 %q", apps[0].RejectReason, rejectReason)
	}
}

func TestWorkflowApplicationListFilter(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)

	svc := workflow.NewService(db, nil, nil)
	ctx := context.Background()
	userUUID := createTestUser(t, db, "filter@test.com")
	seedBalance(t, db, userUUID, 1000)
	adminUUID := createTestUser(t, db, "admin3@test.com")

	// 创建 3 个申请：1 pending, 1 approved, 1 rejected
	for i := 0; i < 3; i++ {
		order := &storage.CertOrder{
			UserUUID: userUUID, IssuanceTmplUUID: "tmpl", AmountCents: 100,
		}
		if err := svc.CreateOrder(ctx, order); err != nil {
			t.Fatalf("创建订单失败: %v", err)
		}
		markOrderPaid(t, db, order.UUID)
		app := &storage.CertApplication{
			OrderUUID: order.UUID, UserUUID: userUUID,
			SubjectJSON: `{}`, SANJSON: `{}`, KeyType: "ec256",
		}
		if err := svc.CreateApplication(ctx, app); err != nil {
			t.Fatalf("创建申请失败: %v", err)
		}
		switch i {
		case 1:
			svc.ApproveApplication(ctx, app.UUID, adminUUID)
		case 2:
			svc.RejectApplication(ctx, app.UUID, adminUUID, "测试拒绝")
		}
	}

	// 查询所有
	all, total, err := svc.ListApplications(ctx, userUUID, "", 1, 10)
	if err != nil {
		t.Fatalf("ListApplications(all) 失败: %v", err)
	}
	if total != 3 || len(all) != 3 {
		t.Errorf("全部申请: total=%d, len=%d，期望各为 3", total, len(all))
	}

	// 仅查询 pending
	pending, pendingTotal, _ := svc.ListApplications(ctx, userUUID, "pending", 1, 10)
	if pendingTotal != 1 || len(pending) != 1 {
		t.Errorf("pending 申请: total=%d, len=%d，期望各为 1", pendingTotal, len(pending))
	}
}
