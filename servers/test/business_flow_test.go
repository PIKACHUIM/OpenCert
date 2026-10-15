// Package test - 业务全流程测试（真实 CA 签发）。
//
// 覆盖：自助模式零金额订单 → 免审自动签发（落托管容器）、
// 需审批 → 审批签发到用户智能卡、驳回不产生余额、订单份数约束、
// 已支付订单不可取消、云智能卡商品下单与库存预占/归还。
package test

import (
	"context"
	"crypto/x509/pkix"
	"strings"
	"testing"

	"github.com/globaltrusts/server-card/internal/ca"
	"github.com/globaltrusts/server-card/internal/issuance"
	"github.com/globaltrusts/server-card/internal/portal"
	"github.com/globaltrusts/server-card/internal/storage"
	"github.com/globaltrusts/server-card/internal/workflow"
)

type flowEnv struct {
	db  *storage.DB
	wf  *workflow.Service
	ctx context.Context
}

// newFlowEnv 构造带真实 CA、颁发模板与两个申请模板（免审 / 需审批）的环境。
func newFlowEnv(t *testing.T) (*flowEnv, string, string) {
	t.Helper()
	return newFlowEnvWithDB(t, setupServerDB(t))
}

// newFlowEnvWithDB 在指定数据库上构造签发环境。
func newFlowEnvWithDB(t *testing.T, db *storage.DB) (*flowEnv, string, string) {
	t.Helper()
	ctx := context.Background()
	caSvc := ca.NewService(db, testMasterKey)
	issSvc := issuance.NewService(db)

	root, err := caSvc.CreateSelfSignedCA(ctx, "Flow Test CA", pkix.Name{CommonName: "Flow Test CA"}, "ec256", 1)
	if err != nil {
		t.Fatalf("创建 CA 失败: %v", err)
	}
	tmpl := &storage.IssuanceTemplate{
		Name: "SSL 颁发模板", ValidDays: "[365]", AllowedKeyTypes: `["ec256","rsa2048"]`,
		AllowedCAUUIDs: `["` + root.UUID + `"]`, Category: "ssl", Enabled: true, Stock: -1,
	}
	if err := issSvc.CreateIssuanceTemplate(ctx, tmpl); err != nil {
		t.Fatalf("创建颁发模板失败: %v", err)
	}

	insert := func(uuid string, requireApproval int) {
		if _, err := db.ExecContext(ctx,
			`INSERT INTO cert_apply_templates
			 (uuid, name, issuance_tmpl_uuid, valid_days, ca_uuid, enabled, require_approval,
			  allow_renewal, allowed_key_types, price_cents, description, created_at, updated_at)
			 VALUES (?, ?, ?, 365, ?, 1, ?, 1, '["ec256","rsa2048"]', 0, '', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
			uuid, "申请模板-"+uuid, tmpl.UUID, root.UUID, requireApproval); err != nil {
			t.Fatalf("插入申请模板失败: %v", err)
		}
	}
	insert("tmpl-auto", 0)
	insert("tmpl-review", 1)

	return &flowEnv{db: db, wf: workflow.NewService(db, caSvc, issSvc), ctx: ctx}, "tmpl-auto", "tmpl-review"
}

func (e *flowEnv) orderStatus(t *testing.T, orderUUID string) storage.CertOrderStatus {
	t.Helper()
	o, err := e.wf.GetOrder(e.ctx, orderUUID)
	if err != nil {
		t.Fatalf("查询订单失败: %v", err)
	}
	return o.Status
}

func TestFlowSelfServiceAutoIssueToHostingContainer(t *testing.T) {
	t.Parallel()
	env, autoTmpl, _ := newFlowEnv(t)
	userUUID := createTestUser(t, env.db, "auto@test.com")

	order, err := env.wf.CreateSelfServiceOrder(env.ctx, userUUID, autoTmpl, "auto@test.com")
	if err != nil {
		t.Fatalf("创建自助订单失败: %v", err)
	}
	if order.Status != storage.CertOrderPaid || order.AmountCents != 0 {
		t.Fatalf("自助订单应为 0 元已支付，实际 %s / %d", order.Status, order.AmountCents)
	}

	app := &storage.CertApplication{
		OrderUUID: order.UUID, UserUUID: userUUID,
		SubjectJSON: `{"CN":"auto.example.com"}`, SANJSON: `{"dns":["auto.example.com"]}`, KeyType: "ec256",
	}
	autoIssued, issueErr, err := env.wf.SubmitApplication(env.ctx, app)
	if err != nil {
		t.Fatalf("提交申请失败: %v", err)
	}
	if issueErr != nil {
		t.Fatalf("自动签发失败: %v", issueErr)
	}
	if !autoIssued {
		t.Fatal("免审模板应自动签发")
	}

	got, err := env.wf.GetApplication(env.ctx, app.UUID)
	if err != nil || got.Status != "approved" || got.CertUUID == "" {
		t.Fatalf("申请应已通过并关联证书，实际 %+v err=%v", got, err)
	}

	// 证书应落在用户的托管容器，而不是空卡号（外键约束）
	cert, err := storage.NewCertRepo(env.db).GetByUUID(env.ctx, got.CertUUID)
	if err != nil {
		t.Fatalf("查询证书失败: %v", err)
	}
	card, err := storage.NewCardRepo(env.db).GetByUUID(env.ctx, cert.CardUUID)
	if err != nil || !card.IsHosting() || card.UserUUID != userUUID {
		t.Fatalf("证书应存入用户托管容器，实际卡片 %+v err=%v", card, err)
	}
	if cert.OrderNo != order.OrderNo {
		t.Errorf("证书应记录订单号，期望 %s 实际 %s", order.OrderNo, cert.OrderNo)
	}
	if st := env.orderStatus(t, order.UUID); st != storage.CertOrderCompleted {
		t.Errorf("单份订单签发后应完成，实际 %s", st)
	}

	// 托管容器不计入用户开卡数量
	if n, _ := storage.NewCardRepo(env.db).CountUserCards(env.ctx, userUUID); n != 0 {
		t.Errorf("托管容器不应计入开卡数量，实际 %d", n)
	}

	// 份数用尽后不能再提交
	_, _, err = env.wf.SubmitApplication(env.ctx, &storage.CertApplication{
		OrderUUID: order.UUID, UserUUID: userUUID, SubjectJSON: `{"CN":"x.example.com"}`, SANJSON: `{}`, KeyType: "ec256",
	})
	if err == nil {
		t.Error("订单份数用尽后应拒绝继续申请")
	}
}

func TestFlowReviewApproveIntoUserCardAndReject(t *testing.T) {
	t.Parallel()
	env, _, reviewTmpl := newFlowEnv(t)
	userUUID := createTestUser(t, env.db, "review@test.com")
	adminUUID := createTestUser(t, env.db, "reviewer@test.com")

	userCard := &storage.Card{UserUUID: userUUID, CardName: "我的云卡"}
	if err := storage.NewCardRepo(env.db).Create(env.ctx, userCard); err != nil {
		t.Fatalf("创建卡片失败: %v", err)
	}

	// 付费订单（模拟已支付，金额 500 分，未冻结）
	order := &storage.CertOrder{UserUUID: userUUID, CertApplyTmplUUID: reviewTmpl, AmountCents: 500, SKUCode: "sku"}
	if err := env.wf.CreateOrder(env.ctx, order); err != nil {
		t.Fatalf("创建订单失败: %v", err)
	}
	markOrderPaid(t, env.db, order.UUID)

	// 驳回路径：订单回到已支付，且不能凭空增加余额
	rejectApp := &storage.CertApplication{
		OrderUUID: order.UUID, UserUUID: userUUID,
		SubjectJSON: `{"CN":"bad.example.com"}`, SANJSON: `{"dns":["bad.example.com"]}`, KeyType: "ec256",
	}
	if autoIssued, _, err := env.wf.SubmitApplication(env.ctx, rejectApp); err != nil || autoIssued {
		t.Fatalf("需审批模板应进入待审核，autoIssued=%v err=%v", autoIssued, err)
	}
	if st := env.orderStatus(t, order.UUID); st != storage.CertOrderReviewing {
		t.Errorf("提交后订单应为审核中，实际 %s", st)
	}
	if err := env.wf.RejectApplication(env.ctx, rejectApp.UUID, adminUUID, "主体不符"); err != nil {
		t.Fatalf("驳回失败: %v", err)
	}
	if st := env.orderStatus(t, order.UUID); st != storage.CertOrderPaid {
		t.Errorf("驳回后订单应回到已支付，实际 %s", st)
	}
	var available int64
	env.db.QueryRowContext(env.ctx, //nolint:errcheck
		`SELECT COALESCE(SUM(available_cents), 0) FROM user_balances WHERE user_uuid = ?`, userUUID).Scan(&available)
	if available != 0 {
		t.Errorf("驳回不应给用户增加余额，实际可用 %d 分", available)
	}

	// 重新提交并审批，证书签入用户指定的智能卡
	app := &storage.CertApplication{
		OrderUUID: order.UUID, UserUUID: userUUID, CardUUID: userCard.UUID,
		SubjectJSON: `{"CN":"good.example.com"}`, SANJSON: `{"dns":["good.example.com"]}`, KeyType: "rsa2048",
	}
	if _, _, err := env.wf.SubmitApplication(env.ctx, app); err != nil {
		t.Fatalf("重新提交失败: %v", err)
	}
	if err := env.wf.ApproveApplication(env.ctx, app.UUID, adminUUID); err != nil {
		t.Fatalf("审批签发失败: %v", err)
	}
	got, _ := env.wf.GetApplication(env.ctx, app.UUID)
	cert, err := storage.NewCertRepo(env.db).GetByUUID(env.ctx, got.CertUUID)
	if err != nil {
		t.Fatalf("查询证书失败: %v", err)
	}
	if cert.CardUUID != userCard.UUID {
		t.Errorf("证书应签入用户智能卡 %s，实际 %s", userCard.UUID, cert.CardUUID)
	}
	if len(cert.PrivateData) == 0 {
		t.Error("云端生成密钥的证书应托管私钥")
	}
	if st := env.orderStatus(t, order.UUID); st != storage.CertOrderCompleted {
		t.Errorf("签发后订单应完成，实际 %s", st)
	}

	// 他人卡片不能作为目标
	other := createTestUser(t, env.db, "other-card@test.com")
	otherOrder, _ := env.wf.CreateSelfServiceOrder(env.ctx, other, reviewTmpl, "o@test.com")
	_, _, err = env.wf.SubmitApplication(env.ctx, &storage.CertApplication{
		OrderUUID: otherOrder.UUID, UserUUID: other, CardUUID: userCard.UUID,
		SubjectJSON: `{"CN":"x.example.com"}`, SANJSON: `{}`, KeyType: "ec256",
	})
	if err == nil || !strings.Contains(err.Error(), "不属于") {
		t.Errorf("不应允许签入他人智能卡，实际: %v", err)
	}
}

func TestFlowCancelOnlyPendingOrders(t *testing.T) {
	t.Parallel()
	env, autoTmpl, _ := newFlowEnv(t)
	userUUID := createTestUser(t, env.db, "cancel@test.com")

	pending := &storage.CertOrder{UserUUID: userUUID, CertApplyTmplUUID: autoTmpl, AmountCents: 100, SKUCode: "sku"}
	if err := env.wf.CreateOrder(env.ctx, pending); err != nil {
		t.Fatalf("创建订单失败: %v", err)
	}
	if err := env.wf.CancelOrder(env.ctx, pending.UUID, userUUID); err != nil {
		t.Fatalf("待支付订单应可取消: %v", err)
	}

	paid, _ := env.wf.CreateSelfServiceOrder(env.ctx, userUUID, autoTmpl, "c@test.com")
	if err := env.wf.CancelOrder(env.ctx, paid.UUID, userUUID); err == nil {
		t.Error("已支付订单不应允许取消（需走退款）")
	}
}

func TestFlowCloudCardProductOrderAndStock(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)
	ctx := context.Background()
	svc := portal.NewService(storage.NewPortalRepo(db), workflow.NewService(db, nil, nil))
	userUUID := createTestUser(t, db, "cardbuyer@test.com")

	p := &storage.PortalProduct{
		Code: "cloudcard-std", Name: "云端智能卡", Category: storage.ProductCategoryCloudCard,
		Visible: true, Enabled: true,
	}
	if err := svc.CreateProduct(ctx, p); err != nil {
		t.Fatalf("创建商品失败: %v", err)
	}
	sku := &storage.PortalProductSKU{
		ProductUUID: p.UUID, Code: "cloudcard-1y", Name: "标准版", PriceCents: 0,
		Stock: 2, MinQty: 1, MaxQty: 2, DeliveryMode: storage.DeliveryCloudCard, Enabled: true,
	}
	if err := svc.CreateSKU(ctx, sku); err != nil {
		t.Fatalf("创建规格失败: %v", err)
	}

	// 云智能卡商品不需要证书申请模板
	order, err := svc.CreateOrder(ctx, userUUID, portal.CreateOrderInput{SKUCode: "cloudcard-1y", Quantity: 2, ApplicantEmail: "a@b.com"})
	if err != nil {
		t.Fatalf("云智能卡商品应可下单: %v", err)
	}
	if workflow.SpecKind(order.SpecJSON) != storage.OrderKindCard {
		t.Errorf("订单类型应为 card，实际 %s", workflow.SpecKind(order.SpecJSON))
	}
	if order.AmountCents != 0 {
		t.Errorf("免费规格金额应为 0，实际 %d", order.AmountCents)
	}

	// 库存已被预占，再下单应失败
	if _, err := svc.CreateOrder(ctx, userUUID, portal.CreateOrderInput{SKUCode: "cloudcard-1y", Quantity: 1, ApplicantEmail: "a@b.com"}); err == nil {
		t.Error("库存预占后应无法超卖")
	}

	// 取消订单归还库存
	if err := svc.CancelOrder(ctx, order.OrderNo, userUUID); err != nil {
		t.Fatalf("取消订单失败: %v", err)
	}
	restored, err := storage.NewPortalRepo(db).GetSKUByCode(ctx, "cloudcard-1y")
	if err != nil || restored.Stock != 2 {
		t.Errorf("取消后库存应恢复为 2，实际 %+v err=%v", restored, err)
	}

	// 证书订单不能用来开卡、智能卡订单不能用来申请证书
	cardOrder, _ := svc.CreateOrder(ctx, userUUID, portal.CreateOrderInput{SKUCode: "cloudcard-1y", Quantity: 1, ApplicantEmail: "a@b.com"})
	markOrderPaid(t, db, cardOrder.UUID)
	err = workflow.NewService(db, nil, nil).CreateApplication(ctx, &storage.CertApplication{
		OrderUUID: cardOrder.UUID, UserUUID: userUUID, SubjectJSON: `{}`, SANJSON: `{}`,
	})
	if err == nil {
		t.Error("智能卡订单不应用于申请证书")
	}
}

func TestFlowBusinessModesValidation(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)
	ctx := context.Background()
	svc := portal.NewService(storage.NewPortalRepo(db), workflow.NewService(db, nil, nil))

	m := svc.GetBusinessModes(ctx)
	if m.CertApplyMode != storage.ModeSales || m.CardApplyMode != storage.ModeSales {
		t.Errorf("缺省应为销售模式，实际 %+v", m)
	}
	if err := svc.UpdateSiteSettings(ctx, map[string]string{"card_apply_mode": "free"}); err == nil {
		t.Error("非法模式取值应被拒绝")
	}
	if err := svc.UpdateSiteSettings(ctx, map[string]string{"card_self_limit": "-1"}); err == nil {
		t.Error("非法开卡上限应被拒绝")
	}
	if err := svc.UpdateSiteSettings(ctx, map[string]string{
		"cert_apply_mode": "self", "card_apply_mode": "self", "card_self_limit": "3",
	}); err != nil {
		t.Fatalf("保存业务模式失败: %v", err)
	}
	m = svc.GetBusinessModes(ctx)
	if m.CertApplyMode != "self" || m.CardApplyMode != "self" || m.CardSelfLimit != 3 {
		t.Errorf("业务模式未生效，实际 %+v", m)
	}
}
