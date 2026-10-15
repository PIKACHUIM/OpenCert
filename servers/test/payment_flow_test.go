// Package test - 支付与退款链路测试。
//
// 覆盖：免费订单、余额支付、余额不足、渠道直付与回调校验、重复回调幂等、
// 余额退款与渠道退款失败的真实状态。
package test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/globaltrusts/server-card/internal/payment"
	"github.com/globaltrusts/server-card/internal/storage"
	"github.com/globaltrusts/server-card/internal/workflow"
)

// stubProvider 是用于测试的支付渠道桩。
type stubProvider struct {
	refunds    []payment.RefundReq
	refundFail bool
	payURL     string
}

func (p *stubProvider) Name() string { return "测试渠道" }
func (p *stubProvider) Type() string { return "stubpay" }

func (p *stubProvider) CreateOrder(ctx context.Context, req payment.CreateOrderReq) (*payment.CreateOrderResp, error) {
	return &payment.CreateOrderResp{PayURL: p.payURL, QRCode: "stub-qr", TradeNo: "TRADE-" + req.OrderNo}, nil
}

func (p *stubProvider) QueryOrder(ctx context.Context, orderNo string) (*payment.QueryOrderResp, error) {
	return &payment.QueryOrderResp{OrderNo: orderNo, Status: "pending"}, nil
}

func (p *stubProvider) VerifyCallback(ctx context.Context, body []byte, headers map[string]string) (*payment.CallbackData, error) {
	var req struct {
		OrderNo     string `json:"order_no"`
		TradeNo     string `json:"trade_no"`
		AmountCents int64  `json:"amount_cents"`
		Status      string `json:"status"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	return &payment.CallbackData{
		OrderNo: req.OrderNo, TradeNo: req.TradeNo,
		AmountCents: req.AmountCents, Status: req.Status, RawData: body,
	}, nil
}

func (p *stubProvider) Refund(ctx context.Context, req payment.RefundReq) (*payment.RefundResp, error) {
	p.refunds = append(p.refunds, req)
	if p.refundFail {
		return &payment.RefundResp{RefundNo: req.RefundNo, Status: "failed"}, nil
	}
	return &payment.RefundResp{RefundNo: req.RefundNo, Status: "success"}, nil
}

// newCheckoutEnv 构造带桩渠道的支付环境，并创建一个待支付订单。
func newCheckoutEnv(t *testing.T, amountCents int64) (*payment.Service, *workflow.Service, *stubProvider, *storage.CertOrder) {
	t.Helper()
	db := setupServerDB(t)
	registry := payment.NewRegistry()
	stub := &stubProvider{payURL: "https://pay.example/stub"}
	registry.Register(stub)

	paySvc := payment.NewService(db, registry)
	wfSvc := workflow.NewService(db, nil, nil)
	ctx := context.Background()

	userUUID := createTestUser(t, db, "checkout@test.com")
	order := &storage.CertOrder{UserUUID: userUUID, AmountCents: amountCents}
	if err := wfSvc.CreateOrder(ctx, order); err != nil {
		t.Fatalf("创建订单失败: %v", err)
	}
	return paySvc, wfSvc, stub, order
}

// orderStatus 读取订单当前状态。
func orderStatus(t *testing.T, wfSvc *workflow.Service, orderNo string) string {
	t.Helper()
	o, err := wfSvc.GetOrderByNo(context.Background(), orderNo)
	if err != nil {
		t.Fatalf("查询订单失败: %v", err)
	}
	return string(o.Status)
}

func TestCheckoutFreeOrderSettlesImmediately(t *testing.T) {
	t.Parallel()
	paySvc, wfSvc, _, order := newCheckoutEnv(t, 0)
	ctx := context.Background()

	res, err := paySvc.CreateCertOrderPayment(ctx, payment.CheckoutInput{
		UserUUID: order.UserUUID, OrderNo: order.OrderNo, Channel: storage.ChannelBalance,
	})
	if err != nil {
		t.Fatalf("免费订单支付失败: %v", err)
	}
	if !res.Settled {
		t.Error("零金额订单应直接完成支付")
	}
	if res.Channel != storage.ChannelFree {
		t.Errorf("渠道应为 free，实际 %q", res.Channel)
	}
	if got := orderStatus(t, wfSvc, order.OrderNo); got != string(storage.CertOrderPaid) {
		t.Errorf("订单状态应为 paid，实际 %q", got)
	}
}

// TestCheckoutWithBalanceAndRefund 验证余额支付、重复支付拦截与退款回到余额。
func TestCheckoutWithBalanceAndRefund(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)
	registry := payment.NewRegistry()
	registry.Register(&stubProvider{payURL: "https://pay.example/stub"})
	paySvc := payment.NewService(db, registry)
	wfSvc := workflow.NewService(db, nil, nil)
	ctx := context.Background()

	userUUID := createTestUser(t, db, "balance@test.com")
	seedBalance(t, db, userUUID, 10000)

	order := &storage.CertOrder{UserUUID: userUUID, AmountCents: 6800}
	if err := wfSvc.CreateOrder(ctx, order); err != nil {
		t.Fatalf("创建订单失败: %v", err)
	}

	// 余额支付
	res, err := paySvc.CreateCertOrderPayment(ctx, payment.CheckoutInput{
		UserUUID: userUUID, OrderNo: order.OrderNo, Channel: storage.ChannelBalance,
	})
	if err != nil {
		t.Fatalf("余额支付失败: %v", err)
	}
	if !res.Settled {
		t.Error("余额支付应立即完成")
	}
	if got := orderStatus(t, wfSvc, order.OrderNo); got != string(storage.CertOrderPaid) {
		t.Fatalf("订单状态应为 paid，实际 %q", got)
	}

	// 已支付订单不可重复支付
	if _, err := paySvc.CreateCertOrderPayment(ctx, payment.CheckoutInput{
		UserUUID: userUUID, OrderNo: order.OrderNo, Channel: storage.ChannelBalance,
	}); err == nil {
		t.Error("已支付订单不应再次支付")
	}

	// 申请退款并审批
	refund, err := paySvc.RequestCertOrderRefund(ctx, userUUID, order.OrderNo, "测试退款")
	if err != nil {
		t.Fatalf("申请退款失败: %v", err)
	}
	if refund.Channel != storage.ChannelBalance {
		t.Errorf("退款渠道应为 balance，实际 %q", refund.Channel)
	}
	if err := paySvc.ApproveRefund(ctx, refund.UUID, "admin-uuid"); err != nil {
		t.Fatalf("审批退款失败: %v", err)
	}

	if got := orderStatus(t, wfSvc, order.OrderNo); got != string(storage.CertOrderRefunded) {
		t.Errorf("订单状态应为 refunded，实际 %q", got)
	}

	// 余额应回到初始值
	balance, err := paySvc.GetBalance(ctx, userUUID)
	if err != nil {
		t.Fatalf("查询余额失败: %v", err)
	}
	if balance.AvailableCents != 10000 {
		t.Errorf("退款后余额应恢复为 10000，实际 %d", balance.AvailableCents)
	}
}

func TestCheckoutBalanceInsufficient(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)
	paySvc := payment.NewService(db, payment.NewRegistry())
	wfSvc := workflow.NewService(db, nil, nil)
	ctx := context.Background()

	userUUID := createTestUser(t, db, "poor@test.com")
	seedBalance(t, db, userUUID, 100)

	order := &storage.CertOrder{UserUUID: userUUID, AmountCents: 6800}
	if err := wfSvc.CreateOrder(ctx, order); err != nil {
		t.Fatalf("创建订单失败: %v", err)
	}

	_, err := paySvc.CreateCertOrderPayment(ctx, payment.CheckoutInput{
		UserUUID: userUUID, OrderNo: order.OrderNo, Channel: storage.ChannelBalance,
	})
	if err == nil {
		t.Fatal("余额不足应拒绝支付")
	}
	if !strings.Contains(err.Error(), "余额不足") {
		t.Errorf("错误信息应提示余额不足，实际: %v", err)
	}
	if got := orderStatus(t, wfSvc, order.OrderNo); got != string(storage.CertOrderPendingPayment) {
		t.Errorf("支付失败后订单应保持待支付，实际 %q", got)
	}
}

func TestCheckoutChannelCallbackValidation(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)
	registry := payment.NewRegistry()
	stub := &stubProvider{payURL: "https://pay.example/stub"}
	registry.Register(stub)
	paySvc := payment.NewService(db, registry)
	wfSvc := workflow.NewService(db, nil, nil)
	ctx := context.Background()

	userUUID := createTestUser(t, db, "channel@test.com")
	order := &storage.CertOrder{UserUUID: userUUID, AmountCents: 6800}
	if err := wfSvc.CreateOrder(ctx, order); err != nil {
		t.Fatalf("创建订单失败: %v", err)
	}

	res, err := paySvc.CreateCertOrderPayment(ctx, payment.CheckoutInput{
		UserUUID: userUUID, OrderNo: order.OrderNo, Channel: "stubpay",
	})
	if err != nil {
		t.Fatalf("发起渠道支付失败: %v", err)
	}
	if res.Settled {
		t.Error("渠道支付不应立即结算")
	}
	if res.PayURL == "" {
		t.Error("应返回支付链接")
	}
	if got := orderStatus(t, wfSvc, order.OrderNo); got != string(storage.CertOrderPendingPayment) {
		t.Errorf("渠道支付前订单应为待支付，实际 %q", got)
	}

	// 金额不符的回调必须被拒绝，且不改动订单
	bad := &payment.CallbackData{OrderNo: order.OrderNo, TradeNo: "T-bad", AmountCents: 1, Status: "paid"}
	if err := paySvc.HandleChannelCallback(ctx, "stubpay", bad); err == nil {
		t.Error("金额不符的回调应被拒绝")
	}
	if got := orderStatus(t, wfSvc, order.OrderNo); got != string(storage.CertOrderPendingPayment) {
		t.Errorf("非法回调后订单应仍为待支付，实际 %q", got)
	}

	// 正确回调完成结算
	good := &payment.CallbackData{OrderNo: order.OrderNo, TradeNo: "T-ok", AmountCents: 6800, Status: "paid"}
	if err := paySvc.HandleChannelCallback(ctx, "stubpay", good); err != nil {
		t.Fatalf("合法回调处理失败: %v", err)
	}
	if got := orderStatus(t, wfSvc, order.OrderNo); got != string(storage.CertOrderPaid) {
		t.Fatalf("回调后订单应为 paid，实际 %q", got)
	}

	// 重复回调必须幂等
	if err := paySvc.HandleChannelCallback(ctx, "stubpay", good); err != nil {
		t.Fatalf("重复回调应被幂等忽略，实际错误: %v", err)
	}

	// 消费流水只应有一条
	var consumeCount int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM consume_records WHERE order_no = ? AND consume_type = 'cert_purchase'`,
		order.OrderNo).Scan(&consumeCount); err != nil {
		t.Fatalf("查询消费记录失败: %v", err)
	}
	if consumeCount != 1 {
		t.Errorf("消费记录应只有 1 条，实际 %d", consumeCount)
	}
}

func TestCheckoutChannelRefundFailureIsRecorded(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)
	registry := payment.NewRegistry()
	stub := &stubProvider{payURL: "https://pay.example/stub", refundFail: true}
	registry.Register(stub)
	paySvc := payment.NewService(db, registry)
	wfSvc := workflow.NewService(db, nil, nil)
	ctx := context.Background()

	userUUID := createTestUser(t, db, "chanrefund@test.com")
	order := &storage.CertOrder{UserUUID: userUUID, AmountCents: 6800}
	if err := wfSvc.CreateOrder(ctx, order); err != nil {
		t.Fatalf("创建订单失败: %v", err)
	}

	if _, err := paySvc.CreateCertOrderPayment(ctx, payment.CheckoutInput{
		UserUUID: userUUID, OrderNo: order.OrderNo, Channel: "stubpay",
	}); err != nil {
		t.Fatalf("发起渠道支付失败: %v", err)
	}
	if err := paySvc.HandleChannelCallback(ctx, "stubpay", &payment.CallbackData{
		OrderNo: order.OrderNo, TradeNo: "T-ok", AmountCents: 6800, Status: "paid",
	}); err != nil {
		t.Fatalf("回调处理失败: %v", err)
	}

	refund, err := paySvc.RequestCertOrderRefund(ctx, userUUID, order.OrderNo, "渠道退款")
	if err != nil {
		t.Fatalf("申请退款失败: %v", err)
	}
	if refund.Channel != "stubpay" {
		t.Errorf("退款渠道应为 stubpay，实际 %q", refund.Channel)
	}

	// 渠道退款失败：审批应报错，工单置 failed，订单保持已支付
	if err := paySvc.ApproveRefund(ctx, refund.UUID, "admin-uuid"); err == nil {
		t.Fatal("渠道退款失败时审批应返回错误")
	}
	if got := orderStatus(t, wfSvc, order.OrderNo); got != string(storage.CertOrderPaid) {
		t.Errorf("渠道退款失败时订单应保持 paid，实际 %q", got)
	}

	var status, failReason string
	if err := db.QueryRowContext(ctx,
		`SELECT status, fail_reason FROM refund_requests WHERE uuid = ?`, refund.UUID,
	).Scan(&status, &failReason); err != nil {
		t.Fatalf("查询退款工单失败: %v", err)
	}
	if status != string(storage.OrderStatusFailed) {
		t.Errorf("退款工单应为 failed，实际 %q", status)
	}
	if failReason == "" {
		t.Error("退款失败应记录失败原因")
	}
}
