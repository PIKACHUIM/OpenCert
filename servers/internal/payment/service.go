// Package payment - 支付服务层，处理充值、回调、余额管理。
package payment

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/globaltrusts/server-card/internal/storage"
	"github.com/google/uuid"
)

// Service 是支付服务。
type Service struct {
	db       *storage.DB
	registry *Registry
}

// NewService 创建支付服务。
func NewService(db *storage.DB, registry *Registry) *Service {
	return &Service{db: db, registry: registry}
}

// CreateRechargeOrder 创建充值订单。
func (s *Service) CreateRechargeOrder(ctx context.Context, userUUID string, amountCents int64, channel string, notifyURL string) (*storage.RechargeOrder, *CreateOrderResp, error) {
	if amountCents <= 0 {
		return nil, nil, fmt.Errorf("充值金额必须大于0")
	}

	provider, err := s.registry.Get(channel)
	if err != nil {
		return nil, nil, fmt.Errorf("不支持的支付渠道: %s", channel)
	}

	orderNo := fmt.Sprintf("RC%s%s", time.Now().Format("20060102150405"), uuid.New().String()[:8])
	order := &storage.RechargeOrder{
		OrderNo:     orderNo,
		UserUUID:    userUUID,
		AmountCents: amountCents,
		Channel:     channel,
		Status:      storage.OrderStatusPending,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(30 * time.Minute),
	}

	// 写入数据库
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO recharge_orders (order_no, user_uuid, amount_cents, channel, status, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		order.OrderNo, order.UserUUID, order.AmountCents, order.Channel, order.Status, order.CreatedAt, order.ExpiresAt,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("创建订单失败: %w", err)
	}

	// 调用支付插件创建支付链接
	payResp, err := provider.CreateOrder(ctx, CreateOrderReq{
		OrderNo:     orderNo,
		AmountCents: amountCents,
		Subject:     "OpenCert 账户充值",
		NotifyURL:   notifyURL,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("创建支付链接失败: %w", err)
	}

	return order, payResp, nil
}

// HandleCallback 处理支付回调：先验签，再按业务订单 / 充值订单分派结算。
//
// 具体校验与幂等逻辑见 checkout.go 的 HandleChannelCallback。
func (s *Service) HandleCallback(ctx context.Context, channel string, body []byte, headers map[string]string) error {
	provider, err := s.registry.Get(channel)
	if err != nil {
		return fmt.Errorf("未知支付渠道: %s", channel)
	}

	data, err := provider.VerifyCallback(ctx, body, headers)
	if err != nil {
		return fmt.Errorf("回调验证失败: %w", err)
	}

	if data.Status != "paid" {
		slog.Warn("支付回调状态非成功", "order_no", data.OrderNo, "status", data.Status)
		return nil
	}

	return s.HandleChannelCallback(ctx, channel, data)
}

// DeductBalance 从用户余额中扣除金额（购买证书服务时调用）。
func (s *Service) DeductBalance(ctx context.Context, userUUID string, amountCents int64, consumeType string, remark string) error {
	if amountCents <= 0 {
		return fmt.Errorf("扣除金额必须大于0")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开启事务失败: %w", err)
	}
	defer tx.Rollback()

	// 检查余额是否充足
	var available int64
	err = tx.QueryRowContext(ctx,
		`SELECT available_cents FROM user_balances WHERE user_uuid = ?`, userUUID,
	).Scan(&available)
	if err == sql.ErrNoRows {
		return fmt.Errorf("余额不足")
	}
	if err != nil {
		return fmt.Errorf("查询余额失败: %w", err)
	}
	if available < amountCents {
		return fmt.Errorf("余额不足: 可用 %d 分，需要 %d 分", available, amountCents)
	}

	// 扣减余额
	_, err = tx.ExecContext(ctx,
		`UPDATE user_balances SET available_cents = available_cents - ?, total_consume = total_consume + ? WHERE user_uuid = ?`,
		amountCents, amountCents, userUUID,
	)
	if err != nil {
		return fmt.Errorf("扣减余额失败: %w", err)
	}

	// 写入消费记录
	_, err = tx.ExecContext(ctx,
		`INSERT INTO consume_records (uuid, user_uuid, consume_type, amount_cents, remark, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		uuid.New().String(), userUUID, consumeType, amountCents, remark, time.Now(),
	)
	if err != nil {
		return fmt.Errorf("写入消费记录失败: %w", err)
	}

	return tx.Commit()
}

// GetBalance 查询用户余额。
func (s *Service) GetBalance(ctx context.Context, userUUID string) (*storage.UserBalance, error) {
	b := &storage.UserBalance{UserUUID: userUUID}
	err := s.db.QueryRowContext(ctx,
		`SELECT available_cents, frozen_cents, total_recharge, total_consume
		 FROM user_balances WHERE user_uuid = ?`, userUUID,
	).Scan(&b.AvailableCents, &b.FrozenCents, &b.TotalRecharge, &b.TotalConsume)
	if err == sql.ErrNoRows {
		return b, nil // 返回零余额
	}
	return b, err
}

// ListOrders 查询用户的充值订单列表（分页）。
func (s *Service) ListOrders(ctx context.Context, userUUID string, page, pageSize int) ([]*storage.RechargeOrder, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 50 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	// 查询总数
	var total int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM recharge_orders WHERE user_uuid = ?`, userUUID,
	).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT order_no, user_uuid, amount_cents, channel, status, created_at, paid_at, expires_at
		 FROM recharge_orders WHERE user_uuid = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`,
		userUUID, pageSize, offset,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var orders []*storage.RechargeOrder
	for rows.Next() {
		o := &storage.RechargeOrder{}
		if err := rows.Scan(&o.OrderNo, &o.UserUUID, &o.AmountCents, &o.Channel, &o.Status, &o.CreatedAt, &o.PaidAt, &o.ExpiresAt); err != nil {
			return nil, 0, err
		}
		orders = append(orders, o)
	}
	return orders, total, rows.Err()
}

// CloseExpiredOrders 关闭超时未支付的订单（定时任务调用）。
func (s *Service) CloseExpiredOrders(ctx context.Context) (int64, error) {
	result, err := s.db.ExecContext(ctx,
		`UPDATE recharge_orders SET status = ? WHERE status = ? AND expires_at < ?`,
		storage.OrderStatusClosed, storage.OrderStatusPending, time.Now(),
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// CreateRefund 创建退款工单。
func (s *Service) CreateRefund(ctx context.Context, userUUID, orderNo, reason string) (*storage.RefundRequest, error) {
	if orderNo == "" {
		return nil, fmt.Errorf("订单号不能为空")
	}

	// 查询原始订单
	var order storage.RechargeOrder
	err := s.db.QueryRowContext(ctx,
		`SELECT order_no, user_uuid, amount_cents, channel, status FROM recharge_orders WHERE order_no = ?`, orderNo,
	).Scan(&order.OrderNo, &order.UserUUID, &order.AmountCents, &order.Channel, &order.Status)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("订单不存在: %s", orderNo)
	}
	if err != nil {
		return nil, fmt.Errorf("查询订单失败: %w", err)
	}

	// 验证订单归属
	if order.UserUUID != userUUID {
		return nil, fmt.Errorf("无权操作此订单")
	}

	// 仅已支付的订单可以退款
	if order.Status != storage.OrderStatusPaid {
		return nil, fmt.Errorf("订单状态不允许退款: %s", order.Status)
	}

	// 检查是否已有退款工单
	var existingCount int
	err = s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM refund_requests WHERE order_no = ? AND status IN ('pending', 'paid')`, orderNo,
	).Scan(&existingCount)
	if err != nil {
		return nil, fmt.Errorf("查询退款记录失败: %w", err)
	}
	if existingCount > 0 {
		return nil, fmt.Errorf("该订单已有退款申请")
	}

	// 创建退款工单
	refund := &storage.RefundRequest{
		UUID:        uuid.New().String(),
		UserUUID:    userUUID,
		OrderNo:     orderNo,
		AmountCents: order.AmountCents,
		Reason:      reason,
		Status:      storage.OrderStatusPending,
		CreatedAt:   time.Now(),
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO refund_requests (uuid, user_uuid, order_no, amount_cents, reason, status, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		refund.UUID, refund.UserUUID, refund.OrderNo, refund.AmountCents, refund.Reason, refund.Status, refund.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("创建退款工单失败: %w", err)
	}

	slog.Info("退款工单已创建", "refund_uuid", refund.UUID, "order_no", orderNo, "amount_cents", refund.AmountCents)
	return refund, nil
}

// ListRefunds 查询用户的退款工单列表。
func (s *Service) ListRefunds(ctx context.Context, userUUID string, page, pageSize int) ([]*storage.RefundRequest, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 50 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	var total int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM refund_requests WHERE user_uuid = ?`, userUUID,
	).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT uuid, user_uuid, order_no, amount_cents, reason, status, approved_by, created_at, processed_at
		 FROM refund_requests WHERE user_uuid = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`,
		userUUID, pageSize, offset,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var refunds []*storage.RefundRequest
	for rows.Next() {
		r := &storage.RefundRequest{}
		var approvedBy sql.NullString
		var processedAt sql.NullTime
		if err := rows.Scan(&r.UUID, &r.UserUUID, &r.OrderNo, &r.AmountCents, &r.Reason, &r.Status, &approvedBy, &r.CreatedAt, &processedAt); err != nil {
			return nil, 0, err
		}
		if approvedBy.Valid {
			r.ApprovedBy = approvedBy.String
		}
		if processedAt.Valid {
			r.ProcessedAt = &processedAt.Time
		}
		refunds = append(refunds, r)
	}
	return refunds, total, rows.Err()
}

// 退款相关的实现见 refund.go：
//   ApproveRefund / RejectRefund / RequestCertOrderRefund / ListAllRefunds 等。
