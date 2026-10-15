// Package payment - 退款：申请、渠道原路退款与审批。
//
// 状态约定（refund_requests.status）：
//
//	pending  — 已提交，等待审批
//	paid     — 已成功退款（余额已退回或渠道已受理成功）
//	failed   — 渠道退款失败，记录 fail_reason，订单保持已支付
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

// RequestCertOrderRefund 用户为已支付但尚未签发的订单申请退款。
func (s *Service) RequestCertOrderRefund(ctx context.Context, userUUID, orderNo, reason string) (*storage.RefundRequest, error) {
	if orderNo == "" {
		return nil, fmt.Errorf("订单号不能为空")
	}

	order := &certOrderRow{}
	err := s.db.QueryRowContext(ctx,
		`SELECT uuid, order_no, user_uuid, amount_cents, status FROM cert_orders WHERE order_no = ?`, orderNo,
	).Scan(&order.UUID, &order.OrderNo, &order.UserUUID, &order.AmountCents, &order.Status)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("订单不存在: %s", orderNo)
	}
	if err != nil {
		return nil, fmt.Errorf("查询订单失败: %w", err)
	}
	if order.UserUUID != userUUID {
		return nil, fmt.Errorf("订单不存在")
	}

	// 已完成（已签发）的订单不允许自助退款，需走人工流程
	if order.Status == string(storage.CertOrderCompleted) {
		return nil, fmt.Errorf("订单已完成签发，如需退款请联系客服")
	}
	if order.Status != string(storage.CertOrderPaid) {
		return nil, fmt.Errorf("仅已支付订单可申请退款，当前状态: %s", order.Status)
	}

	// 已履约（已开卡或已有进行中/已通过的证书申请）的订单不能自助退款
	var fulfilled int
	if err := s.db.QueryRowContext(ctx,
		`SELECT (SELECT COUNT(*) FROM cards WHERE order_no = ?) +
		        (SELECT COUNT(*) FROM cert_applications WHERE order_uuid = ? AND status <> 'rejected')`,
		order.OrderNo, order.UUID,
	).Scan(&fulfilled); err != nil {
		return nil, fmt.Errorf("查询订单履约情况失败: %w", err)
	}
	if fulfilled > 0 {
		return nil, fmt.Errorf("该订单已开卡或已提交证书申请，如需退款请联系客服")
	}

	// 同一订单只允许一笔未完结的退款工单
	var existing int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM refund_requests WHERE order_no = ? AND status IN ('pending', 'paid')`, orderNo,
	).Scan(&existing); err != nil {
		return nil, fmt.Errorf("查询退款记录失败: %w", err)
	}
	if existing > 0 {
		return nil, fmt.Errorf("该订单已有退款申请")
	}

	// 取最近一次成功的支付尝试，确定原路退款渠道
	var channel string
	err = s.db.QueryRowContext(ctx,
		`SELECT channel FROM payment_attempts
		 WHERE biz_type = ? AND biz_uuid = ? AND status = ?
		 ORDER BY paid_at DESC LIMIT 1`,
		storage.PaymentBizCertOrder, order.UUID, storage.PaymentAttemptPaid,
	).Scan(&channel)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("查询支付记录失败: %w", err)
	}

	refund := &storage.RefundRequest{
		UUID:        uuid.New().String(),
		UserUUID:    userUUID,
		OrderNo:     orderNo,
		BizType:     string(storage.PaymentBizCertOrder),
		BizUUID:     order.UUID,
		Channel:     channel,
		AmountCents: order.AmountCents,
		Reason:      reason,
		Status:      storage.OrderStatusPending,
		CreatedAt:   time.Now(),
	}

	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO refund_requests
		 (uuid, user_uuid, order_no, biz_type, biz_uuid, channel, amount_cents, reason, status, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		refund.UUID, refund.UserUUID, refund.OrderNo, refund.BizType, refund.BizUUID,
		refund.Channel, refund.AmountCents, refund.Reason, refund.Status, refund.CreatedAt,
	); err != nil {
		return nil, fmt.Errorf("创建退款工单失败: %w", err)
	}

	slog.Info("退款工单已创建",
		"refund_uuid", refund.UUID, "order_no", orderNo,
		"amount_cents", refund.AmountCents, "channel", refund.Channel)
	return refund, nil
}

// ListUserRefunds 查询用户的退款工单（含业务订单退款）。
func (s *Service) ListUserRefunds(ctx context.Context, userUUID string, page, pageSize int) ([]*storage.RefundRequest, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 50 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	var total int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM refund_requests WHERE user_uuid = ?`, userUUID).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT uuid, user_uuid, order_no, biz_type, biz_uuid, channel, refund_no, fail_reason,
		        amount_cents, reason, status, approved_by, created_at, processed_at
		 FROM refund_requests WHERE user_uuid = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`,
		userUUID, pageSize, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	refunds := []*storage.RefundRequest{}
	for rows.Next() {
		r, err := scanRefund(rows.Scan)
		if err != nil {
			return nil, 0, err
		}
		refunds = append(refunds, r)
	}
	return refunds, total, rows.Err()
}

// ListAllRefunds 查询全部退款工单（管理员审批列表）。
func (s *Service) ListAllRefunds(ctx context.Context, status string, page, pageSize int) ([]*storage.RefundRequest, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	query := `SELECT COUNT(*) FROM refund_requests WHERE 1=1`
	args := []interface{}{}
	if status != "" {
		query += ` AND status = ?`
		args = append(args, status)
	}
	var total int
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	listQuery := `SELECT uuid, user_uuid, order_no, biz_type, biz_uuid, channel, refund_no, fail_reason,
	                     amount_cents, reason, status, approved_by, created_at, processed_at
	              FROM refund_requests WHERE 1=1`
	if status != "" {
		listQuery += ` AND status = ?`
	}
	listQuery += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`
	args = append(args, pageSize, offset)

	rows, err := s.db.QueryContext(ctx, listQuery, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	refunds := []*storage.RefundRequest{}
	for rows.Next() {
		r, err := scanRefund(rows.Scan)
		if err != nil {
			return nil, 0, err
		}
		refunds = append(refunds, r)
	}
	return refunds, total, rows.Err()
}

func scanRefund(scan func(dest ...interface{}) error) (*storage.RefundRequest, error) {
	r := &storage.RefundRequest{}
	var approvedBy sql.NullString
	var processedAt sql.NullTime
	if err := scan(&r.UUID, &r.UserUUID, &r.OrderNo, &r.BizType, &r.BizUUID, &r.Channel,
		&r.RefundNo, &r.FailReason, &r.AmountCents, &r.Reason, &r.Status,
		&approvedBy, &r.CreatedAt, &processedAt); err != nil {
		return nil, err
	}
	if approvedBy.Valid {
		r.ApprovedBy = approvedBy.String
	}
	if processedAt.Valid {
		r.ProcessedAt = &processedAt.Time
	}
	return r, nil
}

// ApproveRefund 管理员审批退款。
//
// 余额支付原路退回余额；第三方渠道调用渠道退款接口，只有渠道返回成功才标记为已退款。
// 渠道失败时保留 pending→failed 的真实结果，避免"页面上显示退款成功但未到账"。
func (s *Service) ApproveRefund(ctx context.Context, refundUUID, adminUUID string) error {
	refund := &storage.RefundRequest{}
	err := s.db.QueryRowContext(ctx,
		`SELECT uuid, user_uuid, order_no, biz_type, biz_uuid, channel, amount_cents, reason, status
		 FROM refund_requests WHERE uuid = ?`, refundUUID,
	).Scan(&refund.UUID, &refund.UserUUID, &refund.OrderNo, &refund.BizType, &refund.BizUUID,
		&refund.Channel, &refund.AmountCents, &refund.Reason, &refund.Status)
	if err == sql.ErrNoRows {
		return fmt.Errorf("退款工单不存在: %s", refundUUID)
	}
	if err != nil {
		return fmt.Errorf("查询退款工单失败: %w", err)
	}
	if refund.Status != storage.OrderStatusPending {
		return fmt.Errorf("退款工单状态不允许审批: %s", refund.Status)
	}
	if refund.BizType == string(storage.PaymentBizCertOrder) {
		return s.approveCertOrderRefund(ctx, refund, adminUUID)
	}
	return s.approveRechargeRefund(ctx, refund, adminUUID)
}

// RejectRefund 管理员驳回退款申请。
func (s *Service) RejectRefund(ctx context.Context, refundUUID, adminUUID, reason string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE refund_requests SET status = ?, approved_by = ?, fail_reason = ?, processed_at = ?
		 WHERE uuid = ? AND status = ?`,
		storage.OrderStatusFailed, adminUUID, reason, time.Now(), refundUUID, storage.OrderStatusPending)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("退款工单不存在或已处理")
	}
	return nil
}

// approveCertOrderRefund 审批业务订单退款。
func (s *Service) approveCertOrderRefund(ctx context.Context, refund *storage.RefundRequest, adminUUID string) error {
	refundNo := fmt.Sprintf("RF%s", uuid.New().String()[:16])

	switch refund.Channel {
	case storage.ChannelFree:
		// 免费订单无需资金往来，直接关闭工单与订单
		return s.finishCertOrderRefund(ctx, refund, adminUUID, refundNo, false)

	case storage.ChannelBalance, "":
		return s.refundToBalance(ctx, refund, adminUUID, refundNo)

	case storage.ChannelOffline:
		// 线下收款的订单由财务线下退回，系统记录退款结果并关闭订单
		return s.finishCertOrderRefund(ctx, refund, adminUUID, refundNo, true)

	default:
		provider, err := s.registry.Get(refund.Channel)
		if err != nil {
			s.markRefundFailed(ctx, refund.UUID, refundNo, "支付渠道不可用: "+err.Error()) //nolint:errcheck
			return fmt.Errorf("支付渠道不可用，无法原路退款: %w", err)
		}
		resp, err := provider.Refund(ctx, RefundReq{
			OrderNo:     refund.OrderNo,
			RefundNo:    refundNo,
			AmountCents: refund.AmountCents,
			Reason:      refund.Reason,
		})
		if err != nil {
			s.markRefundFailed(ctx, refund.UUID, refundNo, err.Error()) //nolint:errcheck
			return fmt.Errorf("渠道退款失败: %w", err)
		}
		if resp != nil && resp.Status == "failed" {
			s.markRefundFailed(ctx, refund.UUID, refundNo, "渠道返回退款失败") //nolint:errcheck
			return fmt.Errorf("渠道退款失败")
		}
		// 渠道返回 pending 时按"已受理"记录，等待对账确认
		return s.finishCertOrderRefund(ctx, refund, adminUUID, refundNo, true)
	}
}

// refundToBalance 把款项退回账户余额（余额支付订单）。
func (s *Service) refundToBalance(ctx context.Context, refund *storage.RefundRequest, adminUUID, refundNo string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开启事务失败: %w", err)
	}
	defer tx.Rollback()

	now := time.Now()
	res, err := tx.ExecContext(ctx,
		`UPDATE refund_requests SET status = ?, approved_by = ?, refund_no = ?, processed_at = ?
		 WHERE uuid = ? AND status = ?`,
		storage.OrderStatusPaid, adminUUID, refundNo, now, refund.UUID, storage.OrderStatusPending)
	if err != nil {
		return fmt.Errorf("更新退款工单失败: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("退款工单已被处理")
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE user_balances SET available_cents = available_cents + ?, total_consume = total_consume - ?
		 WHERE user_uuid = ?`,
		refund.AmountCents, refund.AmountCents, refund.UserUUID,
	); err != nil {
		return fmt.Errorf("退回余额失败: %w", err)
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO consume_records (uuid, user_uuid, order_no, consume_type, amount_cents, remark, created_at)
		 VALUES (?, ?, ?, 'refund', ?, ?, ?)`,
		uuid.New().String(), refund.UserUUID, refund.OrderNo, -refund.AmountCents,
		"订单退款退回余额", now,
	); err != nil {
		return fmt.Errorf("写入退款记录失败: %w", err)
	}

	if err := s.markBizOrderRefunded(ctx, tx, refund); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交事务失败: %w", err)
	}

	slog.Info("订单退款成功（余额）", "refund_uuid", refund.UUID, "order_no", refund.OrderNo,
		"amount_cents", refund.AmountCents, "admin", adminUUID)
	return nil
}

// finishCertOrderRefund 记录渠道/免费退款结果并关闭订单。
func (s *Service) finishCertOrderRefund(ctx context.Context, refund *storage.RefundRequest, adminUUID, refundNo string, chargeChannel bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开启事务失败: %w", err)
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx,
		`UPDATE refund_requests SET status = ?, approved_by = ?, refund_no = ?, processed_at = ?
		 WHERE uuid = ? AND status = ?`,
		storage.OrderStatusPaid, adminUUID, refundNo, time.Now(), refund.UUID, storage.OrderStatusPending)
	if err != nil {
		return fmt.Errorf("更新退款工单失败: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("退款工单已被处理")
	}

	if chargeChannel {
		// 渠道退款：资金不进入余额，只回冲消费统计
		if _, err := tx.ExecContext(ctx,
			`UPDATE user_balances SET total_consume = total_consume - ? WHERE user_uuid = ?`,
			refund.AmountCents, refund.UserUUID,
		); err != nil {
			return fmt.Errorf("更新消费统计失败: %w", err)
		}
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO consume_records (uuid, user_uuid, order_no, consume_type, amount_cents, remark, created_at)
		 VALUES (?, ?, ?, 'refund', ?, ?, ?)`,
		uuid.New().String(), refund.UserUUID, refund.OrderNo, -refund.AmountCents,
		fmt.Sprintf("订单退款（%s）", refund.Channel), time.Now(),
	); err != nil {
		return fmt.Errorf("写入退款记录失败: %w", err)
	}

	if err := s.markBizOrderRefunded(ctx, tx, refund); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交事务失败: %w", err)
	}

	slog.Info("订单退款已受理", "refund_uuid", refund.UUID, "order_no", refund.OrderNo,
		"channel", refund.Channel, "refund_no", refundNo, "admin", adminUUID)
	return nil
}

// markBizOrderRefunded 把业务订单标记为已退款（条件更新，避免覆盖已签发状态）。
func (s *Service) markBizOrderRefunded(ctx context.Context, tx *sql.Tx, refund *storage.RefundRequest) error {
	if refund.BizUUID == "" {
		return nil
	}
	res, err := tx.ExecContext(ctx,
		`UPDATE cert_orders SET status = ?, updated_at = ?
		 WHERE uuid = ? AND status IN (?, ?)`,
		storage.CertOrderRefunded, time.Now(), refund.BizUUID,
		storage.CertOrderPaid, storage.CertOrderApplying)
	if err != nil {
		return fmt.Errorf("更新订单状态失败: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("订单已进入签发流程，无法直接退款，请先取消申请")
	}
	return nil
}

func (s *Service) markRefundFailed(ctx context.Context, refundUUID, refundNo, reason string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE refund_requests SET status = ?, refund_no = ?, fail_reason = ?, processed_at = ?
		 WHERE uuid = ? AND status = ?`,
		storage.OrderStatusFailed, refundNo, reason, time.Now(), refundUUID, storage.OrderStatusPending)
	return err
}

// approveRechargeRefund 审批充值订单退款（历史路径：退回余额并关闭充值单）。
func (s *Service) approveRechargeRefund(ctx context.Context, refund *storage.RefundRequest, adminUUID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开启事务失败: %w", err)
	}
	defer tx.Rollback()

	now := time.Now()
	res, err := tx.ExecContext(ctx,
		`UPDATE refund_requests SET status = 'paid', approved_by = ?, processed_at = ? WHERE uuid = ? AND status = ?`,
		adminUUID, now, refund.UUID, storage.OrderStatusPending)
	if err != nil {
		return fmt.Errorf("更新退款工单失败: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("退款工单已被处理")
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE recharge_orders SET status = ? WHERE order_no = ?`,
		storage.OrderStatusRefunded, refund.OrderNo); err != nil {
		return fmt.Errorf("更新订单状态失败: %w", err)
	}

	// 条件扣减：余额不足以冲回时整体失败，避免出现负数余额
	res, err = tx.ExecContext(ctx,
		`UPDATE user_balances SET available_cents = available_cents - ?, total_recharge = total_recharge - ?
		 WHERE user_uuid = ? AND available_cents >= ?`,
		refund.AmountCents, refund.AmountCents, refund.UserUUID, refund.AmountCents)
	if err != nil {
		return fmt.Errorf("扣减余额失败: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("用户可用余额不足，无法完成退款冲回")
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO consume_records (uuid, user_uuid, order_no, consume_type, amount_cents, remark, created_at)
		 VALUES (?, ?, ?, 'refund', ?, ?, ?)`,
		uuid.New().String(), refund.UserUUID, refund.OrderNo, -refund.AmountCents,
		fmt.Sprintf("退款: 订单 %s", refund.OrderNo), now,
	); err != nil {
		return fmt.Errorf("写入退款记录失败: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交事务失败: %w", err)
	}

	slog.Info("充值退款审批通过", "refund_uuid", refund.UUID, "admin", adminUUID,
		"amount_cents", refund.AmountCents)
	return nil
}
