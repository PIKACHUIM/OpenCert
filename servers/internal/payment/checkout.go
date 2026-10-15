// Package payment - 业务订单收银台（证书/云卡订单的直付、余额支付与回调结算）。
//
// 设计要点：
//   - 支付事实以 payment_attempts 为准：渠道、金额、业务归属均持久化，
//     回调必须与已有尝试匹配后才入账，不能仅凭单号前缀推断。
//   - 状态迁移全部使用带条件的 UPDATE，配合唯一索引实现幂等，
//     重复回调、重复点击与换渠道支付都不会重复履约或重复扣款。
//   - 每次"以某渠道支付某笔订单"只允许一笔待支付尝试，换渠道时关闭旧尝试。
package payment

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/globaltrusts/server-card/internal/storage"
	"github.com/google/uuid"
)

// 支付尝试有效期：与渠道订单保持一致的 30 分钟。
const attemptTTL = 30 * time.Minute

// CheckoutInput 是发起支付的请求。
type CheckoutInput struct {
	UserUUID  string
	OrderNo   string // 对外订单号
	Channel   string // balance / free / alipay / wechat / stripe / paypal
	NotifyURL string
	ReturnURL string
	Subject   string
}

// CheckoutResult 是发起支付的结果。
type CheckoutResult struct {
	OrderNo     string `json:"order_no"`
	Channel     string `json:"channel"`
	AmountCents int64  `json:"amount_cents"`
	Currency    string `json:"currency"`
	// Settled 为 true 表示已直接完成（免费订单或余额支付），无需跳转渠道
	Settled bool   `json:"settled"`
	PayURL  string `json:"pay_url,omitempty"`
	QRCode  string `json:"qr_code,omitempty"`
	TradeNo string `json:"trade_no,omitempty"`
}

// AvailableChannel 是可用的支付渠道。
type AvailableChannel struct {
	Channel string `json:"channel"`
	Name    string `json:"name"`
	Type    string `json:"type"`
}

// ListChannels 返回当前已启用的第三方支付渠道，以及始终可用的余额渠道。
// 余额是否可用由前端根据账户余额与订单金额判断。
func (s *Service) ListChannels(ctx context.Context) []AvailableChannel {
	channels := []AvailableChannel{{Channel: storage.ChannelBalance, Name: "账户余额", Type: "balance"}}

	rows, err := s.db.QueryContext(ctx,
		`SELECT name, plugin_type FROM payment_plugins WHERE enabled = 1 ORDER BY sort_weight DESC, created_at DESC`)
	if err != nil {
		slog.Warn("查询支付渠道失败", "error", err)
		return channels
	}
	defer rows.Close()

	for rows.Next() {
		var name, pluginType string
		if err := rows.Scan(&name, &pluginType); err != nil {
			continue
		}
		// 仅返回已成功加载到注册中心的渠道，避免前端展示不可用渠道
		if _, err := s.registry.Get(pluginType); err != nil {
			continue
		}
		channels = append(channels, AvailableChannel{Channel: pluginType, Name: name, Type: pluginType})
	}
	return channels
}

// CreateCertOrderPayment 为证书/云卡订单发起支付。
//
// 免费订单与余额支付会在同一事务内完成结算并返回 Settled=true；
// 第三方渠道会创建待支付尝试并返回支付链接或二维码。
func (s *Service) CreateCertOrderPayment(ctx context.Context, in CheckoutInput) (*CheckoutResult, error) {
	order, err := s.loadCertOrder(ctx, in.OrderNo)
	if err != nil {
		return nil, err
	}
	if order.UserUUID != in.UserUUID {
		return nil, fmt.Errorf("订单不存在")
	}
	if order.Status == string(storage.CertOrderPaid) ||
		order.Status == string(storage.CertOrderCompleted) {
		return nil, fmt.Errorf("订单已支付")
	}
	if order.Status != string(storage.CertOrderPendingPayment) {
		return nil, fmt.Errorf("订单状态不允许支付: %s", order.Status)
	}

	result := &CheckoutResult{
		OrderNo:     order.OrderNo,
		Channel:     in.Channel,
		AmountCents: order.AmountCents,
		Currency:    "CNY",
	}

	// 零金额订单：直接完成，不产生资金流水
	if order.AmountCents == 0 {
		if err := s.settleCertOrderPaid(ctx, order, storage.ChannelFree, 0, ""); err != nil {
			return nil, err
		}
		result.Channel = storage.ChannelFree
		result.Settled = true
		return result, nil
	}

	switch in.Channel {
	case storage.ChannelFree:
		return nil, fmt.Errorf("非零金额订单不能使用免费渠道")

	case storage.ChannelBalance:
		if err := s.payCertOrderWithBalance(ctx, order); err != nil {
			return nil, err
		}
		result.Settled = true
		return result, nil

	case "":
		return nil, fmt.Errorf("请选择支付渠道")

	default:
		provider, err := s.registry.Get(in.Channel)
		if err != nil {
			return nil, fmt.Errorf("不支持的支付渠道: %s", in.Channel)
		}

		// 换渠道时先关闭旧的待支付尝试，保证同一订单只有一笔有效尝试
		if err := s.closePendingAttempts(ctx, storage.PaymentBizCertOrder, order.UUID); err != nil {
			return nil, err
		}

		attempt := &storage.PaymentAttempt{
			UUID:        uuid.New().String(),
			BizType:     storage.PaymentBizCertOrder,
			BizUUID:     order.UUID,
			OrderNo:     order.OrderNo,
			UserUUID:    order.UserUUID,
			Channel:     in.Channel,
			AmountCents: order.AmountCents,
			Currency:    "CNY",
			Status:      storage.PaymentAttemptPending,
			CreatedAt:   time.Now(),
		}
		expires := time.Now().Add(attemptTTL)
		attempt.ExpiresAt = &expires

		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO payment_attempts
			 (uuid, biz_type, biz_uuid, order_no, user_uuid, channel, amount_cents, currency, status, created_at, expires_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			attempt.UUID, attempt.BizType, attempt.BizUUID, attempt.OrderNo, attempt.UserUUID,
			attempt.Channel, attempt.AmountCents, attempt.Currency, attempt.Status,
			attempt.CreatedAt, attempt.ExpiresAt,
		); err != nil {
			return nil, fmt.Errorf("创建支付尝试失败: %w", err)
		}

		subject := in.Subject
		if subject == "" {
			subject = "OpenCert 订单 " + order.OrderNo
		}
		resp, err := provider.CreateOrder(ctx, CreateOrderReq{
			OrderNo:     order.OrderNo,
			AmountCents: order.AmountCents,
			Subject:     subject,
			NotifyURL:   in.NotifyURL,
			ReturnURL:   in.ReturnURL,
		})
		if err != nil {
			// 渠道下单失败：关闭该尝试，允许用户换渠道重试
			s.closeAttempt(ctx, attempt.UUID) //nolint:errcheck
			return nil, fmt.Errorf("创建支付链接失败: %w", err)
		}

		if resp.TradeNo != "" {
			s.db.ExecContext(ctx, //nolint:errcheck
				`UPDATE payment_attempts SET transaction_id = ? WHERE uuid = ?`, resp.TradeNo, attempt.UUID)
		}

		result.PayURL = resp.PayURL
		result.QRCode = resp.QRCode
		result.TradeNo = resp.TradeNo
		return result, nil
	}
}

// ConfirmOfflinePayment 管理员确认线下到账（对公转账、现场付款等）。
//
// 未接入在线支付插件时，这是销售模式下唯一的收款方式，因此必须：
//   - 仅作用于待支付订单（条件更新，重复确认幂等）；
//   - 记录凭证号/备注作为交易号，写入支付记录与消费流水，便于对账。
func (s *Service) ConfirmOfflinePayment(ctx context.Context, orderNo, reference string) error {
	reference = strings.TrimSpace(reference)
	if reference == "" {
		return fmt.Errorf("请填写到账凭证号或备注，便于对账")
	}
	order, err := s.loadCertOrder(ctx, orderNo)
	if err != nil {
		return err
	}
	if order.Status != string(storage.CertOrderPendingPayment) {
		return fmt.Errorf("仅待支付订单可确认到账，当前状态: %s", order.Status)
	}
	// 关闭进行中的在线支付尝试，避免后续渠道回调重复入账
	if err := s.closePendingAttempts(ctx, storage.PaymentBizCertOrder, order.UUID); err != nil {
		return err
	}
	channel := storage.ChannelOffline
	if order.AmountCents == 0 {
		channel = storage.ChannelFree
	}
	return s.settleCertOrderPaid(ctx, order, channel, order.AmountCents, reference)
}

// GetOrderPaymentState 查询订单的支付尝试（用于前端轮询）。
func (s *Service) GetOrderPaymentState(ctx context.Context, orderNo string) (*storage.PaymentAttempt, error) {
	attempt := &storage.PaymentAttempt{}
	var paidAt, expiresAt sql.NullTime
	err := s.db.QueryRowContext(ctx,
		`SELECT uuid, biz_type, biz_uuid, order_no, user_uuid, channel, amount_cents, currency,
		        status, transaction_id, created_at, paid_at, expires_at
		 FROM payment_attempts WHERE order_no = ?
		 ORDER BY created_at DESC LIMIT 1`, orderNo,
	).Scan(&attempt.UUID, &attempt.BizType, &attempt.BizUUID, &attempt.OrderNo, &attempt.UserUUID,
		&attempt.Channel, &attempt.AmountCents, &attempt.Currency, &attempt.Status,
		&attempt.TransactionID, &attempt.CreatedAt, &paidAt, &expiresAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("该订单暂无支付记录")
	}
	if err != nil {
		return nil, err
	}
	if paidAt.Valid {
		attempt.PaidAt = &paidAt.Time
	}
	if expiresAt.Valid {
		attempt.ExpiresAt = &expiresAt.Time
	}
	return attempt, nil
}

// ---- 内部实现 ----

// certOrderRow 是结算所需的订单最小字段集。
type certOrderRow struct {
	UUID        string
	OrderNo     string
	UserUUID    string
	AmountCents int64
	Status      string
}

func (s *Service) loadCertOrder(ctx context.Context, orderNo string) (*certOrderRow, error) {
	if orderNo == "" {
		return nil, fmt.Errorf("缺少订单号")
	}
	o := &certOrderRow{}
	err := s.db.QueryRowContext(ctx,
		`SELECT uuid, order_no, user_uuid, amount_cents, status FROM cert_orders WHERE order_no = ?`, orderNo,
	).Scan(&o.UUID, &o.OrderNo, &o.UserUUID, &o.AmountCents, &o.Status)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("订单不存在: %s", orderNo)
	}
	if err != nil {
		return nil, fmt.Errorf("查询订单失败: %w", err)
	}
	return o, nil
}

func (s *Service) closePendingAttempts(ctx context.Context, bizType storage.PaymentBizType, bizUUID string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE payment_attempts SET status = ? WHERE biz_type = ? AND biz_uuid = ? AND status = ?`,
		storage.PaymentAttemptClosed, bizType, bizUUID, storage.PaymentAttemptPending)
	return err
}

func (s *Service) closeAttempt(ctx context.Context, attemptUUID string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE payment_attempts SET status = ? WHERE uuid = ? AND status = ?`,
		storage.PaymentAttemptClosed, attemptUUID, storage.PaymentAttemptPending)
	return err
}

// payCertOrderWithBalance 使用账户余额支付订单。
func (s *Service) payCertOrderWithBalance(ctx context.Context, order *certOrderRow) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开启事务失败: %w", err)
	}
	defer tx.Rollback()

	var available int64
	err = tx.QueryRowContext(ctx,
		`SELECT available_cents FROM user_balances WHERE user_uuid = ?`, order.UserUUID).Scan(&available)
	if err == sql.ErrNoRows {
		return fmt.Errorf("余额不足: 可用 0 分，需要 %d 分", order.AmountCents)
	}
	if err != nil {
		return fmt.Errorf("查询余额失败: %w", err)
	}
	if available < order.AmountCents {
		return fmt.Errorf("余额不足: 可用 %d 分，需要 %d 分", available, order.AmountCents)
	}

	// 条件扣减：即使并发请求同时到达也不会扣成负数
	res, err := tx.ExecContext(ctx,
		`UPDATE user_balances SET available_cents = available_cents - ?, total_consume = total_consume + ?
		 WHERE user_uuid = ? AND available_cents >= ?`,
		order.AmountCents, order.AmountCents, order.UserUUID, order.AmountCents)
	if err != nil {
		return fmt.Errorf("扣减余额失败: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("余额不足，请刷新后重试")
	}

	// 余额支付不经过第三方渠道，直接结算
	if _, err := s.settleCertOrderPaidTx(ctx, tx, order, storage.ChannelBalance, order.AmountCents, "", true); err != nil {
		return err
	}

	attemptNo := uuid.New().String()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO payment_attempts
		 (uuid, biz_type, biz_uuid, order_no, user_uuid, channel, amount_cents, currency, status, created_at, paid_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, 'CNY', ?, ?, ?)`,
		attemptNo, storage.PaymentBizCertOrder, order.UUID, order.OrderNo, order.UserUUID,
		storage.ChannelBalance, order.AmountCents, storage.PaymentAttemptPaid, time.Now(), time.Now(),
	); err != nil {
		return fmt.Errorf("记录支付尝试失败: %w", err)
	}

	return tx.Commit()
}

// settleCertOrderPaid 在独立事务中结算订单，并留下可追溯的支付记录。
//
// 免费订单同样会写入一条 channel=free 的支付尝试，保证任何已支付订单
// 都能通过支付记录解释其资金来源，而不是只有"订单状态变了"。
func (s *Service) settleCertOrderPaid(ctx context.Context, order *certOrderRow, channel string, amountCents int64, txID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开启事务失败: %w", err)
	}
	defer tx.Rollback()

	settled, err := s.settleCertOrderPaidTx(ctx, tx, order, channel, amountCents, txID, false)
	if err != nil {
		return err
	}
	if !settled {
		// 已被并发结算，保持幂等
		return tx.Commit()
	}

	now := time.Now()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO payment_attempts
		 (uuid, biz_type, biz_uuid, order_no, user_uuid, channel, amount_cents, currency, status, transaction_id, created_at, paid_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, 'CNY', ?, ?, ?, ?)`,
		uuid.New().String(), storage.PaymentBizCertOrder, order.UUID, order.OrderNo, order.UserUUID,
		channel, amountCents, storage.PaymentAttemptPaid, txID, now, now,
	); err != nil {
		return fmt.Errorf("记录支付尝试失败: %w", err)
	}

	return tx.Commit()
}

// settleCertOrderPaidTx 在给定事务内把订单置为已支付并记录消费流水。
//
// 返回 settled=false 表示订单此前已结算（幂等命中），调用方不应重复记账。
// balanceDeducted 表示可用余额已在同一事务内扣减，避免重复计入消费。
func (s *Service) settleCertOrderPaidTx(
	ctx context.Context,
	tx *sql.Tx,
	order *certOrderRow,
	channel string,
	amountCents int64,
	txID string,
	balanceDeducted bool,
) (bool, error) {
	now := time.Now()

	// 条件更新：仅当仍处于待支付时生效，天然防重复入账
	res, err := tx.ExecContext(ctx,
		`UPDATE cert_orders SET status = ?, paid_at = ?, updated_at = ?
		 WHERE uuid = ? AND status = ?`,
		storage.CertOrderPaid, now, now, order.UUID, storage.CertOrderPendingPayment)
	if err != nil {
		return false, fmt.Errorf("更新订单状态失败: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// 已结算过：幂等返回，不产生第二笔流水
		return false, nil
	}

	if amountCents > 0 {
		// 第三方渠道支付时资金未进入余额，只累计消费额
		if !balanceDeducted {
			if _, err := tx.ExecContext(ctx,
				`UPDATE user_balances SET total_consume = total_consume + ? WHERE user_uuid = ?`,
				amountCents, order.UserUUID,
			); err != nil {
				return false, fmt.Errorf("更新消费统计失败: %w", err)
			}
		}

		remark := fmt.Sprintf("订单支付（%s）", channel)
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO consume_records (uuid, user_uuid, order_no, consume_type, amount_cents, remark, created_at)
			 VALUES (?, ?, ?, 'cert_purchase', ?, ?, ?)`,
			uuid.New().String(), order.UserUUID, order.OrderNo, amountCents, remark, now,
		); err != nil {
			return false, fmt.Errorf("写入消费记录失败: %w", err)
		}
	}

	slog.Info("订单已支付",
		"order_no", order.OrderNo, "channel", channel, "amount_cents", amountCents, "transaction_id", txID)
	return true, nil
}

// markAttemptPaid 把待支付尝试置为已支付（条件更新，保证只成功一次）。
func markAttemptPaid(ctx context.Context, tx *sql.Tx, attemptUUID string, data *CallbackData) error {
	_, err := tx.ExecContext(ctx,
		`UPDATE payment_attempts SET status = ?, transaction_id = ?, raw_callback = ?, paid_at = ?
		 WHERE uuid = ? AND status = ?`,
		storage.PaymentAttemptPaid, data.TradeNo, string(data.RawData), time.Now(),
		attemptUUID, storage.PaymentAttemptPending)
	return err
}

// ---- 回调分派 ----

// HandleChannelCallback 处理支付平台回调。
//
// 分派顺序：先按 (订单号, 渠道) 匹配业务订单支付尝试，匹配不到再回退到充值订单。
// 无论走哪条路径，都必须通过渠道、金额与状态校验后才入账。
func (s *Service) HandleChannelCallback(ctx context.Context, channel string, data *CallbackData) error {
	if data.OrderNo == "" {
		return fmt.Errorf("回调缺少订单号")
	}

	if handled, err := s.handleCertOrderCallback(ctx, channel, data); handled {
		return err
	}
	return s.handleRechargeCallback(ctx, channel, data)
}

// handleCertOrderCallback 处理业务订单（证书/云卡）支付回调。
// 返回 handled 表示该回调是否属于业务订单支付。
func (s *Service) handleCertOrderCallback(ctx context.Context, channel string, data *CallbackData) (bool, error) {
	attempt := &storage.PaymentAttempt{}
	var expiresAt sql.NullTime
	err := s.db.QueryRowContext(ctx,
		`SELECT uuid, biz_type, biz_uuid, order_no, user_uuid, channel, amount_cents, currency, status, expires_at
		 FROM payment_attempts WHERE order_no = ? AND channel = ?
		 ORDER BY created_at DESC LIMIT 1`, data.OrderNo, channel,
	).Scan(&attempt.UUID, &attempt.BizType, &attempt.BizUUID, &attempt.OrderNo, &attempt.UserUUID,
		&attempt.Channel, &attempt.AmountCents, &attempt.Currency, &attempt.Status, &expiresAt)
	if err == sql.ErrNoRows {
		return false, nil // 不属于业务订单，交给充值路径
	}
	if err != nil {
		return true, fmt.Errorf("查询支付尝试失败: %w", err)
	}
	if expiresAt.Valid {
		attempt.ExpiresAt = &expiresAt.Time
	}

	switch attempt.Status {
	case storage.PaymentAttemptPaid:
		// 重复回调：直接确认，不重复入账
		slog.Info("支付回调重复，已忽略", "order_no", data.OrderNo, "channel", channel)
		return true, nil
	case storage.PaymentAttemptPending:
		// 继续校验
	default:
		// 尝试已被关闭/失败，但渠道确实收到了款项：必须人工对账，不能静默忽略资金事实
		s.db.ExecContext(ctx, //nolint:errcheck
			`UPDATE payment_attempts SET raw_callback = ? WHERE uuid = ?`, string(data.RawData), attempt.UUID)
		return true, fmt.Errorf("订单 %s 的支付尝试已处于 %s 状态却收到成功回调，需人工对账", data.OrderNo, attempt.Status)
	}

	// 金额校验：以防篡改或渠道串单
	if data.AmountCents != 0 && data.AmountCents != attempt.AmountCents {
		return true, fmt.Errorf("回调金额不符：订单 %s 应付 %d 分，回调 %d 分",
			data.OrderNo, attempt.AmountCents, data.AmountCents)
	}

	order := &certOrderRow{}
	err = s.db.QueryRowContext(ctx,
		`SELECT uuid, order_no, user_uuid, amount_cents, status FROM cert_orders WHERE uuid = ?`, attempt.BizUUID,
	).Scan(&order.UUID, &order.OrderNo, &order.UserUUID, &order.AmountCents, &order.Status)
	if err != nil {
		return true, fmt.Errorf("读取订单失败: %w", err)
	}
	if data.AmountCents != 0 && data.AmountCents != order.AmountCents {
		return true, fmt.Errorf("回调金额与订单金额不符：订单 %s 应付 %d 分，回调 %d 分",
			order.OrderNo, order.AmountCents, data.AmountCents)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return true, fmt.Errorf("开启事务失败: %w", err)
	}
	defer tx.Rollback()

	if err := markAttemptPaid(ctx, tx, attempt.UUID, data); err != nil {
		return true, fmt.Errorf("更新支付尝试失败: %w", err)
	}
	if _, err := s.settleCertOrderPaidTx(ctx, tx, order, channel, attempt.AmountCents, data.TradeNo, false); err != nil {
		return true, err
	}
	return true, tx.Commit()
}

// handleRechargeCallback 处理账户充值回调。
//
// 相比早期实现补充了渠道与金额校验，并把状态更新改为条件更新，
// 避免并发重复回调造成重复充值。
func (s *Service) handleRechargeCallback(ctx context.Context, channel string, data *CallbackData) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开启事务失败: %w", err)
	}
	defer tx.Rollback()

	var (
		userUUID    string
		amountCents int64
		orderChan   string
		status      string
	)
	err = tx.QueryRowContext(ctx,
		`SELECT user_uuid, amount_cents, channel, status FROM recharge_orders WHERE order_no = ?`, data.OrderNo,
	).Scan(&userUUID, &amountCents, &orderChan, &status)
	if err == sql.ErrNoRows {
		return fmt.Errorf("订单不存在: %s", data.OrderNo)
	}
	if err != nil {
		return fmt.Errorf("查询订单失败: %w", err)
	}

	if status != string(storage.OrderStatusPending) {
		slog.Info("充值订单已处理，跳过", "order_no", data.OrderNo, "status", status)
		return nil
	}
	if orderChan != "" && orderChan != channel {
		return fmt.Errorf("回调渠道不符：订单 %s 使用 %s，回调来自 %s", data.OrderNo, orderChan, channel)
	}
	if data.AmountCents != 0 && data.AmountCents != amountCents {
		return fmt.Errorf("回调金额不符：订单 %s 应付 %d 分，回调 %d 分", data.OrderNo, amountCents, data.AmountCents)
	}

	now := time.Now()
	res, err := tx.ExecContext(ctx,
		`UPDATE recharge_orders SET status = ?, paid_at = ?, callback_data = ? WHERE order_no = ? AND status = ?`,
		storage.OrderStatusPaid, now, data.RawData, data.OrderNo, storage.OrderStatusPending)
	if err != nil {
		return fmt.Errorf("更新订单状态失败: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		slog.Info("充值订单已被并发处理", "order_no", data.OrderNo)
		return tx.Commit()
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO user_balances (user_uuid, available_cents, frozen_cents, total_recharge, total_consume)
		 VALUES (?, ?, 0, ?, 0)
		 ON CONFLICT(user_uuid) DO UPDATE SET
		   available_cents = available_cents + ?,
		   total_recharge = total_recharge + ?`,
		userUUID, amountCents, amountCents, amountCents, amountCents,
	); err != nil {
		return fmt.Errorf("更新余额失败: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交事务失败: %w", err)
	}

	slog.Info("充值成功", "order_no", data.OrderNo, "user", userUUID, "amount_cents", amountCents)
	return nil
}
