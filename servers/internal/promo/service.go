// Package promo 提供销售侧的优惠与订阅能力：
//   - 优惠码：下单时抵扣金额（满减/折扣、适用商品、总量与每人限用、有效期）；
//   - 订阅套餐：周期内可用指定证书开通模板申请若干张证书，并可设置单证有效期、是否允许吊销、吊销后是否释放额度；
//   - 兑换码：兑换订阅套餐或账户余额。
package promo

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/globaltrusts/server-card/internal/storage"
	"github.com/google/uuid"
)

// Service 是优惠与订阅服务。
type Service struct {
	db *storage.DB
	mu sync.Mutex // 串行化订阅额度占用，避免并发超用
}

// NewService 创建服务。
func NewService(db *storage.DB) *Service { return &Service{db: db} }

// ======================= 优惠码 =======================

// Coupon 是优惠码。
type Coupon struct {
	UUID             string     `json:"uuid"`
	Code             string     `json:"code"`
	Name             string     `json:"name"`
	DiscountType     string     `json:"discount_type"`      // amount=立减（分）/ percent=折扣（减免百分比 1-100）
	DiscountValue    int64      `json:"discount_value"`     // 立减金额（分）或减免百分比
	MinAmountCents   int64      `json:"min_amount_cents"`   // 订单满多少可用
	MaxDiscountCents int64      `json:"max_discount_cents"` // 折扣封顶（0 = 不封顶）
	ProductCodes     []string   `json:"product_codes"`      // 适用商品编码（空 = 全部）
	TotalLimit       int        `json:"total_limit"`        // 总可用次数（-1 = 不限）
	UsedCount        int        `json:"used_count"`
	PerUserLimit     int        `json:"per_user_limit"` // 每人可用次数（0 = 不限）
	ValidFrom        *time.Time `json:"valid_from,omitempty"`
	ValidUntil       *time.Time `json:"valid_until,omitempty"`
	Enabled          bool       `json:"enabled"`
	CreatedAt        time.Time  `json:"created_at"`
}

const couponColumns = `uuid, code, name, discount_type, discount_value, min_amount_cents, max_discount_cents,
	product_codes, total_limit, used_count, per_user_limit, valid_from, valid_until, enabled, created_at`

func scanCoupon(scan func(dest ...interface{}) error) (*Coupon, error) {
	c := &Coupon{}
	var products string
	var from, until sql.NullTime
	var enabled int
	if err := scan(&c.UUID, &c.Code, &c.Name, &c.DiscountType, &c.DiscountValue, &c.MinAmountCents, &c.MaxDiscountCents,
		&products, &c.TotalLimit, &c.UsedCount, &c.PerUserLimit, &from, &until, &enabled, &c.CreatedAt); err != nil {
		return nil, err
	}
	c.ProductCodes = []string{}
	json.Unmarshal([]byte(products), &c.ProductCodes) //nolint:errcheck
	if from.Valid {
		c.ValidFrom = &from.Time
	}
	if until.Valid {
		c.ValidUntil = &until.Time
	}
	c.Enabled = enabled == 1
	return c, nil
}

func normCode(code string) string { return strings.ToUpper(strings.TrimSpace(code)) }

// ListCoupons 查询全部优惠码。
func (s *Service) ListCoupons(ctx context.Context) ([]*Coupon, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+couponColumns+` FROM promo_coupons ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []*Coupon{}
	for rows.Next() {
		c, err := scanCoupon(rows.Scan)
		if err != nil {
			return nil, err
		}
		list = append(list, c)
	}
	return list, rows.Err()
}

// SaveCoupon 创建或更新优惠码（code 留空时自动生成）。
func (s *Service) SaveCoupon(ctx context.Context, c *Coupon) error {
	c.Code = normCode(c.Code)
	if c.Code == "" {
		c.Code = randomCode(10)
	}
	if len(c.Code) < 4 || len(c.Code) > 32 {
		return fmt.Errorf("优惠码长度需为 4-32 位")
	}
	switch c.DiscountType {
	case "amount":
		if c.DiscountValue <= 0 {
			return fmt.Errorf("立减金额需大于 0")
		}
	case "percent":
		if c.DiscountValue <= 0 || c.DiscountValue > 100 {
			return fmt.Errorf("减免百分比需在 1-100 之间")
		}
	default:
		return fmt.Errorf("优惠类型只能为 amount 或 percent")
	}
	if c.TotalLimit == 0 {
		c.TotalLimit = -1
	}
	if c.ValidFrom != nil && c.ValidUntil != nil && !c.ValidUntil.After(*c.ValidFrom) {
		return fmt.Errorf("结束时间需晚于开始时间")
	}
	if c.ProductCodes == nil {
		c.ProductCodes = []string{}
	}
	products, _ := json.Marshal(c.ProductCodes)
	var err error
	if c.UUID == "" {
		c.UUID = uuid.New().String()
		c.CreatedAt = time.Now()
		_, err = s.db.ExecContext(ctx, `INSERT INTO promo_coupons (`+couponColumns+`, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?)`,
			c.UUID, c.Code, c.Name, c.DiscountType, c.DiscountValue, c.MinAmountCents, c.MaxDiscountCents,
			string(products), c.TotalLimit, c.PerUserLimit, c.ValidFrom, c.ValidUntil, storage.BoolToInt(c.Enabled),
			c.CreatedAt, c.CreatedAt)
	} else {
		_, err = s.db.ExecContext(ctx, `UPDATE promo_coupons SET code = ?, name = ?, discount_type = ?, discount_value = ?,
			min_amount_cents = ?, max_discount_cents = ?, product_codes = ?, total_limit = ?, per_user_limit = ?,
			valid_from = ?, valid_until = ?, enabled = ?, updated_at = ? WHERE uuid = ?`,
			c.Code, c.Name, c.DiscountType, c.DiscountValue, c.MinAmountCents, c.MaxDiscountCents, string(products),
			c.TotalLimit, c.PerUserLimit, c.ValidFrom, c.ValidUntil, storage.BoolToInt(c.Enabled), time.Now(), c.UUID)
	}
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "unique") {
		return fmt.Errorf("优惠码 %s 已存在", c.Code)
	}
	return err
}

// DeleteCoupon 删除优惠码（已使用的建议停用而非删除，以保留对账记录）。
func (s *Service) DeleteCoupon(ctx context.Context, id string) error {
	var used int
	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM promo_coupon_usages WHERE coupon_uuid = ?`, id).Scan(&used) //nolint:errcheck
	if used > 0 {
		return fmt.Errorf("该优惠码已被使用 %d 次，请改为停用", used)
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM promo_coupons WHERE uuid = ?`, id)
	return err
}

// PreviewCoupon 计算优惠金额（不占用次数）。
func (s *Service) PreviewCoupon(ctx context.Context, code, userUUID, productCode string, amountCents int64) (int64, *Coupon, error) {
	c, err := scanCoupon(s.db.QueryRowContext(ctx,
		`SELECT `+couponColumns+` FROM promo_coupons WHERE code = ?`, normCode(code)).Scan)
	if err != nil {
		return 0, nil, fmt.Errorf("优惠码无效")
	}
	now := time.Now()
	switch {
	case !c.Enabled:
		return 0, nil, fmt.Errorf("优惠码已停用")
	case c.ValidFrom != nil && now.Before(*c.ValidFrom):
		return 0, nil, fmt.Errorf("优惠码尚未生效")
	case c.ValidUntil != nil && now.After(*c.ValidUntil):
		return 0, nil, fmt.Errorf("优惠码已过期")
	case c.TotalLimit >= 0 && c.UsedCount >= c.TotalLimit:
		return 0, nil, fmt.Errorf("优惠码已被领完")
	case amountCents < c.MinAmountCents:
		return 0, nil, fmt.Errorf("订单满 %.2f 元可用", float64(c.MinAmountCents)/100)
	}
	if len(c.ProductCodes) > 0 {
		ok := false
		for _, p := range c.ProductCodes {
			if p == productCode {
				ok = true
			}
		}
		if !ok {
			return 0, nil, fmt.Errorf("该优惠码不适用于此商品")
		}
	}
	if c.PerUserLimit > 0 {
		var n int
		s.db.QueryRowContext(ctx, //nolint:errcheck
			`SELECT COUNT(*) FROM promo_coupon_usages WHERE coupon_uuid = ? AND user_uuid = ?`, c.UUID, userUUID).Scan(&n)
		if n >= c.PerUserLimit {
			return 0, nil, fmt.Errorf("您已使用过该优惠码")
		}
	}
	discount := c.DiscountValue
	if c.DiscountType == "percent" {
		discount = amountCents * c.DiscountValue / 100
		if c.MaxDiscountCents > 0 && discount > c.MaxDiscountCents {
			discount = c.MaxDiscountCents
		}
	}
	if discount > amountCents {
		discount = amountCents
	}
	return discount, c, nil
}

// ConsumeCoupon 下单时占用优惠码（条件更新防并发超用），返回优惠金额。
func (s *Service) ConsumeCoupon(ctx context.Context, code, userUUID, orderNo, productCode string, amountCents int64) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	discount, c, err := s.PreviewCoupon(ctx, code, userUUID, productCode, amountCents)
	if err != nil {
		return 0, err
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE promo_coupons SET used_count = used_count + 1 WHERE uuid = ? AND (total_limit < 0 OR used_count < total_limit)`, c.UUID)
	if err != nil {
		return 0, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return 0, fmt.Errorf("优惠码已被领完")
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO promo_coupon_usages (uuid, coupon_uuid, user_uuid, order_no, discount_cents, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		uuid.New().String(), c.UUID, userUUID, orderNo, discount, time.Now()); err != nil {
		s.db.ExecContext(ctx, `UPDATE promo_coupons SET used_count = used_count - 1 WHERE uuid = ?`, c.UUID) //nolint:errcheck
		return 0, fmt.Errorf("记录优惠码使用失败: %w", err)
	}
	return discount, nil
}

// ReleaseCoupon 订单取消/关闭时归还优惠码次数（幂等）。
func (s *Service) ReleaseCoupon(ctx context.Context, orderNo string) {
	var couponUUID string
	if err := s.db.QueryRowContext(ctx,
		`SELECT coupon_uuid FROM promo_coupon_usages WHERE order_no = ?`, orderNo).Scan(&couponUUID); err != nil {
		return
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM promo_coupon_usages WHERE order_no = ?`, orderNo)
	if err != nil {
		return
	}
	if n, _ := res.RowsAffected(); n > 0 {
		s.db.ExecContext(ctx, //nolint:errcheck
			`UPDATE promo_coupons SET used_count = used_count - 1 WHERE uuid = ? AND used_count > 0`, couponUUID)
	}
}

// ======================= 订阅套餐 =======================

// PlanItem 是套餐中的一项额度。
type PlanItem struct {
	CertApplyTmplUUID string `json:"cert_apply_tmpl_uuid"` // 可使用的证书开通模板
	Quota             int    `json:"quota"`                // 周期内可申请张数
	ValidDays         int    `json:"valid_days"`           // 单张证书有效期（0 = 按开通模板）
}

// Plan 是订阅套餐。
type Plan struct {
	UUID               string     `json:"uuid"`
	Code               string     `json:"code"`
	Name               string     `json:"name"`
	Description        string     `json:"description"`
	PeriodDays         int        `json:"period_days"` // 订阅周期（天）
	PriceCents         int64      `json:"price_cents"`
	Items              []PlanItem `json:"items"`
	AllowRevoke        bool       `json:"allow_revoke"`         // 用户可否自行吊销套餐内证书
	RevokeReleaseQuota bool       `json:"revoke_release_quota"` // 吊销后是否释放额度
	Visible            bool       `json:"visible"`              // 是否在前台售卖
	Enabled            bool       `json:"enabled"`
	SortWeight         int        `json:"sort_weight"`
	CreatedAt          time.Time  `json:"created_at"`
}

const planColumns = `uuid, code, name, description, period_days, price_cents, items, allow_revoke, revoke_release_quota,
	visible, enabled, sort_weight, created_at`

func scanPlan(scan func(dest ...interface{}) error) (*Plan, error) {
	p := &Plan{}
	var items string
	var allow, release, visible, enabled int
	if err := scan(&p.UUID, &p.Code, &p.Name, &p.Description, &p.PeriodDays, &p.PriceCents, &items,
		&allow, &release, &visible, &enabled, &p.SortWeight, &p.CreatedAt); err != nil {
		return nil, err
	}
	p.Items = []PlanItem{}
	json.Unmarshal([]byte(items), &p.Items) //nolint:errcheck
	p.AllowRevoke, p.RevokeReleaseQuota, p.Visible, p.Enabled = allow == 1, release == 1, visible == 1, enabled == 1
	return p, nil
}

// ListPlans 查询套餐；publicOnly 时仅返回可售套餐。
func (s *Service) ListPlans(ctx context.Context, publicOnly bool) ([]*Plan, error) {
	q := `SELECT ` + planColumns + ` FROM promo_plans`
	if publicOnly {
		q += ` WHERE visible = 1 AND enabled = 1`
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY sort_weight DESC, created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []*Plan{}
	for rows.Next() {
		p, err := scanPlan(rows.Scan)
		if err != nil {
			return nil, err
		}
		list = append(list, p)
	}
	return list, rows.Err()
}

// GetPlan 按 UUID 或编码查询套餐。
func (s *Service) GetPlan(ctx context.Context, idOrCode string) (*Plan, error) {
	p, err := scanPlan(s.db.QueryRowContext(ctx,
		`SELECT `+planColumns+` FROM promo_plans WHERE uuid = ? OR code = ?`, idOrCode, idOrCode).Scan)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("订阅套餐不存在")
	}
	return p, err
}

// SavePlan 创建或更新套餐（已发放的订阅使用快照，不受修改影响）。
func (s *Service) SavePlan(ctx context.Context, p *Plan) error {
	p.Code = strings.ToLower(strings.TrimSpace(p.Code))
	if p.Name == "" || p.Code == "" {
		return fmt.Errorf("请填写套餐名称与编码")
	}
	if p.PeriodDays <= 0 || p.PeriodDays > 3650 {
		return fmt.Errorf("订阅周期需在 1-3650 天之间")
	}
	if p.PriceCents < 0 {
		return fmt.Errorf("价格不能为负")
	}
	if len(p.Items) == 0 {
		return fmt.Errorf("请至少配置一项证书额度")
	}
	for i, it := range p.Items {
		if it.CertApplyTmplUUID == "" || it.Quota <= 0 {
			return fmt.Errorf("第 %d 项额度配置不完整", i+1)
		}
		var issuanceUUID string
		if err := s.db.QueryRowContext(ctx,
			`SELECT issuance_tmpl_uuid FROM cert_apply_templates WHERE uuid = ?`, it.CertApplyTmplUUID).Scan(&issuanceUUID); err != nil {
			return fmt.Errorf("第 %d 项的证书开通模板不存在", i+1)
		}
		if it.ValidDays < 0 || it.ValidDays > 3650 {
			return fmt.Errorf("第 %d 项的证书有效期无效", i+1)
		}
		// 单证有效期必须落在颁发模板允许列表内，否则签发时会被拒绝
		if it.ValidDays > 0 && issuanceUUID != "" {
			allowed, err := s.issuanceValidDays(ctx, issuanceUUID)
			if err == nil && len(allowed) > 0 && !containsInt(allowed, it.ValidDays) {
				return fmt.Errorf("第 %d 项的单证有效期 %d 天不在颁发模板允许列表 %v 中", i+1, it.ValidDays, allowed)
			}
		}
	}
	items, _ := json.Marshal(p.Items)
	var err error
	if p.UUID == "" {
		p.UUID = uuid.New().String()
		p.CreatedAt = time.Now()
		_, err = s.db.ExecContext(ctx, `INSERT INTO promo_plans (`+planColumns+`, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			p.UUID, p.Code, p.Name, p.Description, p.PeriodDays, p.PriceCents, string(items),
			storage.BoolToInt(p.AllowRevoke), storage.BoolToInt(p.RevokeReleaseQuota),
			storage.BoolToInt(p.Visible), storage.BoolToInt(p.Enabled), p.SortWeight, p.CreatedAt, p.CreatedAt)
	} else {
		_, err = s.db.ExecContext(ctx, `UPDATE promo_plans SET code = ?, name = ?, description = ?, period_days = ?, price_cents = ?,
			items = ?, allow_revoke = ?, revoke_release_quota = ?, visible = ?, enabled = ?, sort_weight = ?, updated_at = ? WHERE uuid = ?`,
			p.Code, p.Name, p.Description, p.PeriodDays, p.PriceCents, string(items),
			storage.BoolToInt(p.AllowRevoke), storage.BoolToInt(p.RevokeReleaseQuota),
			storage.BoolToInt(p.Visible), storage.BoolToInt(p.Enabled), p.SortWeight, time.Now(), p.UUID)
	}
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "unique") {
		return fmt.Errorf("套餐编码 %s 已存在", p.Code)
	}
	return err
}

// DeletePlan 删除套餐（存在订阅时拒绝）。
func (s *Service) DeletePlan(ctx context.Context, id string) error {
	var n int
	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM promo_subscriptions WHERE plan_uuid = ?`, id).Scan(&n) //nolint:errcheck
	if n > 0 {
		return fmt.Errorf("该套餐已有 %d 个订阅，请改为停用", n)
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM promo_plans WHERE uuid = ?`, id)
	return err
}

// issuanceValidDays 读取颁发模板允许的有效期列表。
func (s *Service) issuanceValidDays(ctx context.Context, issuanceUUID string) ([]int, error) {
	var raw string
	if err := s.db.QueryRowContext(ctx, `SELECT valid_days FROM issuance_templates WHERE uuid = ?`, issuanceUUID).Scan(&raw); err != nil {
		return nil, err
	}
	var days []int
	json.Unmarshal([]byte(raw), &days) //nolint:errcheck
	return days, nil
}

func containsInt(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// ======================= 订阅 =======================

// Subscription 是用户的订阅实例（套餐内容为发放时快照）。
type Subscription struct {
	UUID      string       `json:"uuid"`
	UserUUID  string       `json:"user_uuid"`
	Username  string       `json:"username,omitempty"`
	PlanUUID  string       `json:"plan_uuid"`
	Plan      Plan         `json:"plan"`
	Source    string       `json:"source"` // order / redeem / admin
	SourceRef string       `json:"source_ref"`
	StartsAt  time.Time    `json:"starts_at"`
	EndsAt    time.Time    `json:"ends_at"`
	Status    string       `json:"status"` // active / cancelled
	Usage     []QuotaUsage `json:"usage,omitempty"`
	CreatedAt time.Time    `json:"created_at"`
}

// QuotaUsage 是某一额度项的使用情况。
type QuotaUsage struct {
	PlanItem
	TemplateName string `json:"template_name"`
	Used         int    `json:"used"`
	Remaining    int    `json:"remaining"`
}

// Active 判断订阅当前是否可用。
func (s *Subscription) Active(now time.Time) bool {
	return s.Status == "active" && !now.Before(s.StartsAt) && now.Before(s.EndsAt)
}

const subColumns = `uuid, user_uuid, plan_uuid, plan_snapshot, source, source_ref, starts_at, ends_at, status, created_at`

func scanSub(scan func(dest ...interface{}) error) (*Subscription, error) {
	sub := &Subscription{}
	var snap string
	if err := scan(&sub.UUID, &sub.UserUUID, &sub.PlanUUID, &snap, &sub.Source, &sub.SourceRef,
		&sub.StartsAt, &sub.EndsAt, &sub.Status, &sub.CreatedAt); err != nil {
		return nil, err
	}
	json.Unmarshal([]byte(snap), &sub.Plan) //nolint:errcheck
	return sub, nil
}

// Grant 发放订阅（source+source_ref 唯一，重复发放幂等返回已有订阅）。
func (s *Service) Grant(ctx context.Context, userUUID, planIDOrCode, source, sourceRef string) (*Subscription, error) {
	var existing string
	if err := s.db.QueryRowContext(ctx,
		`SELECT uuid FROM promo_subscriptions WHERE source = ? AND source_ref = ?`, source, sourceRef).Scan(&existing); err == nil {
		return s.GetSubscription(ctx, existing)
	}
	p, err := s.GetPlan(ctx, planIDOrCode)
	if err != nil {
		return nil, err
	}
	snap, _ := json.Marshal(p)
	now := time.Now()
	sub := &Subscription{UUID: uuid.New().String(), UserUUID: userUUID, PlanUUID: p.UUID, Plan: *p,
		Source: source, SourceRef: sourceRef, StartsAt: now, EndsAt: now.AddDate(0, 0, p.PeriodDays), Status: "active", CreatedAt: now}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO promo_subscriptions (`+subColumns+`, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sub.UUID, userUUID, p.UUID, string(snap), source, sourceRef, sub.StartsAt, sub.EndsAt, sub.Status, now, now); err != nil {
		return nil, fmt.Errorf("发放订阅失败: %w", err)
	}
	return sub, nil
}

// GetSubscription 查询订阅。
func (s *Service) GetSubscription(ctx context.Context, id string) (*Subscription, error) {
	sub, err := scanSub(s.db.QueryRowContext(ctx, `SELECT `+subColumns+` FROM promo_subscriptions WHERE uuid = ?`, id).Scan)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("订阅不存在")
	}
	return sub, err
}

// ListSubscriptions 查询订阅（userUUID 为空表示全部），附带额度使用情况。
func (s *Service) ListSubscriptions(ctx context.Context, userUUID string) ([]*Subscription, error) {
	q := `SELECT ` + subColumns + ` FROM promo_subscriptions`
	args := []interface{}{}
	if userUUID != "" {
		q += ` WHERE user_uuid = ?`
		args = append(args, userUUID)
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY created_at DESC LIMIT 500`, args...)
	if err != nil {
		return nil, err
	}
	list := []*Subscription{}
	for rows.Next() {
		sub, err := scanSub(rows.Scan)
		if err != nil {
			rows.Close()
			return nil, err
		}
		list = append(list, sub)
	}
	rows.Close()
	for _, sub := range list {
		sub.Usage = s.usage(ctx, sub)
	}
	return list, nil
}

// CancelSubscription 管理员终止订阅（已签发证书不受影响）。
func (s *Service) CancelSubscription(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE promo_subscriptions SET status = 'cancelled', updated_at = ? WHERE uuid = ?`, time.Now(), id)
	return err
}

// usedCount 统计订阅中某模板已占用的额度：未被驳回的申请；允许释放时不计已吊销证书。
func (s *Service) usedCount(ctx context.Context, sub *Subscription, tmplUUID string) int {
	release := 0
	if sub.Plan.RevokeReleaseQuota {
		release = 1
	}
	var n int
	s.db.QueryRowContext(ctx, //nolint:errcheck
		`SELECT COUNT(*) FROM cert_applications a
		 JOIN cert_orders o ON o.uuid = a.order_uuid
		 LEFT JOIN certificates c ON c.uuid = a.cert_uuid
		 WHERE o.subscription_uuid = ? AND o.cert_apply_tmpl_uuid = ? AND a.status <> 'rejected'
		   AND (? = 0 OR c.revocation_status IS NULL OR c.revocation_status <> 'revoked')`,
		sub.UUID, tmplUUID, release).Scan(&n)
	return n
}

// ListSubscriptionUsage 返回订阅各额度项的使用情况。
func (s *Service) ListSubscriptionUsage(ctx context.Context, sub *Subscription) []QuotaUsage {
	return s.usage(ctx, sub)
}

func (s *Service) usage(ctx context.Context, sub *Subscription) []QuotaUsage {
	out := []QuotaUsage{}
	for _, it := range sub.Plan.Items {
		var name string
		s.db.QueryRowContext(ctx, `SELECT name FROM cert_apply_templates WHERE uuid = ?`, it.CertApplyTmplUUID).Scan(&name) //nolint:errcheck
		used := s.usedCount(ctx, sub, it.CertApplyTmplUUID)
		rem := it.Quota - used
		if rem < 0 {
			rem = 0
		}
		out = append(out, QuotaUsage{PlanItem: it, TemplateName: name, Used: used, Remaining: rem})
	}
	return out
}

// ReserveQuota 校验订阅额度并返回该额度项（调用方需在锁内创建订单与申请）。
// 返回的 unlock 必须在申请落库后调用，以保证额度判断与占用的原子性。
func (s *Service) ReserveQuota(ctx context.Context, subUUID, userUUID, tmplUUID string) (*PlanItem, func(), error) {
	s.mu.Lock()
	unlock := s.mu.Unlock
	sub, err := s.GetSubscription(ctx, subUUID)
	if err != nil || sub.UserUUID != userUUID {
		unlock()
		return nil, nil, fmt.Errorf("订阅不存在")
	}
	if !sub.Active(time.Now()) {
		unlock()
		return nil, nil, fmt.Errorf("订阅已过期或已终止")
	}
	for _, it := range sub.Plan.Items {
		if it.CertApplyTmplUUID != tmplUUID {
			continue
		}
		if s.usedCount(ctx, sub, tmplUUID) >= it.Quota {
			unlock()
			return nil, nil, fmt.Errorf("该证书类型的订阅额度已用完")
		}
		item := it
		return &item, unlock, nil
	}
	unlock()
	return nil, nil, fmt.Errorf("订阅不包含该证书类型")
}

// PlanOfOrder 返回订单所属订阅的套餐快照（非订阅订单返回 nil）。
func (s *Service) PlanOfOrder(ctx context.Context, subscriptionUUID string) *Plan {
	if subscriptionUUID == "" {
		return nil
	}
	sub, err := s.GetSubscription(ctx, subscriptionUUID)
	if err != nil {
		return nil
	}
	return &sub.Plan
}

// ActivatePaidPlanOrders 为已支付的套餐订单发放订阅并将订单置为已完成（幂等，可重复调用）。
func (s *Service) ActivatePaidPlanOrders(ctx context.Context, userUUID string) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT order_no, spec_json FROM cert_orders WHERE user_uuid = ? AND status = 'paid' AND product_code LIKE 'plan:%'`, userUUID)
	if err != nil {
		return
	}
	type row struct{ no, spec string }
	var list []row
	for rows.Next() {
		var x row
		if rows.Scan(&x.no, &x.spec) == nil {
			list = append(list, x)
		}
	}
	rows.Close()
	for _, x := range list {
		var spec struct {
			PlanUUID string `json:"plan_uuid"`
		}
		if json.Unmarshal([]byte(x.spec), &spec) != nil || spec.PlanUUID == "" {
			continue
		}
		if _, err := s.Grant(ctx, userUUID, spec.PlanUUID, "order", x.no); err != nil {
			continue
		}
		s.db.ExecContext(ctx, //nolint:errcheck
			`UPDATE cert_orders SET status = 'completed', updated_at = ? WHERE order_no = ? AND status = 'paid'`, time.Now(), x.no)
	}
}

// ======================= 兑换码 =======================

// RedeemCode 是兑换码。
type RedeemCode struct {
	UUID         string     `json:"uuid"`
	Code         string     `json:"code"`
	BatchName    string     `json:"batch_name"`
	GrantType    string     `json:"grant_type"` // plan / balance
	PlanUUID     string     `json:"plan_uuid,omitempty"`
	BalanceCents int64      `json:"balance_cents,omitempty"`
	MaxUses      int        `json:"max_uses"`
	UsedCount    int        `json:"used_count"`
	ValidUntil   *time.Time `json:"valid_until,omitempty"`
	Enabled      bool       `json:"enabled"`
	CreatedAt    time.Time  `json:"created_at"`
}

const redeemColumns = `uuid, code, batch_name, grant_type, plan_uuid, balance_cents, max_uses, used_count, valid_until, enabled, created_at`

func scanRedeem(scan func(dest ...interface{}) error) (*RedeemCode, error) {
	c := &RedeemCode{}
	var until sql.NullTime
	var enabled int
	if err := scan(&c.UUID, &c.Code, &c.BatchName, &c.GrantType, &c.PlanUUID, &c.BalanceCents, &c.MaxUses,
		&c.UsedCount, &until, &enabled, &c.CreatedAt); err != nil {
		return nil, err
	}
	if until.Valid {
		c.ValidUntil = &until.Time
	}
	c.Enabled = enabled == 1
	return c, nil
}

// ListRedeemCodes 查询兑换码（batch 为空表示全部）。
func (s *Service) ListRedeemCodes(ctx context.Context, batch string) ([]*RedeemCode, error) {
	q := `SELECT ` + redeemColumns + ` FROM promo_redeem_codes`
	args := []interface{}{}
	if batch != "" {
		q += ` WHERE batch_name = ?`
		args = append(args, batch)
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY created_at DESC LIMIT 2000`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []*RedeemCode{}
	for rows.Next() {
		c, err := scanRedeem(rows.Scan)
		if err != nil {
			return nil, err
		}
		list = append(list, c)
	}
	return list, rows.Err()
}

// GenerateRedeemCodes 批量生成兑换码。
func (s *Service) GenerateRedeemCodes(ctx context.Context, tmpl RedeemCode, count int) ([]*RedeemCode, error) {
	if count <= 0 || count > 1000 {
		return nil, fmt.Errorf("单次生成数量需在 1-1000 之间")
	}
	switch tmpl.GrantType {
	case "plan":
		if _, err := s.GetPlan(ctx, tmpl.PlanUUID); err != nil {
			return nil, err
		}
		tmpl.BalanceCents = 0
	case "balance":
		if tmpl.BalanceCents <= 0 {
			return nil, fmt.Errorf("兑换金额需大于 0")
		}
		tmpl.PlanUUID = ""
	default:
		return nil, fmt.Errorf("兑换类型只能为 plan 或 balance")
	}
	if tmpl.MaxUses <= 0 {
		tmpl.MaxUses = 1
	}
	out := []*RedeemCode{}
	now := time.Now()
	for i := 0; i < count; i++ {
		c := tmpl
		c.UUID = uuid.New().String()
		c.Code = randomCode(16)
		c.Enabled, c.CreatedAt = true, now
		if _, err := s.db.ExecContext(ctx, `INSERT INTO promo_redeem_codes (`+redeemColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, 1, ?)`,
			c.UUID, c.Code, c.BatchName, c.GrantType, c.PlanUUID, c.BalanceCents, c.MaxUses, c.ValidUntil, now); err != nil {
			return out, fmt.Errorf("生成兑换码失败: %w", err)
		}
		out = append(out, &c)
	}
	return out, nil
}

// SetRedeemEnabled 启用/停用兑换码。
func (s *Service) SetRedeemEnabled(ctx context.Context, id string, enabled bool) error {
	_, err := s.db.ExecContext(ctx, `UPDATE promo_redeem_codes SET enabled = ? WHERE uuid = ?`, storage.BoolToInt(enabled), id)
	return err
}

// RedeemResult 是兑换结果。
type RedeemResult struct {
	GrantType    string        `json:"grant_type"`
	Subscription *Subscription `json:"subscription,omitempty"`
	BalanceCents int64         `json:"balance_cents,omitempty"`
}

// Redeem 用户兑换：每个兑换码每人限用一次，总次数由 max_uses 控制。
func (s *Service) Redeem(ctx context.Context, code, userUUID string) (*RedeemResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, err := scanRedeem(s.db.QueryRowContext(ctx,
		`SELECT `+redeemColumns+` FROM promo_redeem_codes WHERE code = ?`, normCode(code)).Scan)
	if err != nil {
		return nil, fmt.Errorf("兑换码无效")
	}
	if !c.Enabled {
		return nil, fmt.Errorf("兑换码已停用")
	}
	if c.ValidUntil != nil && time.Now().After(*c.ValidUntil) {
		return nil, fmt.Errorf("兑换码已过期")
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE promo_redeem_codes SET used_count = used_count + 1 WHERE uuid = ? AND used_count < max_uses`, c.UUID)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, fmt.Errorf("兑换码已被使用")
	}
	usageUUID := uuid.New().String()
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO promo_redeem_usages (uuid, code_uuid, user_uuid, created_at) VALUES (?, ?, ?, ?)`,
		usageUUID, c.UUID, userUUID, time.Now()); err != nil {
		s.db.ExecContext(ctx, `UPDATE promo_redeem_codes SET used_count = used_count - 1 WHERE uuid = ?`, c.UUID) //nolint:errcheck
		return nil, fmt.Errorf("您已兑换过该兑换码")
	}

	out := &RedeemResult{GrantType: c.GrantType}
	switch c.GrantType {
	case "plan":
		sub, err := s.Grant(ctx, userUUID, c.PlanUUID, "redeem", usageUUID)
		if err != nil {
			return nil, err
		}
		out.Subscription = sub
	case "balance":
		now := time.Now()
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO user_balances (user_uuid, available_cents, frozen_cents, total_recharge, total_consume)
			 VALUES (?, ?, 0, ?, 0)
			 ON CONFLICT(user_uuid) DO UPDATE SET available_cents = available_cents + ?, total_recharge = total_recharge + ?`,
			userUUID, c.BalanceCents, c.BalanceCents, c.BalanceCents, c.BalanceCents); err != nil {
			return nil, fmt.Errorf("入账失败: %w", err)
		}
		s.db.ExecContext(ctx, //nolint:errcheck
			`INSERT INTO consume_records (uuid, user_uuid, order_no, consume_type, amount_cents, remark, created_at)
			 VALUES (?, ?, ?, 'redeem', ?, ?, ?)`,
			uuid.New().String(), userUUID, c.Code, -c.BalanceCents, "兑换码充值", now)
		out.BalanceCents = c.BalanceCents
	}
	return out, nil
}

// randomCode 生成不含易混淆字符的随机码。
func randomCode(n int) string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, n)
	for i := range b {
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		b[i] = alphabet[idx.Int64()]
	}
	return string(b)
}
