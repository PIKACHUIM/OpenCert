// Package portal 提供门户（官网/商城）的商品目录、报价与下单编排。
//
// 设计要点：
//   - 商品（portal_products）负责"卖什么"，规格（portal_product_skus）负责"按什么价格卖"，
//     证书开通参数仍由 cert_apply_templates / issuance_templates 承担。
//   - 价格始终由服务端根据 SKU 计算，客户端传入的金额一律忽略。
package portal

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/globaltrusts/server-card/internal/promo"
	"github.com/globaltrusts/server-card/internal/storage"
	"github.com/globaltrusts/server-card/internal/workflow"
)

// Service 是门户服务。
type Service struct {
	repo        *storage.PortalRepo
	workflowSvc *workflow.Service
	promoSvc    *promo.Service // 优惠码与订阅（可选）
}

// NewService 创建门户服务。
func NewService(repo *storage.PortalRepo, workflowSvc *workflow.Service) *Service {
	return &Service{repo: repo, workflowSvc: workflowSvc}
}

// SetPromo 注入优惠与订阅服务。
func (s *Service) SetPromo(p *promo.Service) { s.promoSvc = p }

// ---- 输出模型 ----

// ProductView 是商品及其规格的聚合视图。
type ProductView struct {
	Product *storage.PortalProduct      `json:"product"`
	SKUs    []*storage.PortalProductSKU `json:"skus"`
}

// Quote 是服务端权威报价。
type Quote struct {
	ProductCode       string    `json:"product_code"`
	ProductName       string    `json:"product_name"`
	SKUCode           string    `json:"sku_code"`
	SKUName           string    `json:"sku_name"`
	Quantity          int       `json:"quantity"`
	UnitPriceCents    int64     `json:"unit_price_cents"`
	TotalCents        int64     `json:"total_cents"`
	Currency          string    `json:"currency"`
	DurationMonths    int       `json:"duration_months"`
	ValidDays         int       `json:"valid_days"` // 证书有效期（天，0=按颁发模板默认值）
	DeliveryMode      string    `json:"delivery_mode"`
	KeyTypes          []string  `json:"key_types"`
	SANIncluded       int       `json:"san_included"`
	CertApplyTmplUUID string    `json:"cert_apply_tmpl_uuid"`
	SANPolicy         string    `json:"san_policy"`
	Stock             int       `json:"stock"`
	InStock           bool      `json:"in_stock"`
	DiscountCents     int64     `json:"discount_cents"`
	PayableCents      int64     `json:"payable_cents"`
	CouponError       string    `json:"coupon_error,omitempty"`
	QuotedAt          time.Time `json:"quoted_at"`
}

// ---- 目录查询 ----

// ListProducts 查询商品列表（publicOnly=true 时仅返回前台可见商品），并附带可用规格。
func (s *Service) ListProducts(ctx context.Context, publicOnly bool, category string) ([]*ProductView, error) {
	products, err := s.repo.ListProducts(ctx, publicOnly, category)
	if err != nil {
		return nil, err
	}
	if len(products) == 0 {
		return []*ProductView{}, nil
	}

	ids := make([]string, 0, len(products))
	for _, p := range products {
		ids = append(ids, p.UUID)
	}
	skuMap, err := s.repo.ListSKUsByProducts(ctx, ids, publicOnly)
	if err != nil {
		return nil, err
	}

	views := make([]*ProductView, 0, len(products))
	for _, p := range products {
		skus := skuMap[p.UUID]
		if skus == nil {
			skus = []*storage.PortalProductSKU{}
		}
		views = append(views, &ProductView{Product: p, SKUs: skus})
	}
	return views, nil
}

// GetProductDetail 按商品编码查询详情。
// publicOnly=true 时，不可见或未启用的商品按"不存在"处理，避免未发布内容被探测。
func (s *Service) GetProductDetail(ctx context.Context, code string, publicOnly bool) (*ProductView, error) {
	p, err := s.repo.GetProductByCode(ctx, code)
	if err != nil {
		return nil, err
	}
	if publicOnly && (!p.Visible || !p.Enabled) {
		return nil, fmt.Errorf("商品不存在: %s", code)
	}

	skus, err := s.repo.ListSKUsByProduct(ctx, p.UUID, publicOnly)
	if err != nil {
		return nil, err
	}
	return &ProductView{Product: p, SKUs: skus}, nil
}

// ---- 报价 ----

// Quote 根据规格编码与数量生成服务端权威报价。
func (s *Service) Quote(ctx context.Context, skuCode string, quantity int) (*Quote, error) {
	sku, err := s.repo.GetSKUByCode(ctx, skuCode)
	if err != nil {
		return nil, err
	}
	if !sku.Enabled {
		return nil, fmt.Errorf("该规格已下架")
	}

	product, err := s.repo.GetProductByUUID(ctx, sku.ProductUUID)
	if err != nil {
		return nil, err
	}
	if !product.Visible || !product.Enabled {
		return nil, fmt.Errorf("该商品暂不可购买")
	}

	if quantity <= 0 {
		quantity = sku.MinQty
	}
	if quantity < sku.MinQty {
		return nil, fmt.Errorf("最少购买 %d 份", sku.MinQty)
	}
	if sku.MaxQty > 0 && quantity > sku.MaxQty {
		return nil, fmt.Errorf("单次最多购买 %d 份", sku.MaxQty)
	}

	keyTypes := []string{}
	if sku.KeyTypes != "" {
		if err := json.Unmarshal([]byte(sku.KeyTypes), &keyTypes); err != nil {
			keyTypes = []string{}
		}
	}

	return &Quote{
		ProductCode:       product.Code,
		ProductName:       product.Name,
		SKUCode:           sku.Code,
		SKUName:           sku.Name,
		Quantity:          quantity,
		UnitPriceCents:    sku.PriceCents,
		TotalCents:        sku.PriceCents * int64(quantity),
		Currency:          sku.Currency,
		DurationMonths:    sku.DurationMonths,
		ValidDays:         sku.ValidDays,
		DeliveryMode:      string(sku.DeliveryMode),
		KeyTypes:          keyTypes,
		SANIncluded:       sku.SANIncluded,
		CertApplyTmplUUID: sku.CertApplyTmplUUID,
		SANPolicy:         sku.SANPolicy,
		Stock:             sku.Stock,
		InStock:           sku.InStock(quantity),
		PayableCents:      sku.PriceCents * int64(quantity),
		QuotedAt:          time.Now(),
	}, nil
}

// QuoteWithCoupon 报价并预览优惠码（优惠码无效时返回原价与原因，不报错）。
func (s *Service) QuoteWithCoupon(ctx context.Context, skuCode string, quantity int, coupon, userUUID string) (*Quote, error) {
	q, err := s.Quote(ctx, skuCode, quantity)
	if err != nil || strings.TrimSpace(coupon) == "" || s.promoSvc == nil {
		return q, err
	}
	d, _, cErr := s.promoSvc.PreviewCoupon(ctx, coupon, userUUID, q.ProductCode, q.TotalCents)
	if cErr != nil {
		q.CouponError = cErr.Error()
		return q, nil
	}
	q.DiscountCents, q.PayableCents = d, q.TotalCents-d
	return q, nil
}

// ---- 下单 ----

// CreateOrderInput 是门户下单入参。金额、单价与模板关联均由服务端解析。
type CreateOrderInput struct {
	SKUCode        string `json:"sku_code"`
	Quantity       int    `json:"quantity"`
	ApplicantEmail string `json:"applicant_email"`
	CouponCode     string `json:"coupon_code"`
}

// CreateOrder 创建门户证书订单草稿。
//
// 服务端根据 SKU 重新计算金额并解析关联的证书申请模板；客户端传入的价格不会被采纳。
// 订单初始状态为待支付，具体支付与履约在后续阶段接入。
func (s *Service) CreateOrder(ctx context.Context, userUUID string, in CreateOrderInput) (*storage.CertOrder, error) {
	if userUUID == "" {
		return nil, fmt.Errorf("下单前请先登录")
	}

	quote, err := s.Quote(ctx, in.SKUCode, in.Quantity)
	if err != nil {
		return nil, err
	}
	if !quote.InStock {
		return nil, fmt.Errorf("库存不足")
	}

	product, err := s.repo.GetProductByCode(ctx, quote.ProductCode)
	if err != nil {
		return nil, err
	}

	// 订单类型：云智能卡商品凭订单开卡；其余商品凭订单申请证书，必须关联证书申请模板
	kind := storage.OrderKindCert
	if product.Category == storage.ProductCategoryCloudCard {
		kind = storage.OrderKindCard
	}
	if kind == storage.OrderKindCert && quote.CertApplyTmplUUID == "" {
		return nil, fmt.Errorf("该规格尚未配置证书申请模板，暂时无法购买")
	}

	email := strings.TrimSpace(in.ApplicantEmail)
	if email == "" || !strings.Contains(email, "@") {
		return nil, fmt.Errorf("请提供有效的联系邮箱")
	}

	spec, err := json.Marshal(map[string]interface{}{
		"kind":             kind,
		"category":         product.Category,
		"product_code":     quote.ProductCode,
		"product_name":     quote.ProductName,
		"sku_code":         quote.SKUCode,
		"sku_name":         quote.SKUName,
		"quantity":         quote.Quantity,
		"unit_price_cents": quote.UnitPriceCents,
		"currency":         quote.Currency,
		"duration_months":  quote.DurationMonths,
		"valid_days":       quote.ValidDays, // 签发时按此有效期收窄（颁发模板范围内的快照）
		"delivery_mode":    quote.DeliveryMode,
		"key_types":        quote.KeyTypes,
		"san_included":     quote.SANIncluded,
		"san_policy":       json.RawMessage(normalizeObject(quote.SANPolicy)),
	})
	if err != nil {
		return nil, fmt.Errorf("生成规格快照失败: %w", err)
	}

	// 预占库存（条件扣减，不限库存的规格不扣）；下单失败或取消时归还
	if ok, err := s.repo.ReserveStock(ctx, quote.SKUCode, quote.Quantity); err != nil {
		return nil, err
	} else if !ok {
		return nil, fmt.Errorf("库存不足")
	}

	order := &storage.CertOrder{
		OrderNo:           storage.GenerateOrderNo(),
		UserUUID:          userUUID,
		ProductCode:       quote.ProductCode,
		SKUCode:           quote.SKUCode,
		SpecJSON:          string(spec),
		ApplicantEmail:    email,
		AmountCents:       quote.TotalCents,
		CertApplyTmplUUID: quote.CertApplyTmplUUID,
	}

	// 优惠码：条件占用次数，订单创建失败时归还
	if code := strings.TrimSpace(in.CouponCode); code != "" {
		if s.promoSvc == nil {
			s.repo.ReleaseStock(ctx, quote.SKUCode, quote.Quantity) //nolint:errcheck
			return nil, fmt.Errorf("优惠码功能未启用")
		}
		d, err := s.promoSvc.ConsumeCoupon(ctx, code, userUUID, order.OrderNo, quote.ProductCode, quote.TotalCents)
		if err != nil {
			s.repo.ReleaseStock(ctx, quote.SKUCode, quote.Quantity) //nolint:errcheck
			return nil, err
		}
		order.CouponCode = strings.ToUpper(code)
		order.DiscountCents = d
		order.AmountCents = quote.TotalCents - d
	}

	// 由工作流落库；CreateOrder 会再次按模板校验价格，避免客户端影响金额。
	if err := s.workflowSvc.CreateOrder(ctx, order); err != nil {
		s.repo.ReleaseStock(ctx, quote.SKUCode, quote.Quantity) //nolint:errcheck
		if s.promoSvc != nil {
			s.promoSvc.ReleaseCoupon(ctx, order.OrderNo)
		}
		return nil, err
	}
	return order, nil
}

func normalizeObject(v string) string {
	if strings.TrimSpace(v) == "" {
		return "{}"
	}
	return v
}

// CreatePlanOrder 购买订阅套餐：生成套餐订单，支付后自动发放订阅。
func (s *Service) CreatePlanOrder(ctx context.Context, userUUID, planCode, email, coupon string) (*storage.CertOrder, error) {
	if s.promoSvc == nil {
		return nil, fmt.Errorf("订阅功能未启用")
	}
	p, err := s.promoSvc.GetPlan(ctx, planCode)
	if err != nil {
		return nil, err
	}
	if !p.Visible || !p.Enabled {
		return nil, fmt.Errorf("该订阅套餐暂不可购买")
	}
	email = strings.TrimSpace(email)
	if !strings.Contains(email, "@") {
		return nil, fmt.Errorf("请提供有效的联系邮箱")
	}
	spec, _ := json.Marshal(map[string]interface{}{
		"kind": "plan", "plan_uuid": p.UUID, "product_name": "订阅：" + p.Name, "sku_name": p.Name,
		"quantity": 1, "unit_price_cents": p.PriceCents, "period_days": p.PeriodDays,
	})
	order := &storage.CertOrder{
		OrderNo: storage.GenerateOrderNo(), UserUUID: userUUID, ProductCode: "plan:" + p.Code,
		SKUCode: "plan:" + p.Code, SpecJSON: string(spec), ApplicantEmail: email, AmountCents: p.PriceCents,
	}
	if code := strings.TrimSpace(coupon); code != "" {
		d, err := s.promoSvc.ConsumeCoupon(ctx, code, userUUID, order.OrderNo, order.ProductCode, p.PriceCents)
		if err != nil {
			return nil, err
		}
		order.CouponCode, order.DiscountCents, order.AmountCents = strings.ToUpper(code), d, p.PriceCents-d
	}
	if err := s.workflowSvc.CreateOrder(ctx, order); err != nil {
		s.promoSvc.ReleaseCoupon(ctx, order.OrderNo)
		return nil, err
	}
	return order, nil
}

// CloseStaleOrders 关闭超时未支付的证书/智能卡/套餐订单，归还库存与优惠码。
func (s *Service) CloseStaleOrders(ctx context.Context) (int, error) {
	hours := 24
	if settings, err := s.GetSiteSettings(ctx); err == nil {
		if n, err := strconv.Atoi(settings["order_expire_hours"]); err == nil && n > 0 {
			hours = n
		}
	}
	nos, err := s.workflowSvc.ListStalePendingOrders(ctx, time.Now().Add(-time.Duration(hours)*time.Hour))
	if err != nil {
		return 0, err
	}
	closed := 0
	for _, no := range nos {
		if s.CancelOrder(ctx, no, "") == nil {
			closed++
		}
	}
	return closed, nil
}

// CancelOrder 取消待支付订单并归还库存。operatorUUID 为空表示管理员操作。
func (s *Service) CancelOrder(ctx context.Context, orderNo, userUUID string) error {
	order, err := s.workflowSvc.GetOrderByNo(ctx, orderNo)
	if err != nil {
		return err
	}
	if err := s.workflowSvc.CancelOrder(ctx, order.UUID, userUUID); err != nil {
		return err
	}
	if order.SKUCode != "" && !strings.HasPrefix(order.SKUCode, "plan:") {
		s.repo.ReleaseStock(ctx, order.SKUCode, workflow.SpecQuantity(order.SpecJSON)) //nolint:errcheck
	}
	if s.promoSvc != nil {
		s.promoSvc.ReleaseCoupon(ctx, order.OrderNo)
	}
	return nil
}

// BusinessModes 是证书与智能卡的申请模式。
type BusinessModes struct {
	CertApplyMode string `json:"cert_apply_mode"` // self / sales
	CardApplyMode string `json:"card_apply_mode"` // self / sales
	CardSelfLimit int    `json:"card_self_limit"` // 自助模式下每个用户可开卡数量上限
}

// GetBusinessModes 读取业务模式配置（缺省为销售模式，最安全）。
func (s *Service) GetBusinessModes(ctx context.Context) BusinessModes {
	m := BusinessModes{CertApplyMode: storage.ModeSales, CardApplyMode: storage.ModeSales, CardSelfLimit: 1}
	settings, err := s.GetSiteSettings(ctx)
	if err != nil {
		return m
	}
	if v := settings["cert_apply_mode"]; v == storage.ModeSelfService || v == storage.ModeSales {
		m.CertApplyMode = v
	}
	if v := settings["card_apply_mode"]; v == storage.ModeSelfService || v == storage.ModeSales {
		m.CardApplyMode = v
	}
	if n, err := strconv.Atoi(settings["card_self_limit"]); err == nil && n >= 0 {
		m.CardSelfLimit = n
	}
	return m
}

// ---- 站点配置 ----

// DefaultSiteSettings 返回站点配置默认值；数据库中已有的键会覆盖默认值。
func DefaultSiteSettings() map[string]string {
	return map[string]string{
		"site_name":        "OpenCert",
		"site_tagline":     "云端证书与智能卡服务平台",
		"site_description": "统一申请、签发与管理数字证书，并通过云端智能卡在设备上安全使用。",
		"contact_email":    "",
		"contact_phone":    "",
		"icp_record":       "",
		"footer_note":      "",
		"help_url":         "",
		"client_download":  "",
		"driver_download":  "",
		"terms_url":        "",
		"privacy_url":      "",
		// 业务模式：sales=必须购买订单；self=允许自助申请（缺省为销售模式）
		"cert_apply_mode": storage.ModeSales,
		"card_apply_mode": storage.ModeSales,
		"card_self_limit": "1",
		// 待支付订单超时关闭（小时），关闭时归还库存与优惠码
		"order_expire_hours": "24",
		// 自助/订阅申请（无商品规格）时单张证书的 SAN 限制
		"self_san_policy": `{"max_dns":5,"max_email":1,"max_ip":0,"allow_wildcard":false,"ip_versions":["v4","v6"]}`,
	}
}

// GetSiteSettings 返回站点配置（默认值 + 数据库覆盖值）。
func (s *Service) GetSiteSettings(ctx context.Context) (map[string]string, error) {
	stored, err := s.repo.GetSiteSettings(ctx)
	if err != nil {
		return nil, err
	}
	merged := DefaultSiteSettings()
	for k, v := range stored {
		if v != "" {
			merged[k] = v
		}
	}
	return merged, nil
}

// allowedSettingKeys 限制可写入的站点配置键，避免任意键污染配置表。
var allowedSettingKeys = map[string]bool{
	"site_name": true, "site_tagline": true, "site_description": true,
	"contact_email": true, "contact_phone": true, "icp_record": true,
	"footer_note": true, "help_url": true, "client_download": true,
	"driver_download": true, "terms_url": true, "privacy_url": true,
	"cert_apply_mode": true, "card_apply_mode": true, "card_self_limit": true,
	"order_expire_hours": true, "self_san_policy": true,
}

// UpdateSiteSettings 更新站点配置（仅允许白名单键）。
func (s *Service) UpdateSiteSettings(ctx context.Context, settings map[string]string) error {
	clean := make(map[string]string, len(settings))
	for k, v := range settings {
		if !allowedSettingKeys[k] {
			return fmt.Errorf("不支持的配置项: %s", k)
		}
		if len(v) > 2048 {
			return fmt.Errorf("配置项 %s 内容过长", k)
		}
		switch k {
		case "cert_apply_mode", "card_apply_mode":
			if v != storage.ModeSelfService && v != storage.ModeSales {
				return fmt.Errorf("配置项 %s 只能为 self 或 sales", k)
			}
		case "card_self_limit":
			if n, err := strconv.Atoi(v); err != nil || n < 0 || n > 1000 {
				return fmt.Errorf("自助开卡上限需为 0-1000 的整数")
			}
		case "order_expire_hours":
			if n, err := strconv.Atoi(v); err != nil || n < 1 || n > 720 {
				return fmt.Errorf("订单超时时间需为 1-720 小时")
			}
		case "self_san_policy":
			var p map[string]interface{}
			if err := json.Unmarshal([]byte(v), &p); err != nil {
				return fmt.Errorf("自助申请 SAN 限制需为 JSON 对象")
			}
		}
		clean[k] = v
	}
	return s.repo.SetSiteSettings(ctx, clean)
}

// ---- 商品与规格管理 ----

// ListAllProducts 返回全部商品（含未发布），供运营后台使用。
func (s *Service) ListAllProducts(ctx context.Context, category string) ([]*ProductView, error) {
	return s.ListProducts(ctx, false, category)
}

// CreateProduct 创建商品。
func (s *Service) CreateProduct(ctx context.Context, p *storage.PortalProduct) error {
	if err := validateProduct(p); err != nil {
		return err
	}
	exists, err := s.repo.CodeExists(ctx, p.Code, "")
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("商品编码已存在: %s", p.Code)
	}
	return s.repo.CreateProduct(ctx, p)
}

// UpdateProduct 更新商品。
func (s *Service) UpdateProduct(ctx context.Context, p *storage.PortalProduct) error {
	if err := validateProduct(p); err != nil {
		return err
	}
	if p.UUID == "" {
		return fmt.Errorf("缺少商品 UUID")
	}
	exists, err := s.repo.CodeExists(ctx, p.Code, p.UUID)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("商品编码已存在: %s", p.Code)
	}
	return s.repo.UpdateProduct(ctx, p)
}

// DeleteProduct 删除商品。
func (s *Service) DeleteProduct(ctx context.Context, productUUID string) error {
	return s.repo.DeleteProduct(ctx, productUUID)
}

// ListSKUs 查询指定商品的规格（含未启用）。
func (s *Service) ListSKUs(ctx context.Context, productUUID string) ([]*storage.PortalProductSKU, error) {
	return s.repo.ListSKUsByProduct(ctx, productUUID, false)
}

// CreateSKU 创建规格。
func (s *Service) CreateSKU(ctx context.Context, sku *storage.PortalProductSKU) error {
	if err := validateSKU(sku); err != nil {
		return err
	}
	if _, err := s.repo.GetProductByUUID(ctx, sku.ProductUUID); err != nil {
		return err
	}
	return s.repo.CreateSKU(ctx, sku)
}

// UpdateSKU 更新规格。
func (s *Service) UpdateSKU(ctx context.Context, sku *storage.PortalProductSKU) error {
	if err := validateSKU(sku); err != nil {
		return err
	}
	if sku.UUID == "" {
		return fmt.Errorf("缺少规格 UUID")
	}
	return s.repo.UpdateSKU(ctx, sku)
}

// DeleteSKU 删除规格。
func (s *Service) DeleteSKU(ctx context.Context, skuUUID string) error {
	return s.repo.DeleteSKU(ctx, skuUUID)
}

// ---- 校验 ----

func validateProduct(p *storage.PortalProduct) error {
	if strings.TrimSpace(p.Code) == "" {
		return fmt.Errorf("商品编码不能为空")
	}
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("商品名称不能为空")
	}
	switch p.Category {
	case storage.ProductCategorySSL, storage.ProductCategoryCodeSign,
		storage.ProductCategoryEmail, storage.ProductCategoryDocSign,
		storage.ProductCategoryCloudCard:
	default:
		return fmt.Errorf("不支持的商品分类: %s", p.Category)
	}
	for _, raw := range []string{p.Features, p.Highlights} {
		if raw == "" {
			continue
		}
		var arr []string
		if err := json.Unmarshal([]byte(raw), &arr); err != nil {
			return fmt.Errorf("商品权益/高亮项必须是 JSON 字符串数组")
		}
	}
	return nil
}

func validateSKU(s *storage.PortalProductSKU) error {
	if strings.TrimSpace(s.Code) == "" {
		return fmt.Errorf("规格编码不能为空")
	}
	if strings.TrimSpace(s.Name) == "" {
		return fmt.Errorf("规格名称不能为空")
	}
	if s.PriceCents < 0 {
		return fmt.Errorf("价格不能为负数")
	}
	if s.Currency == "" {
		s.Currency = "CNY"
	}
	if s.MinQty <= 0 {
		s.MinQty = 1
	}
	if s.MaxQty < s.MinQty {
		s.MaxQty = s.MinQty
	}
	if s.Stock < -1 {
		s.Stock = -1
	}
	switch s.DeliveryMode {
	case storage.DeliveryDownload, storage.DeliveryCloudCard, storage.DeliveryCSR:
	case "":
		s.DeliveryMode = storage.DeliveryCloudCard
	default:
		return fmt.Errorf("不支持的交付方式: %s", s.DeliveryMode)
	}
	if s.KeyTypes == "" {
		s.KeyTypes = `["ec256","rsa2048"]`
	} else {
		var arr []string
		if err := json.Unmarshal([]byte(s.KeyTypes), &arr); err != nil {
			return fmt.Errorf("密钥算法必须是 JSON 字符串数组")
		}
	}
	return nil
}
