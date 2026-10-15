// Package test - 门户（官网/商城）服务层测试。
//
// 覆盖商品/规格校验、前台可见性隔离与服务端权威报价等核心规则。
package test

import (
	"context"
	"testing"

	"github.com/globaltrusts/server-card/internal/portal"
	"github.com/globaltrusts/server-card/internal/storage"
	"github.com/globaltrusts/server-card/internal/workflow"
)

// newPortalService 构造一个仅依赖数据库的门户服务。
func newPortalService(t *testing.T) (*portal.Service, context.Context) {
	t.Helper()
	db := setupServerDB(t)
	return portal.NewService(storage.NewPortalRepo(db), workflow.NewService(db, nil, nil)), context.Background()
}

// seedProduct 创建商品并按需创建规格，返回商品 UUID。
func seedProduct(t *testing.T, svc *portal.Service, ctx context.Context, code string, visible bool) *storage.PortalProduct {
	t.Helper()
	p := &storage.PortalProduct{
		Code:     code,
		Name:     "测试商品",
		Category: storage.ProductCategorySSL,
		Level:    "dv",
		Summary:  "用于测试",
		Features: `["权益一"]`,
		Visible:  visible,
		Enabled:  true,
	}
	if err := svc.CreateProduct(ctx, p); err != nil {
		t.Fatalf("创建商品失败: %v", err)
	}
	return p
}

func TestPortalProductValidation(t *testing.T) {
	t.Parallel()
	svc, ctx := newPortalService(t)

	// 非法分类应被拒绝
	err := svc.CreateProduct(ctx, &storage.PortalProduct{
		Code: "bad-cat", Name: "非法分类", Category: "unknown",
	})
	if err == nil {
		t.Error("非法商品分类应被拒绝")
	}

	// 权益字段必须是 JSON 字符串数组
	err = svc.CreateProduct(ctx, &storage.PortalProduct{
		Code: "bad-features", Name: "非法权益", Category: storage.ProductCategorySSL, Features: `{"a":1}`,
	})
	if err == nil {
		t.Error("非数组的权益字段应被拒绝")
	}

	// 编码重复应被拒绝
	seedProduct(t, svc, ctx, "dup-code", true)
	err = svc.CreateProduct(ctx, &storage.PortalProduct{
		Code: "dup-code", Name: "重复编码", Category: storage.ProductCategorySSL,
	})
	if err == nil {
		t.Error("重复的商品编码应被拒绝")
	}
}

func TestPortalSKUValidation(t *testing.T) {
	t.Parallel()
	svc, ctx := newPortalService(t)
	p := seedProduct(t, svc, ctx, "sku-validate", true)

	// 负数价格应被拒绝
	err := svc.CreateSKU(ctx, &storage.PortalProductSKU{
		ProductUUID: p.UUID, Code: "sku-neg", Name: "负价", PriceCents: -1,
	})
	if err == nil {
		t.Error("负数价格应被拒绝")
	}

	// 不存在的商品应被拒绝
	err = svc.CreateSKU(ctx, &storage.PortalProductSKU{
		ProductUUID: "not-exists", Code: "sku-orphan", Name: "孤儿规格", PriceCents: 100,
	})
	if err == nil {
		t.Error("挂载到不存在商品的规格应被拒绝")
	}

	// 合法规格应被规范化（默认币种/起购数量/交付方式）
	sku := &storage.PortalProductSKU{
		ProductUUID: p.UUID, Code: "sku-ok", Name: "标准版", PriceCents: 5000,
	}
	if err := svc.CreateSKU(ctx, sku); err != nil {
		t.Fatalf("创建规格失败: %v", err)
	}
	if sku.Currency != "CNY" {
		t.Errorf("币种应默认 CNY，实际 %q", sku.Currency)
	}
	if sku.MinQty != 1 {
		t.Errorf("起购数量应默认为 1，实际 %d", sku.MinQty)
	}
	if sku.MaxQty < sku.MinQty {
		t.Errorf("限购数量不应小于起购数量，实际 %d", sku.MaxQty)
	}
	if sku.DeliveryMode == "" {
		t.Error("交付方式应有默认值")
	}
}

func TestPortalStorefrontVisibility(t *testing.T) {
	t.Parallel()
	svc, ctx := newPortalService(t)

	seedProduct(t, svc, ctx, "hidden-product", false)
	seedProduct(t, svc, ctx, "public-product", true)

	public, err := svc.ListProducts(ctx, true, "")
	if err != nil {
		t.Fatalf("ListProducts 失败: %v", err)
	}
	if len(public) != 1 || public[0].Product.Code != "public-product" {
		t.Errorf("前台应只看到 1 个已发布商品，实际 %d", len(public))
	}

	all, err := svc.ListAllProducts(ctx, "")
	if err != nil {
		t.Fatalf("ListAllProducts 失败: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("运营端应看到全部 2 个商品，实际 %d", len(all))
	}

	// 未发布商品即使知道编码也不能从前台读取
	if _, err := svc.GetProductDetail(ctx, "hidden-product", true); err == nil {
		t.Error("未发布商品不应通过前台接口读取")
	}
	if _, err := svc.GetProductDetail(ctx, "hidden-product", false); err != nil {
		t.Errorf("运营端应能读取未发布商品: %v", err)
	}
}

func TestPortalQuote(t *testing.T) {
	t.Parallel()
	svc, ctx := newPortalService(t)
	p := seedProduct(t, svc, ctx, "quote-product", true)

	sku := &storage.PortalProductSKU{
		ProductUUID: p.UUID, Code: "quote-sku", Name: "1 年版",
		PriceCents: 6800, Stock: 3, MinQty: 1, MaxQty: 5, DurationMonths: 12,
		DeliveryMode: storage.DeliveryDownload, KeyTypes: `["ec256","rsa2048"]`, SANIncluded: 2,
		Enabled: true,
	}
	if err := svc.CreateSKU(ctx, sku); err != nil {
		t.Fatalf("创建规格失败: %v", err)
	}

	q, err := svc.Quote(ctx, "quote-sku", 3)
	if err != nil {
		t.Fatalf("Quote 失败: %v", err)
	}
	if q.TotalCents != 20400 {
		t.Errorf("总额 = %d，期望 20400", q.TotalCents)
	}
	if len(q.KeyTypes) != 2 {
		t.Errorf("密钥算法应解析为 2 项，实际 %d", len(q.KeyTypes))
	}
	if !q.InStock {
		t.Error("库存 3、购买 3 时应可售")
	}

	// 超过限购应被拒绝
	if _, err := svc.Quote(ctx, "quote-sku", 6); err == nil {
		t.Error("超过限购数量应被拒绝")
	}

	// 库存不足时报价成功但标记不可售（由调用方决定是否下单）
	q4, err := svc.Quote(ctx, "quote-sku", 4)
	if err != nil {
		t.Fatalf("Quote 失败: %v", err)
	}
	if q4.InStock {
		t.Error("库存 3 时购买 4 份应标记为无货")
	}

	// 未上架的规格不可报价
	hidden := &storage.PortalProductSKU{
		ProductUUID: p.UUID, Code: "quote-hidden", Name: "已停用",
		PriceCents: 100, Stock: -1, Enabled: false,
	}
	if err := svc.CreateSKU(ctx, hidden); err != nil {
		t.Fatalf("创建规格失败: %v", err)
	}
	if _, err := svc.Quote(ctx, "quote-hidden", 1); err == nil {
		t.Error("已停用规格不应可报价")
	}
}

func TestPortalOrderRequiresLoginAndTemplate(t *testing.T) {
	t.Parallel()
	svc, ctx := newPortalService(t)
	p := seedProduct(t, svc, ctx, "order-product", true)

	// 云卡交付但未关联开通模板 → 禁止下单
	sku := &storage.PortalProductSKU{
		ProductUUID: p.UUID, Code: "order-sku", Name: "云卡套餐",
		PriceCents: 9900, Stock: -1, MinQty: 1, MaxQty: 5,
		DeliveryMode: storage.DeliveryCloudCard,
		Enabled:      true,
	}
	if err := svc.CreateSKU(ctx, sku); err != nil {
		t.Fatalf("创建规格失败: %v", err)
	}

	_, err := svc.CreateOrder(ctx, "", portal.CreateOrderInput{SKUCode: "order-sku", Quantity: 1})
	if err == nil {
		t.Error("未登录（无用户）时应拒绝下单")
	}

	_, err = svc.CreateOrder(ctx, "user-1", portal.CreateOrderInput{
		SKUCode: "order-sku", Quantity: 1, ApplicantEmail: "a@b.com",
	})
	if err == nil {
		t.Error("云卡规格未关联开通模板时应拒绝下单")
	}
}
