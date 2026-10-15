// Package payment 提供支付系统的插件化接口和服务。
package payment

import (
	"context"
	"fmt"
	"sync"
)

// PaymentProvider 是支付插件接口，所有支付渠道需实现此接口。
type PaymentProvider interface {
	// Name 返回插件名称。
	Name() string

	// Type 返回插件类型标识（alipay/wechat/stripe/paypal）。
	Type() string

	// CreateOrder 创建支付订单，返回支付链接或二维码内容。
	CreateOrder(ctx context.Context, req CreateOrderReq) (*CreateOrderResp, error)

	// QueryOrder 查询订单状态。
	QueryOrder(ctx context.Context, orderNo string) (*QueryOrderResp, error)

	// VerifyCallback 验证支付回调签名，返回解析后的回调数据。
	VerifyCallback(ctx context.Context, body []byte, headers map[string]string) (*CallbackData, error)

	// Refund 执行退款操作。
	Refund(ctx context.Context, req RefundReq) (*RefundResp, error)
}

// CreateOrderReq 是创建订单请求。
type CreateOrderReq struct {
	OrderNo     string // 内部订单号
	AmountCents int64  // 金额（分）
	Subject     string // 订单标题
	NotifyURL   string // 回调通知地址
	ReturnURL   string // 前端跳转地址（可选）
}

// CreateOrderResp 是创建订单响应。
type CreateOrderResp struct {
	PayURL  string // 支付链接
	QRCode  string // 二维码内容（可选）
	TradeNo string // 第三方交易号（可选）
}

// QueryOrderResp 是查询订单响应。
type QueryOrderResp struct {
	OrderNo string
	TradeNo string
	Status  string // paid/pending/failed/closed
	PaidAt  string // 支付时间（ISO 8601）
}

// CallbackData 是回调解析后的数据。
type CallbackData struct {
	OrderNo     string
	TradeNo     string
	AmountCents int64
	Status      string // paid/failed
	RawData     []byte
}

// RefundReq 是退款请求。
type RefundReq struct {
	OrderNo     string
	RefundNo    string // 退款单号
	AmountCents int64  // 退款金额（分）
	Reason      string
}

// RefundResp 是退款响应。
type RefundResp struct {
	RefundNo string
	Status   string // success/pending/failed
}

// Registry 是支付插件注册中心。
type Registry struct {
	mu        sync.RWMutex
	providers map[string]PaymentProvider
}

// NewRegistry 创建插件注册中心。
func NewRegistry() *Registry {
	return &Registry{
		providers: make(map[string]PaymentProvider),
	}
}

// Register 注册支付插件。
func (r *Registry) Register(p PaymentProvider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers[p.Type()] = p
}

// Replace 以一组新的插件整体替换当前注册表（热更新时使用）。
// 整体替换保证被停用或删除的插件立即下线，而不是残留在内存中继续收款。
func (r *Registry) Replace(providers map[string]PaymentProvider) {
	next := make(map[string]PaymentProvider, len(providers))
	for k, v := range providers {
		next[k] = v
	}
	r.mu.Lock()
	r.providers = next
	r.mu.Unlock()
}

// ---- 插件工厂（扩展点）----

// ProviderFactory 根据解密后的 JSON 配置构造支付插件。
type ProviderFactory func(rawConfig []byte) (PaymentProvider, error)

var (
	factoryMu sync.RWMutex
	factories = map[string]ProviderFactory{}
)

// RegisterFactory 注册新的支付插件类型。
//
// 新渠道只需实现 PaymentProvider 接口，并在包初始化时调用：
//
//	func init() { payment.RegisterFactory("unionpay", NewUnionPayProvider) }
//
// 管理端创建 plugin_type=unionpay 的插件后即可热加载，无需改动收银台与回调代码。
func RegisterFactory(pluginType string, f ProviderFactory) {
	factoryMu.Lock()
	defer factoryMu.Unlock()
	factories[pluginType] = f
}

// lookupFactory 查找已注册的插件工厂。
func lookupFactory(pluginType string) (ProviderFactory, bool) {
	factoryMu.RLock()
	defer factoryMu.RUnlock()
	f, ok := factories[pluginType]
	return f, ok
}

// SupportedTypes 返回可创建的插件类型（内置 + 已注册工厂）。
func SupportedTypes() []string {
	types := []string{"alipay", "wechat", "stripe", "paypal"}
	factoryMu.RLock()
	defer factoryMu.RUnlock()
	for t := range factories {
		types = append(types, t)
	}
	return types
}

// Get 获取指定类型的支付插件。
func (r *Registry) Get(pluginType string) (PaymentProvider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[pluginType]
	if !ok {
		return nil, fmt.Errorf("支付插件不存在: %s", pluginType)
	}
	return p, nil
}

// List 返回所有已注册的插件类型。
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	types := make([]string, 0, len(r.providers))
	for t := range r.providers {
		types = append(types, t)
	}
	return types
}
