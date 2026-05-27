// Package payment - Stripe 渠道实现（Checkout Session + Webhook）。
//
// 设计要点：
//   - 仅依赖标准库；不引入 stripe-go 三方 SDK
//   - 接口：POST /v1/checkout/sessions（创建支付会话，返回托管 URL）
//          GET  /v1/checkout/sessions/{id}（查询）
//          POST /v1/refunds（退款）
//   - Webhook：HMAC-SHA256(t={timestamp},v1={signature}) 签名校验
//
// 配置项（PaymentPlugin.Config 中的 JSON 字段）：
//   - secret_key:       Stripe 私钥（sk_live_xxx / sk_test_xxx）
//   - webhook_secret:   Webhook 签名密钥（whsec_xxx）
//   - currency:         默认币种，如 "usd"
//   - gateway:          API 网关，默认 https://api.stripe.com
package payment

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// StripeProvider 实现 PaymentProvider。
type StripeProvider struct {
	SecretKey     string
	WebhookSecret string
	Currency      string
	Gateway       string
	httpClient    *http.Client
}

// StripeConfig 是 PaymentPlugin.Config 反序列化结构。
type StripeConfig struct {
	SecretKey     string `json:"secret_key"`
	WebhookSecret string `json:"webhook_secret"`
	Currency      string `json:"currency,omitempty"`
	Gateway       string `json:"gateway,omitempty"`
}

// NewStripeProvider 通过 JSON 配置创建 Stripe 插件。
func NewStripeProvider(rawConfig []byte) (*StripeProvider, error) {
	var cfg StripeConfig
	if err := json.Unmarshal(rawConfig, &cfg); err != nil {
		return nil, fmt.Errorf("解析 Stripe 配置失败: %w", err)
	}
	if cfg.SecretKey == "" {
		return nil, errors.New("Stripe 配置缺少 secret_key")
	}
	currency := cfg.Currency
	if currency == "" {
		currency = "usd"
	}
	gateway := cfg.Gateway
	if gateway == "" {
		gateway = "https://api.stripe.com"
	}
	return &StripeProvider{
		SecretKey:     cfg.SecretKey,
		WebhookSecret: cfg.WebhookSecret,
		Currency:      currency,
		Gateway:       gateway,
		httpClient:    &http.Client{Timeout: 15 * time.Second},
	}, nil
}

// Name 实现 PaymentProvider。
func (p *StripeProvider) Name() string { return "Stripe" }

// Type 实现 PaymentProvider。
func (p *StripeProvider) Type() string { return "stripe" }

// CreateOrder 实现 PaymentProvider，创建 Checkout Session。
func (p *StripeProvider) CreateOrder(ctx context.Context, req CreateOrderReq) (*CreateOrderResp, error) {
	form := url.Values{}
	form.Set("mode", "payment")
	form.Set("client_reference_id", req.OrderNo)
	form.Set("success_url", req.ReturnURL+"?status=success&order_no="+req.OrderNo)
	form.Set("cancel_url", req.ReturnURL+"?status=cancel&order_no="+req.OrderNo)
	form.Set("payment_method_types[0]", "card")
	form.Set("line_items[0][price_data][currency]", p.Currency)
	form.Set("line_items[0][price_data][product_data][name]", req.Subject)
	form.Set("line_items[0][price_data][unit_amount]", strconv.FormatInt(req.AmountCents, 10))
	form.Set("line_items[0][quantity]", "1")
	if req.NotifyURL != "" {
		// Stripe 通过 Dashboard 配置 Webhook，此字段仅记录用
		form.Set("metadata[notify_url]", req.NotifyURL)
	}
	form.Set("metadata[order_no]", req.OrderNo)

	respBody, err := p.doRequest(ctx, http.MethodPost,
		"/v1/checkout/sessions", form.Encode())
	if err != nil {
		return nil, err
	}
	var s struct {
		ID  string `json:"id"`
		URL string `json:"url"`
	}
	if err := json.Unmarshal(respBody, &s); err != nil {
		return nil, fmt.Errorf("解析 Checkout 响应失败: %w (body=%s)", err, string(respBody))
	}
	if s.URL == "" {
		return nil, fmt.Errorf("Checkout 响应缺少 url: %s", string(respBody))
	}
	return &CreateOrderResp{
		PayURL:  s.URL,
		TradeNo: s.ID,
	}, nil
}

// QueryOrder 实现 PaymentProvider。
// 注意：Stripe Checkout 是按 session ID 查询；此处假定上游已存 sessionID 在 orderNo 字段；
// 若需要按内部 orderNo 反查 sessionID，可通过 metadata.order_no 列表搜索。
func (p *StripeProvider) QueryOrder(ctx context.Context, sessionID string) (*QueryOrderResp, error) {
	respBody, err := p.doRequest(ctx, http.MethodGet,
		"/v1/checkout/sessions/"+sessionID, "")
	if err != nil {
		return nil, err
	}
	var s struct {
		ID            string            `json:"id"`
		PaymentStatus string            `json:"payment_status"`
		Status        string            `json:"status"`
		Metadata      map[string]string `json:"metadata"`
	}
	if err := json.Unmarshal(respBody, &s); err != nil {
		return nil, fmt.Errorf("解析查询响应失败: %w", err)
	}
	return &QueryOrderResp{
		OrderNo: s.Metadata["order_no"],
		TradeNo: s.ID,
		Status:  mapStripeStatus(s.PaymentStatus),
	}, nil
}

// VerifyCallback 实现 PaymentProvider。
// Stripe-Signature header 形如：t=1492774577,v1=5257a869...,v0=...
// 待签字符串 = "{t}.{body}"，HMAC-SHA256(secret) 与 v1 比对。
func (p *StripeProvider) VerifyCallback(ctx context.Context, body []byte, headers map[string]string) (*CallbackData, error) {
	sigHeader := headers["Stripe-Signature"]
	if sigHeader == "" {
		return nil, errors.New("回调缺少 Stripe-Signature 头")
	}
	if p.WebhookSecret == "" {
		return nil, errors.New("Webhook 未配置 webhook_secret，无法验签")
	}

	// 解析 t / v1
	var ts, v1 string
	for _, kv := range strings.Split(sigHeader, ",") {
		kv = strings.TrimSpace(kv)
		if strings.HasPrefix(kv, "t=") {
			ts = kv[2:]
		} else if strings.HasPrefix(kv, "v1=") && v1 == "" {
			v1 = kv[3:]
		}
	}
	if ts == "" || v1 == "" {
		return nil, errors.New("Stripe-Signature 缺少 t 或 v1")
	}
	// 防重放：5 分钟时窗
	tsInt, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("Stripe-Signature t 解析失败: %w", err)
	}
	if abs64(time.Now().Unix()-tsInt) > 300 {
		return nil, errors.New("Stripe-Signature 时间戳过期（>5min）")
	}

	mac := hmac.New(sha256.New, []byte(p.WebhookSecret))
	mac.Write([]byte(ts + "." + string(body)))
	expect := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expect), []byte(v1)) {
		return nil, errors.New("Stripe Webhook 签名校验失败")
	}

	// 解析 event
	var evt struct {
		Type string `json:"type"`
		Data struct {
			Object struct {
				ID                string            `json:"id"`
				PaymentIntent     string            `json:"payment_intent"`
				PaymentStatus     string            `json:"payment_status"`
				AmountTotal       int64             `json:"amount_total"`
				ClientReferenceID string            `json:"client_reference_id"`
				Metadata          map[string]string `json:"metadata"`
			} `json:"object"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &evt); err != nil {
		return nil, fmt.Errorf("解析 Stripe event 失败: %w", err)
	}

	orderNo := evt.Data.Object.ClientReferenceID
	if orderNo == "" {
		orderNo = evt.Data.Object.Metadata["order_no"]
	}
	status := "failed"
	if evt.Type == "checkout.session.completed" && evt.Data.Object.PaymentStatus == "paid" {
		status = "paid"
	}
	return &CallbackData{
		OrderNo:     orderNo,
		TradeNo:     evt.Data.Object.PaymentIntent,
		AmountCents: evt.Data.Object.AmountTotal,
		Status:      status,
		RawData:     body,
	}, nil
}

// Refund 实现 PaymentProvider，调用 /v1/refunds（按 PaymentIntent 退款）。
func (p *StripeProvider) Refund(ctx context.Context, req RefundReq) (*RefundResp, error) {
	form := url.Values{}
	form.Set("payment_intent", req.OrderNo) // 调用方传入 PaymentIntent ID
	form.Set("amount", strconv.FormatInt(req.AmountCents, 10))
	if req.Reason != "" {
		form.Set("reason", "requested_by_customer")
		form.Set("metadata[reason]", req.Reason)
	}
	form.Set("metadata[refund_no]", req.RefundNo)

	respBody, err := p.doRequest(ctx, http.MethodPost, "/v1/refunds", form.Encode())
	if err != nil {
		return nil, err
	}
	var r struct {
		ID     string `json:"id"`
		Status string `json:"status"` // succeeded/pending/failed
	}
	if err := json.Unmarshal(respBody, &r); err != nil {
		return nil, fmt.Errorf("解析退款响应失败: %w", err)
	}
	status := "pending"
	switch r.Status {
	case "succeeded":
		status = "success"
	case "failed", "canceled":
		status = "failed"
	}
	return &RefundResp{RefundNo: req.RefundNo, Status: status}, nil
}

// doRequest 发起带 Bearer 鉴权的 Stripe API 请求。
// body 为 application/x-www-form-urlencoded 字符串；GET 时传空。
func (p *StripeProvider) doRequest(ctx context.Context, method, path, formBody string) ([]byte, error) {
	var rdr io.Reader
	if formBody != "" {
		rdr = bytes.NewBufferString(formBody)
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, p.Gateway+path, rdr)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+p.SecretKey)
	httpReq.Header.Set("Stripe-Version", "2024-04-10")
	if formBody != "" {
		httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("Stripe 请求失败: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("Stripe 返回错误 status=%d body=%s", resp.StatusCode, string(respBody))
	}
	return respBody, nil
}

// mapStripeStatus 将 Stripe payment_status 映射为统一状态。
func mapStripeStatus(s string) string {
	switch s {
	case "paid":
		return "paid"
	case "unpaid":
		return "pending"
	case "no_payment_required":
		return "paid"
	default:
		return "failed"
	}
}

// abs64 返回 int64 绝对值。
func abs64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}
