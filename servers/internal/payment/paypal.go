// Package payment - PayPal 渠道实现（Orders v2 API）。
//
// 设计要点：
//   - 仅依赖标准库；不引入 paypal-sdk
//   - 协议：PayPal Orders v2（OAuth2 Client Credentials + JSON）
//   - 接口：POST /v2/checkout/orders（创建订单）；
//          GET  /v2/checkout/orders/{id}（查询）；
//          POST /v2/payments/captures/{capture_id}/refund（退款）
//   - Webhook：通过 PayPal /v1/notifications/verify-webhook-signature 接口验签
//
// 配置项（PaymentPlugin.Config 中的 JSON 字段）：
//   - client_id:        PayPal App Client ID
//   - client_secret:    PayPal App Secret
//   - webhook_id:       已创建的 Webhook ID（用于通知验签）
//   - currency:         默认币种，如 "USD"
//   - sandbox:          true 时使用 sandbox 网关
//   - gateway:          自定义网关（覆盖 sandbox 推断）
package payment

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// PayPalProvider 实现 PaymentProvider。
type PayPalProvider struct {
	ClientID     string
	ClientSecret string
	WebhookID    string
	Currency     string
	Gateway      string
	httpClient   *http.Client

	tokenMu  sync.Mutex
	token    string
	tokenExp time.Time
}

// PayPalConfig 是 PaymentPlugin.Config 反序列化结构。
type PayPalConfig struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	WebhookID    string `json:"webhook_id"`
	Currency     string `json:"currency,omitempty"`
	Sandbox      bool   `json:"sandbox,omitempty"`
	Gateway      string `json:"gateway,omitempty"`
}

// NewPayPalProvider 通过 JSON 配置创建 PayPal 插件。
func NewPayPalProvider(rawConfig []byte) (*PayPalProvider, error) {
	var cfg PayPalConfig
	if err := json.Unmarshal(rawConfig, &cfg); err != nil {
		return nil, fmt.Errorf("解析 PayPal 配置失败: %w", err)
	}
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, errors.New("PayPal 配置缺少 client_id / client_secret")
	}
	currency := cfg.Currency
	if currency == "" {
		currency = "USD"
	}
	gateway := cfg.Gateway
	if gateway == "" {
		if cfg.Sandbox {
			gateway = "https://api-m.sandbox.paypal.com"
		} else {
			gateway = "https://api-m.paypal.com"
		}
	}
	return &PayPalProvider{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		WebhookID:    cfg.WebhookID,
		Currency:     currency,
		Gateway:      gateway,
		httpClient:   &http.Client{Timeout: 15 * time.Second},
	}, nil
}

// Name 实现 PaymentProvider。
func (p *PayPalProvider) Name() string { return "PayPal" }

// Type 实现 PaymentProvider。
func (p *PayPalProvider) Type() string { return "paypal" }

// CreateOrder 实现 PaymentProvider，创建 PayPal 订单并返回 approve link。
func (p *PayPalProvider) CreateOrder(ctx context.Context, req CreateOrderReq) (*CreateOrderResp, error) {
	body := map[string]interface{}{
		"intent": "CAPTURE",
		"purchase_units": []map[string]interface{}{
			{
				"reference_id": req.OrderNo,
				"description":  req.Subject,
				"custom_id":    req.OrderNo,
				"amount": map[string]interface{}{
					"currency_code": p.Currency,
					"value":         fmt.Sprintf("%.2f", float64(req.AmountCents)/100.0),
				},
			},
		},
		"application_context": map[string]string{
			"return_url": req.ReturnURL,
			"cancel_url": req.ReturnURL + "?status=cancel&order_no=" + req.OrderNo,
		},
	}
	bodyBytes, _ := json.Marshal(body)

	respBody, err := p.doRequest(ctx, http.MethodPost, "/v2/checkout/orders", bodyBytes)
	if err != nil {
		return nil, err
	}
	var r struct {
		ID     string `json:"id"`
		Status string `json:"status"`
		Links  []struct {
			Href   string `json:"href"`
			Rel    string `json:"rel"`
			Method string `json:"method"`
		} `json:"links"`
	}
	if err := json.Unmarshal(respBody, &r); err != nil {
		return nil, fmt.Errorf("解析 PayPal 创建订单响应失败: %w (body=%s)", err, string(respBody))
	}
	var approveURL string
	for _, l := range r.Links {
		if l.Rel == "approve" {
			approveURL = l.Href
			break
		}
	}
	if approveURL == "" {
		return nil, fmt.Errorf("PayPal 响应缺少 approve link: %s", string(respBody))
	}
	return &CreateOrderResp{
		PayURL:  approveURL,
		TradeNo: r.ID,
	}, nil
}

// QueryOrder 实现 PaymentProvider。
// 这里 orderNo 应是 PayPal Order ID（CreateOrder 返回的 TradeNo）。
func (p *PayPalProvider) QueryOrder(ctx context.Context, paypalOrderID string) (*QueryOrderResp, error) {
	respBody, err := p.doRequest(ctx, http.MethodGet,
		"/v2/checkout/orders/"+paypalOrderID, nil)
	if err != nil {
		return nil, err
	}
	var r struct {
		ID            string `json:"id"`
		Status        string `json:"status"` // CREATED/SAVED/APPROVED/VOIDED/COMPLETED/PAYER_ACTION_REQUIRED
		PurchaseUnits []struct {
			ReferenceID string `json:"reference_id"`
			CustomID    string `json:"custom_id"`
		} `json:"purchase_units"`
		UpdateTime string `json:"update_time"`
	}
	if err := json.Unmarshal(respBody, &r); err != nil {
		return nil, fmt.Errorf("解析查询响应失败: %w", err)
	}
	orderNo := ""
	if len(r.PurchaseUnits) > 0 {
		orderNo = r.PurchaseUnits[0].CustomID
		if orderNo == "" {
			orderNo = r.PurchaseUnits[0].ReferenceID
		}
	}
	return &QueryOrderResp{
		OrderNo: orderNo,
		TradeNo: r.ID,
		Status:  mapPayPalStatus(r.Status),
		PaidAt:  r.UpdateTime,
	}, nil
}

// VerifyCallback 实现 PaymentProvider。
// 通过 PayPal /v1/notifications/verify-webhook-signature 接口委托验签。
func (p *PayPalProvider) VerifyCallback(ctx context.Context, body []byte, headers map[string]string) (*CallbackData, error) {
	if p.WebhookID == "" {
		return nil, errors.New("PayPal 未配置 webhook_id，无法验签")
	}

	// 1) 解析 webhook event（先解析以便验签失败时也能拿到 order_no 用于排错）
	var evt struct {
		EventType string          `json:"event_type"`
		Resource  json.RawMessage `json:"resource"`
	}
	if err := json.Unmarshal(body, &evt); err != nil {
		return nil, fmt.Errorf("解析 PayPal Webhook 失败: %w", err)
	}

	// 2) 委托 PayPal 验签
	var rawBody json.RawMessage = body
	verifyReq := map[string]interface{}{
		"transmission_id":    headers["Paypal-Transmission-Id"],
		"transmission_time":  headers["Paypal-Transmission-Time"],
		"cert_url":           headers["Paypal-Cert-Url"],
		"auth_algo":          headers["Paypal-Auth-Algo"],
		"transmission_sig":   headers["Paypal-Transmission-Sig"],
		"webhook_id":         p.WebhookID,
		"webhook_event":      rawBody,
	}
	verifyBody, _ := json.Marshal(verifyReq)
	respBody, err := p.doRequest(ctx, http.MethodPost,
		"/v1/notifications/verify-webhook-signature", verifyBody)
	if err != nil {
		return nil, fmt.Errorf("调用 PayPal 验签接口失败: %w", err)
	}
	var verifyResp struct {
		VerificationStatus string `json:"verification_status"`
	}
	if err := json.Unmarshal(respBody, &verifyResp); err != nil {
		return nil, fmt.Errorf("解析验签响应失败: %w", err)
	}
	if verifyResp.VerificationStatus != "SUCCESS" {
		return nil, fmt.Errorf("PayPal Webhook 验签失败: status=%s", verifyResp.VerificationStatus)
	}

	// 3) 解析 resource 取订单号与金额
	var res struct {
		ID       string `json:"id"`
		Status   string `json:"status"`
		CustomID string `json:"custom_id"`
		Amount   struct {
			Value        string `json:"value"`
			CurrencyCode string `json:"currency_code"`
		} `json:"amount"`
		PurchaseUnits []struct {
			ReferenceID string `json:"reference_id"`
			CustomID    string `json:"custom_id"`
			Amount      struct {
				Value string `json:"value"`
			} `json:"amount"`
		} `json:"purchase_units"`
	}
	_ = json.Unmarshal(evt.Resource, &res)

	orderNo := res.CustomID
	if orderNo == "" && len(res.PurchaseUnits) > 0 {
		orderNo = res.PurchaseUnits[0].CustomID
		if orderNo == "" {
			orderNo = res.PurchaseUnits[0].ReferenceID
		}
	}
	amountStr := res.Amount.Value
	if amountStr == "" && len(res.PurchaseUnits) > 0 {
		amountStr = res.PurchaseUnits[0].Amount.Value
	}
	amountCents, _ := parseYuanToCents(amountStr) // 元 → 分（按 2 位小数解析即可）

	status := "failed"
	switch evt.EventType {
	case "PAYMENT.CAPTURE.COMPLETED", "CHECKOUT.ORDER.APPROVED":
		status = "paid"
	case "PAYMENT.CAPTURE.PENDING":
		status = "pending"
	case "PAYMENT.CAPTURE.DENIED", "PAYMENT.CAPTURE.REFUNDED":
		status = "failed"
	}

	return &CallbackData{
		OrderNo:     orderNo,
		TradeNo:     res.ID,
		AmountCents: amountCents,
		Status:      status,
		RawData:     body,
	}, nil
}

// Refund 实现 PaymentProvider。
// 注意：PayPal 退款需要 capture_id（不是 order_id），调用方应通过 QueryOrder 提取后传入 RefundReq.OrderNo。
func (p *PayPalProvider) Refund(ctx context.Context, req RefundReq) (*RefundResp, error) {
	body := map[string]interface{}{
		"amount": map[string]string{
			"value":         fmt.Sprintf("%.2f", float64(req.AmountCents)/100.0),
			"currency_code": p.Currency,
		},
		"note_to_payer": req.Reason,
		"invoice_id":    req.RefundNo,
	}
	bodyBytes, _ := json.Marshal(body)

	respBody, err := p.doRequest(ctx, http.MethodPost,
		"/v2/payments/captures/"+req.OrderNo+"/refund", bodyBytes)
	if err != nil {
		return nil, err
	}
	var r struct {
		ID     string `json:"id"`
		Status string `json:"status"` // COMPLETED/PENDING/CANCELLED/FAILED
	}
	if err := json.Unmarshal(respBody, &r); err != nil {
		return nil, fmt.Errorf("解析退款响应失败: %w", err)
	}
	status := "pending"
	switch r.Status {
	case "COMPLETED":
		status = "success"
	case "FAILED", "CANCELLED":
		status = "failed"
	}
	return &RefundResp{RefundNo: req.RefundNo, Status: status}, nil
}

// doRequest 发起带 OAuth2 Bearer 鉴权的 PayPal API 请求。
func (p *PayPalProvider) doRequest(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	token, err := p.getAccessToken(ctx)
	if err != nil {
		return nil, err
	}
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, p.Gateway+path, rdr)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Accept", "application/json")
	if body != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("PayPal 请求失败: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("PayPal 返回错误 status=%d body=%s", resp.StatusCode, string(respBody))
	}
	return respBody, nil
}

// getAccessToken 用 client_credentials 换 access_token，并缓存到过期前 60s。
func (p *PayPalProvider) getAccessToken(ctx context.Context) (string, error) {
	p.tokenMu.Lock()
	defer p.tokenMu.Unlock()

	if p.token != "" && time.Now().Before(p.tokenExp.Add(-60*time.Second)) {
		return p.token, nil
	}

	form := "grant_type=client_credentials"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		p.Gateway+"/v1/oauth2/token", bytes.NewBufferString(form))
	if err != nil {
		return "", err
	}
	creds := base64.StdEncoding.EncodeToString([]byte(p.ClientID + ":" + p.ClientSecret))
	req.Header.Set("Authorization", "Basic "+creds)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("PayPal OAuth2 失败: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("PayPal OAuth2 错误 status=%d body=%s", resp.StatusCode, string(body))
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", fmt.Errorf("解析 token 响应失败: %w", err)
	}
	if tr.AccessToken == "" {
		return "", errors.New("PayPal 返回空 access_token")
	}
	p.token = tr.AccessToken
	p.tokenExp = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	return p.token, nil
}

// mapPayPalStatus 将 PayPal Order Status 映射为统一状态。
func mapPayPalStatus(s string) string {
	switch s {
	case "COMPLETED":
		return "paid"
	case "APPROVED", "CREATED", "SAVED", "PAYER_ACTION_REQUIRED":
		return "pending"
	case "VOIDED":
		return "closed"
	default:
		return "failed"
	}
}

// _ 占用，避免误删 strconv 导入（refund 金额前置校验时可启用）
var _ = strconv.Itoa
