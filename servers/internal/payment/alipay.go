// Package payment - 支付宝渠道实现（电脑网站支付 / 手机网站支付）。
//
// 设计要点：
//   - 仅依赖标准库与项目已有依赖，不引入 alipay-sdk-go 重型依赖
//   - 协议：支付宝开放平台 OpenAPI 1.0（RSA2 签名）
//   - 接口：alipay.trade.page.pay (PC) / alipay.trade.wap.pay (H5)
//   - 回调：异步通知 notify_url（POST form-urlencoded）
//   - 关键签名：商户私钥 RSA-SHA256 / 验证支付宝公钥 RSA-SHA256
//
// 配置项（PaymentPlugin.Config 中的 JSON 字段）：
//   - app_id:           商户 App ID
//   - private_key:      商户应用私钥（PEM）
//   - alipay_pubkey:    支付宝公钥（PEM）— 用于回调验签
//   - gateway:          网关地址，默认 https://openapi.alipay.com/gateway.do
//   - sandbox:          true 时使用沙箱网关 https://openapi.alipaydev.com/gateway.do
package payment

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// AlipayProvider 实现 PaymentProvider。
type AlipayProvider struct {
	AppID         string
	PrivateKey    *rsa.PrivateKey
	AlipayPubKey  *rsa.PublicKey
	Gateway       string
	httpClient    *http.Client
}

// AlipayConfig 是从 PaymentPlugin.Config JSON 反序列化的结构。
type AlipayConfig struct {
	AppID        string `json:"app_id"`
	PrivateKey   string `json:"private_key"`
	AlipayPubKey string `json:"alipay_pubkey"`
	Gateway      string `json:"gateway,omitempty"`
	Sandbox      bool   `json:"sandbox,omitempty"`
}

// NewAlipayProvider 通过 JSON 配置创建支付宝插件。
func NewAlipayProvider(rawConfig []byte) (*AlipayProvider, error) {
	var cfg AlipayConfig
	if err := json.Unmarshal(rawConfig, &cfg); err != nil {
		return nil, fmt.Errorf("解析支付宝配置失败: %w", err)
	}
	if cfg.AppID == "" || cfg.PrivateKey == "" || cfg.AlipayPubKey == "" {
		return nil, errors.New("支付宝配置缺少 app_id / private_key / alipay_pubkey")
	}
	priv, err := parseRSAPrivateKeyPEM([]byte(cfg.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("解析商户私钥失败: %w", err)
	}
	pub, err := parseRSAPublicKeyPEM([]byte(cfg.AlipayPubKey))
	if err != nil {
		return nil, fmt.Errorf("解析支付宝公钥失败: %w", err)
	}

	gateway := cfg.Gateway
	if gateway == "" {
		if cfg.Sandbox {
			gateway = "https://openapi.alipaydev.com/gateway.do"
		} else {
			gateway = "https://openapi.alipay.com/gateway.do"
		}
	}

	return &AlipayProvider{
		AppID:        cfg.AppID,
		PrivateKey:   priv,
		AlipayPubKey: pub,
		Gateway:      gateway,
		httpClient:   &http.Client{Timeout: 15 * time.Second},
	}, nil
}

// Name 实现 PaymentProvider。
func (p *AlipayProvider) Name() string { return "支付宝" }

// Type 实现 PaymentProvider。
func (p *AlipayProvider) Type() string { return "alipay" }

// CreateOrder 实现 PaymentProvider。
// 使用 alipay.trade.page.pay 直接生成完整跳转 URL（含签名），由前端跳转至此 URL 完成支付。
func (p *AlipayProvider) CreateOrder(ctx context.Context, req CreateOrderReq) (*CreateOrderResp, error) {
	bizContent := map[string]string{
		"out_trade_no": req.OrderNo,
		"total_amount": fmt.Sprintf("%.2f", float64(req.AmountCents)/100.0),
		"subject":      req.Subject,
		"product_code": "FAST_INSTANT_TRADE_PAY",
	}
	bizJSON, _ := json.Marshal(bizContent)

	params := map[string]string{
		"app_id":      p.AppID,
		"method":      "alipay.trade.page.pay",
		"format":      "JSON",
		"charset":     "utf-8",
		"sign_type":   "RSA2",
		"timestamp":   time.Now().Format("2006-01-02 15:04:05"),
		"version":     "1.0",
		"notify_url":  req.NotifyURL,
		"return_url":  req.ReturnURL,
		"biz_content": string(bizJSON),
	}

	sign, err := p.signRSA2(params)
	if err != nil {
		return nil, fmt.Errorf("签名失败: %w", err)
	}
	params["sign"] = sign

	values := make(url.Values, len(params))
	for k, v := range params {
		if v != "" {
			values.Set(k, v)
		}
	}
	payURL := p.Gateway + "?" + values.Encode()
	return &CreateOrderResp{PayURL: payURL}, nil
}

// QueryOrder 实现 PaymentProvider。
func (p *AlipayProvider) QueryOrder(ctx context.Context, orderNo string) (*QueryOrderResp, error) {
	bizJSON, _ := json.Marshal(map[string]string{"out_trade_no": orderNo})
	params := map[string]string{
		"app_id":      p.AppID,
		"method":      "alipay.trade.query",
		"format":      "JSON",
		"charset":     "utf-8",
		"sign_type":   "RSA2",
		"timestamp":   time.Now().Format("2006-01-02 15:04:05"),
		"version":     "1.0",
		"biz_content": string(bizJSON),
	}
	sign, err := p.signRSA2(params)
	if err != nil {
		return nil, err
	}
	params["sign"] = sign

	values := make(url.Values, len(params))
	for k, v := range params {
		values.Set(k, v)
	}
	httpReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, p.Gateway,
		strings.NewReader(values.Encode()))
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=utf-8")

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("请求支付宝查询接口失败: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}
	queryRespRaw, ok := raw["alipay_trade_query_response"]
	if !ok {
		return nil, fmt.Errorf("响应缺少 alipay_trade_query_response: %s", string(body))
	}
	var qr struct {
		Code        string `json:"code"`
		Msg         string `json:"msg"`
		OutTradeNo  string `json:"out_trade_no"`
		TradeNo     string `json:"trade_no"`
		TradeStatus string `json:"trade_status"` // WAIT_BUYER_PAY/TRADE_SUCCESS/TRADE_CLOSED/TRADE_FINISHED
		SendPayDate string `json:"send_pay_date"`
	}
	if err := json.Unmarshal(queryRespRaw, &qr); err != nil {
		return nil, fmt.Errorf("解析查询响应失败: %w", err)
	}
	if qr.Code != "10000" {
		return nil, fmt.Errorf("支付宝查询失败: code=%s msg=%s", qr.Code, qr.Msg)
	}
	status := mapAlipayTradeStatus(qr.TradeStatus)
	return &QueryOrderResp{
		OrderNo: qr.OutTradeNo,
		TradeNo: qr.TradeNo,
		Status:  status,
		PaidAt:  qr.SendPayDate,
	}, nil
}

// VerifyCallback 实现 PaymentProvider。
// 支付宝异步通知格式：application/x-www-form-urlencoded。
// 验签规则：除 sign / sign_type 外的所有字段按 key 字典序拼接 k=v&k=v，用支付宝公钥验签。
func (p *AlipayProvider) VerifyCallback(ctx context.Context, body []byte, headers map[string]string) (*CallbackData, error) {
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, fmt.Errorf("解析回调表单失败: %w", err)
	}
	sign := form.Get("sign")
	if sign == "" {
		return nil, errors.New("回调缺少 sign")
	}

	// 拼接待验签字符串
	keys := make([]string, 0, len(form))
	for k := range form {
		if k == "sign" || k == "sign_type" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		v := form.Get(k)
		if v == "" {
			continue
		}
		parts = append(parts, k+"="+v)
	}
	signStr := strings.Join(parts, "&")

	sigBytes, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		return nil, fmt.Errorf("sign 解码失败: %w", err)
	}
	hashed := sha256.Sum256([]byte(signStr))
	if err := rsa.VerifyPKCS1v15(p.AlipayPubKey, crypto.SHA256, hashed[:], sigBytes); err != nil {
		return nil, fmt.Errorf("回调验签失败: %w", err)
	}

	// 解析金额（元 → 分）
	totalAmt := form.Get("total_amount")
	amountCents, _ := parseYuanToCents(totalAmt)

	return &CallbackData{
		OrderNo:     form.Get("out_trade_no"),
		TradeNo:     form.Get("trade_no"),
		AmountCents: amountCents,
		Status:      mapAlipayTradeStatus(form.Get("trade_status")),
		RawData:     body,
	}, nil
}

// Refund 实现 PaymentProvider，使用 alipay.trade.refund。
func (p *AlipayProvider) Refund(ctx context.Context, req RefundReq) (*RefundResp, error) {
	bizContent := map[string]string{
		"out_trade_no":   req.OrderNo,
		"out_request_no": req.RefundNo,
		"refund_amount":  fmt.Sprintf("%.2f", float64(req.AmountCents)/100.0),
		"refund_reason":  req.Reason,
	}
	bizJSON, _ := json.Marshal(bizContent)
	params := map[string]string{
		"app_id":      p.AppID,
		"method":      "alipay.trade.refund",
		"format":      "JSON",
		"charset":     "utf-8",
		"sign_type":   "RSA2",
		"timestamp":   time.Now().Format("2006-01-02 15:04:05"),
		"version":     "1.0",
		"biz_content": string(bizJSON),
	}
	sign, err := p.signRSA2(params)
	if err != nil {
		return nil, err
	}
	params["sign"] = sign

	values := make(url.Values, len(params))
	for k, v := range params {
		values.Set(k, v)
	}
	httpReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, p.Gateway,
		strings.NewReader(values.Encode()))
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=utf-8")

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("请求支付宝退款接口失败: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}
	refundRaw, ok := raw["alipay_trade_refund_response"]
	if !ok {
		return nil, fmt.Errorf("响应缺少 alipay_trade_refund_response: %s", string(body))
	}
	var rr struct {
		Code string `json:"code"`
		Msg  string `json:"msg"`
		Fund string `json:"fund_change"`
	}
	if err := json.Unmarshal(refundRaw, &rr); err != nil {
		return nil, fmt.Errorf("解析退款响应失败: %w", err)
	}
	status := "failed"
	if rr.Code == "10000" {
		status = "success"
	}
	return &RefundResp{RefundNo: req.RefundNo, Status: status}, nil
}

// signRSA2 用商户私钥对参数做 RSA-SHA256 签名（base64）。
func (p *AlipayProvider) signRSA2(params map[string]string) (string, error) {
	keys := make([]string, 0, len(params))
	for k, v := range params {
		if k == "sign" || v == "" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+params[k])
	}
	hashed := sha256.Sum256([]byte(strings.Join(parts, "&")))
	sig, err := rsa.SignPKCS1v15(nil, p.PrivateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// mapAlipayTradeStatus 将支付宝 trade_status 映射为统一状态。
func mapAlipayTradeStatus(s string) string {
	switch s {
	case "TRADE_SUCCESS", "TRADE_FINISHED":
		return "paid"
	case "WAIT_BUYER_PAY":
		return "pending"
	case "TRADE_CLOSED":
		return "closed"
	default:
		return "failed"
	}
}

// parseRSAPrivateKeyPEM 兼容 PKCS#1 / PKCS#8 PEM 私钥。
func parseRSAPrivateKeyPEM(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("PEM 解码失败")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rk, ok := k.(*rsa.PrivateKey); ok {
			return rk, nil
		}
		return nil, errors.New("PKCS#8 私钥不是 RSA 类型")
	}
	return nil, errors.New("无法解析 RSA 私钥（既非 PKCS#1 也非 PKCS#8）")
}

// parseRSAPublicKeyPEM 兼容 PKIX PEM 公钥。
func parseRSAPublicKeyPEM(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("PEM 解码失败")
	}
	if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		if rp, ok := pub.(*rsa.PublicKey); ok {
			return rp, nil
		}
		return nil, errors.New("公钥不是 RSA 类型")
	}
	if pub, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return pub, nil
	}
	return nil, errors.New("无法解析 RSA 公钥")
}

// parseYuanToCents 将 "12.34" 转为分（int64）。
func parseYuanToCents(yuan string) (int64, error) {
	yuan = strings.TrimSpace(yuan)
	if yuan == "" {
		return 0, nil
	}
	f, err := strconv.ParseFloat(yuan, 64)
	if err != nil {
		return 0, err
	}
	return int64(f*100 + 0.5), nil
}
