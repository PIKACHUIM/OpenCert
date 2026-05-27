// Package payment - 微信支付渠道实现（v3 API）。
//
// 设计要点：
//   - 仅依赖标准库，不引入 wechatpay-apiv3 等三方 SDK
//   - 协议：微信支付 V3（HTTP Authorization 头签名 + 平台证书验签）
//   - 接口：POST /v3/pay/transactions/native (Native 扫码)；
//          GET  /v3/pay/transactions/out-trade-no/{out_trade_no}（查询）；
//          POST /v3/refund/domestic/refunds（退款）
//   - 回调：JSON Body + AEAD-AES-256-GCM 解密 resource.ciphertext
//
// 配置项（PaymentPlugin.Config 中的 JSON 字段）：
//   - mch_id:           商户号
//   - app_id:           关联的 AppID（公众号 / 小程序 / App）
//   - serial_no:        商户证书序列号
//   - private_key:      商户 API 私钥（PEM, PKCS#8）
//   - api_v3_key:       APIv3 密钥（32 字节 base64？官方为 32 ASCII 字符）
//   - platform_cert:    微信支付平台证书（PEM）— 用于回调验签
//   - gateway:          网关地址，默认 https://api.mch.weixin.qq.com
package payment

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// WeChatProvider 实现 PaymentProvider。
type WeChatProvider struct {
	MchID          string
	AppID          string
	SerialNo       string
	PrivateKey     *rsa.PrivateKey
	APIV3Key       []byte
	PlatformCert   *x509.Certificate
	Gateway        string
	httpClient     *http.Client
}

// WeChatConfig 是 PaymentPlugin.Config 反序列化结构。
type WeChatConfig struct {
	MchID        string `json:"mch_id"`
	AppID        string `json:"app_id"`
	SerialNo     string `json:"serial_no"`
	PrivateKey   string `json:"private_key"`
	APIV3Key     string `json:"api_v3_key"`
	PlatformCert string `json:"platform_cert"`
	Gateway      string `json:"gateway,omitempty"`
}

// NewWeChatProvider 通过 JSON 配置创建微信支付插件。
func NewWeChatProvider(rawConfig []byte) (*WeChatProvider, error) {
	var cfg WeChatConfig
	if err := json.Unmarshal(rawConfig, &cfg); err != nil {
		return nil, fmt.Errorf("解析微信支付配置失败: %w", err)
	}
	if cfg.MchID == "" || cfg.AppID == "" || cfg.SerialNo == "" ||
		cfg.PrivateKey == "" || cfg.APIV3Key == "" {
		return nil, errors.New("微信支付配置缺少必要字段")
	}
	priv, err := parseRSAPrivateKeyPEM([]byte(cfg.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("解析商户私钥失败: %w", err)
	}
	if len(cfg.APIV3Key) != 32 {
		return nil, fmt.Errorf("APIv3 密钥应为 32 字节 ASCII，实际 %d", len(cfg.APIV3Key))
	}

	var platformCert *x509.Certificate
	if cfg.PlatformCert != "" {
		block, _ := pem.Decode([]byte(cfg.PlatformCert))
		if block == nil {
			return nil, errors.New("解析平台证书 PEM 失败")
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("解析平台证书失败: %w", err)
		}
		platformCert = c
	}

	gateway := cfg.Gateway
	if gateway == "" {
		gateway = "https://api.mch.weixin.qq.com"
	}

	return &WeChatProvider{
		MchID:        cfg.MchID,
		AppID:        cfg.AppID,
		SerialNo:     cfg.SerialNo,
		PrivateKey:   priv,
		APIV3Key:     []byte(cfg.APIV3Key),
		PlatformCert: platformCert,
		Gateway:      gateway,
		httpClient:   &http.Client{Timeout: 15 * time.Second},
	}, nil
}

// Name 实现 PaymentProvider。
func (p *WeChatProvider) Name() string { return "微信支付" }

// Type 实现 PaymentProvider。
func (p *WeChatProvider) Type() string { return "wechat" }

// CreateOrder 实现 PaymentProvider，使用 Native 扫码下单。
func (p *WeChatProvider) CreateOrder(ctx context.Context, req CreateOrderReq) (*CreateOrderResp, error) {
	body := map[string]interface{}{
		"appid":        p.AppID,
		"mchid":        p.MchID,
		"description":  req.Subject,
		"out_trade_no": req.OrderNo,
		"notify_url":   req.NotifyURL,
		"amount": map[string]interface{}{
			"total":    req.AmountCents,
			"currency": "CNY",
		},
	}
	bodyBytes, _ := json.Marshal(body)

	respBody, err := p.doRequest(ctx, http.MethodPost,
		"/v3/pay/transactions/native", bodyBytes)
	if err != nil {
		return nil, err
	}
	var r struct {
		CodeURL string `json:"code_url"`
	}
	if err := json.Unmarshal(respBody, &r); err != nil {
		return nil, fmt.Errorf("解析下单响应失败: %w (body=%s)", err, string(respBody))
	}
	if r.CodeURL == "" {
		return nil, fmt.Errorf("下单响应缺少 code_url: %s", string(respBody))
	}
	return &CreateOrderResp{
		PayURL: r.CodeURL,
		QRCode: r.CodeURL,
	}, nil
}

// QueryOrder 实现 PaymentProvider。
func (p *WeChatProvider) QueryOrder(ctx context.Context, orderNo string) (*QueryOrderResp, error) {
	path := fmt.Sprintf("/v3/pay/transactions/out-trade-no/%s?mchid=%s", orderNo, p.MchID)
	respBody, err := p.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	var r struct {
		OutTradeNo    string `json:"out_trade_no"`
		TransactionID string `json:"transaction_id"`
		TradeState    string `json:"trade_state"`
		SuccessTime   string `json:"success_time"`
	}
	if err := json.Unmarshal(respBody, &r); err != nil {
		return nil, fmt.Errorf("解析查询响应失败: %w", err)
	}
	return &QueryOrderResp{
		OrderNo: r.OutTradeNo,
		TradeNo: r.TransactionID,
		Status:  mapWeChatTradeState(r.TradeState),
		PaidAt:  r.SuccessTime,
	}, nil
}

// VerifyCallback 实现 PaymentProvider。
//   - 验签：用平台证书公钥验 RSA-SHA256(headers["Wechatpay-Signature"])
//   - 解密：用 APIv3 Key 对 resource.ciphertext 做 AEAD-AES-256-GCM 解密
func (p *WeChatProvider) VerifyCallback(ctx context.Context, body []byte, headers map[string]string) (*CallbackData, error) {
	timestamp := headers["Wechatpay-Timestamp"]
	nonce := headers["Wechatpay-Nonce"]
	signature := headers["Wechatpay-Signature"]
	if timestamp == "" || nonce == "" || signature == "" {
		return nil, errors.New("回调缺少 Wechatpay-Timestamp/Nonce/Signature 头")
	}

	if p.PlatformCert != nil {
		signStr := timestamp + "\n" + nonce + "\n" + string(body) + "\n"
		sigBytes, err := base64.StdEncoding.DecodeString(signature)
		if err != nil {
			return nil, fmt.Errorf("Wechatpay-Signature 解码失败: %w", err)
		}
		hashed := sha256.Sum256([]byte(signStr))
		pubKey, ok := p.PlatformCert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("平台证书非 RSA")
		}
		if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], sigBytes); err != nil {
			return nil, fmt.Errorf("回调验签失败: %w", err)
		}
	}

	// 解密 resource.ciphertext
	var notify struct {
		EventType string `json:"event_type"`
		Resource  struct {
			AlgorithmStr string `json:"algorithm"`
			Ciphertext   string `json:"ciphertext"`
			AssociatedData string `json:"associated_data"`
			Nonce        string `json:"nonce"`
		} `json:"resource"`
	}
	if err := json.Unmarshal(body, &notify); err != nil {
		return nil, fmt.Errorf("解析回调 body 失败: %w", err)
	}
	plain, err := decryptAEAD(p.APIV3Key, notify.Resource.AssociatedData,
		notify.Resource.Nonce, notify.Resource.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("回调解密失败: %w", err)
	}

	var resource struct {
		OutTradeNo    string `json:"out_trade_no"`
		TransactionID string `json:"transaction_id"`
		TradeState    string `json:"trade_state"`
		Amount        struct {
			Total int64 `json:"total"`
		} `json:"amount"`
	}
	if err := json.Unmarshal(plain, &resource); err != nil {
		return nil, fmt.Errorf("解析解密后的资源失败: %w", err)
	}

	return &CallbackData{
		OrderNo:     resource.OutTradeNo,
		TradeNo:     resource.TransactionID,
		AmountCents: resource.Amount.Total,
		Status:      mapWeChatTradeState(resource.TradeState),
		RawData:     body,
	}, nil
}

// Refund 实现 PaymentProvider，调用 /v3/refund/domestic/refunds。
func (p *WeChatProvider) Refund(ctx context.Context, req RefundReq) (*RefundResp, error) {
	body := map[string]interface{}{
		"out_trade_no":  req.OrderNo,
		"out_refund_no": req.RefundNo,
		"reason":        req.Reason,
		"amount": map[string]interface{}{
			"refund":   req.AmountCents,
			"total":    req.AmountCents, // 简化：全额退款
			"currency": "CNY",
		},
	}
	bodyBytes, _ := json.Marshal(body)
	respBody, err := p.doRequest(ctx, http.MethodPost,
		"/v3/refund/domestic/refunds", bodyBytes)
	if err != nil {
		return nil, err
	}
	var r struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(respBody, &r); err != nil {
		return nil, fmt.Errorf("解析退款响应失败: %w", err)
	}
	status := "pending"
	if r.Status == "SUCCESS" {
		status = "success"
	} else if r.Status == "ABNORMAL" || r.Status == "CLOSED" {
		status = "failed"
	}
	return &RefundResp{RefundNo: req.RefundNo, Status: status}, nil
}

// doRequest 发起带 v3 签名的 HTTPS 请求。
func (p *WeChatProvider) doRequest(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	// 1) 构造签名串
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	nonce, err := genNonceStr(32)
	if err != nil {
		return nil, err
	}
	signStr := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n",
		method, path, timestamp, nonce, string(body))
	hashed := sha256.Sum256([]byte(signStr))
	sigBytes, err := rsa.SignPKCS1v15(nil, p.PrivateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return nil, fmt.Errorf("V3 请求签名失败: %w", err)
	}
	signature := base64.StdEncoding.EncodeToString(sigBytes)

	auth := fmt.Sprintf(
		`WECHATPAY2-SHA256-RSA2048 mchid="%s",nonce_str="%s",signature="%s",timestamp="%s",serial_no="%s"`,
		p.MchID, nonce, signature, timestamp, p.SerialNo,
	)

	// 2) 发起 HTTP
	httpReq, err := http.NewRequestWithContext(ctx, method, p.Gateway+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", auth)
	httpReq.Header.Set("Accept", "application/json")
	if body != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("微信支付请求失败: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("微信支付返回错误 status=%d body=%s", resp.StatusCode, string(respBody))
	}
	return respBody, nil
}

// decryptAEAD 用 AES-256-GCM 解密 base64(密文) 为明文。
// 用于微信支付回调资源解密：APIv3 Key 即 AES key（32 字节）；
// nonce/associated 为字符串；ciphertext 为 base64(密文+tag)。
func decryptAEAD(key []byte, associated, nonce, ciphertext string) ([]byte, error) {
	ctBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("ciphertext base64 解码失败: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("AES key 错误: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM 初始化失败: %w", err)
	}
	plain, err := gcm.Open(nil, []byte(nonce), ctBytes, []byte(associated))
	if err != nil {
		return nil, fmt.Errorf("AEAD 解密失败: %w", err)
	}
	return plain, nil
}

// genNonceStr 生成指定长度的随机十六进制串（n 必须为偶数）。
func genNonceStr(n int) (string, error) {
	if n%2 != 0 {
		n++
	}
	buf := make([]byte, n/2)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// mapWeChatTradeState 将微信 trade_state 映射为统一状态。
func mapWeChatTradeState(s string) string {
	switch strings.ToUpper(s) {
	case "SUCCESS":
		return "paid"
	case "USERPAYING", "NOTPAY":
		return "pending"
	case "CLOSED", "REVOKED":
		return "closed"
	default:
		return "failed"
	}
}

// _ 占用 math/big 导入，避免编译器误报；后续若启用付款明文证书序列号比对将启用。
var _ = big.NewInt
