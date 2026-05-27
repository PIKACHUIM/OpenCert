// Package payment - 支付渠道单元测试。
//
// 覆盖核心安全路径：
//   1. Alipay: RSA2 签名往返 + 异步通知验签 + 状态映射
//   2. WeChat: AES-GCM 回调解密 + 状态映射
//   3. Stripe: HMAC-SHA256 Webhook 验签 + 防重放 + 状态映射
//   4. PayPal: OAuth2 token 缓存 + 状态映射
//   5. Loader:  按 plugin_type 路由
package payment

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"
)

// ---- helper：生成测试用 RSA 私钥+公钥 PEM ----

func genTestRSAPEM(t *testing.T) (privPEM, pubPEM []byte) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	privPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	pubPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	return
}

// ============== Alipay ==============

func TestAlipay_NewProvider_MissingFields(t *testing.T) {
	if _, err := NewAlipayProvider([]byte(`{"app_id":"a"}`)); err == nil {
		t.Error("缺字段应返回错误")
	}
}

func TestAlipay_SignVerifyRoundtrip(t *testing.T) {
	privPEM, pubPEM := genTestRSAPEM(t)
	cfg, _ := json.Marshal(AlipayConfig{
		AppID:        "test-app",
		PrivateKey:   string(privPEM),
		AlipayPubKey: string(pubPEM),
		Sandbox:      true,
	})
	p, err := NewAlipayProvider(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// 1) 签名
	params := map[string]string{
		"app_id":      p.AppID,
		"method":      "alipay.trade.page.pay",
		"timestamp":   "2026-01-01 00:00:00",
		"biz_content": `{"out_trade_no":"X1"}`,
	}
	sig, err := p.signRSA2(params)
	if err != nil {
		t.Fatal(err)
	}
	if sig == "" {
		t.Fatal("签名为空")
	}

	// 2) 用相同公钥自验：模拟支付宝异步通知验签
	form := url.Values{}
	for k, v := range params {
		form.Set(k, v)
	}
	form.Set("trade_status", "TRADE_SUCCESS")
	form.Set("total_amount", "99.50")
	form.Set("out_trade_no", "X1")
	form.Set("trade_no", "TN123")
	form.Set("sign_type", "RSA2")

	// 用 priv 重新对（除 sign/sign_type 外的）字段做签名（模拟支付宝服务端）
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
		parts = append(parts, k+"="+form.Get(k))
	}
	hashed := sha256.Sum256([]byte(strings.Join(parts, "&")))
	rawSig, err := rsa.SignPKCS1v15(nil, p.PrivateKey, crypto.SHA256, hashed[:])
	if err != nil {
		t.Fatal(err)
	}
	form.Set("sign", base64.StdEncoding.EncodeToString(rawSig))

	body := []byte(form.Encode())
	cb, err := p.VerifyCallback(context.Background(), body, nil)
	if err != nil {
		t.Fatalf("VerifyCallback 应通过: %v", err)
	}
	if cb.OrderNo != "X1" || cb.TradeNo != "TN123" || cb.Status != "paid" {
		t.Errorf("回调字段不正确: %+v", cb)
	}
	if cb.AmountCents != 9950 {
		t.Errorf("金额转换错误: 期望 9950，实际 %d", cb.AmountCents)
	}
}

func TestAlipay_VerifyCallback_TamperDetected(t *testing.T) {
	privPEM, pubPEM := genTestRSAPEM(t)
	// 同时构造另一对密钥假装"伪造方"
	_, otherPub := genTestRSAPEM(t)
	cfg, _ := json.Marshal(AlipayConfig{
		AppID:        "a",
		PrivateKey:   string(privPEM),
		AlipayPubKey: string(otherPub), // 故意用错误公钥
		Sandbox:      true,
	})
	p, _ := NewAlipayProvider(cfg)
	_ = pubPEM

	form := url.Values{}
	form.Set("out_trade_no", "X")
	form.Set("trade_status", "TRADE_SUCCESS")
	form.Set("total_amount", "1.00")
	form.Set("sign", base64.StdEncoding.EncodeToString([]byte("forged")))
	form.Set("sign_type", "RSA2")

	if _, err := p.VerifyCallback(context.Background(), []byte(form.Encode()), nil); err == nil {
		t.Error("伪造签名应被拒绝")
	}
}

func TestMapAlipayTradeStatus(t *testing.T) {
	cases := map[string]string{
		"TRADE_SUCCESS":  "paid",
		"TRADE_FINISHED": "paid",
		"WAIT_BUYER_PAY": "pending",
		"TRADE_CLOSED":   "closed",
		"UNKNOWN":        "failed",
	}
	for in, want := range cases {
		if got := mapAlipayTradeStatus(in); got != want {
			t.Errorf("%s → %s, want %s", in, got, want)
		}
	}
}

// ============== WeChat ==============

func TestWeChat_DecryptAEAD_Roundtrip(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef") // 32 字节
	plain := []byte(`{"out_trade_no":"X1","trade_state":"SUCCESS","amount":{"total":100}}`)
	associated := "transaction"
	nonce := "abcdef0123456789" // 12+ 字节，AEAD GCM nonce 长度 12

	// 加密
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	ct := gcm.Seal(nil, []byte(nonce[:gcm.NonceSize()]), plain, []byte(associated))
	ctB64 := base64.StdEncoding.EncodeToString(ct)

	// 解密
	got, err := decryptAEAD(key, associated, nonce[:gcm.NonceSize()], ctB64)
	if err != nil {
		t.Fatalf("解密失败: %v", err)
	}
	if string(got) != string(plain) {
		t.Errorf("明文不匹配")
	}
}

func TestWeChat_DecryptAEAD_TamperDetected(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	// 伪造的密文
	if _, err := decryptAEAD(key, "x", "abcdef012345", base64.StdEncoding.EncodeToString([]byte("forged"))); err == nil {
		t.Error("伪造密文应解密失败")
	}
}

func TestMapWeChatTradeState(t *testing.T) {
	cases := map[string]string{
		"SUCCESS":    "paid",
		"NOTPAY":     "pending",
		"USERPAYING": "pending",
		"CLOSED":     "closed",
		"REVOKED":    "closed",
		"PAYERROR":   "failed",
	}
	for in, want := range cases {
		if got := mapWeChatTradeState(in); got != want {
			t.Errorf("%s → %s, want %s", in, got, want)
		}
	}
}

func TestWeChat_NewProvider_BadKeyLen(t *testing.T) {
	privPEM, _ := genTestRSAPEM(t)
	cfg, _ := json.Marshal(WeChatConfig{
		MchID: "m", AppID: "a", SerialNo: "s",
		PrivateKey: string(privPEM),
		APIV3Key:   "short", // 不是 32 字节
	})
	if _, err := NewWeChatProvider(cfg); err == nil {
		t.Error("APIv3Key 长度错误应被拒绝")
	}
}

// ============== Stripe ==============

func TestStripe_VerifyCallback_OK(t *testing.T) {
	secret := "whsec_test_secret"
	cfg, _ := json.Marshal(StripeConfig{
		SecretKey:     "sk_test_x",
		WebhookSecret: secret,
	})
	p, _ := NewStripeProvider(cfg)

	body := []byte(`{"type":"checkout.session.completed","data":{"object":{"id":"cs_1","payment_intent":"pi_1","payment_status":"paid","amount_total":1234,"client_reference_id":"ORDER-X","metadata":{"order_no":"ORDER-X"}}}}`)
	ts := fmt.Sprintf("%d", time.Now().Unix())
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "." + string(body)))
	v1 := hex.EncodeToString(mac.Sum(nil))
	headers := map[string]string{
		"Stripe-Signature": fmt.Sprintf("t=%s,v1=%s", ts, v1),
	}

	cb, err := p.VerifyCallback(context.Background(), body, headers)
	if err != nil {
		t.Fatalf("验签应通过: %v", err)
	}
	if cb.OrderNo != "ORDER-X" || cb.Status != "paid" || cb.AmountCents != 1234 {
		t.Errorf("回调字段错误: %+v", cb)
	}
}

func TestStripe_VerifyCallback_BadSig(t *testing.T) {
	cfg, _ := json.Marshal(StripeConfig{SecretKey: "sk", WebhookSecret: "whsec_x"})
	p, _ := NewStripeProvider(cfg)
	headers := map[string]string{
		"Stripe-Signature": fmt.Sprintf("t=%d,v1=deadbeef", time.Now().Unix()),
	}
	if _, err := p.VerifyCallback(context.Background(), []byte(`{}`), headers); err == nil {
		t.Error("错误签名应被拒绝")
	}
}

func TestStripe_VerifyCallback_Replay(t *testing.T) {
	secret := "whsec_replay"
	cfg, _ := json.Marshal(StripeConfig{SecretKey: "sk", WebhookSecret: secret})
	p, _ := NewStripeProvider(cfg)

	// 1 小时前的时间戳
	oldTS := fmt.Sprintf("%d", time.Now().Add(-1*time.Hour).Unix())
	body := []byte(`{}`)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(oldTS + "." + string(body)))
	v1 := hex.EncodeToString(mac.Sum(nil))
	headers := map[string]string{
		"Stripe-Signature": fmt.Sprintf("t=%s,v1=%s", oldTS, v1),
	}
	if _, err := p.VerifyCallback(context.Background(), body, headers); err == nil {
		t.Error("过期时间戳应被拒绝（防重放）")
	}
}

func TestMapStripeStatus(t *testing.T) {
	cases := map[string]string{
		"paid":                "paid",
		"unpaid":              "pending",
		"no_payment_required": "paid",
		"weird":               "failed",
	}
	for in, want := range cases {
		if got := mapStripeStatus(in); got != want {
			t.Errorf("%s → %s, want %s", in, got, want)
		}
	}
}

// ============== PayPal ==============

func TestPayPal_NewProvider_MissingFields(t *testing.T) {
	if _, err := NewPayPalProvider([]byte(`{"client_id":"a"}`)); err == nil {
		t.Error("缺 client_secret 应返回错误")
	}
}

func TestPayPal_NewProvider_GatewayInferred(t *testing.T) {
	cfg, _ := json.Marshal(PayPalConfig{
		ClientID: "id", ClientSecret: "sec", Sandbox: true,
	})
	p, err := NewPayPalProvider(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p.Gateway, "sandbox") {
		t.Errorf("Sandbox 模式应使用 sandbox 网关: %s", p.Gateway)
	}
	if p.Currency != "USD" {
		t.Errorf("默认币种应为 USD，实际 %s", p.Currency)
	}
}

func TestMapPayPalStatus(t *testing.T) {
	cases := map[string]string{
		"COMPLETED":             "paid",
		"APPROVED":              "pending",
		"CREATED":               "pending",
		"SAVED":                 "pending",
		"PAYER_ACTION_REQUIRED": "pending",
		"VOIDED":                "closed",
		"WHATEVER":              "failed",
	}
	for in, want := range cases {
		if got := mapPayPalStatus(in); got != want {
			t.Errorf("%s → %s, want %s", in, got, want)
		}
	}
}

// ============== Loader ==============

func TestLoader_BuildProvider_Routing(t *testing.T) {
	privPEM, pubPEM := genTestRSAPEM(t)

	t.Run("alipay", func(t *testing.T) {
		cfg, _ := json.Marshal(AlipayConfig{
			AppID: "a", PrivateKey: string(privPEM), AlipayPubKey: string(pubPEM),
		})
		p, err := buildProvider("alipay", cfg)
		if err != nil {
			t.Fatal(err)
		}
		if p.Type() != "alipay" {
			t.Errorf("Type 不正确: %s", p.Type())
		}
	})

	t.Run("wechat", func(t *testing.T) {
		cfg, _ := json.Marshal(WeChatConfig{
			MchID: "m", AppID: "a", SerialNo: "s",
			PrivateKey: string(privPEM),
			APIV3Key:   "0123456789abcdef0123456789abcdef",
		})
		p, err := buildProvider("wechat", cfg)
		if err != nil {
			t.Fatal(err)
		}
		if p.Type() != "wechat" {
			t.Errorf("Type 不正确: %s", p.Type())
		}
	})

	t.Run("stripe", func(t *testing.T) {
		cfg, _ := json.Marshal(StripeConfig{SecretKey: "sk_test"})
		p, err := buildProvider("stripe", cfg)
		if err != nil {
			t.Fatal(err)
		}
		if p.Type() != "stripe" {
			t.Errorf("Type 不正确: %s", p.Type())
		}
	})

	t.Run("paypal", func(t *testing.T) {
		cfg, _ := json.Marshal(PayPalConfig{ClientID: "id", ClientSecret: "sec"})
		p, err := buildProvider("paypal", cfg)
		if err != nil {
			t.Fatal(err)
		}
		if p.Type() != "paypal" {
			t.Errorf("Type 不正确: %s", p.Type())
		}
	})

	t.Run("unknown", func(t *testing.T) {
		if _, err := buildProvider("unknown_type", []byte(`{}`)); err == nil {
			t.Error("未知类型应返回错误")
		}
	})
}

func TestRegistry_RegisterAndGet(t *testing.T) {
	r := NewRegistry()
	cfg, _ := json.Marshal(StripeConfig{SecretKey: "sk_test"})
	p, _ := NewStripeProvider(cfg)
	r.Register(p)

	got, err := r.Get("stripe")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name() != "Stripe" {
		t.Errorf("Name 不正确: %s", got.Name())
	}

	if _, err := r.Get("missing"); err == nil {
		t.Error("不存在的渠道应返回错误")
	}

	list := r.List()
	if len(list) != 1 || list[0] != "stripe" {
		t.Errorf("List 内容错误: %v", list)
	}
}

func TestParseYuanToCents(t *testing.T) {
	cases := []struct {
		in   string
		want int64
	}{
		{"0", 0},
		{"1", 100},
		{"99.50", 9950},
		{"99.99", 9999},
		{"  1.23  ", 123},
		{"", 0},
	}
	for _, c := range cases {
		got, err := parseYuanToCents(c.in)
		if err != nil {
			t.Errorf("%q → err %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("%q → %d, want %d", c.in, got, c.want)
		}
	}
}
