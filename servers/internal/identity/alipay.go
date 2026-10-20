package identity

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// ---- 支付宝身份验证 ----
//
// 流程：
//  1. alipay.user.certify.open.initialize 创建认证订单，返回 certify_id；
//  2. 把用户跳转到支付宝认证页（certify_url）；
//  3. 用户在支付宝内完成刷脸/证件核验；
//  4. 平台通过 alipay.user.certify.open.query 查询结果（回调不可达时也能补偿）。
//
// 签名算法：RSA2（SHA256withRSA），参数按字典序拼接待签串。

const alipayDefaultGateway = "https://openapi.alipay.com/gateway.do"

type alipayDriver struct {
	http *http.Client
}

func init() {
	RegisterIdentityDriver("alipay", &alipayDriver{http: &http.Client{Timeout: 15 * time.Second}})
}

// alipaySign 计算 RSA2 签名（base64）。
func alipaySign(privateKey *rsa.PrivateKey, content string) (string, error) {
	sum := sha256.Sum256([]byte(content))
	sig, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// parseRSAPrivateKey 解析支付宝应用私钥（支持带 PEM 头、纯 base64、PKCS#8 / PKCS#1）。
func parseRSAPrivateKey(raw string) (*rsa.PrivateKey, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("应用私钥为空")
	}
	der := []byte(raw)
	if block, _ := pem.Decode([]byte(raw)); block != nil {
		der = block.Bytes
	} else {
		cleaned := strings.Join(strings.Fields(raw), "")
		if decoded, err := base64.StdEncoding.DecodeString(cleaned); err == nil {
			der = decoded
		}
	}
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if rk, ok := k.(*rsa.PrivateKey); ok {
			return rk, nil
		}
		return nil, fmt.Errorf("应用私钥不是 RSA 私钥")
	}
	if rk, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return rk, nil
	}
	return nil, fmt.Errorf("无法解析应用私钥（支持 PKCS#8 / PKCS#1）")
}

// alipaySignContent 按支付宝规则拼接待签名字符串：过滤空值与 sign，按键名字典序。
func alipaySignContent(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k, v := range params {
		if k == "sign" || strings.TrimSpace(v) == "" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	for i, k := range keys {
		if i > 0 {
			sb.WriteByte('&')
		}
		sb.WriteString(k)
		sb.WriteByte('=')
		sb.WriteString(params[k])
	}
	return sb.String()
}

// call 发起一次 OpenAPI 调用并返回原始 JSON 响应。
func (d *alipayDriver) call(ctx context.Context, cfg map[string]string, method string, biz map[string]interface{}) (map[string]interface{}, error) {
	priv, err := parseRSAPrivateKey(cfg["private_key"])
	if err != nil {
		return nil, err
	}
	bizJSON, err := json.Marshal(biz)
	if err != nil {
		return nil, err
	}
	params := map[string]string{
		"app_id":      cfg["app_id"],
		"method":      method,
		"format":      "JSON",
		"charset":     "utf-8",
		"sign_type":   "RSA2",
		"timestamp":   time.Now().Format("2006-01-02 15:04:05"),
		"version":     "1.0",
		"biz_content": string(bizJSON),
	}
	sign, err := alipaySign(priv, alipaySignContent(params))
	if err != nil {
		return nil, fmt.Errorf("支付宝签名失败: %w", err)
	}
	params["sign"] = sign

	form := url.Values{}
	for k, v := range params {
		form.Set(k, v)
	}
	gateway := strings.TrimSpace(cfg["gateway"])
	if gateway == "" {
		gateway = alipayDefaultGateway
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, gateway, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=utf-8")
	resp, err := d.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求支付宝失败: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out map[string]interface{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("支付宝返回内容无法解析: %s", strings.TrimSpace(string(raw)))
	}
	// 失败时支付宝返回 {"alipay_xxx_response":{"code":"40004","sub_msg":"..."}}
	key := strings.ReplaceAll(method, ".", "_") + "_response"
	if node, ok := out[key].(map[string]interface{}); ok {
		if code, _ := node["code"].(string); code != "" && code != "10000" {
			msg, _ := node["sub_msg"].(string)
			if msg == "" {
				msg, _ = node["msg"].(string)
			}
			return nil, fmt.Errorf("支付宝返回 %s: %s", code, msg)
		}
	}
	return out, nil
}

func (d *alipayDriver) Start(ctx context.Context, s *Store, p *Provider, sess *Session, in StartInput) (string, error) {
	biz := map[string]interface{}{
		"outer_order_no": sess.UUID,
		"biz_code":       "IDENTITY_VERIFICATION",
	}
	identity := map[string]interface{}{
		"identity_type": "CERT_INFO",
		"cert_type":     firstNonEmpty(p.Config["identity_param"], "IDENTITY_CARD"),
	}
	if name := firstNonEmpty(in.Fields["name"], in.Fields["real_name"], in.Fields["CN"]); name != "" {
		identity["cert_name"] = name
	}
	if no := firstNonEmpty(in.Fields["id_number"], in.Fields["cert_no"], in.Fields["id_card"]); no != "" {
		identity["cert_no"] = no
	}
	biz["identity_param"] = identity

	returnURL := firstNonEmpty(p.Config["return_url"], in.ReturnURL)
	if returnURL != "" {
		biz["merchant_config"] = map[string]interface{}{"return_url": returnURL}
	}

	out, err := d.call(ctx, p.Config, "alipay.user.certify.open.initialize", biz)
	if err != nil {
		return "", err
	}
	node, _ := out["alipay_user_certify_open_initialize_response"].(map[string]interface{})
	if node == nil {
		return "", fmt.Errorf("支付宝未返回认证订单")
	}
	// 新版直接返回 certify_url；旧版返回 certify_id，需要拼认证页地址
	if u, ok := node["certify_url"].(string); ok && u != "" {
		return u, nil
	}
	certifyID, _ := node["certify_id"].(string)
	if certifyID == "" {
		return "", fmt.Errorf("支付宝未返回认证地址或认证 ID")
	}
	gateway := firstNonEmpty(p.Config["gateway"], alipayDefaultGateway)
	return gateway + "?certify_id=" + url.QueryEscape(certifyID), nil
}

func (d *alipayDriver) Callback(ctx context.Context, s *Store, p *Provider, r *http.Request, body []byte) (*CallbackResult, []byte, error) {
	// 支付宝通过 return_url 返回，不带可信结果；这里只用于把请求转成查询，
	// 真实结果一律以查询接口为准。
	sessionID := firstNonEmpty(r.URL.Query().Get("out_order_no"), r.URL.Query().Get("session"))
	if sessionID == "" {
		return nil, nil, fmt.Errorf("回调缺少 session")
	}
	res, err := s.QueryIdentity(ctx, p.UUID, sessionID)
	if err != nil {
		return nil, nil, err
	}
	return res, []byte(`{"code":0,"message":"ok"}`), nil
}

func (d *alipayDriver) Query(ctx context.Context, s *Store, p *Provider, sess *Session) (*CallbackResult, error) {
	out, err := d.call(ctx, p.Config, "alipay.user.certify.open.query", map[string]interface{}{
		"certify_id": sess.UUID,
	})
	if err != nil {
		return nil, err
	}
	node, _ := out["alipay_user_certify_open_query_response"].(map[string]interface{})
	if node == nil {
		return nil, fmt.Errorf("支付宝未返回查询结果")
	}
	passed, _ := node["passed"].(string)
	status := strings.ToUpper(passed)
	result := &CallbackResult{
		SessionUUID:     sess.UUID,
		SubjectInfoUUID: sess.SubjectInfoUUID,
		Passed:          status == "T" || status == "TRUE" || status == "PASSED",
		Message:         firstNonEmpty(passed, ""),
	}
	return s.applyCallbackResult(ctx, p, sess.UUID, result.Passed, result.Message)
}
