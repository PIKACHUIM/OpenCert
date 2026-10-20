package identity

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ---- 三方回调认证 ----
//
// 平台把用户跳转到管理员配置的实名页面，并带上 session / callback / return / expires 参数；
// 实名服务在用户完成后回调本平台（JSON 或 form），本平台校验签名后更新会话。
//
// 校验方式：
//   - hmac ：X-Signature = hex(HMAC-SHA256(secret, body))，并校验时间戳（±10 分钟）
//   - token：X-Callback-Token == secret（恒定时间比较）
//   - none ：不校验（仅建议内网联调使用）

// callbackDriver 实现「三方回调认证」。
type callbackDriver struct {
	http *http.Client
}

func newCallbackDriver(client *http.Client) *callbackDriver {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &callbackDriver{http: client}
}

func init() {
	RegisterIdentityDriver("callback", newCallbackDriver(nil))
	// 旧名称仍可用，实际走 callback 实现
	RegisterIdentityDriver("webhook", newCallbackDriver(nil))
}

func (d *callbackDriver) Start(ctx context.Context, s *Store, p *Provider, sess *Session, in StartInput) (string, error) {
	raw := strings.TrimSpace(p.Config["request_url"])
	if raw == "" {
		return "", fmt.Errorf("实名页面地址未配置")
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return "", fmt.Errorf("实名页面地址必须是 http 或 https 地址")
	}
	// 只允许 http(s)，并拒绝链路本地地址（云环境的元数据服务），避免被用作内网探测跳板
	if err := guardCallbackURL(u); err != nil {
		return "", err
	}

	callbackURL := strings.TrimRight(in.BaseURL, "/") + "/api/identity/callback/" + p.UUID
	expires := time.Now().Add(30 * time.Minute).Unix()
	if sess.ExpiresAt != nil {
		expires = sess.ExpiresAt.Unix()
	}
	vars := map[string]string{
		"session":  sess.UUID,
		"callback": callbackURL,
		"return":   in.ReturnURL,
		"expires":  strconv.FormatInt(expires, 10),
	}
	for k, v := range in.Fields {
		if _, exists := vars[k]; !exists {
			vars[k] = v
		}
	}

	method := strings.ToUpper(strings.TrimSpace(p.Config["request_method"]))
	if method == "" {
		method = http.MethodGet
	}
	if method == http.MethodGet {
		q := u.Query()
		for k, v := range vars {
			q.Set(k, v)
		}
		u.RawQuery = q.Encode()
		return u.String(), nil
	}

	// POST：把变量渲染进请求体模板，从响应里取出跳转地址返回给前端
	body := renderTemplate(p.Config["request_body_template"], vars)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(body))
	if err != nil {
		return "", err
	}
	applyHeaders(req, p.Config["request_headers"])
	resp, err := d.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("请求实名页面失败: %w", err)
	}
	defer resp.Body.Close()
	rawResp, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("实名页面返回 %d: %s", resp.StatusCode, strings.TrimSpace(string(rawResp)))
	}
	if target := extractPath(rawResp, p.Config["result_url_path"], "data.url"); target != "" {
		return target, nil
	}
	return "", fmt.Errorf("实名页面响应中没有找到跳转地址，请检查「跳转地址取值」配置")
}

func (d *callbackDriver) Callback(ctx context.Context, s *Store, p *Provider, r *http.Request, body []byte) (*CallbackResult, []byte, error) {
	mode := strings.ToLower(strings.TrimSpace(p.Config["verify_mode"]))
	if mode == "" {
		mode = "hmac"
	}
	secret := p.Config["secret"]
	switch mode {
	case "none":
		// 不校验
	case "token":
		got := r.Header.Get("X-Callback-Token")
		if secret == "" || subtle.ConstantTimeCompare([]byte(got), []byte(secret)) != 1 {
			return nil, nil, fmt.Errorf("回调凭证校验失败")
		}
	case "hmac":
		if secret == "" {
			return nil, nil, fmt.Errorf("未配置回调签名密钥")
		}
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		want := hex.EncodeToString(mac.Sum(nil))
		got := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Signature")))
		if subtle.ConstantTimeCompare([]byte(want), []byte(got)) != 1 {
			return nil, nil, fmt.Errorf("回调签名校验失败")
		}
	default:
		return nil, nil, fmt.Errorf("不支持的回调校验方式: %s", mode)
	}

	values := parseCallbackBody(p.Config["callback_format"], body)
	sessionID := firstNonEmpty(values["session"], r.URL.Query().Get("session"))
	if sessionID == "" {
		return nil, nil, fmt.Errorf("回调缺少 session")
	}
	if ts := values["timestamp"]; ts != "" {
		sec, err := strconv.ParseInt(ts, 10, 64)
		if err != nil {
			return nil, nil, fmt.Errorf("回调时间戳格式错误")
		}
		if d := time.Since(time.Unix(sec, 0)); d > 10*time.Minute || d < -10*time.Minute {
			return nil, nil, fmt.Errorf("回调已过期")
		}
	}

	// 允许第三方用不同字段表达结果
	status := strings.ToLower(firstNonEmpty(values["status"], values["result"], values["code"]))
	passed := status == "passed" || status == "pass" || status == "success" ||
		status == "ok" || status == "0" || status == "true"
	message := firstNonEmpty(values["message"], values["msg"])

	res, err := s.applyCallbackResult(ctx, p, sessionID, passed, message)
	if err != nil {
		return nil, nil, err
	}
	respBody := []byte(p.Config["response_body"])
	if len(respBody) == 0 {
		respBody = []byte(`{"code":0,"message":"ok"}`)
	}
	return res, respBody, nil
}

func (d *callbackDriver) Query(ctx context.Context, s *Store, p *Provider, sess *Session) (*CallbackResult, error) {
	return nil, &ErrDriverNotSupported{Op: "查询"}
}

// parseCallbackBody 按配置的格式解析回调内容（JSON 或 form），统一成扁平字符串表。
func parseCallbackBody(format string, body []byte) map[string]string {
	values := map[string]string{}
	if strings.EqualFold(format, "form") {
		if v, err := url.ParseQuery(string(body)); err == nil {
			for k := range v {
				values[k] = v.Get(k)
			}
		}
		return values
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		// 非 JSON 时退回 form 解析，兼容第三方不按约定发送
		if v, e := url.ParseQuery(string(body)); e == nil {
			for k := range v {
				values[k] = v.Get(k)
			}
		}
		return values
	}
	for k, v := range raw {
		switch t := v.(type) {
		case string:
			values[k] = t
		case float64:
			values[k] = strconv.FormatFloat(t, 'f', -1, 64)
		case bool:
			values[k] = strconv.FormatBool(t)
		}
	}
	return values
}

// renderTemplate 渲染请求模板，对变量做 JSON 字符串转义，避免拼出非法 JSON。
func renderTemplate(tpl string, vars map[string]string) string {
	if strings.TrimSpace(tpl) == "" {
		return ""
	}
	out := tpl
	// 除引号与反斜杠外，还要把控制字符转成 \uXXXX：原始换行会直接破坏 JSON 请求体
	escaper := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`, "\t", `\t`)
	for k, v := range vars {
		escaped := escaper.Replace(v)
		out = strings.ReplaceAll(out, "{{"+k+"}}", escaped)
		out = strings.ReplaceAll(out, "${"+k+"}", escaped)
	}
	return out
}

// applyHeaders 解析每行一个 "名称: 值" 的请求头配置。
func applyHeaders(req *http.Request, raw string) {
	req.Header.Set("Content-Type", "application/json")
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		idx := strings.Index(line, ":")
		if idx <= 0 {
			continue
		}
		req.Header.Set(strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+1:]))
	}
}

// extractPath 按点号路径从 JSON 响应中取值（如 data.url）。
func extractPath(body []byte, paths ...string) string {
	var cur interface{}
	parsed := false
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !parsed {
			if err := json.Unmarshal(body, &cur); err != nil {
				return ""
			}
			parsed = true
		}
		node := cur
		for _, seg := range strings.Split(p, ".") {
			m, ok := node.(map[string]interface{})
			if !ok {
				node = nil
				break
			}
			node = m[seg]
		}
		if s, ok := node.(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// guardCallbackURL 拒绝链路本地地址（169.254.0.0/16 与 fe80::/10），
// 云环境中该网段几乎是元数据服务的固定地址，不能由认证配置随意访问。
// 内网地址与回环地址仍然允许，便于私有化部署把认证服务放在同一内网。
func guardCallbackURL(u *url.URL) error {
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("实名页面地址缺少主机名")
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		// 解析失败交给实际请求时报错，避免此处误判为配置错误
		return nil
	}
	for _, ip := range ips {
		if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("实名页面地址不能指向链路本地地址")
		}
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
