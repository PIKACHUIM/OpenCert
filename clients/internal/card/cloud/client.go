// Package cloud 提供 servers 的 HTTP 客户端。
// Cloud Slot 通过此客户端与 servers 通信。
package cloud

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// 认证与授权相关的可判定错误。
//
// 调用方需要据此区分"账号问题"与"云卡 PIN 问题"，并避免在 PIN 错误时
// 盲目重试消耗重试次数。
var (
	// ErrTOTPRequired 表示账号启用了二次验证，需要先完成 TOTP 校验
	ErrTOTPRequired = errors.New("账号需要动态验证码（TOTP）二次验证")
	// ErrPINRequired 表示高敏操作需要有效的云卡 PIN 会话
	ErrPINRequired = errors.New("需要云卡 PIN 授权")
	// ErrDeliveryDenied 表示云端策略不允许下发该证书的私钥
	ErrDeliveryDenied = errors.New("云端策略不允许下发该证书")
	// ErrInvalidCredentials 表示账号或密码错误
	ErrInvalidCredentials = errors.New("账号或密码错误")
)

// Client 是 servers（OpenCert Platform）的 HTTP 客户端。
type Client struct {
	mu             sync.RWMutex
	baseURL        string
	token          string
	tokenExpiresAt time.Time // Token 过期时间
	httpClient     *http.Client
	allowInsecure  bool // 是否允许非 HTTPS（仅开发环境）

	// 云卡 PIN 会话：cardUUID -> 会话令牌（仅驻留内存，不落盘）
	pinMu       sync.RWMutex
	pinSessions map[string]pinSession
}

// NewClient 创建 servers 客户端。
// baseURL 生产环境必须为 https://，开发环境可通过 allowInsecure=true 允许 http://。
func NewClient(baseURL string, allowInsecure bool) (*Client, error) {
	// 校验 URL scheme
	if !strings.HasPrefix(baseURL, "https://") {
		if !allowInsecure {
			return nil, fmt.Errorf("Cloud Slot 要求 HTTPS 连接，当前 URL: %s（如需开发环境使用 HTTP，请设置 allow_insecure_cloud=true）", baseURL)
		}
		slog.Warn("⚠️ Cloud Slot 使用不安全的 HTTP 连接", "url", baseURL)
	}

	// 配置 TLS：不跳过证书验证
	tlsConfig := &tls.Config{
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS12,
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	return &Client{
		baseURL:       strings.TrimRight(baseURL, "/"),
		allowInsecure: allowInsecure,
		pinSessions:   make(map[string]pinSession),
		httpClient: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		},
	}, nil
}

// SetToken 设置认证 Token 和过期时间。
func (c *Client) SetToken(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = token
	// 默认设置 Token 有效期为 1 小时
	c.tokenExpiresAt = time.Now().Add(1 * time.Hour)
}

// SetTokenWithExpiry 设置认证 Token 和自定义过期时间。
func (c *Client) SetTokenWithExpiry(token string, expiresAt time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = token
	c.tokenExpiresAt = expiresAt
}

// Token 返回当前 Token。
func (c *Client) Token() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.token
}

// IsTokenExpiringSoon 检查 Token 是否即将过期（剩余时间 < 总时间的 20%）。
func (c *Client) IsTokenExpiringSoon() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.token == "" {
		return false
	}
	remaining := time.Until(c.tokenExpiresAt)
	return remaining < 12*time.Minute // 1小时的20%
}

// IsTokenExpired 检查 Token 是否已过期。
func (c *Client) IsTokenExpired() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.token == "" {
		return true
	}
	return time.Now().After(c.tokenExpiresAt)
}

// EnsureToken 确保 Token 有效，过期或即将过期时自动 refresh。
func (c *Client) EnsureToken(ctx context.Context) error {
	if c.IsTokenExpired() || c.IsTokenExpiringSoon() {
		_, err := c.Refresh(ctx)
		if err != nil {
			slog.Warn("JWT Token 刷新失败", "error", err)
			return fmt.Errorf("token refresh 失败: %w", err)
		}
		slog.Debug("JWT Token 已自动刷新")
	}
	return nil
}

// ---- 认证 API ----

// LoginResponse 是登录响应。
//
// 当账号绑定了 TOTP 时，服务端不会返回 token，而是返回
// require_totp + session_token，必须先调用 VerifyTOTP 完成二次验证。
type LoginResponse struct {
	Token     string `json:"token"`
	UserUUID  string `json:"user_uuid"`
	Username  string `json:"username"`
	Role      string `json:"role"`
	ExpiresAt string `json:"expires_at"`

	RequireTOTP  bool   `json:"require_totp"`
	SessionToken string `json:"session_token"`
}

// Login 登录 servers，获取 JWT Token。
//
// 若账号启用了二次验证，将返回 ErrTOTPRequired 且不写入任何 Token，
// 避免出现"登录成功但 Token 为空、后续操作全部 401"的静默失败。
func (c *Client) Login(ctx context.Context, username, password string) (*LoginResponse, error) {
	body := map[string]string{"username": username, "password": password}
	var resp LoginResponse
	if err := c.post(ctx, "/api/auth/login", body, &resp); err != nil {
		// 401 通常意味着账号或密码错误，转换为可判定错误，便于上层提示
		if strings.Contains(err.Error(), "401") {
			return nil, fmt.Errorf("%w: %v", ErrInvalidCredentials, err)
		}
		return nil, fmt.Errorf("登录失败: %w", err)
	}

	if resp.RequireTOTP {
		c.clearToken()
		return &resp, ErrTOTPRequired
	}
	if resp.Token == "" {
		c.clearToken()
		return nil, fmt.Errorf("登录失败: 服务端未返回访问令牌")
	}

	// 必须同时记录过期时间：否则 tokenExpiresAt 为零值，IsTokenExpired 恒为 true，
	// 之后的每次签名/解密都会先触发一次多余的 /api/auth/refresh。
	c.SetTokenWithExpiry(resp.Token, resolveTokenExpiry(resp.ExpiresAt))
	return &resp, nil
}

// VerifyTOTP 使用登录返回的 session_token 完成二次验证。
func (c *Client) VerifyTOTP(ctx context.Context, sessionToken, code string) (*LoginResponse, error) {
	if sessionToken == "" {
		return nil, fmt.Errorf("缺少会话令牌，请重新输入账号密码")
	}
	if code == "" {
		return nil, fmt.Errorf("请输入动态验证码")
	}

	var resp LoginResponse
	if err := c.post(ctx, "/api/auth/totp-verify",
		map[string]string{"session_token": sessionToken, "code": code}, &resp); err != nil {
		// 验证码错误会消耗失败次数，因此不在这里自动重试
		return nil, fmt.Errorf("二次验证失败: %w", err)
	}
	if resp.Token == "" {
		return nil, fmt.Errorf("二次验证失败: 服务端未返回访问令牌")
	}
	c.SetTokenWithExpiry(resp.Token, resolveTokenExpiry(resp.ExpiresAt))
	return &resp, nil
}

// clearToken 清空本地 Token 状态（登录未完成或退出时使用）。
func (c *Client) clearToken() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = ""
	c.tokenExpiresAt = time.Time{}
}

// Refresh 刷新 Token。
func (c *Client) Refresh(ctx context.Context) (*LoginResponse, error) {
	var resp LoginResponse
	if err := c.post(ctx, "/api/auth/refresh", nil, &resp); err != nil {
		return nil, fmt.Errorf("刷新 Token 失败: %w", err)
	}
	c.SetTokenWithExpiry(resp.Token, resolveTokenExpiry(resp.ExpiresAt))
	return &resp, nil
}

// resolveTokenExpiry 解析服务端返回的 expires_at（RFC3339）。
// 缺失或格式不可识别时回退为 1 小时，避免使用零值时间导致 Token 被判定为已过期。
func resolveTokenExpiry(raw string) time.Time {
	if raw != "" {
		if t, err := time.Parse(time.RFC3339, raw); err == nil {
			return t
		}
	}
	return time.Now().Add(1 * time.Hour)
}

// ---- 卡片 API ----

// Card 是云端卡片信息。
type Card struct {
	UUID      string    `json:"uuid"`
	UserUUID  string    `json:"user_uuid"`
	CardName  string    `json:"card_name"`
	Remark    string    `json:"remark"`
	CreatedAt time.Time `json:"created_at"`
}

// ListCards 列出用户的所有云端卡片。
func (c *Client) ListCards(ctx context.Context) ([]*Card, error) {
	var resp struct {
		Cards []*Card `json:"cards"`
	}
	if err := c.get(ctx, "/api/cards", &resp); err != nil {
		return nil, fmt.Errorf("获取卡片列表失败: %w", err)
	}
	return resp.Cards, nil
}

// ---- 证书 API ----

// Cert 是云端证书信息（不含私钥）。
//
// 除公开的证书内容外，还同步有效期、主体与吊销状态等元数据，
// 否则客户端无法展示证书信息，也无法感知证书已过期或被吊销。
type Cert struct {
	UUID                string     `json:"uuid"`
	CardUUID            string     `json:"card_uuid"`
	CertType            string     `json:"cert_type"`
	KeyType             string     `json:"key_type"`
	CertContent         []byte     `json:"cert_content"`
	Remark              string     `json:"remark"`
	CAUUID              string     `json:"ca_uuid,omitempty"`
	SerialNumber        string     `json:"serial_number,omitempty"`
	SerialHex           string     `json:"serial_hex,omitempty"`
	SubjectDN           string     `json:"subject_dn,omitempty"`
	IssuerDN            string     `json:"issuer_dn,omitempty"`
	NotBefore           *time.Time `json:"not_before,omitempty"`
	NotAfter            *time.Time `json:"not_after,omitempty"`
	KeyUsage            int        `json:"key_usage,omitempty"`
	SANDNS              string     `json:"san_dns,omitempty"`
	SANIP               string     `json:"san_ip,omitempty"`
	SANEmail            string     `json:"san_email,omitempty"`
	SANURI              string     `json:"san_uris,omitempty"`
	RevocationStatus    string     `json:"revocation_status,omitempty"`
	IssuanceTmplUUID    string     `json:"issuance_tmpl_uuid,omitempty"`
	CertificatePolicies string     `json:"certificate_policies,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
}

// ListCerts 列出卡片的所有证书。
func (c *Client) ListCerts(ctx context.Context, cardUUID string) ([]*Cert, error) {
	var resp struct {
		Certs []*Cert `json:"certs"`
	}
	if err := c.get(ctx, fmt.Sprintf("/api/cards/%s/certs", cardUUID), &resp); err != nil {
		return nil, fmt.Errorf("获取证书列表失败: %w", err)
	}
	return resp.Certs, nil
}

// ---- 云卡 PIN 会话 ----

// pinSession 是某张云卡的 PIN 授权会话。
type pinSession struct {
	Token     string
	ExpiresAt time.Time
}

// VerifyPIN 校验云卡 PIN，成功后缓存会话令牌。
//
// 服务端返回字段为 pin_session_token / expires_at，与旧的 session_token
// 假设不同，这里按实际契约解析。
func (c *Client) VerifyPIN(ctx context.Context, cardUUID, pin string) (time.Time, error) {
	if cardUUID == "" {
		return time.Time{}, fmt.Errorf("缺少云卡 UUID")
	}
	if pin == "" {
		return time.Time{}, fmt.Errorf("请输入云卡 PIN")
	}

	var resp struct {
		Success   bool   `json:"success"`
		Session   string `json:"pin_session_token"`
		ExpiresAt string `json:"expires_at"`
		TTL       int    `json:"ttl_seconds"`
		Remaining int    `json:"remaining"`
	}
	if err := c.post(ctx, fmt.Sprintf("/api/cards/%s/verify-pin", cardUUID),
		map[string]string{"pin": pin}, &resp); err != nil {
		return time.Time{}, fmt.Errorf("云卡 PIN 校验失败: %w", err)
	}
	if !resp.Success || resp.Session == "" {
		return time.Time{}, fmt.Errorf("云卡 PIN 校验失败，剩余尝试次数 %d", resp.Remaining)
	}

	expiresAt := resolveTokenExpiry(resp.ExpiresAt)
	if resp.ExpiresAt == "" && resp.TTL > 0 {
		expiresAt = time.Now().Add(time.Duration(resp.TTL) * time.Second)
	}

	c.pinMu.Lock()
	c.pinSessions[cardUUID] = pinSession{Token: resp.Session, ExpiresAt: expiresAt}
	c.pinMu.Unlock()

	return expiresAt, nil
}

// ClearPINSession 清除指定云卡的 PIN 会话（退出登录或账号切换时调用）。
func (c *Client) ClearPINSession(cardUUID string) {
	c.pinMu.Lock()
	defer c.pinMu.Unlock()
	if cardUUID == "" {
		c.pinSessions = make(map[string]pinSession)
		return
	}
	delete(c.pinSessions, cardUUID)
}

// HasPINSession 判断某张云卡是否持有有效的 PIN 会话。
func (c *Client) HasPINSession(cardUUID string) bool {
	c.pinMu.RLock()
	defer c.pinMu.RUnlock()
	s, ok := c.pinSessions[cardUUID]
	return ok && s.Token != "" && time.Now().Before(s.ExpiresAt)
}

// pinToken 返回有效的 PIN 会话令牌，过期则返回空串并清理。
func (c *Client) pinToken(cardUUID string) string {
	c.pinMu.RLock()
	s, ok := c.pinSessions[cardUUID]
	c.pinMu.RUnlock()
	if !ok || s.Token == "" {
		return ""
	}
	if time.Now().After(s.ExpiresAt) {
		c.ClearPINSession(cardUUID)
		return ""
	}
	return s.Token
}

// ---- 签名/解密 API ----

// Sign 请求 servers 使用云端私钥签名。
//
// 会附带已有的云卡 PIN 会话；若服务端要求 PIN 而本地没有有效会话，
// 返回 ErrPINRequired，由上层提示用户输入 PIN，而不是无差别报错或重试。
func (c *Client) Sign(ctx context.Context, cardUUID, certUUID, mechanism string, data []byte) ([]byte, error) {
	body := map[string]interface{}{
		"cert_uuid": certUUID,
		"mechanism": mechanism,
		"data":      data,
	}
	var resp struct {
		Signature []byte `json:"signature"`
	}
	if err := c.postWithPIN(ctx, fmt.Sprintf("/api/cards/%s/sign", cardUUID), cardUUID, body, &resp); err != nil {
		return nil, fmt.Errorf("云端签名失败: %w", err)
	}
	return resp.Signature, nil
}

// Decrypt 请求 servers 使用云端私钥解密（仅 RSA 私钥支持）。
func (c *Client) Decrypt(ctx context.Context, cardUUID, certUUID, mechanism string, ciphertext []byte) ([]byte, error) {
	body := map[string]interface{}{
		"cert_uuid":  certUUID,
		"mechanism":  mechanism,
		"ciphertext": ciphertext,
	}
	var resp struct {
		Plaintext []byte `json:"plaintext"`
	}
	if err := c.postWithPIN(ctx, fmt.Sprintf("/api/cards/%s/decrypt", cardUUID), cardUUID, body, &resp); err != nil {
		return nil, fmt.Errorf("云端解密失败: %w", err)
	}
	return resp.Plaintext, nil
}

// ---- HTTP 工具方法 ----

// postWithPIN 发送需要云卡 PIN 授权的 POST 请求。
// 本地无有效会话时不预判失败，而是直接请求，由服务端 401 + X-PIN-Required 决定，
// 这样服务端对"未设置 PIN 的历史卡片放行"的兼容行为也能正常工作。
func (c *Client) postWithPIN(ctx context.Context, path, cardUUID string, body interface{}, out interface{}) error {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("序列化请求体失败: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bodyReader)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token := c.pinToken(cardUUID); token != "" {
		req.Header.Set("X-PIN-Session", token)
	}
	return c.do(req, out)
}

func (c *Client) get(ctx context.Context, path string, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	return c.do(req, out)
}

func (c *Client) post(ctx context.Context, path string, body interface{}, out interface{}) error {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("序列化请求体失败: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bodyReader)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, out)
}

// ErrNetworkUnavailable 表示网络不可用。
var ErrNetworkUnavailable = fmt.Errorf("网络不可用")

// HTTPStatusError 携带 HTTP 状态码与服务端错误信息，
// 便于调用方按状态码分支处理（例如把证书下发的 403 解释为"策略不允许"）。
type HTTPStatusError struct {
	StatusCode int
	Message    string
}

func (e *HTTPStatusError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("服务端错误 [%d]: %s", e.StatusCode, e.Message)
	}
	return fmt.Sprintf("HTTP 错误: %d", e.StatusCode)
}

// IsHTTPStatus 判断错误是否为指定状态码。
func IsHTTPStatus(err error, status int) bool {
	var se *HTTPStatusError
	if errors.As(err, &se) {
		return se.StatusCode == status
	}
	return false
}

func (c *Client) do(req *http.Request, out interface{}) error {
	c.mu.RLock()
	token := c.token
	c.mu.RUnlock()

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// 判断是否为网络不可用
		return fmt.Errorf("%w: %v", ErrNetworkUnavailable, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("读取响应失败: %w", err)
	}

	// 401 有两种语义：账号 Token 失效，或高敏操作缺少 PIN 授权，必须区分处理
	if resp.StatusCode == http.StatusUnauthorized {
		if resp.Header.Get("X-PIN-Required") == "true" {
			var errResp struct {
				Error string `json:"error"`
			}
			json.Unmarshal(respBody, &errResp) //nolint:errcheck
			if errResp.Error != "" {
				return fmt.Errorf("%w: %s", ErrPINRequired, errResp.Error)
			}
			return ErrPINRequired
		}
		return fmt.Errorf("认证失败: Token 无效或已过期")
	}

	if resp.StatusCode >= 400 {
		var errResp struct {
			Error string `json:"error"`
		}
		json.Unmarshal(respBody, &errResp) //nolint:errcheck
		return &HTTPStatusError{StatusCode: resp.StatusCode, Message: errResp.Error}
	}

	if out != nil {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("解析响应失败: %w", err)
		}
	}
	return nil
}

// IsNetworkError 判断错误是否为网络不可用。
func IsNetworkError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "网络不可用") ||
		strings.Contains(err.Error(), "connection refused") ||
		strings.Contains(err.Error(), "no such host") ||
		strings.Contains(err.Error(), "i/o timeout")
}

// ---- 证书下发 API ----

// DeliveredCert 是云端下发的证书及其私钥（PEM 格式）。
// CanRedeliver 表示该证书云端策略是否允许再次下发。
type DeliveredCert struct {
	CertPEM      string `json:"cert_pem"`
	KeyPEM       string `json:"key_pem"`
	ChainPEM     string `json:"chain_pem,omitempty"`
	Algorithm    string `json:"algorithm,omitempty"` // rsa2048 / ec256 等
	CanRedeliver bool   `json:"can_redeliver"`
	SerialNumber string `json:"serial_number,omitempty"`
	CommonName   string `json:"common_name,omitempty"`
	NotBefore    string `json:"not_before,omitempty"`
	NotAfter     string `json:"not_after,omitempty"`
}

// DownloadCertWithKey 从 servers 下发指定证书（含私钥）。
//
// 云端接口：POST /api/certificates/{uuid}/download，响应体为 DeliveredCert。
// 私钥交付需要云端密钥存储策略允许，返回 403 时统一转换为 ErrDeliveryDenied，
// 调用方据此提示"该证书不允许下发"，而不是重试。
func (c *Client) DownloadCertWithKey(ctx context.Context, certUUID string) (*DeliveredCert, error) {
	if certUUID == "" {
		return nil, fmt.Errorf("certUUID 不能为空")
	}
	var resp DeliveredCert
	path := fmt.Sprintf("/api/certificates/%s/download", certUUID)
	body := map[string]interface{}{
		"include_key": true,
		"method":      "cloud",
	}
	if err := c.post(ctx, path, body, &resp); err != nil {
		if IsHTTPStatus(err, http.StatusForbidden) {
			return nil, fmt.Errorf("%w: %v", ErrDeliveryDenied, err)
		}
		return nil, fmt.Errorf("下发云端证书失败: %w", err)
	}
	if resp.KeyPEM == "" {
		return nil, fmt.Errorf("%w: 云端未返回私钥材料", ErrDeliveryDenied)
	}
	return &resp, nil
}
