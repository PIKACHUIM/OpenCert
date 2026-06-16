// Package api 提供与 client-card 后端服务通信的 HTTP 客户端。
package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Response 后端 API 统一响应格式
type Response struct {
	Code    int             `json:"code"`    // 0=成功，非0=错误
	Message string          `json:"message"` // 错误消息
	Data    json.RawMessage `json:"data"`    // 响应数据

	// HTTPStatus 保存原始 HTTP 状态码，用于 428 等特殊判断
	HTTPStatus int `json:"-"`
}

// IsSuccess 响应是否成功
func (r *Response) IsSuccess() bool {
	return r.Code == 0
}

// Error 返回错误描述
func (r *Response) Error() string {
	return fmt.Sprintf("API错误[code=%d]: %s", r.Code, r.Message)
}

// DecodeData 将 data 字段解析到目标对象
func (r *Response) DecodeData(v interface{}) error {
	if r.Data == nil {
		return nil
	}
	return json.Unmarshal(r.Data, v)
}

// ---- 数据模型 ----

// SlotType 卡片 Slot 类型
type SlotType string

const (
	SlotTypeLocal SlotType = "local"
	SlotTypeTPM2  SlotType = "tpm2"
	SlotTypeTPMSC SlotType = "tpmsc"
	SlotTypeCloud SlotType = "cloud"
)

// CertType 证书类型
type CertType string

const (
	CertTypeX509 CertType = "x509"
)

// SecurityLevel 安全等级
type SecurityLevel string

const (
	SecurityLevelHigh   SecurityLevel = "high"
	SecurityLevelMedium SecurityLevel = "medium"
	SecurityLevelLow    SecurityLevel = "low"
)

// User 用户信息
type User struct {
	UUID                string `json:"uuid"`
	UserType            string `json:"user_type"`
	Role                string `json:"role"`
	Username            string `json:"username"`
	DisplayName         string `json:"display_name"`
	Email               string `json:"email"`
	CloudURL            string `json:"cloud_url,omitempty"`
	Enabled             bool   `json:"enabled"`
	TwoFAEnabled        bool   `json:"two_fa_enabled"`
	PasswordlessEnabled bool   `json:"passwordless_enabled"`
	CreatedAt           string `json:"created_at"`
	UpdatedAt           string `json:"updated_at"`
}

// Card 智能卡信息
type Card struct {
	UUID          string         `json:"uuid"`
	SlotType      SlotType       `json:"slot_type"`
	CardName      string         `json:"card_name"`
	UserUUID      string         `json:"user_uuid"`
	Remark        string         `json:"remark,omitempty"`
	SecurityLevel SecurityLevel  `json:"security_level"`
	CloudURL      string         `json:"cloud_url,omitempty"`
	CloudCardUUID string         `json:"cloud_card_uuid,omitempty"`
	Enabled       bool           `json:"enabled"`
	PINRetries    int            `json:"pin_retries"`
	PINFailedCount int           `json:"pin_failed_count"`
	PINLocked     bool           `json:"pin_locked"`
	CreatedAt     string         `json:"created_at"`
	ExpiresAt     string         `json:"expires_at,omitempty"`
	CertStats     *CertStats     `json:"cert_stats,omitempty"`
}

// CertStats 证书统计
type CertStats struct {
	X509  int `json:"x509"`
	FIDO  int `json:"fido"`
	TOTP  int `json:"totp"`
	Creds int `json:"creds"`
}

// Certificate 证书信息（列表项）
type Certificate struct {
	UUID        string   `json:"uuid"`
	CardUUID    string   `json:"card_uuid"`
	SlotType    SlotType `json:"slot_type"`
	CertType    CertType `json:"cert_type"`
	KeyType     string   `json:"key_type"`
	CertContent string   `json:"cert_content,omitempty"`
	CommonName  string   `json:"common_name,omitempty"`
	IssuerCN    string   `json:"issuer_cn,omitempty"`
	Remark      string   `json:"remark,omitempty"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
}

// CertDetail 证书详细信息（/certs/{uuid}/detail 返回）
type CertDetail struct {
	CommonName        string        `json:"common_name"`
	Organization      string        `json:"organization,omitempty"`
	OrgUnit           string        `json:"org_unit,omitempty"`
	Country           string        `json:"country,omitempty"`
	State             string        `json:"state,omitempty"`
	Locality          string        `json:"locality,omitempty"`
	Street            string        `json:"street,omitempty"`
	SubjectSerial     string        `json:"subject_serial,omitempty"`
	Description       string        `json:"description,omitempty"`
	IssuerCN          string        `json:"issuer_cn"`
	IssuerOrg         string        `json:"issuer_org,omitempty"`
	IssuerOU          string        `json:"issuer_ou,omitempty"`
	IssuerCountry     string        `json:"issuer_country,omitempty"`
	IssuerState       string        `json:"issuer_state,omitempty"`
	IssuerLocality    string        `json:"issuer_locality,omitempty"`
	IssuerStreet      string        `json:"issuer_street,omitempty"`
	IssuerSerial      string        `json:"issuer_serial,omitempty"`
	IssuerDescription string        `json:"issuer_description,omitempty"`
	NotBefore         string        `json:"not_before"`
	NotAfter          string        `json:"not_after"`
	SerialNumber      string        `json:"serial_number"`
	SHA1Fingerprint   string        `json:"sha1_fingerprint"`
	SHA256Fingerprint string        `json:"sha256_fingerprint,omitempty"`
	KeyUsage          []string      `json:"key_usage"`
	ExtKeyUsage       []string      `json:"ext_key_usage"`
	IsCA              bool          `json:"is_ca"`
	MaxPathLen        int           `json:"max_path_len"`
	MaxPathLenZero    bool          `json:"max_path_len_zero"`
	KeyBits           int           `json:"key_bits,omitempty"`
	SANDNSNames       []string      `json:"san_dns,omitempty"`
	SANIPAddresses    []string      `json:"san_ip,omitempty"`
	SANEmailAddresses []string      `json:"san_email,omitempty"`
	SANURIs           []string      `json:"san_uri,omitempty"`
	CRLDistPoints     []string      `json:"crl_dist_points,omitempty"`
	OCSPServers       []string      `json:"ocsp_servers,omitempty"`
	IssuingCertURL    []string      `json:"issuing_cert_url,omitempty"`
	CPSURLs           []string      `json:"cps_urls,omitempty"`
	CertPolicies      []CertPolicy  `json:"cert_policies,omitempty"`
	SignatureAlgo     string        `json:"signature_algo"`
	PublicKeyAlgo     string        `json:"public_key_algo"`
	IsSelfSigned      bool          `json:"is_self_signed"`
}

// CertPolicy 证书策略
type CertPolicy struct {
	OID         string `json:"oid"`
	Description string `json:"description,omitempty"`
}

// ---- 请求结构 ----

// LoginRequest 本地登录请求
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	TOTPCode string `json:"totp_code,omitempty"`
}

// CloudLoginRequest 云端登录请求
type CloudLoginRequest struct {
	CloudURL string `json:"cloud_url"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// AuthToken 认证令牌
type AuthToken struct {
	Token    string `json:"token"`
	UserUUID string `json:"user_uuid"`
	Username string `json:"username"`
	Role     string `json:"role"`
	UserType string `json:"user_type,omitempty"`
	CloudURL string `json:"cloud_url,omitempty"`
	CloudUser string `json:"cloud_user,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// ImportCertRequest 导入证书请求
type ImportCertRequest struct {
	Mode         string `json:"mode"`          // pem / pfx
	CertPEM      string `json:"cert_pem"`      // PEM 格式证书
	KeyPEM       string `json:"key_pem"`       // PEM 格式私钥
	PFXB64       string `json:"pfx_b64"`       // base64 编码的 PFX/PKCS12
	PFXPassword  string `json:"pfx_password"`  // PFX 密码
	CardPassword string `json:"card_password"` // 卡片密码
	Remark       string `json:"remark"`
}

// DeliverRequest 云端证书下发请求
type DeliverRequest struct {
	CertUUID     string `json:"cert_uuid"`
	SourceCloud  string `json:"source_cloud_url,omitempty"`
	SourceCard   string `json:"source_card_uuid,omitempty"`
	Target       string `json:"target"`                      // "database" | "card"
	TargetCard   string `json:"target_card_uuid,omitempty"`  // Target=card 时必填
	CardPassword string `json:"card_password,omitempty"`     // Target=card 时必填
	Remark       string `json:"remark,omitempty"`
}

// DeliverResponse 下发成功响应
type DeliverResponse struct {
	Target     string `json:"target"`
	UUID       string `json:"uuid"`
	CommonName string `json:"common_name,omitempty"`
	CardUUID   string `json:"card_uuid,omitempty"`
}

// HealthResponse 健康检查响应
type HealthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version"`
}

// ---- HTTP 客户端 ----

// Client 后端 API 客户端
type Client struct {
	baseURL    string
	httpClient *http.Client
	token      string
}

// NewClient 创建新的 API 客户端
func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// SetToken 设置认证令牌
func (c *Client) SetToken(token string) {
	c.token = token
}

// BaseURL 返回后端地址
func (c *Client) BaseURL() string {
	return c.baseURL
}

// ---- 通用请求方法 ----

func (c *Client) doRequest(ctx context.Context, method, path string, body interface{}) (*Response, error) {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("序列化请求体失败: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	if ct := resp.Header.Get("Content-Type"); strings.Contains(ct, "text/html") || (len(respData) > 0 && respData[0] == '<') {
		return nil, fmt.Errorf("后端返回 HTML 而非 JSON（HTTP %d），请检查 BackendURL 是否正确，当前: %s", resp.StatusCode, c.baseURL)
	}

	var apiResp Response
	if err := json.Unmarshal(respData, &apiResp); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w (body: %s)", err, string(respData))
	}

	// 保存 HTTP 状态码到独立字段，用于 428 等特殊判断
	apiResp.HTTPStatus = resp.StatusCode

	return &apiResp, nil
}

func (c *Client) get(ctx context.Context, path string) (*Response, error) {
	return c.doRequest(ctx, http.MethodGet, path, nil)
}

func (c *Client) post(ctx context.Context, path string, body interface{}) (*Response, error) {
	return c.doRequest(ctx, http.MethodPost, path, body)
}

func (c *Client) put(ctx context.Context, path string, body interface{}) (*Response, error) {
	return c.doRequest(ctx, http.MethodPut, path, body)
}

func (c *Client) delete(ctx context.Context, path string, body interface{}) (*Response, error) {
	return c.doRequest(ctx, http.MethodDelete, path, body)
}

// ---- API 方法 ----

// Health 健康检查
func (c *Client) Health(ctx context.Context) (*HealthResponse, error) {
	resp, err := c.get(ctx, "/api/health")
	if err != nil {
		return nil, err
	}
	if !resp.IsSuccess() {
		return nil, fmt.Errorf("健康检查失败: %s", resp.Message)
	}
	var result HealthResponse
	if err := resp.DecodeData(&result); err != nil {
		return nil, fmt.Errorf("解析健康检查响应失败: %w", err)
	}
	return &result, nil
}

// Login 本地登录
func (c *Client) Login(ctx context.Context, req *LoginRequest) (*AuthToken, error) {
	resp, err := c.post(ctx, "/api/auth/login", req)
	if err != nil {
		return nil, err
	}
	// 428 需要验证码
	if resp.HTTPStatus == 428 {
		return nil, &ErrNeed2FA{Message: resp.Message}
	}
	if !resp.IsSuccess() {
		return nil, fmt.Errorf("登录失败: %s", resp.Message)
	}
	var token AuthToken
	if err := resp.DecodeData(&token); err != nil {
		return nil, fmt.Errorf("解析登录响应失败: %w", err)
	}
	c.SetToken(token.Token)
	return &token, nil
}

// CloudLogin 云端登录
func (c *Client) CloudLogin(ctx context.Context, req *CloudLoginRequest) (*AuthToken, error) {
	resp, err := c.post(ctx, "/api/auth/cloud-login", req)
	if err != nil {
		return nil, err
	}
	if !resp.IsSuccess() {
		return nil, fmt.Errorf("云端登录失败: %s", resp.Message)
	}
	var token AuthToken
	if err := resp.DecodeData(&token); err != nil {
		return nil, fmt.Errorf("解析云端登录响应失败: %w", err)
	}
	c.SetToken(token.Token)
	return &token, nil
}

// Logout 注销
func (c *Client) Logout(ctx context.Context) error {
	_, err := c.delete(ctx, "/api/auth/logout", nil)
	c.SetToken("")
	return err
}

// ListCards 获取卡片列表
func (c *Client) ListCards(ctx context.Context) ([]Card, error) {
	resp, err := c.get(ctx, "/api/cards")
	if err != nil {
		return nil, err
	}
	if !resp.IsSuccess() {
		return nil, fmt.Errorf("获取卡片列表失败: %s", resp.Message)
	}
	var cards []Card
	if err := resp.DecodeData(&cards); err != nil {
		return nil, fmt.Errorf("解析卡片列表失败: %w", err)
	}
	return cards, nil
}

// GetCard 获取单个卡片
func (c *Client) GetCard(ctx context.Context, uuid string) (*Card, error) {
	resp, err := c.get(ctx, "/api/cards/"+uuid)
	if err != nil {
		return nil, err
	}
	if !resp.IsSuccess() {
		return nil, fmt.Errorf("获取卡片失败: %s", resp.Message)
	}
	var card Card
	if err := resp.DecodeData(&card); err != nil {
		return nil, fmt.Errorf("解析卡片信息失败: %w", err)
	}
	return &card, nil
}

// DeleteCard 删除卡片
func (c *Client) DeleteCard(ctx context.Context, uuid string, userUUID, userPassword string) error {
	resp, err := c.delete(ctx, "/api/cards/"+uuid, map[string]string{
		"user_uuid":     userUUID,
		"user_password": userPassword,
	})
	if err != nil {
		return err
	}
	if !resp.IsSuccess() {
		return fmt.Errorf("删除卡片失败: %s", resp.Message)
	}
	return nil
}

// ListCerts 获取证书列表
func (c *Client) ListCerts(ctx context.Context, cardUUID string) ([]Certificate, error) {
	resp, err := c.get(ctx, "/api/cards/"+cardUUID+"/certs")
	if err != nil {
		return nil, err
	}
	if !resp.IsSuccess() {
		return nil, fmt.Errorf("获取证书列表失败: %s", resp.Message)
	}
	var certs []Certificate
	if err := resp.DecodeData(&certs); err != nil {
		return nil, fmt.Errorf("解析证书列表失败: %w", err)
	}
	return certs, nil
}

// GetCertDetail 获取证书详情
func (c *Client) GetCertDetail(ctx context.Context, cardUUID, certUUID string) (*CertDetail, error) {
	resp, err := c.get(ctx, "/api/cards/"+cardUUID+"/certs/"+certUUID+"/detail")
	if err != nil {
		return nil, err
	}
	if !resp.IsSuccess() {
		return nil, fmt.Errorf("获取证书详情失败: %s", resp.Message)
	}
	var detail CertDetail
	if err := resp.DecodeData(&detail); err != nil {
		return nil, fmt.Errorf("解析证书详情失败: %w", err)
	}
	return &detail, nil
}

// DeleteCert 删除证书
func (c *Client) DeleteCert(ctx context.Context, cardUUID, certUUID string) error {
	resp, err := c.delete(ctx, "/api/cards/"+cardUUID+"/certs/"+certUUID, nil)
	if err != nil {
		return err
	}
	if !resp.IsSuccess() {
		return fmt.Errorf("删除证书失败: %s", resp.Message)
	}
	return nil
}

// ExportCert 导出证书
func (c *Client) ExportCert(ctx context.Context, cardUUID, certUUID, format string) (map[string]interface{}, error) {
	resp, err := c.post(ctx, "/api/cards/"+cardUUID+"/certs/"+certUUID+"/export", map[string]string{
		"format": format,
	})
	if err != nil {
		return nil, err
	}
	if !resp.IsSuccess() {
		return nil, fmt.Errorf("导出证书失败: %s", resp.Message)
	}
	var result map[string]interface{}
	if err := resp.DecodeData(&result); err != nil {
		return nil, fmt.Errorf("解析导出结果失败: %w", err)
	}
	return result, nil
}

// ImportCert 导入证书到卡片
func (c *Client) ImportCert(ctx context.Context, cardUUID string, req *ImportCertRequest) error {
	resp, err := c.post(ctx, "/api/cards/"+cardUUID+"/certs/import", req)
	if err != nil {
		return err
	}
	if !resp.IsSuccess() {
		return fmt.Errorf("导入证书失败: %s", resp.Message)
	}
	return nil
}

// GenerateKey 生成密钥对
func (c *Client) GenerateKey(ctx context.Context, cardUUID string, keyType, password, remark string) error {
	resp, err := c.post(ctx, "/api/cards/"+cardUUID+"/keygen", map[string]string{
		"key_type": keyType,
		"password": password,
		"remark":   remark,
	})
	if err != nil {
		return err
	}
	if !resp.IsSuccess() {
		return fmt.Errorf("生成密钥对失败: %s", resp.Message)
	}
	return nil
}

// ResetPIN 重置 PIN
func (c *Client) ResetPIN(ctx context.Context, cardUUID, newPassword string) error {
	resp, err := c.post(ctx, "/api/cards/"+cardUUID+"/reset-pin", map[string]string{
		"new_password": newPassword,
	})
	if err != nil {
		return err
	}
	if !resp.IsSuccess() {
		return fmt.Errorf("重置PIN失败: %s", resp.Message)
	}
	return nil
}

// ExportCard 备份卡片
func (c *Client) ExportCard(ctx context.Context, cardUUID, password string) (map[string]interface{}, error) {
	resp, err := c.post(ctx, "/api/cards/"+cardUUID+"/export", map[string]string{
		"password": password,
	})
	if err != nil {
		return nil, err
	}
	if !resp.IsSuccess() {
		return nil, fmt.Errorf("备份卡片失败: %s", resp.Message)
	}
	var result map[string]interface{}
	if err := resp.DecodeData(&result); err != nil {
		return nil, fmt.Errorf("解析备份结果失败: %w", err)
	}
	return result, nil
}

// RestoreCard 恢复卡片
func (c *Client) RestoreCard(ctx context.Context, backupData, password string) error {
	resp, err := c.post(ctx, "/api/cards/restore", map[string]string{
		"backup_data": backupData,
		"password":    password,
	})
	if err != nil {
		return err
	}
	if !resp.IsSuccess() {
		return fmt.Errorf("恢复卡片失败: %s", resp.Message)
	}
	return nil
}

// UpdateCard 更新卡片信息
func (c *Client) UpdateCard(ctx context.Context, uuid string, data map[string]interface{}) error {
	resp, err := c.put(ctx, "/api/cards/"+uuid, data)
	if err != nil {
		return err
	}
	if !resp.IsSuccess() {
		return fmt.Errorf("更新卡片失败: %s", resp.Message)
	}
	return nil
}

// CloudDeliver 云端证书下发
func (c *Client) CloudDeliver(ctx context.Context, req *DeliverRequest) (*DeliverResponse, error) {
	resp, err := c.post(ctx, "/api/cloud/deliver", req)
	if err != nil {
		return nil, err
	}
	if !resp.IsSuccess() {
		return nil, fmt.Errorf("证书下发失败: %s", resp.Message)
	}
	var result DeliverResponse
	if err := resp.DecodeData(&result); err != nil {
		return nil, fmt.Errorf("解析下发结果失败: %w", err)
	}
	return &result, nil
}

// GetCurrentUser 获取当前用户信息
func (c *Client) GetCurrentUser(ctx context.Context) (*User, error) {
	resp, err := c.get(ctx, "/api/users/me")
	if err != nil {
		return nil, err
	}
	if !resp.IsSuccess() {
		return nil, fmt.Errorf("获取用户信息失败: %s", resp.Message)
	}
	var user User
	if err := resp.DecodeData(&user); err != nil {
		return nil, fmt.Errorf("解析用户信息失败: %w", err)
	}
	return &user, nil
}

// TOTPEntry TOTP 条目
type TOTPEntry struct {
	UUID      string `json:"uuid"`
	CardUUID  string `json:"card_uuid"`
	OTPType   string `json:"otp_type"`
	Issuer    string `json:"issuer"`
	Account   string `json:"account"`
	Algorithm string `json:"algorithm"`
	Digits    int    `json:"digits"`
	Period    int    `json:"period"`
}

// ListTOTPs 列出卡片下的 TOTP 条目
func (c *Client) ListTOTPs(ctx context.Context, cardUUID string) ([]TOTPEntry, error) {
	resp, err := c.get(ctx, "/api/cards/"+cardUUID+"/totp")
	if err != nil {
		return nil, err
	}
	if !resp.IsSuccess() {
		return nil, fmt.Errorf("获取TOTP列表失败: %s", resp.Message)
	}
	var entries []TOTPEntry
	if err := resp.DecodeData(&entries); err != nil {
		return nil, fmt.Errorf("解析TOTP列表失败: %w", err)
	}
	return entries, nil
}

// GetTOTPCode 获取 TOTP 验证码（需卡片密码）
func (c *Client) GetTOTPCode(ctx context.Context, totpUUID, cardPassword string) (string, int, error) {
	resp, err := c.get(ctx, "/api/totp/"+totpUUID+"/code?card_password="+cardPassword)
	if err != nil {
		return "", 0, err
	}
	if !resp.IsSuccess() {
		return "", 0, fmt.Errorf("%s", resp.Message)
	}
	var result struct {
		Code      string `json:"code"`
		Remaining int    `json:"remaining"`
		Period    int    `json:"period"`
	}
	if err := resp.DecodeData(&result); err != nil {
		return "", 0, fmt.Errorf("解析验证码失败: %w", err)
	}
	return result.Code, result.Remaining, nil
}

// DeleteTOTP 删除 TOTP 条目
func (c *Client) DeleteTOTP(ctx context.Context, totpUUID string) error {
	resp, err := c.delete(ctx, "/api/totp/"+totpUUID, nil)
	if err != nil {
		return err
	}
	if !resp.IsSuccess() {
		return fmt.Errorf("删除TOTP失败: %s", resp.Message)
	}
	return nil
}

// GetCredentialSecret 解密凭据私密内容（需卡片密码）
func (c *Client) GetCredentialSecret(ctx context.Context, cardUUID, certUUID, cardPassword string) ([]byte, error) {
	resp, err := c.post(ctx, "/api/cards/"+cardUUID+"/credentials/"+certUUID+"/secret", map[string]string{
		"card_password": cardPassword,
	})
	if err != nil {
		return nil, err
	}
	if !resp.IsSuccess() {
		return nil, fmt.Errorf("%s", resp.Message)
	}
	var result struct {
		SecretData string `json:"secret_data"`
	}
	if err := resp.DecodeData(&result); err != nil {
		return nil, fmt.Errorf("解析凭据内容失败: %w", err)
	}
	return base64.StdEncoding.DecodeString(result.SecretData)
}

// ---- 错误类型 ----

// ErrNeed2FA 表示需要 2FA 验证码
type ErrNeed2FA struct {
	Message string
}

func (e *ErrNeed2FA) Error() string {
	return e.Message
}

// IsNeed2FA 判断错误是否为需要 2FA
func IsNeed2FA(err error) bool {
	_, ok := err.(*ErrNeed2FA)
	return ok
}
