package identity

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/globaltrusts/server-card/configs"
	"github.com/globaltrusts/server-card/internal/mailer"
	"github.com/globaltrusts/server-card/internal/storage"
	"github.com/google/uuid"
)

// 认证接口类型。
const (
	KindEmail    = "email"    // 邮件发送（邮箱验证码）
	KindIdentity = "identity" // 实名认证（跳转第三方，完成后回调）
)

// secretMask 是返回给前端的密钥占位符；更新时原样提交表示保留旧值。
const secretMask = "******"

// DriverField 描述驱动的一个配置项（前端据此动态渲染表单）。
type DriverField struct {
	Key      string `json:"key"`
	Label    string `json:"label"`
	Secret   bool   `json:"secret,omitempty"`
	Required bool   `json:"required,omitempty"`
	Help     string `json:"help,omitempty"`
}

// DriverInfo 描述一个认证接口驱动。
type DriverInfo struct {
	Kind        string        `json:"kind"`
	Driver      string        `json:"driver"`
	Name        string        `json:"name"`
	Available   bool          `json:"available"` // false = 插件位已预留，尚未实现
	Description string        `json:"description"`
	Fields      []DriverField `json:"fields"`
}

// Drivers 是内置驱动目录。新增第三方实名接口时，在此登记并实现 identityDriver。
var Drivers = []DriverInfo{
	{Kind: KindEmail, Driver: "smtp", Name: "SMTP 邮件", Available: true,
		Description: "通过标准 SMTP（支持 STARTTLS）发送验证码邮件",
		Fields: []DriverField{
			{Key: "host", Label: "SMTP 服务器", Required: true},
			{Key: "port", Label: "端口", Required: true, Help: "常用 587（STARTTLS）或 25"},
			{Key: "username", Label: "用户名"},
			{Key: "password", Label: "密码/授权码", Secret: true},
			{Key: "from", Label: "发件地址", Required: true},
			{Key: "from_name", Label: "发件人名称"},
		}},
	{Kind: KindEmail, Driver: "resend", Name: "Resend", Available: true,
		Description: "通过 Resend HTTP API 发送邮件（https://resend.com）",
		Fields: []DriverField{
			{Key: "api_key", Label: "API Key", Secret: true, Required: true},
			{Key: "from", Label: "发件地址", Required: true, Help: "需为 Resend 已验证域名下的地址，如 OpenCert <noreply@example.com>"},
			{Key: "endpoint", Label: "API 地址", Help: "缺省 https://api.resend.com/emails"},
		}},
	{Kind: KindIdentity, Driver: "webhook", Name: "通用实名回调", Available: true,
		Description: "跳转到自建/第三方实名页面，完成后以 HMAC 签名回调本平台，适配任意实名服务",
		Fields: []DriverField{
			{Key: "redirect_url", Label: "实名页面地址", Required: true, Help: "平台会追加 session、callback、return 参数"},
			{Key: "secret", Label: "回调签名密钥", Secret: true, Required: true, Help: "回调头 X-Signature = hex(HMAC-SHA256(secret, body))"},
		}},
	{Kind: KindIdentity, Driver: "alipay", Name: "支付宝身份验证", Available: false,
		Description: "支付宝开放平台 alipay.user.certify（插件位已预留）",
		Fields: []DriverField{
			{Key: "app_id", Label: "AppID", Required: true},
			{Key: "private_key", Label: "应用私钥", Secret: true, Required: true},
			{Key: "alipay_public_key", Label: "支付宝公钥", Required: true},
		}},
	{Kind: KindIdentity, Driver: "wechat", Name: "微信实名核身", Available: false,
		Description: "微信/腾讯云实名核身（插件位已预留）",
		Fields: []DriverField{
			{Key: "app_id", Label: "AppID", Required: true},
			{Key: "secret_id", Label: "SecretId", Required: true},
			{Key: "secret_key", Label: "SecretKey", Secret: true, Required: true},
		}},
}

func driverInfo(kind, driver string) *DriverInfo {
	for i := range Drivers {
		if Drivers[i].Kind == kind && Drivers[i].Driver == driver {
			return &Drivers[i]
		}
	}
	return nil
}

// Provider 是一个已配置的认证接口实例。
type Provider struct {
	UUID      string            `json:"uuid"`
	Name      string            `json:"name"`
	Kind      string            `json:"kind"`
	Driver    string            `json:"driver"`
	Config    map[string]string `json:"config"` // 返回前端时密钥已脱敏
	Enabled   bool              `json:"enabled"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// Cipher 是配置加解密函数（由服务端主密钥实现）。
type Cipher interface {
	EncryptData(data []byte) ([]byte, error)
	DecryptData(blob []byte) ([]byte, error)
}

// Store 管理认证接口与实名会话。
type Store struct {
	db       *storage.DB
	cipher   Cipher
	fallback mailer.Mailer // 未指定邮件接口时使用的系统 SMTP
	http     *http.Client
}

// NewStore 创建认证接口存储。
func NewStore(db *storage.DB, cipher Cipher, fallback mailer.Mailer) *Store {
	return &Store{db: db, cipher: cipher, fallback: fallback, http: &http.Client{Timeout: 15 * time.Second}}
}

func (s *Store) encode(cfg map[string]string) (string, error) {
	raw, _ := json.Marshal(cfg)
	if s.cipher == nil {
		return string(raw), nil
	}
	enc, err := s.cipher.EncryptData(raw)
	if err != nil {
		return "", fmt.Errorf("加密接口配置失败: %w", err)
	}
	return "enc:" + hex.EncodeToString(enc), nil
}

func (s *Store) decode(v string) map[string]string {
	cfg := map[string]string{}
	if strings.HasPrefix(v, "enc:") && s.cipher != nil {
		blob, err := hex.DecodeString(strings.TrimPrefix(v, "enc:"))
		if err != nil {
			return cfg
		}
		raw, err := s.cipher.DecryptData(blob)
		if err != nil {
			return cfg
		}
		v = string(raw)
	}
	json.Unmarshal([]byte(v), &cfg) //nolint:errcheck
	return cfg
}

func (s *Store) scan(scan func(dest ...interface{}) error) (*Provider, error) {
	p := &Provider{}
	var enc string
	var enabled int
	if err := scan(&p.UUID, &p.Name, &p.Kind, &p.Driver, &enc, &enabled, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return nil, err
	}
	p.Enabled = enabled == 1
	p.Config = s.decode(enc)
	return p, nil
}

const providerColumns = `uuid, name, kind, driver, config_enc, enabled, created_at, updated_at`

// List 查询认证接口（kind 为空表示全部），密钥脱敏。
func (s *Store) List(ctx context.Context, kind string) ([]*Provider, error) {
	q := `SELECT ` + providerColumns + ` FROM verify_providers`
	args := []interface{}{}
	if kind != "" {
		q += ` WHERE kind = ?`
		args = append(args, kind)
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY created_at`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []*Provider{}
	for rows.Next() {
		p, err := s.scan(rows.Scan)
		if err != nil {
			return nil, err
		}
		maskSecrets(p)
		list = append(list, p)
	}
	return list, rows.Err()
}

// Get 查询认证接口（含明文配置，仅供服务端内部使用）。
func (s *Store) Get(ctx context.Context, id string) (*Provider, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+providerColumns+` FROM verify_providers WHERE uuid = ?`, id)
	p, err := s.scan(row.Scan)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("认证接口不存在")
	}
	return p, err
}

func maskSecrets(p *Provider) {
	info := driverInfo(p.Kind, p.Driver)
	if info == nil {
		return
	}
	for _, f := range info.Fields {
		if f.Secret && p.Config[f.Key] != "" {
			p.Config[f.Key] = secretMask
		}
	}
}

// Save 创建或更新认证接口；更新时脱敏占位符保留原密钥。
func (s *Store) Save(ctx context.Context, p *Provider) error {
	info := driverInfo(p.Kind, p.Driver)
	if info == nil {
		return fmt.Errorf("不支持的认证接口: %s/%s", p.Kind, p.Driver)
	}
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("请填写接口名称")
	}
	if p.Config == nil {
		p.Config = map[string]string{}
	}
	if p.UUID != "" {
		old, err := s.Get(ctx, p.UUID)
		if err != nil {
			return err
		}
		for _, f := range info.Fields {
			if f.Secret && p.Config[f.Key] == secretMask {
				p.Config[f.Key] = old.Config[f.Key]
			}
		}
	}
	for _, f := range info.Fields {
		p.Config[f.Key] = strings.TrimSpace(p.Config[f.Key])
		if f.Required && p.Config[f.Key] == "" {
			return fmt.Errorf("请填写%s", f.Label)
		}
	}
	enc, err := s.encode(p.Config)
	if err != nil {
		return err
	}
	now := time.Now()
	if p.UUID == "" {
		p.UUID = uuid.New().String()
		p.CreatedAt = now
		_, err = s.db.ExecContext(ctx,
			`INSERT INTO verify_providers (`+providerColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			p.UUID, p.Name, p.Kind, p.Driver, enc, storage.BoolToInt(p.Enabled), now, now)
	} else {
		_, err = s.db.ExecContext(ctx,
			`UPDATE verify_providers SET name = ?, config_enc = ?, enabled = ?, updated_at = ? WHERE uuid = ?`,
			p.Name, enc, storage.BoolToInt(p.Enabled), now, p.UUID)
	}
	p.UpdatedAt = now
	maskSecrets(p)
	return err
}

// Delete 删除认证接口（被模板引用时拒绝）。
func (s *Store) Delete(ctx context.Context, id string) error {
	var refs int
	s.db.QueryRowContext(ctx, //nolint:errcheck
		`SELECT (SELECT COUNT(*) FROM subject_templates WHERE verify_provider_uuid = ?) +
		        (SELECT COUNT(*) FROM extension_templates WHERE verify_policy LIKE ?)`, id, "%"+id+"%").Scan(&refs)
	if refs > 0 {
		return fmt.Errorf("该接口正被主体/扩展信息模板使用，请先修改模板")
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM verify_providers WHERE uuid = ?`, id)
	return err
}

// ---- 邮件发送 ----

// SendMail 通过指定邮件接口发送；providerUUID 为空或接口停用时使用系统 SMTP。
func (s *Store) SendMail(ctx context.Context, providerUUID, to, subject, body string) error {
	if providerUUID != "" {
		p, err := s.Get(ctx, providerUUID)
		if err != nil {
			return err
		}
		if p.Kind != KindEmail {
			return fmt.Errorf("接口 %s 不是邮件接口", p.Name)
		}
		if !p.Enabled {
			return fmt.Errorf("邮件接口 %s 已停用", p.Name)
		}
		switch p.Driver {
		case "smtp":
			port, _ := strconv.Atoi(p.Config["port"])
			if port == 0 {
				port = 587
			}
			m := mailer.New(configs.SMTPConfig{
				Enabled: true, Host: p.Config["host"], Port: port, Username: p.Config["username"],
				Password: p.Config["password"], From: p.Config["from"], FromName: p.Config["from_name"],
			})
			return m.Send(to, subject, body)
		case "resend":
			return s.sendResend(ctx, p.Config, to, subject, body)
		}
		return fmt.Errorf("不支持的邮件驱动: %s", p.Driver)
	}
	if s.fallback == nil {
		return fmt.Errorf("未配置邮件接口")
	}
	return s.fallback.Send(to, subject, body)
}

func (s *Store) sendResend(ctx context.Context, cfg map[string]string, to, subject, body string) error {
	endpoint := cfg["endpoint"]
	if endpoint == "" {
		endpoint = "https://api.resend.com/emails"
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"from": cfg["from"], "to": []string{to}, "subject": subject, "text": body,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg["api_key"])
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.http.Do(req)
	if err != nil {
		return fmt.Errorf("Resend 请求失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("Resend 返回 %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}

// ---- 实名认证会话 ----

// Session 是一次实名认证会话。
type Session struct {
	UUID            string     `json:"uuid"`
	ProviderUUID    string     `json:"provider_uuid"`
	SubjectInfoUUID string     `json:"subject_info_uuid"`
	UserUUID        string     `json:"user_uuid"`
	Status          string     `json:"status"` // pending/passed/failed
	Message         string     `json:"message,omitempty"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
}

// StartIdentity 创建实名会话并返回跳转地址。
//
// baseURL 为平台对外地址（用于回调），returnURL 为认证完成后回到的前端页面。
func (s *Store) StartIdentity(ctx context.Context, providerUUID, subjectInfoUUID, userUUID, baseURL, returnURL string) (string, error) {
	p, err := s.Get(ctx, providerUUID)
	if err != nil {
		return "", err
	}
	if p.Kind != KindIdentity || !p.Enabled {
		return "", fmt.Errorf("实名认证接口不可用")
	}
	info := driverInfo(p.Kind, p.Driver)
	if info == nil || !info.Available {
		return "", fmt.Errorf("实名认证接口「%s」尚未接入，请联系管理员改用人工审核或通用回调接口", p.Name)
	}

	now := time.Now()
	sess := &Session{UUID: uuid.New().String(), ProviderUUID: providerUUID, SubjectInfoUUID: subjectInfoUUID,
		UserUUID: userUUID, Status: "pending", CreatedAt: now}
	exp := now.Add(30 * time.Minute)
	sess.ExpiresAt = &exp
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO identity_sessions (uuid, provider_uuid, subject_info_uuid, user_uuid, status, expires_at, created_at, updated_at)
		 VALUES (?, ?, ?, ?, 'pending', ?, ?, ?)`,
		sess.UUID, providerUUID, subjectInfoUUID, userUUID, exp, now, now); err != nil {
		return "", fmt.Errorf("创建实名会话失败: %w", err)
	}

	switch p.Driver {
	case "webhook":
		u, err := url.Parse(p.Config["redirect_url"])
		if err != nil {
			return "", fmt.Errorf("实名页面地址无效")
		}
		q := u.Query()
		q.Set("session", sess.UUID)
		q.Set("callback", strings.TrimRight(baseURL, "/")+"/api/identity/callback/"+providerUUID)
		q.Set("return", returnURL)
		q.Set("expires", strconv.FormatInt(exp.Unix(), 10))
		u.RawQuery = q.Encode()
		return u.String(), nil
	}
	return "", fmt.Errorf("不支持的实名驱动: %s", p.Driver)
}

// CallbackResult 是实名回调的解析结果。
type CallbackResult struct {
	SessionUUID     string
	SubjectInfoUUID string
	Passed          bool
	Message         string
}

// HandleCallback 校验实名回调签名并更新会话状态（幂等）。
func (s *Store) HandleCallback(ctx context.Context, providerUUID string, body []byte, signature string) (*CallbackResult, error) {
	p, err := s.Get(ctx, providerUUID)
	if err != nil {
		return nil, err
	}
	if p.Driver != "webhook" {
		return nil, fmt.Errorf("该接口不支持回调")
	}
	mac := hmac.New(sha256.New, []byte(p.Config["secret"]))
	mac.Write(body)
	want := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(strings.ToLower(strings.TrimSpace(signature)))) {
		return nil, fmt.Errorf("回调签名校验失败")
	}
	var cb struct {
		Session   string `json:"session"`
		Status    string `json:"status"` // passed / failed
		Message   string `json:"message"`
		Timestamp int64  `json:"timestamp"`
	}
	if err := json.Unmarshal(body, &cb); err != nil {
		return nil, fmt.Errorf("回调格式错误")
	}
	if d := time.Since(time.Unix(cb.Timestamp, 0)); d > 10*time.Minute || d < -10*time.Minute {
		return nil, fmt.Errorf("回调已过期")
	}

	var subjectUUID, status string
	var expiresAt sql.NullTime
	if err := s.db.QueryRowContext(ctx,
		`SELECT subject_info_uuid, status, expires_at FROM identity_sessions WHERE uuid = ? AND provider_uuid = ?`,
		cb.Session, providerUUID).Scan(&subjectUUID, &status, &expiresAt); err != nil {
		return nil, fmt.Errorf("实名会话不存在")
	}
	if status != "pending" {
		return &CallbackResult{SessionUUID: cb.Session, SubjectInfoUUID: subjectUUID, Passed: status == "passed"}, nil
	}
	if expiresAt.Valid && time.Now().After(expiresAt.Time) {
		return nil, fmt.Errorf("实名会话已过期，请重新发起认证")
	}
	newStatus := "failed"
	if cb.Status == "passed" {
		newStatus = "passed"
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE identity_sessions SET status = ?, message = ?, updated_at = ? WHERE uuid = ? AND status = 'pending'`,
		newStatus, cb.Message, time.Now(), cb.Session); err != nil {
		return nil, err
	}
	return &CallbackResult{SessionUUID: cb.Session, SubjectInfoUUID: subjectUUID, Passed: newStatus == "passed", Message: cb.Message}, nil
}

// SortedDrivers 按类型返回驱动目录（前端下拉）。
func SortedDrivers() []DriverInfo {
	list := append([]DriverInfo(nil), Drivers...)
	sort.SliceStable(list, func(i, j int) bool { return list[i].Kind < list[j].Kind })
	return list
}
