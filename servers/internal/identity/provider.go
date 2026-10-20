package identity

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	KindDomain   = "domain"   // 域名所有权验证（DNS/HTTP/TLS）
	KindIdentity = "identity" // 实名认证（跳转第三方，完成后回调）
)

// secretMask 是返回给前端的密钥占位符；更新时原样提交表示保留旧值。
const secretMask = "******"

// DriverField 描述驱动的一个配置项（前端据此动态渲染表单）。
type DriverField struct {
	Key         string   `json:"key"`
	Label       string   `json:"label"`
	Type        string   `json:"type,omitempty"`    // text（默认）/ password / number / select / textarea
	Options     []string `json:"options,omitempty"` // type=select 时的可选值
	Default     string   `json:"default,omitempty"` // 新建时的默认值
	Group       string   `json:"group,omitempty"`   // 分组标题（同一驱动的字段可分组展示）
	Placeholder string   `json:"placeholder,omitempty"`
	Secret      bool     `json:"secret,omitempty"`
	Required    bool     `json:"required,omitempty"`
	Help        string   `json:"help,omitempty"`
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
		Description: "通过标准 SMTP 发送验证码与通知邮件，支持 STARTTLS 与隐式 SSL",
		Fields: []DriverField{
			{Key: "host", Label: "SMTP 服务器", Required: true, Placeholder: "smtp.example.com"},
			{Key: "port", Label: "端口", Type: "number", Required: true, Default: "587",
				Help: "587（STARTTLS）、465（SSL）或 25（明文）"},
			{Key: "tls_mode", Label: "加密方式", Type: "select", Default: "starttls",
				Options: []string{"starttls", "ssl", "none"}, Help: "starttls 最常用；465 端口请选 ssl"},
			{Key: "timeout", Label: "超时（秒）", Type: "number", Default: "15"},
			{Key: "username", Label: "用户名"},
			{Key: "password", Label: "密码 / 授权码", Type: "password", Secret: true},
			{Key: "from", Label: "发件地址", Required: true, Placeholder: "noreply@example.com"},
			{Key: "from_name", Label: "发件人名称"},
		}},
	{Kind: KindEmail, Driver: "resend", Name: "Resend", Available: true,
		Description: "通过 Resend 发送邮件，适合没有自有邮件服务器的场景",
		Fields: []DriverField{
			{Key: "api_key", Label: "API Key", Type: "password", Secret: true, Required: true},
			{Key: "from", Label: "发件地址", Required: true, Help: "需为 Resend 已验证域名下的地址，如 OpenCert <noreply@example.com>"},
			{Key: "endpoint", Label: "API 地址", Default: "https://api.resend.com/emails"},
		}},
	{Kind: KindDomain, Driver: "dns_txt", Name: "DNS TXT 验证", Available: true,
		Description: "在域名 DNS 中添加一条 TXT 记录即可证明所有权，开箱即用",
		Fields: []DriverField{
			{Key: "record_prefix", Label: "记录前缀", Default: "_opencert", Help: "在域名前添加该前缀作为 TXT 记录名"},
			{Key: "resolver", Label: "解析服务器", Placeholder: "8.8.8.8:53", Help: "留空使用系统默认解析器"},
			{Key: "timeout", Label: "超时（秒）", Type: "number", Default: "15"},
		}},
	{Kind: KindDomain, Driver: "http_file", Name: "HTTP 文件验证", Available: true,
		Description: "在网站根目录放置指定内容的文件即可证明所有权，开箱即用",
		Fields: []DriverField{
			{Key: "path_prefix", Label: "文件路径前缀", Default: "/.well-known/pki-validation/"},
			{Key: "port", Label: "端口", Type: "number", Default: "80", Help: "只做 HTTP 校验，非 80 端口时填写实际端口"},
			{Key: "timeout", Label: "超时（秒）", Type: "number", Default: "15"},
		}},
	{Kind: KindDomain, Driver: "tls_alpn", Name: "TLS-ALPN 验证", Available: true,
		Description: "通过 TLS-ALPN-01（RFC 8737）验证域名对应服务器的控制权，开箱即用",
		Fields: []DriverField{
			{Key: "port", Label: "端口", Type: "number", Default: "443"},
			{Key: "timeout", Label: "超时（秒）", Type: "number", Default: "15"},
		}},
	{Kind: KindIdentity, Driver: "callback", Name: "三方回调认证", Available: true,
		Description: "跳转到自建或第三方实名页面，完成后回调本平台并自动更新审核状态",
		Fields: []DriverField{
			{Key: "request_url", Label: "实名页面地址", Type: "url", Required: true, Group: "请求",
				Help: "平台会自动追加 session、callback、return 参数；也可在请求体模板里引用这些变量"},
			{Key: "request_method", Label: "请求方法", Type: "select", Default: "GET", Options: []string{"GET", "POST"}, Group: "请求"},
			{Key: "request_headers", Label: "请求头", Type: "textarea", Group: "请求",
				Placeholder: "Authorization: Bearer xxx", Help: "每行一个，格式 名称: 值"},
			{Key: "request_body_template", Label: "请求体模板（POST）", Type: "textarea", Group: "请求",
				Placeholder: `{"session":"{{session}}","callback":"{{callback}}"}`, Help: "可用变量：{{session}} {{callback}} {{return}} {{expires}} 以及主体字段"},
			{Key: "result_url_path", Label: "跳转地址取值", Default: "data.url", Group: "请求",
				Help: "从响应 JSON 中取跳转地址的路径，如 data.url"},
			{Key: "verify_mode", Label: "回调校验方式", Type: "select", Default: "hmac", Group: "回调",
				Options: []string{"hmac", "token", "none"}},
			{Key: "secret", Label: "签名密钥", Type: "password", Secret: true, Group: "回调",
				Help: "hmac：X-Signature = hex(HMAC-SHA256(secret, body))；token：校验 X-Callback-Token"},
			{Key: "callback_format", Label: "回调内容格式", Type: "select", Default: "json", Group: "回调",
				Options: []string{"json", "form"}},
			{Key: "response_body", Label: "返回内容", Type: "textarea", Group: "回调",
				Default: `{"code":0,"message":"ok"}`, Help: "回调处理完成后返回给实名服务的内容"},
			{Key: "field_mapping", Label: "主体字段映射", Type: "textarea", Group: "高级",
				Placeholder: `{"certNo":"id_number"}`, Help: "JSON：实名参数 → 主体字段键"},
		}},
	{Kind: KindIdentity, Driver: "alipay", Name: "支付宝身份验证", Available: true,
		Description: "调用支付宝开放平台实名认证，用户在支付宝内完成刷脸或身份证核验",
		Fields: []DriverField{
			{Key: "app_id", Label: "AppID", Required: true, Group: "应用"},
			{Key: "private_key", Label: "应用私钥", Type: "password", Secret: true, Required: true, Group: "应用",
				Help: "PKCS#8 或 PKCS#1 私钥，可带或不带 PEM 头"},
			{Key: "alipay_public_key", Label: "支付宝公钥", Type: "textarea", Required: true, Group: "应用"},
			{Key: "gateway", Label: "网关地址", Default: "https://openapi.alipay.com/gateway.do", Group: "应用"},
			{Key: "return_url", Label: "认证完成后返回地址", Group: "应用",
				Help: "留空则使用平台地址；用户完成认证后回到该页面"},
			{Key: "certify_mode", Label: "核验方式", Type: "select", Default: "FACE", Group: "认证",
				Options: []string{"FACE", "CERT_PHOTO", "CERT_PHOTO_FACE", "MULTI_FACTOR"}},
			{Key: "identity_param", Label: "证件类型", Default: "CERT_INFO", Group: "认证"},
		}},
	{Kind: KindIdentity, Driver: "wechat_faceid", Name: "微信实名（慧眼）", Available: true,
		Description: "通过腾讯云慧眼人脸核身完成实名，用户在微信内完成刷脸",
		Fields: []DriverField{
			{Key: "secret_id", Label: "SecretId", Required: true, Group: "密钥"},
			{Key: "secret_key", Label: "SecretKey", Type: "password", Secret: true, Required: true, Group: "密钥"},
			{Key: "region", Label: "地域", Default: "ap-guangzhou", Group: "密钥"},
			{Key: "rule_id", Label: "规则 ID", Required: true, Group: "核身", Help: "慧眼控制台的 RuleId"},
			{Key: "endpoint", Label: "接口地址", Default: "faceid.tencentcloudapi.com", Group: "核身"},
			{Key: "redirect_url", Label: "完成返回地址", Group: "核身"},
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
	UUID   string            `json:"uuid"`
	Name   string            `json:"name"`
	Kind   string            `json:"kind"`
	Driver string            `json:"driver"`
	Config map[string]string `json:"config"` // 返回前端时密钥已脱敏
	// IsDefault 表示同类接口中的默认项：邮件接口作为系统发信通道，
	// 域名 / 实名接口在模板未显式指定时优先使用。
	IsDefault bool      `json:"is_default"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
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
	var enabled, isDefault int
	if err := scan(&p.UUID, &p.Name, &p.Kind, &p.Driver, &enc, &enabled, &isDefault, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return nil, err
	}
	p.Enabled = enabled == 1
	p.IsDefault = isDefault == 1
	p.Config = s.decode(enc)
	// 历史数据兼容：webhook → callback、wechat → wechat_faceid，并补齐旧字段名
	p.Config = migrateLegacyConfig(p.Driver, p.Config)
	p.Driver = NormalizeDriver(p.Driver)
	return p, nil
}

const providerColumns = `uuid, name, kind, driver, config_enc, enabled, is_default, created_at, updated_at`

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
			`INSERT INTO verify_providers (`+providerColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			p.UUID, p.Name, p.Kind, p.Driver, enc, storage.BoolToInt(p.Enabled),
			storage.BoolToInt(p.IsDefault), now, now)
	} else {
		_, err = s.db.ExecContext(ctx,
			`UPDATE verify_providers SET name = ?, config_enc = ?, enabled = ?, is_default = ?, updated_at = ? WHERE uuid = ?`,
			p.Name, enc, storage.BoolToInt(p.Enabled), storage.BoolToInt(p.IsDefault), now, p.UUID)
	}
	p.UpdatedAt = now
	maskSecrets(p)
	if err != nil {
		return err
	}
	// 设为默认时清除同类接口的默认标记，保证"同类只有一个默认"
	if p.IsDefault {
		return s.SetDefault(ctx, p.UUID)
	}
	return nil
}

// SetDefault 把指定接口设为同类中的默认接口（同事务内清除其它默认标记）。
func (s *Store) SetDefault(ctx context.Context, id string) error {
	p, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	if !p.Enabled {
		return fmt.Errorf("接口「%s」已停用，不能设为默认", p.Name)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.ExecContext(ctx,
		`UPDATE verify_providers SET is_default = 0, updated_at = ? WHERE kind = ? AND uuid <> ?`,
		time.Now(), p.Kind, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE verify_providers SET is_default = 1, updated_at = ? WHERE uuid = ?`, time.Now(), id); err != nil {
		return err
	}
	return tx.Commit()
}

// DefaultProvider 返回某类接口的默认项（未设置时回退到第一个启用的接口）。
// 用于模板未显式指定接口时自动选择，避免"必须手工绑定"才能用。
func (s *Store) DefaultProvider(ctx context.Context, kind string) (*Provider, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+providerColumns+` FROM verify_providers
		 WHERE kind = ? AND enabled = 1
		 ORDER BY is_default DESC, created_at ASC LIMIT 1`, kind)
	p, err := s.scan(row.Scan)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("尚未配置%s接口", kindLabel(kind))
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}

// kindLabel 返回接口类型的中文名称。
func kindLabel(kind string) string {
	switch kind {
	case KindEmail:
		return "邮件"
	case KindDomain:
		return "域名验证"
	case KindIdentity:
		return "实名认证"
	}
	return kind
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

// SendMail 通过指定邮件接口发送；providerUUID 为空时使用系统默认邮件接口，
// 都没有配置时退回环境变量 SMTP。
func (s *Store) SendMail(ctx context.Context, providerUUID, to, subject, body string) error {
	if providerUUID == "" && s != nil {
		// 优先使用后台配置的默认邮件接口
		if p, err := s.DefaultProvider(ctx, KindEmail); err == nil {
			providerUUID = p.UUID
		}
	}
	if providerUUID != "" {
		return s.SendVia(ctx, providerUUID, to, subject, body)
	}
	if s == nil || s.fallback == nil {
		return fmt.Errorf("未配置邮件接口，请在「身份认证审核 - 邮件接口」中添加并设为默认")
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
// fields 为主体信息字段，用于向第三方预填姓名 / 证件号。
func (s *Store) StartIdentity(ctx context.Context, providerUUID, subjectInfoUUID, userUUID, baseURL, returnURL string, fields map[string]string) (string, error) {
	if s == nil {
		return "", fmt.Errorf("实名认证未启用")
	}
	p, err := s.Get(ctx, providerUUID)
	if err != nil {
		return "", err
	}
	if p.Kind != KindIdentity || !p.Enabled {
		return "", fmt.Errorf("实名认证接口不可用")
	}
	driver, err := identityDriverOf(p.Driver)
	if err != nil {
		return "", err
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

	target, err := driver.Start(ctx, s, p, sess, StartInput{BaseURL: baseURL, ReturnURL: returnURL, Fields: fields})
	if err != nil {
		// 发起失败时立刻把会话置为失败，避免留下永远 pending 的脏数据
		s.db.ExecContext(ctx, //nolint:errcheck
			`UPDATE identity_sessions SET status = 'failed', message = ?, updated_at = ? WHERE uuid = ?`,
			err.Error(), time.Now(), sess.UUID)
		return "", err
	}
	return target, nil
}

// CallbackResult 是实名回调的解析结果。
type CallbackResult struct {
	SessionUUID     string
	SubjectInfoUUID string
	Passed          bool
	Message         string
}

// HandleCallback 交由对应驱动校验回调并更新会话状态（幂等）。
func (s *Store) HandleCallback(ctx context.Context, providerUUID string, r *http.Request, body []byte) (*CallbackResult, []byte, error) {
	if s == nil {
		return nil, nil, fmt.Errorf("实名认证未启用")
	}
	p, err := s.Get(ctx, providerUUID)
	if err != nil {
		return nil, nil, err
	}
	driver, err := identityDriverOf(p.Driver)
	if err != nil {
		return nil, nil, err
	}
	return driver.Callback(ctx, s, p, r, body)
}

// QueryIdentity 主动查询实名结果（回调不可达时补偿）。
func (s *Store) QueryIdentity(ctx context.Context, providerUUID, sessionUUID string) (*CallbackResult, error) {
	p, err := s.Get(ctx, providerUUID)
	if err != nil {
		return nil, err
	}
	driver, err := identityDriverOf(p.Driver)
	if err != nil {
		return nil, err
	}
	sess, err := s.GetSession(ctx, sessionUUID)
	if err != nil {
		return nil, err
	}
	res, err := driver.Query(ctx, s, p, sess)
	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, fmt.Errorf("暂未获取到认证结果")
	}
	return res, nil
}

// GetSession 查询实名会话。
func (s *Store) GetSession(ctx context.Context, sessionUUID string) (*Session, error) {
	sess := &Session{}
	var expires sql.NullTime
	err := s.db.QueryRowContext(ctx,
		`SELECT uuid, provider_uuid, subject_info_uuid, user_uuid, status, COALESCE(message, ''), expires_at, created_at
		 FROM identity_sessions WHERE uuid = ?`, sessionUUID,
	).Scan(&sess.UUID, &sess.ProviderUUID, &sess.SubjectInfoUUID, &sess.UserUUID, &sess.Status,
		&sess.Message, &expires, &sess.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("实名会话不存在")
	}
	if err != nil {
		return nil, err
	}
	if expires.Valid {
		sess.ExpiresAt = &expires.Time
	}
	return sess, nil
}

// applyCallbackResult 把驱动解析出的结果写入会话（幂等：已终结的会话不再改写）。
func (s *Store) applyCallbackResult(ctx context.Context, p *Provider, sessionUUID string, passed bool, message string) (*CallbackResult, error) {
	var subjectUUID, status string
	var expiresAt sql.NullTime
	err := s.db.QueryRowContext(ctx,
		`SELECT subject_info_uuid, status, expires_at FROM identity_sessions WHERE uuid = ? AND provider_uuid = ?`,
		sessionUUID, p.UUID).Scan(&subjectUUID, &status, &expiresAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("实名会话不存在")
	}
	if err != nil {
		return nil, err
	}
	if status != "pending" {
		return &CallbackResult{SessionUUID: sessionUUID, SubjectInfoUUID: subjectUUID,
			Passed: status == "passed", Message: message}, nil
	}
	if expiresAt.Valid && time.Now().After(expiresAt.Time) {
		return nil, fmt.Errorf("实名会话已过期，请重新发起认证")
	}
	newStatus := "failed"
	if passed {
		newStatus = "passed"
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE identity_sessions SET status = ?, message = ?, updated_at = ? WHERE uuid = ? AND status = 'pending'`,
		newStatus, message, time.Now(), sessionUUID); err != nil {
		return nil, err
	}
	return &CallbackResult{SessionUUID: sessionUUID, SubjectInfoUUID: subjectUUID, Passed: passed, Message: message}, nil
}

// SystemMailer 返回系统默认邮件接口对应的发信器；未配置默认接口时返回环境变量 SMTP 兜底。
func (s *Store) SystemMailer(ctx context.Context) (mailer.Mailer, error) {
	if s == nil {
		return nil, fmt.Errorf("未配置邮件接口")
	}
	p, err := s.DefaultProvider(ctx, KindEmail)
	if err != nil {
		if s.fallback != nil {
			return s.fallback, nil
		}
		return nil, err
	}
	return s.mailerFor(p)
}

// mailerFor 按邮件接口配置构造发信器。
func (s *Store) mailerFor(p *Provider) (mailer.Mailer, error) {
	switch p.Driver {
	case "smtp":
		port, _ := strconv.Atoi(p.Config["port"])
		if port == 0 {
			port = 587
		}
		timeout, _ := strconv.Atoi(p.Config["timeout"])
		if timeout <= 0 {
			timeout = 15
		}
		mode := strings.ToLower(strings.TrimSpace(p.Config["tls_mode"]))
		if mode == "" {
			if port == 465 {
				mode = "ssl"
			} else {
				mode = "starttls"
			}
		}
		return mailer.New(configs.SMTPConfig{
			Enabled: true, Host: p.Config["host"], Port: port, Username: p.Config["username"],
			Password: p.Config["password"], From: p.Config["from"], FromName: p.Config["from_name"],
			TLSMode: mode, TimeoutSeconds: timeout,
		}), nil
	case "resend":
		return &resendMailer{store: s, cfg: p.Config}, nil
	}
	return nil, fmt.Errorf("不支持的邮件驱动: %s", p.Driver)
}

// resendMailer 把 Resend 接口适配为 mailer.Mailer。
type resendMailer struct {
	store *Store
	cfg   map[string]string
}

func (m *resendMailer) Send(to, subject, body string) error {
	return m.store.sendResend(context.Background(), m.cfg, to, subject, body)
}

// SendVia 使用指定邮件接口发信（用于接口测试）。
func (s *Store) SendVia(ctx context.Context, providerUUID, to, subject, body string) error {
	p, err := s.Get(ctx, providerUUID)
	if err != nil {
		return err
	}
	if p.Kind != KindEmail {
		return fmt.Errorf("接口「%s」不是邮件接口", p.Name)
	}
	if !p.Enabled {
		return fmt.Errorf("邮件接口「%s」已停用", p.Name)
	}
	m, err := s.mailerFor(p)
	if err != nil {
		return err
	}
	return m.Send(to, subject, body)
}

// SortedDrivers 按类型返回驱动目录（前端下拉）。
func SortedDrivers() []DriverInfo {
	list := append([]DriverInfo(nil), Drivers...)
	sort.SliceStable(list, func(i, j int) bool { return list[i].Kind < list[j].Kind })
	return list
}
