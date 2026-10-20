// Package test - 认证接口（邮件 / 域名 / 实名）驱动、默认接口与回调校验测试。
package test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/globaltrusts/server-card/internal/identity"
	"github.com/globaltrusts/server-card/internal/storage"
)

// newIdentityStore 构造只依赖数据库的认证接口存储（不加密配置，便于断言明文）。
func newIdentityStore(t *testing.T) (*identity.Store, *storage.DB, context.Context) {
	t.Helper()
	db := setupServerDB(t)
	return identity.NewStore(db, nil, nil), db, context.Background()
}

func TestProviderDriversCatalog(t *testing.T) {
	t.Parallel()
	kinds := map[string]int{}
	for _, d := range identity.SortedDrivers() {
		kinds[d.Kind]++
		if d.Name == "" || d.Description == "" {
			t.Errorf("驱动 %s/%s 缺少名称或说明", d.Kind, d.Driver)
		}
		for _, f := range d.Fields {
			if f.Key == "" || f.Label == "" {
				t.Errorf("驱动 %s/%s 存在字段缺少 key 或 label", d.Kind, d.Driver)
			}
			if f.Type == "select" && len(f.Options) == 0 {
				t.Errorf("驱动 %s/%s 的下拉字段 %s 没有选项", d.Kind, d.Driver, f.Key)
			}
		}
	}
	if kinds[identity.KindEmail] < 2 {
		t.Errorf("邮件接口应至少有 SMTP 与 Resend 两种，实际 %d", kinds[identity.KindEmail])
	}
	if kinds[identity.KindDomain] < 3 {
		t.Errorf("域名接口应内置 DNS/HTTP/TLS 三种，实际 %d", kinds[identity.KindDomain])
	}
	if kinds[identity.KindIdentity] < 3 {
		t.Errorf("实名接口应含回调/支付宝/微信，实际 %d", kinds[identity.KindIdentity])
	}
	// 三种域名驱动都能映射到验证方式
	for _, d := range identity.Drivers {
		if d.Kind != identity.KindDomain {
			continue
		}
		if identity.MethodOfDriver(d.Driver) == "" {
			t.Errorf("域名驱动 %s 缺少验证方式映射", d.Driver)
		}
	}
}

func TestProviderSaveMaskAndDefault(t *testing.T) {
	t.Parallel()
	store, _, ctx := newIdentityStore(t)

	p1 := &identity.Provider{Name: "主邮件", Kind: identity.KindEmail, Driver: "smtp", Enabled: true,
		Config: map[string]string{"host": "smtp.example.com", "port": "587", "username": "u",
			"password": "secret-pass", "from": "noreply@example.com"}}
	if err := store.Save(ctx, p1); err != nil {
		t.Fatalf("保存邮件接口失败: %v", err)
	}
	// 返回前端时密钥被脱敏
	if p1.Config["password"] != "******" {
		t.Errorf("保存后应脱敏，实际 %q", p1.Config["password"])
	}
	// 内部读取仍是明文
	full, err := store.Get(ctx, p1.UUID)
	if err != nil {
		t.Fatal(err)
	}
	if full.Config["password"] != "secret-pass" {
		t.Errorf("内部读取应为明文，实际 %q", full.Config["password"])
	}

	// 更新时提交脱敏占位符应保留原密码
	update := &identity.Provider{UUID: p1.UUID, Name: "主邮件-改", Kind: identity.KindEmail, Driver: "smtp",
		Enabled: true, Config: map[string]string{"host": "smtp.example.com", "port": "587",
			"password": "******", "from": "noreply@example.com"}}
	if err := store.Save(ctx, update); err != nil {
		t.Fatalf("更新失败: %v", err)
	}
	full, _ = store.Get(ctx, p1.UUID)
	if full.Config["password"] != "secret-pass" || full.Name != "主邮件-改" {
		t.Errorf("更新后应保留原密码并改名: %+v", full.Config["password"])
	}

	// 必填项缺失应被拒绝
	if err := store.Save(ctx, &identity.Provider{Name: "缺 from", Kind: identity.KindEmail, Driver: "smtp",
		Enabled: true, Config: map[string]string{"host": "h", "port": "587"}}); err == nil {
		t.Error("缺少必填项应被拒绝")
	}

	// 第二个邮件接口设为默认后，第一个自动取消默认
	p2 := &identity.Provider{Name: "备用邮件", Kind: identity.KindEmail, Driver: "resend", Enabled: true,
		Config: map[string]string{"api_key": "k", "from": "noreply@example.com"}}
	if err := store.Save(ctx, p2); err != nil {
		t.Fatal(err)
	}
	if err := store.SetDefault(ctx, p2.UUID); err != nil {
		t.Fatalf("设为默认失败: %v", err)
	}
	if err := store.SetDefault(ctx, p2.UUID); err != nil {
		t.Fatalf("重复设为默认应幂等: %v", err)
	}
	list, err := store.List(ctx, identity.KindEmail)
	if err != nil {
		t.Fatal(err)
	}
	defaults := 0
	for _, p := range list {
		if p.IsDefault {
			defaults++
			if p.UUID != p2.UUID {
				t.Errorf("默认接口应为后设置的那个")
			}
		}
	}
	if defaults != 1 {
		t.Errorf("同类应只有一个默认接口，实际 %d", defaults)
	}

	// 停用的接口不能设为默认
	disabled := &identity.Provider{Name: "停用", Kind: identity.KindEmail, Driver: "resend", Enabled: false,
		Config: map[string]string{"api_key": "k", "from": "a@b.com"}}
	if err := store.Save(ctx, disabled); err != nil {
		t.Fatal(err)
	}
	if err := store.SetDefault(ctx, disabled.UUID); err == nil {
		t.Error("停用接口不应能设为默认")
	}
}

func TestProviderLegacyWebhookAlias(t *testing.T) {
	t.Parallel()
	store, db, ctx := newIdentityStore(t)

	// 直接写入一条旧格式的 webhook 记录，读取时应转为 callback 并迁移字段名
	if _, err := db.ExecContext(ctx,
		`INSERT INTO verify_providers (uuid, name, kind, driver, config_enc, enabled, is_default, created_at, updated_at)
		 VALUES ('legacy-webhook', '旧实名', 'identity', 'webhook', ?, 1, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
		`{"redirect_url":"https://verify.example.com/start","secret":"s3cr3t"}`); err != nil {
		t.Fatal(err)
	}
	p, err := store.Get(ctx, "legacy-webhook")
	if err != nil {
		t.Fatal(err)
	}
	if p.Driver != "callback" {
		t.Errorf("旧驱动名应归一化为 callback，实际 %s", p.Driver)
	}
	if p.Config["request_url"] != "https://verify.example.com/start" {
		t.Errorf("旧字段 redirect_url 应迁移为 request_url，实际 %q", p.Config["request_url"])
	}
	if identity.NormalizeDriver("wechat") != "wechat_faceid" {
		t.Error("wechat 应归一化为 wechat_faceid")
	}
}

func TestIdentityCallbackHMAC(t *testing.T) {
	t.Parallel()
	store, db, ctx := newIdentityStore(t)

	p := &identity.Provider{Name: "三方实名", Kind: identity.KindIdentity, Driver: "callback", Enabled: true,
		Config: map[string]string{"request_url": "https://verify.example.com/start", "verify_mode": "hmac",
			"secret": "topsecret", "callback_format": "json"}}
	if err := store.Save(ctx, p); err != nil {
		t.Fatalf("保存实名接口失败: %v", err)
	}

	// 造一个待处理会话
	sessUUID, subjectUUID := "sess-1", "subj-1"
	exp := time.Now().Add(30 * time.Minute)
	if _, err := db.ExecContext(ctx,
		`INSERT INTO identity_sessions (uuid, provider_uuid, subject_info_uuid, user_uuid, status, expires_at, created_at, updated_at)
		 VALUES (?, ?, ?, 'u1', 'pending', ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
		sessUUID, p.UUID, subjectUUID, exp); err != nil {
		t.Fatal(err)
	}

	body := []byte(`{"session":"sess-1","status":"passed","message":"核验通过","timestamp":` +
		itoa(time.Now().Unix()) + `}`)
	mac := hmac.New(sha256.New, []byte("topsecret"))
	mac.Write(body)
	sig := hex.EncodeToString(mac.Sum(nil))

	// 签名错误
	bad := httptest.NewRequest("POST", "/api/identity/callback/"+p.UUID, strings.NewReader(string(body)))
	bad.Header.Set("X-Signature", "deadbeef")
	if _, _, err := store.HandleCallback(ctx, p.UUID, bad, body); err == nil {
		t.Error("签名错误应被拒绝")
	}

	// 签名正确
	req := httptest.NewRequest("POST", "/api/identity/callback/"+p.UUID, strings.NewReader(string(body)))
	req.Header.Set("X-Signature", sig)
	res, respBody, err := store.HandleCallback(ctx, p.UUID, req, body)
	if err != nil {
		t.Fatalf("回调处理失败: %v", err)
	}
	if !res.Passed || res.SubjectInfoUUID != subjectUUID {
		t.Errorf("回调结果不正确: %+v", res)
	}
	if len(respBody) == 0 {
		t.Error("应返回给第三方响应内容")
	}

	// 幂等：重复回调不改变结果，也不报错
	res2, _, err := store.HandleCallback(ctx, p.UUID, req, body)
	if err != nil || !res2.Passed {
		t.Errorf("重复回调应幂等: %v %+v", err, res2)
	}
}

func TestIdentityCallbackTokenMode(t *testing.T) {
	t.Parallel()
	store, db, ctx := newIdentityStore(t)
	p := &identity.Provider{Name: "Token 校验", Kind: identity.KindIdentity, Driver: "callback", Enabled: true,
		Config: map[string]string{"request_url": "https://v.example.com", "verify_mode": "token", "secret": "tk"}}
	if err := store.Save(ctx, p); err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(time.Hour)
	if _, err := db.ExecContext(ctx,
		`INSERT INTO identity_sessions (uuid, provider_uuid, subject_info_uuid, user_uuid, status, expires_at, created_at, updated_at)
		 VALUES ('sess-tk', ?, 'subj-tk', 'u1', 'pending', ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
		p.UUID, exp); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"session":"sess-tk","status":"failed","message":"核验不通过"}`)

	req := httptest.NewRequest("POST", "/api/identity/callback/"+p.UUID, strings.NewReader(string(body)))
	req.Header.Set("X-Callback-Token", "wrong")
	if _, _, err := store.HandleCallback(ctx, p.UUID, req, body); err == nil {
		t.Error("错误的回调凭证应被拒绝")
	}

	req.Header.Set("X-Callback-Token", "tk")
	res, _, err := store.HandleCallback(ctx, p.UUID, req, body)
	if err != nil {
		t.Fatalf("回调失败: %v", err)
	}
	if res.Passed {
		t.Error("状态为 failed 时不应判定为通过")
	}
}

func TestDomainConfigDefaults(t *testing.T) {
	t.Parallel()
	store, _, ctx := newIdentityStore(t)

	// 没有默认接口时报错
	if _, err := store.DomainConfigForProvider(ctx, ""); err == nil {
		t.Error("未配置域名接口时应报错")
	}

	p := &identity.Provider{Name: "DNS 验证", Kind: identity.KindDomain, Driver: "dns_txt", Enabled: true,
		Config: map[string]string{"record_prefix": "_verify", "resolver": "8.8.8.8", "timeout": "5"}}
	if err := store.Save(ctx, p); err != nil {
		t.Fatal(err)
	}
	cfg, err := store.DomainConfigForProvider(ctx, "")
	if err != nil {
		t.Fatalf("应回退到唯一的域名接口: %v", err)
	}
	if cfg.Method != identity.DomainMethodDNS || cfg.RecordPrefix != "_verify" || cfg.Port != 80 {
		t.Errorf("配置解析不正确: %+v", cfg)
	}
	if cfg.Timeout != 5*time.Second {
		t.Errorf("超时应为 5s，实际 %v", cfg.Timeout)
	}

	// HTTP / TLS 的默认端口
	http := &identity.Provider{Name: "HTTP 验证", Kind: identity.KindDomain, Driver: "http_file", Enabled: true}
	if err := store.Save(ctx, http); err != nil {
		t.Fatal(err)
	}
	cfg, _ = store.DomainConfigForProvider(ctx, http.UUID)
	if cfg.Method != identity.DomainMethodHTTP || cfg.PathPrefix != "/.well-known/pki-validation/" {
		t.Errorf("HTTP 默认配置不正确: %+v", cfg)
	}
	if cfg.Port != 80 {
		t.Errorf("HTTP 默认端口应为 80，实际 %d", cfg.Port)
	}
	tls := &identity.Provider{Name: "TLS 验证", Kind: identity.KindDomain, Driver: "tls_alpn", Enabled: true}
	if err := store.Save(ctx, tls); err != nil {
		t.Fatal(err)
	}
	cfg, _ = store.DomainConfigForProvider(ctx, tls.UUID)
	if cfg.Port != 443 {
		t.Errorf("TLS 默认端口应为 443，实际 %d", cfg.Port)
	}
}

func TestIdentityDriverNotSupported(t *testing.T) {
	t.Parallel()
	store, db, ctx := newIdentityStore(t)
	p := &identity.Provider{Name: "回调", Kind: identity.KindIdentity, Driver: "callback", Enabled: true,
		Config: map[string]string{"request_url": "https://v.example.com"}}
	if err := store.Save(ctx, p); err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(time.Hour)
	if _, err := db.ExecContext(ctx,
		`INSERT INTO identity_sessions (uuid, provider_uuid, subject_info_uuid, user_uuid, status, expires_at, created_at, updated_at)
		 VALUES ('sess-q', ?, 'subj-q', 'u1', 'pending', ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
		p.UUID, exp); err != nil {
		t.Fatal(err)
	}
	// 回调认证不支持主动查询，应给出可读错误
	if _, err := store.QueryIdentity(ctx, p.UUID, "sess-q"); err == nil {
		t.Error("不支持的操作应返回错误")
	} else if !strings.Contains(err.Error(), "查询") {
		t.Errorf("错误信息应说明不支持的操作，实际: %v", err)
	}
}

// itoa 避免为单个测试引入 strconv。
func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
