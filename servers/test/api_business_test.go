// Package test - 业务 API 集成测试（真实 HTTP 层）。
//
// 覆盖生产发布前的关键链路：
//   - 三层配置：颁发模板 → 开通模板（绑定主体/扩展模板）→ 商品规格（含 SAN 限制）
//   - 身份验证：主体信息人工审核、扩展信息自动验证与有效期
//   - 销售签发：下单 → 线下到账确认 → 申请向导上下文 → 提交 → 自动签发
//   - SAN 限制拒绝超额申请
//   - 订阅：套餐下单 → 支付后开通额度 → 额度申请与耗尽拒绝
//   - 优惠码预览、兑换码入账（同一用户限一次）
//   - 服务：OCSP 响应服务 CRUD 与路由、证书策略 CRUD 与公开访问、认证接口密钥脱敏
package test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/globaltrusts/server-card/configs"
	"github.com/globaltrusts/server-card/internal/api"
	"github.com/globaltrusts/server-card/internal/auth"
	"github.com/globaltrusts/server-card/internal/ca"
	"github.com/globaltrusts/server-card/internal/card"
	"github.com/globaltrusts/server-card/internal/cps"
	"github.com/globaltrusts/server-card/internal/identity"
	"github.com/globaltrusts/server-card/internal/issuance"
	"github.com/globaltrusts/server-card/internal/mailer"
	"github.com/globaltrusts/server-card/internal/payment"
	"github.com/globaltrusts/server-card/internal/portal"
	"github.com/globaltrusts/server-card/internal/promo"
	"github.com/globaltrusts/server-card/internal/revocation"
	"github.com/globaltrusts/server-card/internal/storage"
	"github.com/globaltrusts/server-card/internal/template"
	"github.com/globaltrusts/server-card/internal/verification"
	"github.com/globaltrusts/server-card/internal/workflow"
	"golang.org/x/crypto/bcrypt"
)

// apiEnv 是集成测试环境：内存文件库 + 真实 HTTP 处理器。
type apiEnv struct {
	t      *testing.T
	srv    *httptest.Server
	client *http.Client
	tokens map[string]string
}

// call 发起请求并解析响应（非 2xx 返回错误）。
func (e *apiEnv) call(method, path, token string, body interface{}, out interface{}) error {
	e.t.Helper()
	var reader io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, e.srv.URL+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s -> %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("解析响应失败: %w (%s)", err, string(raw))
		}
	}
	return nil
}

// mustCall 断言请求成功。
func (e *apiEnv) mustCall(method, path, token string, body interface{}, out interface{}) {
	e.t.Helper()
	if err := e.call(method, path, token, body, out); err != nil {
		e.t.Fatalf("%v", err)
	}
}

// mustFail 断言请求失败（用于校验约束确实生效）。
func (e *apiEnv) mustFail(method, path, token string, body interface{}) {
	e.t.Helper()
	if err := e.call(method, path, token, body, nil); err == nil {
		e.t.Fatalf("%s %s 预期失败但成功", method, path)
	}
}

func newAPIEnv(t *testing.T) *apiEnv {
	t.Helper()
	db := setupServerDB(t)
	ctx := context.Background()

	cfg := &configs.Config{
		API: configs.APIConfig{Host: "127.0.0.1", Port: 0},
		JWT: configs.JWTConfig{Secret: "integration-test-secret-please-ignore", ExpiryHours: 24},
	}
	jwtMgr, err := auth.NewManager(cfg.JWT.Secret, cfg.JWT.ExpiryHours)
	if err != nil {
		t.Fatalf("初始化 JWT 失败: %v", err)
	}

	userRepo := storage.NewUserRepo(db)
	logRepo := storage.NewLogRepo(db)
	cardRepo := storage.NewCardRepo(db)
	certRepo := storage.NewCertRepo(db)

	cardSvc := card.NewService(cardRepo, certRepo, testMasterKey)
	caSvc := ca.NewService(db, testMasterKey)
	issSvc := issuance.NewService(db)

	verifySvc := verification.NewService(db)
	verifySvc.SetMailer(mailer.New(configs.SMTPConfig{}))
	identityStore := identity.NewStore(db, cardSvc, mailer.New(configs.SMTPConfig{}))
	verifySvc.SetProviders(identityStore)

	workflowSvc := workflow.NewService(db, caSvc, issSvc)
	portalSvc := portal.NewService(storage.NewPortalRepo(db), workflowSvc)
	registry := payment.NewRegistry()
	paymentSvc := payment.NewService(db, registry)

	promoSvc := promo.NewService(db)
	portalSvc.SetPromo(promoSvc)

	revocationSvc := revocation.NewService(db, caSvc)
	cpsSvc := cps.NewService(db)
	tmplSvc := template.NewService(db)

	srv := api.NewServer(cfg, db, jwtMgr, &api.Services{
		CardSvc: cardSvc, CASvc: caSvc, IssuanceSvc: issSvc, VerifySvc: verifySvc,
		WorkflowSvc: workflowSvc, PaymentSvc: paymentSvc, TmplSvc: tmplSvc,
		RevocationSvc: revocationSvc, PortalSvc: portalSvc,
		IdentityStore: identityStore, CPSSvc: cpsSvc, PromoSvc: promoSvc,
	}, userRepo, logRepo)

	// 创建管理员与普通用户
	hash, _ := bcrypt.GenerateFromPassword([]byte("AdminPass123"), bcrypt.MinCost)
	if err := userRepo.Create(ctx, &storage.User{
		UUID: "admin-uuid", Username: "admin", DisplayName: "管理员", Email: "admin@test.local",
		PasswordHash: string(hash), Role: "admin", Enabled: true,
	}); err != nil {
		t.Fatalf("创建管理员失败: %v", err)
	}
	hash2, _ := bcrypt.GenerateFromPassword([]byte("BuyerPass123"), bcrypt.MinCost)
	if err := userRepo.Create(ctx, &storage.User{
		UUID: "buyer-uuid", Username: "buyer", DisplayName: "买家", Email: "buyer@test.local",
		PasswordHash: string(hash2), Role: "user", Enabled: true,
	}); err != nil {
		t.Fatalf("创建用户失败: %v", err)
	}

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	env := &apiEnv{t: t, srv: ts, client: ts.Client(), tokens: map[string]string{}}
	for _, u := range []struct{ name, pass string }{{"admin", "AdminPass123"}, {"buyer", "BuyerPass123"}} {
		var resp struct {
			Token string `json:"token"`
		}
		env.mustCall(http.MethodPost, "/api/auth/login", "", map[string]string{
			"username": u.name, "password": u.pass,
		}, &resp)
		if resp.Token == "" {
			t.Fatalf("%s 登录未返回 token", u.name)
		}
		env.tokens[u.name] = resp.Token
	}
	return env
}

func TestAPIBusinessFlow(t *testing.T) {
	env := newAPIEnv(t)
	admin, buyer := env.tokens["admin"], env.tokens["buyer"]
	httpErr := env.call // 便于阅读

	// ---- 站点配置：销售模式 + 自助 SAN 限制 ----
	env.mustCall(http.MethodPut, "/api/site-settings", admin, map[string]string{
		"cert_apply_mode": "sales", "card_apply_mode": "self", "card_self_limit": "2",
		"self_san_policy": `{"max_dns":5,"max_email":1,"max_ip":0,"allow_wildcard":false,"ip_versions":["v4","v6"]}`,
	}, nil)

	var caps struct {
		CertApplyMode string `json:"cert_apply_mode"`
		CanCreateCard bool   `json:"can_create_card"`
		CardApplyMode string `json:"card_apply_mode"`
		Subscriptions []any  `json:"subscriptions"`
	}
	env.mustCall(http.MethodGet, "/api/portal/capabilities", buyer, nil, &caps)
	if caps.CertApplyMode != "sales" {
		t.Fatalf("证书模式应为 sales，实际 %s", caps.CertApplyMode)
	}
	if caps.CardApplyMode != "self" || !caps.CanCreateCard {
		t.Fatalf("自助开卡应可用，实际 mode=%s can=%v", caps.CardApplyMode, caps.CanCreateCard)
	}

	// ---- 三层配置 ----
	var caResp struct {
		UUID string `json:"uuid"`
	}
	env.mustCall(http.MethodPost, "/api/cas", admin, map[string]interface{}{
		"name": "集成测试 CA", "key_type": "ec256", "validity_years": 5, "common_name": "集成测试 CA",
		"organization": "Test Org", "country": "CN",
	}, &caResp)

	var issuance struct {
		UUID string `json:"uuid"`
	}
	env.mustCall(http.MethodPost, "/api/templates/issuance", admin, map[string]interface{}{
		"name": "集成颁发模板", "category": "ssl", "enabled": true, "valid_days": "[365]",
		"allowed_key_types": `["ec256"]`, "allowed_ca_uuids": fmt.Sprintf(`["%s"]`, caResp.UUID),
	}, &issuance)

	var subjectTmpl struct {
		UUID string `json:"uuid"`
	}
	env.mustCall(http.MethodPost, "/api/templates/subject", admin, map[string]string{
		"name": "集成主体模板",
		"fields": `[{"key":"CN","required":true,"derive":"first_domain"},` +
			`{"key":"O","required":true,"min_len":2,"max_len":40,"verify":"manual"}]`,
		"verify_validity": "7d",
	}, &subjectTmpl)

	// 字段名非法应被拒绝
	env.mustFail(http.MethodPost, "/api/templates/subject", admin, map[string]string{
		"name": "非法字段", "fields": `[{"key":"FOO","required":true}]`,
	})

	var extTmpl struct {
		UUID string `json:"uuid"`
	}
	// 域名：免验证（DV 快速通道，便于端到端确定性验证）；邮箱：人工审核；IP：不支持
	env.mustCall(http.MethodPost, "/api/templates/extension", admin, map[string]string{
		"name": "集成扩展模板",
		"verify_policy": `{"domain":{"enabled":true,"mode":"none","methods":["dns","http"],"validity":"7d"},` +
			`"email":{"enabled":true,"mode":"manual","validity":"7d"},"ip":{"enabled":false}}`,
	}, &extTmpl)

	var applyTmpl struct {
		UUID            string `json:"uuid"`
		RequireApproval bool   `json:"require_approval"`
	}
	// 技术配置（CA、有效期、算法、资料要求）统一绑定在颁发模板上
	env.mustCall(http.MethodPut, "/api/templates/issuance/"+issuance.UUID, admin, map[string]interface{}{
		"name": "集成颁发模板", "category": "ssl", "enabled": true, "valid_days": "[365]", "default_valid_days": 365,
		"allowed_key_types": `["ec256"]`, "allowed_ca_uuids": fmt.Sprintf(`["%s"]`, caResp.UUID),
		"default_ca_uuid":   caResp.UUID,
		"subject_tmpl_uuid": subjectTmpl.UUID, "extension_tmpl_uuid": extTmpl.UUID,
	}, nil)
	// 开通模板只管业务规则，旧的技术字段会被忽略
	env.mustCall(http.MethodPost, "/api/templates/cert-apply", admin, map[string]interface{}{
		"name": "集成开通模板", "issuance_tmpl_uuid": issuance.UUID,
		"enabled": true, "require_approval": false, "allow_renewal": true,
	}, &applyTmpl)
	if applyTmpl.RequireApproval {
		t.Fatalf("开通模板审批配置不正确: %+v", applyTmpl)
	}
	// 可申请方式非法应被拒绝
	env.mustFail(http.MethodPost, "/api/templates/cert-apply", admin, map[string]interface{}{
		"name": "非法申请方式", "issuance_tmpl_uuid": issuance.UUID, "enabled": true, "apply_modes": `["bogus"]`,
	})
	// 引用不存在的颁发模板应被拒绝
	env.mustFail(http.MethodPost, "/api/templates/cert-apply", admin, map[string]interface{}{
		"name": "断链模板", "issuance_tmpl_uuid": "missing", "enabled": true,
	})

	// ---- 商品与规格（含 SAN 限制）----
	var product struct {
		UUID string `json:"uuid"`
	}
	env.mustCall(http.MethodPost, "/api/portal/admin/products", admin, map[string]interface{}{
		"code": "it-ssl", "name": "集成 SSL", "category": "ssl", "summary": "test",
		"visible": true, "enabled": true,
	}, &product)

	var sku struct {
		UUID string `json:"uuid"`
		Code string `json:"code"`
	}
	env.mustCall(http.MethodPost, "/api/portal/admin/skus", admin, map[string]interface{}{
		"product_uuid": product.UUID, "code": "it-ssl-1y", "name": "标准版", "price_cents": 10000,
		"currency": "CNY", "stock": 5, "min_qty": 1, "max_qty": 2, "duration_months": 12,
		"delivery_mode": "download", "key_types": `["ec256"]`, "san_included": 1,
		"san_policy":           `{"max_dns":2,"max_email":0,"max_ip":0,"allow_wildcard":false,"ip_versions":["v4","v6"]}`,
		"cert_apply_tmpl_uuid": applyTmpl.UUID, "enabled": true,
	}, &sku)

	// ---- 下单 → 线下到账 ----
	var order struct {
		UUID    string `json:"uuid"`
		OrderNo string `json:"order_no"`
		Status  string `json:"status"`
	}
	env.mustCall(http.MethodPost, "/api/portal/orders", buyer, map[string]interface{}{
		"sku_code": sku.Code, "quantity": 1, "applicant_email": "buyer@test.local",
	}, &order)
	if order.Status != "pending_payment" {
		t.Fatalf("新订单应为待支付，实际 %s", order.Status)
	}
	env.mustCall(http.MethodPost, "/api/portal/admin/orders/"+order.OrderNo+"/confirm-payment", admin,
		map[string]string{"reference": "IT-001"}, nil)
	var paid struct {
		Status string `json:"status"`
	}
	env.mustCall(http.MethodGet, "/api/portal/orders/"+order.OrderNo, buyer, nil, &paid)
	if paid.Status != "paid" {
		t.Fatalf("确认到账后订单应为已支付，实际 %s", paid.Status)
	}

	// ---- 扩展信息：自动验证策略 → 直接通过 ----
	var ext struct {
		ExtensionInfo struct {
			UUID         string `json:"uuid"`
			VerifyStatus string `json:"verify_status"`
			ExpiresAt    string `json:"expires_at"`
		} `json:"extension_info"`
		Instructions string `json:"instructions"`
	}
	env.mustCall(http.MethodPost, "/api/extension-infos", buyer, map[string]string{
		"info_type": "domain", "value": "a.example.com", "tmpl_uuid": extTmpl.UUID,
	}, &ext)
	if ext.ExtensionInfo.VerifyStatus != "verified" || ext.ExtensionInfo.ExpiresAt == "" {
		t.Fatalf("免验证域名应直接通过并带有效期: %+v", ext.ExtensionInfo)
	}
	// 非法域名被拒绝
	env.mustFail(http.MethodPost, "/api/extension-infos", buyer, map[string]string{
		"info_type": "domain", "value": "bad_domain", "tmpl_uuid": extTmpl.UUID,
	})
	// IP 在模板中被禁用
	env.mustFail(http.MethodPost, "/api/extension-infos", buyer, map[string]string{
		"info_type": "ip", "value": "1.2.3.4", "tmpl_uuid": extTmpl.UUID,
	})

	// 邮箱：人工审核策略 → 待人工审核 → 管理员通过 → 已验证
	var emailExt struct {
		ExtensionInfo struct {
			UUID         string `json:"uuid"`
			VerifyStatus string `json:"verify_status"`
		} `json:"extension_info"`
	}
	env.mustCall(http.MethodPost, "/api/extension-infos", buyer, map[string]string{
		"info_type": "email", "value": "ops@example.com", "tmpl_uuid": extTmpl.UUID,
	}, &emailExt)
	if emailExt.ExtensionInfo.VerifyStatus != "reviewing" {
		t.Fatalf("人工策略的邮箱应待人工审核，实际 %s", emailExt.ExtensionInfo.VerifyStatus)
	}
	env.mustCall(http.MethodPost, "/api/extension-infos/"+emailExt.ExtensionInfo.UUID+"/approve", admin, nil, nil)
	var reviews struct {
		Items []struct {
			UUID         string `json:"uuid"`
			VerifyStatus string `json:"verify_status"`
			ExpiresAt    string `json:"expires_at"`
		} `json:"items"`
	}
	env.mustCall(http.MethodGet, "/api/admin/identity-reviews?kind=extension&status=verified", admin, nil, &reviews)
	for _, it := range reviews.Items {
		if it.UUID == emailExt.ExtensionInfo.UUID && it.ExpiresAt == "" {
			t.Fatal("人工审核通过的扩展信息应带有效期")
		}
	}

	// ---- 主体信息：人工字段 → 待审核 → 管理员通过（带有效期）----
	var subject struct {
		UUID   string `json:"uuid"`
		Status string `json:"status"`
	}
	env.mustCall(http.MethodPost, "/api/subject-infos", buyer, map[string]interface{}{
		"subject_tmpl_uuid": subjectTmpl.UUID, "field_values": map[string]string{"O": "集成测试组织"},
	}, &subject)
	if subject.Status != "pending" {
		t.Fatalf("人工字段主体信息应为待审核，实际 %s", subject.Status)
	}
	env.mustCall(http.MethodPost, "/api/subject-infos/"+subject.UUID+"/approve", admin, nil, nil)
	var subjects struct {
		Items []struct {
			UUID      string `json:"uuid"`
			Status    string `json:"status"`
			ExpiresAt string `json:"expires_at"`
		} `json:"items"`
	}
	env.mustCall(http.MethodGet, "/api/subject-infos", buyer, nil, &subjects)
	var approved *struct {
		UUID      string `json:"uuid"`
		Status    string `json:"status"`
		ExpiresAt string `json:"expires_at"`
	}
	for i := range subjects.Items {
		if subjects.Items[i].UUID == subject.UUID {
			approved = &subjects.Items[i]
		}
	}
	if approved == nil || approved.Status != "approved" || approved.ExpiresAt == "" {
		t.Fatalf("主体信息应已通过且带有效期: %+v", approved)
	}

	// ---- 申请向导上下文 ----
	var actx struct {
		Source struct {
			Kind      string `json:"kind"`
			Remaining int    `json:"remaining"`
			SANPolicy struct {
				MaxDNS int `json:"max_dns"`
			} `json:"san_policy"`
		} `json:"source"`
		Subject struct {
			TemplateUUID string `json:"template_uuid"`
			NeedsInfo    bool   `json:"needs_info"`
		} `json:"subject"`
	}
	env.mustCall(http.MethodGet, "/api/portal/apply-context?order_no="+order.OrderNo, buyer, nil, &actx)
	if actx.Subject.TemplateUUID != subjectTmpl.UUID || actx.Source.SANPolicy.MaxDNS != 2 || actx.Source.Remaining != 1 {
		t.Fatalf("申请上下文不正确: %+v", actx)
	}

	// ---- 提交申请：免审批 → 自动签发 ----
	var applyResp struct {
		AutoIssued  bool `json:"auto_issued"`
		Application struct {
			UUID     string `json:"uuid"`
			CertUUID string `json:"cert_uuid"`
			Status   string `json:"status"`
		} `json:"application"`
		Message string `json:"message"`
	}
	env.mustCall(http.MethodPost, "/api/portal/applications", buyer, map[string]interface{}{
		"order_no": order.OrderNo, "subject_info_uuid": subject.UUID,
		"extension_info_uuids": []string{ext.ExtensionInfo.UUID}, "key_type": "ec256",
	}, &applyResp)
	if !applyResp.AutoIssued || applyResp.Application.CertUUID == "" || applyResp.Application.Status != "approved" {
		t.Fatalf("应自动签发并回填证书: %+v", applyResp)
	}

	// ---- SAN 限制：超出 2 个域名被拒绝 ----
	var order2 struct {
		OrderNo string `json:"order_no"`
	}
	env.mustCall(http.MethodPost, "/api/portal/orders", buyer, map[string]interface{}{
		"sku_code": sku.Code, "quantity": 1, "applicant_email": "buyer@test.local",
	}, &order2)
	env.mustCall(http.MethodPost, "/api/portal/admin/orders/"+order2.OrderNo+"/confirm-payment", admin,
		map[string]string{"reference": "IT-002"}, nil)
	extIDs := []string{ext.ExtensionInfo.UUID}
	for _, host := range []string{"b.example.com", "c.example.com"} {
		var e struct {
			ExtensionInfo struct {
				UUID string `json:"uuid"`
			} `json:"extension_info"`
		}
		env.mustCall(http.MethodPost, "/api/extension-infos", buyer, map[string]string{
			"info_type": "domain", "value": host, "tmpl_uuid": extTmpl.UUID,
		}, &e)
		extIDs = append(extIDs, e.ExtensionInfo.UUID)
	}
	env.mustFail(http.MethodPost, "/api/portal/applications", buyer, map[string]interface{}{
		"order_no": order2.OrderNo, "subject_info_uuid": subject.UUID,
		"extension_info_uuids": extIDs, "key_type": "ec256",
	})

	// ---- 优惠码：预览与下单抵扣 ----
	var coupon struct {
		UUID string `json:"uuid"`
		Code string `json:"code"`
	}
	env.mustCall(http.MethodPost, "/api/promo/coupons", admin, map[string]interface{}{
		"code": "ITSAVE10", "name": "集成优惠", "discount_type": "amount", "discount_value": 1000,
		"min_amount_cents": 5000, "total_limit": 1, "per_user_limit": 1, "enabled": true,
	}, &coupon)
	var quote struct {
		TotalCents    int64 `json:"total_cents"`
		DiscountCents int64 `json:"discount_cents"`
		PayableCents  int64 `json:"payable_cents"`
	}
	env.mustCall(http.MethodPost, "/api/portal/quotes/coupon", buyer, map[string]interface{}{
		"sku_code": sku.Code, "quantity": 1, "coupon_code": coupon.Code,
	}, &quote)
	if quote.DiscountCents != 1000 || quote.PayableCents != 9000 {
		t.Fatalf("优惠码抵扣不正确: %+v", quote)
	}

	var discounted struct {
		AmountCents   int64  `json:"amount_cents"`
		DiscountCents int64  `json:"discount_cents"`
		CouponCode    string `json:"coupon_code"`
		OrderNo       string `json:"order_no"`
	}
	env.mustCall(http.MethodPost, "/api/portal/orders", buyer, map[string]interface{}{
		"sku_code": sku.Code, "quantity": 1, "applicant_email": "buyer@test.local", "coupon_code": coupon.Code,
	}, &discounted)
	if discounted.AmountCents != 9000 || discounted.DiscountCents != 1000 {
		t.Fatalf("订单金额应扣除优惠: %+v", discounted)
	}
	// 取消订单后优惠码次数应归还
	env.mustCall(http.MethodPost, "/api/portal/orders/"+discounted.OrderNo+"/cancel", buyer, nil, nil)
	var quote2 struct {
		DiscountCents int64 `json:"discount_cents"`
	}
	env.mustCall(http.MethodPost, "/api/portal/quotes/coupon", buyer, map[string]interface{}{
		"sku_code": sku.Code, "quantity": 1, "coupon_code": coupon.Code,
	}, &quote2)
	if quote2.DiscountCents != 1000 {
		t.Fatalf("取消后优惠码应可再次使用: %+v", quote2)
	}

	// ---- 订阅：套餐 → 支付 → 额度开通 → 额度申请 → 耗尽拒绝 ----
	var plan struct {
		UUID string `json:"uuid"`
		Code string `json:"code"`
	}
	env.mustCall(http.MethodPost, "/api/promo/plans", admin, map[string]interface{}{
		"code": "it-plan", "name": "集成套餐", "period_days": 30, "price_cents": 0,
		"items": []map[string]interface{}{{
			"cert_apply_tmpl_uuid": applyTmpl.UUID, "quota": 1, "valid_days": 365,
		}},
		"allow_revoke": true, "revoke_release_quota": true, "visible": true, "enabled": true,
	}, &plan)
	// 单证有效期不在颁发模板允许列表内 → 拒绝
	env.mustFail(http.MethodPost, "/api/promo/plans", admin, map[string]interface{}{
		"code": "it-plan-bad", "name": "非法有效期", "period_days": 30, "price_cents": 0,
		"items": []map[string]interface{}{{
			"cert_apply_tmpl_uuid": applyTmpl.UUID, "quota": 1, "valid_days": 90,
		}},
		"enabled": true,
	})

	var planOrder struct {
		OrderNo string `json:"order_no"`
	}
	env.mustCall(http.MethodPost, "/api/portal/plans/"+plan.Code+"/orders", buyer,
		map[string]string{"applicant_email": "buyer@test.local"}, &planOrder)
	env.mustCall(http.MethodPost, "/api/portal/admin/orders/"+planOrder.OrderNo+"/confirm-payment", admin,
		map[string]string{"reference": "IT-PLAN"}, nil)

	var subs struct {
		Items []struct {
			UUID   string `json:"uuid"`
			Status string `json:"status"`
			Usage  []struct {
				CertApplyTmplUUID string `json:"cert_apply_tmpl_uuid"`
				Quota             int    `json:"quota"`
				Used              int    `json:"used"`
				Remaining         int    `json:"remaining"`
			} `json:"usage"`
		} `json:"items"`
	}
	env.mustCall(http.MethodGet, "/api/portal/subscriptions", buyer, nil, &subs)
	if len(subs.Items) != 1 || subs.Items[0].Status != "active" {
		t.Fatalf("支付后应自动开通订阅: %+v", subs.Items)
	}
	subUUID := subs.Items[0].UUID

	var subExt struct {
		ExtensionInfo struct {
			UUID string `json:"uuid"`
		} `json:"extension_info"`
	}
	env.mustCall(http.MethodPost, "/api/extension-infos", buyer, map[string]string{
		"info_type": "domain", "value": "sub.example.com", "tmpl_uuid": extTmpl.UUID,
	}, &subExt)

	var subApply struct {
		AutoIssued bool `json:"auto_issued"`
	}
	env.mustCall(http.MethodPost, "/api/portal/applications", buyer, map[string]interface{}{
		"subscription_uuid": subUUID, "cert_apply_tmpl_uuid": applyTmpl.UUID,
		"subject_info_uuid": subject.UUID, "extension_info_uuids": []string{subExt.ExtensionInfo.UUID},
		"key_type": "ec256",
	}, &subApply)
	if !subApply.AutoIssued {
		t.Fatalf("订阅额度申请应自动签发: %+v", subApply)
	}

	env.mustCall(http.MethodGet, "/api/portal/subscriptions", buyer, nil, &subs)
	used := 0
	for _, it := range subs.Items[0].Usage {
		if it.CertApplyTmplUUID == applyTmpl.UUID {
			used = it.Used
		}
	}
	if used != 1 {
		t.Fatalf("订阅额度应被占用 1 张，实际 %d", used)
	}
	env.mustFail(http.MethodPost, "/api/portal/applications", buyer, map[string]interface{}{
		"subscription_uuid": subUUID, "cert_apply_tmpl_uuid": applyTmpl.UUID,
		"subject_info_uuid": subject.UUID, "extension_info_uuids": []string{subExt.ExtensionInfo.UUID},
		"key_type": "ec256",
	})

	// ---- 兑换码：入账并限制重复兑换 ----
	var codes struct {
		Items []struct {
			Code string `json:"code"`
		} `json:"items"`
	}
	env.mustCall(http.MethodPost, "/api/promo/redeem-codes", admin, map[string]interface{}{
		"batch_name": "it", "grant_type": "balance", "balance_cents": 5000, "max_uses": 1, "count": 2,
	}, &codes)
	if len(codes.Items) != 2 {
		t.Fatalf("应生成 2 个兑换码: %+v", codes)
	}
	var redeem struct {
		GrantType    string `json:"grant_type"`
		BalanceCents int64  `json:"balance_cents"`
	}
	env.mustCall(http.MethodPost, "/api/portal/redeem", buyer, map[string]string{"code": codes.Items[0].Code}, &redeem)
	if redeem.BalanceCents != 5000 {
		t.Fatalf("兑换应到账 5000 分: %+v", redeem)
	}
	env.mustFail(http.MethodPost, "/api/portal/redeem", buyer, map[string]string{"code": codes.Items[0].Code})

	// ---- OCSP 响应服务 ----
	var responder struct {
		UUID string `json:"uuid"`
		Path string `json:"path"`
	}
	env.mustCall(http.MethodPost, "/api/ocsp-responders", admin, map[string]interface{}{
		"name": "集成 OCSP", "path": "it-ocsp", "signer_type": "ca", "signer_ref": caResp.UUID,
		"ca_uuids": []string{caResp.UUID}, "next_update_minutes": 60, "unknown_policy": "unknown", "enabled": true,
	}, &responder)
	env.mustFail(http.MethodPost, "/api/ocsp-responders", admin, map[string]interface{}{
		"name": "非法路径", "path": "Bad Path", "signer_type": "ca", "signer_ref": caResp.UUID,
		"ca_uuids": []string{caResp.UUID},
	})
	// 畸形请求：路由可达（非 404）
	resp, err := env.client.Post(env.srv.URL+"/ocsp/r/it-ocsp", "application/ocsp-request", bytes.NewReader([]byte{1, 2, 3}))
	if err != nil {
		t.Fatalf("OCSP 请求失败: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		t.Fatal("OCSP 自定义路径应由后端处理（不应 404 回退到前端）")
	}

	// ---- 证书策略页面 ----
	var policy struct {
		UUID string `json:"uuid"`
	}
	env.mustCall(http.MethodPost, "/api/cert-policies", admin, map[string]interface{}{
		"name": "集成 CPS", "path": "it-cps", "content_type": "markdown",
		"content": "# 集成 CPS\n\n策略正文。", "version": "v1.0", "enabled": true, "is_public": true,
	}, &policy)
	raw, err := http.Get(env.srv.URL + "/policy/it-cps")
	if err != nil {
		t.Fatalf("策略页面请求失败: %v", err)
	}
	body, _ := io.ReadAll(raw.Body)
	raw.Body.Close()
	if raw.StatusCode != http.StatusOK || !strings.Contains(string(body), "集成 CPS") {
		t.Fatalf("策略页面应公开返回正文: %d %s", raw.StatusCode, string(body))
	}
	var publicPolicies struct {
		Items []struct {
			Name string `json:"name"`
		} `json:"items"`
	}
	env.mustCall(http.MethodGet, "/api/portal/policies", "", nil, &publicPolicies)
	if len(publicPolicies.Items) == 0 {
		t.Fatal("公开策略应在信任中心列表中")
	}

	// ---- 认证接口：密钥脱敏 ----
	var provider struct {
		UUID string `json:"uuid"`
	}
	env.mustCall(http.MethodPost, "/api/verify-providers", admin, map[string]interface{}{
		"name": "集成 SMTP", "kind": "email", "driver": "smtp", "enabled": true,
		"config": map[string]string{
			"host": "smtp.example.com", "port": "587", "username": "apikey",
			"password": "super-secret", "from": "noreply@example.com",
		},
	}, &provider)
	var providers struct {
		Items []struct {
			UUID   string            `json:"uuid"`
			Config map[string]string `json:"config"`
		} `json:"items"`
		Drivers []struct {
			Driver    string `json:"driver"`
			Available bool   `json:"available"`
		} `json:"drivers"`
	}
	env.mustCall(http.MethodGet, "/api/verify-providers", admin, nil, &providers)
	masked := ""
	for _, p := range providers.Items {
		if p.UUID == provider.UUID {
			masked = p.Config["password"]
		}
	}
	if masked != "******" {
		t.Fatalf("认证接口密钥应脱敏，实际 %q", masked)
	}
	if len(providers.Drivers) == 0 {
		t.Fatal("驱动目录应返回给前端渲染表单")
	}

	// ---- 运营视图与审计 ----
	var adminOrders struct {
		Total int `json:"total"`
	}
	env.mustCall(http.MethodGet, "/api/portal/admin/orders?page=1&page_size=20", admin, nil, &adminOrders)
	if adminOrders.Total < 3 {
		t.Fatalf("管理员应看到全部订单，实际 %d", adminOrders.Total)
	}
	var audit struct {
		Total int `json:"total"`
	}
	env.mustCall(http.MethodGet, "/api/audit-logs?page=1&page_size=20", admin, nil, &audit)
	if audit.Total < 1 {
		t.Fatal("管理操作应写入审计日志")
	}

	// 普通用户访问管理员接口应被拒绝
	if err := httpErr(http.MethodGet, "/api/verify-providers", buyer, nil, nil); err == nil {
		t.Fatal("普通用户不应访问认证接口管理")
	}
}
