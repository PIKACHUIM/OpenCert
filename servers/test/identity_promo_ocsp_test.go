// Package test - 身份认证规则、模板化验证、独立 OCSP 响应服务、优惠/订阅/兑换码测试。
package test

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/globaltrusts/server-card/internal/ca"
	"github.com/globaltrusts/server-card/internal/identity"
	"github.com/globaltrusts/server-card/internal/issuance"
	"github.com/globaltrusts/server-card/internal/promo"
	"github.com/globaltrusts/server-card/internal/revocation"
	"github.com/globaltrusts/server-card/internal/storage"
	"github.com/globaltrusts/server-card/internal/verification"
	"golang.org/x/crypto/ocsp"
)

func TestIdentitySubjectRules(t *testing.T) {
	t.Parallel()
	fields, err := identity.ParseSubjectFields(`[
		{"key":"cn","required":true,"derive":"first_domain"},
		{"key":"O","required":true,"min_len":2,"max_len":20,"verify":"manual"},
		{"key":"C","required":true,"format":"country","verify":"none","default":"CN"}
	]`)
	if err != nil {
		t.Fatalf("解析字段失败: %v", err)
	}
	if fields[0].Key != "CN" || fields[0].Verify != identity.VerifyNone {
		t.Errorf("派生字段应规范化为免验证，实际 %+v", fields[0])
	}
	if identity.SubjectVerifyMode(fields) != identity.VerifyManual {
		t.Error("存在人工字段时应为人工审核")
	}
	if _, err := identity.ValidateSubjectValues(fields, map[string]string{"O": "A"}); err == nil {
		t.Error("长度不足应报错")
	}
	vals, err := identity.ValidateSubjectValues(fields, map[string]string{"O": "测试公司", "X": "忽略"})
	if err != nil || vals["C"] != "CN" || vals["X"] != "" {
		t.Fatalf("应补默认值并剔除未定义字段，实际 %v err=%v", vals, err)
	}
	if err := identity.ApplyDerivedFields(fields, vals, map[string][]string{}); err == nil {
		t.Error("必填派生字段缺少来源应报错")
	}
	identity.ApplyDerivedFields(fields, vals, map[string][]string{"dns": {"a.example.com"}}) //nolint:errcheck
	if vals["CN"] != "a.example.com" {
		t.Errorf("CN 应派生自第一个域名，实际 %q", vals["CN"])
	}
	if _, err := identity.ParseSubjectFields(`[{"key":"FOO"}]`); err == nil {
		t.Error("不支持的字段应报错")
	}
}

func TestIdentitySANPolicyAndValidity(t *testing.T) {
	t.Parallel()
	p := identity.ParseSANPolicy(`{"max_dns":2,"max_email":1,"max_ip":1,"ip_versions":["v4"],"email_suffixes":["corp.com"]}`, 0)
	if err := p.Check(map[string][]string{"dns": {"a.com", "b.com", "c.com"}}); err == nil {
		t.Error("超过域名数量应报错")
	}
	if err := p.CheckValue("domain", "*.a.com"); err == nil {
		t.Error("未允许通配符时应报错")
	}
	if err := p.CheckValue("ip", "2001:db8::1"); err == nil {
		t.Error("仅允许 IPv4 时 IPv6 应报错")
	}
	if err := p.CheckValue("email", "u@mail.corp.com"); err != nil {
		t.Errorf("子域邮箱应匹配后缀: %v", err)
	}
	if err := p.CheckValue("email", "u@other.com"); err == nil {
		t.Error("不在后缀范围的邮箱应报错")
	}
	for in, want := range map[string]time.Duration{"1d": 24 * time.Hour, "7d": 168 * time.Hour, "12h": 12 * time.Hour, "0": 0} {
		if got, err := identity.ParseValidity(in); err != nil || got != want {
			t.Errorf("ParseValidity(%q) = %v, %v", in, got, err)
		}
	}
	if _, err := identity.ParseValidity("3x"); err == nil {
		t.Error("非法单位应报错")
	}
}

func TestVerificationTemplateModes(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)
	ctx := context.Background()
	iss := issuance.NewService(db)
	svc := verification.NewService(db)
	user := createTestUser(t, db, "modes@test.com")

	// 全部免验证：提交即通过并带有效期
	none := &storage.SubjectTemplate{Name: "免验证", Fields: `[{"key":"CN","required":true,"verify":"none"}]`, VerifyValidity: "7d"}
	if err := iss.CreateSubjectTemplate(ctx, none); err != nil {
		t.Fatal(err)
	}
	info := &storage.SubjectInfo{UserUUID: user, SubjectTmplUUID: none.UUID, FieldValues: `{"CN":"张三"}`}
	if err := svc.CreateSubjectInfo(ctx, info); err != nil {
		t.Fatal(err)
	}
	if info.Status != "approved" || info.ExpiresAt == nil || info.ExpiresAt.Sub(time.Now()) > 7*24*time.Hour+time.Minute {
		t.Errorf("免验证主体应直接通过且 7 天有效，实际 %s %v", info.Status, info.ExpiresAt)
	}

	// 自动接口但未配置实名接口：降级为人工审核
	auto := &storage.SubjectTemplate{Name: "实名", Fields: `[{"key":"CN","required":true,"verify":"auto"}]`}
	iss.CreateSubjectTemplate(ctx, auto) //nolint:errcheck
	a := &storage.SubjectInfo{UserUUID: user, SubjectTmplUUID: auto.UUID, FieldValues: `{"CN":"李四"}`}
	if err := svc.CreateSubjectInfo(ctx, a); err != nil {
		t.Fatal(err)
	}
	if a.Status != "pending" || a.VerifyMode != identity.VerifyManual {
		t.Errorf("无实名接口应降级人工，实际 %s/%s", a.Status, a.VerifyMode)
	}
	if err := svc.RejectSubjectInfoWithReason(ctx, a.UUID, "admin", "证件不清晰"); err != nil {
		t.Fatal(err)
	}
	re, err := svc.ResubmitSubjectInfo(ctx, a.UUID, user, `{"CN":"李四"}`)
	if err != nil || re.Status != "pending" {
		t.Fatalf("驳回后应可重新提交，实际 %+v err=%v", re, err)
	}
	if _, err := svc.ResubmitSubjectInfo(ctx, a.UUID, "someone-else", ""); err == nil {
		t.Error("他人不能重新提交")
	}

	// 字段校验失败
	if err := svc.CreateSubjectInfo(ctx, &storage.SubjectInfo{UserUUID: user, SubjectTmplUUID: none.UUID, FieldValues: `{}`}); err == nil {
		t.Error("必填字段为空应报错")
	}

	// 扩展信息：邮箱人工审核、域名免验证
	ext := &storage.ExtensionTemplate{Name: "混合策略",
		VerifyPolicy: `{"domain":{"enabled":true,"mode":"none","validity":"1d"},"email":{"enabled":true,"mode":"manual"},"ip":{"enabled":false}}`}
	if err := iss.CreateExtensionTemplate(ctx, ext); err != nil {
		t.Fatal(err)
	}
	d := &storage.ExtensionInfo{UserUUID: user, TmplUUID: ext.UUID, InfoType: "domain", Value: "Free.Example.com"}
	if err := svc.CreateExtensionInfo(ctx, d); err != nil {
		t.Fatal(err)
	}
	if d.VerifyStatus != "verified" || d.Value != "free.example.com" || d.ExpiresAt == nil {
		t.Errorf("免验证域名应直接通过并规范化，实际 %+v", d)
	}
	e := &storage.ExtensionInfo{UserUUID: user, TmplUUID: ext.UUID, InfoType: "email", Value: "x@example.com"}
	svc.CreateExtensionInfo(ctx, e) //nolint:errcheck
	if e.VerifyStatus != "reviewing" {
		t.Errorf("人工策略邮箱应待审核，实际 %s", e.VerifyStatus)
	}
	if err := svc.ApproveExtensionInfo(ctx, e.UUID); err != nil {
		t.Fatal(err)
	}
	if err := svc.CreateExtensionInfo(ctx, &storage.ExtensionInfo{UserUUID: user, TmplUUID: ext.UUID, InfoType: "ip", Value: "1.1.1.1"}); err == nil {
		t.Error("策略禁用 IP 时应拒绝")
	}
	if err := svc.CreateExtensionInfo(ctx, &storage.ExtensionInfo{UserUUID: user, InfoType: "domain", Value: "bad_domain"}); err == nil {
		t.Error("非法域名应拒绝")
	}
}

func TestOCSPResponderMultiCA(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)
	ctx := context.Background()
	caSvc := ca.NewService(db, testMasterKey)
	rev := revocation.NewService(db, caSvc)

	mk := func(name string) (*storage.CA, *x509.Certificate) {
		c, err := caSvc.CreateSelfSignedCA(ctx, name, pkix.Name{CommonName: name}, "ec256", 1)
		if err != nil {
			t.Fatalf("创建 CA 失败: %v", err)
		}
		block, _ := pem.Decode([]byte(c.CertPEM))
		cert, _ := x509.ParseCertificate(block.Bytes)
		return c, cert
	}
	ca1, _ := mk("OCSP CA 1")
	ca2, ca2Cert := mk("OCSP CA 2")
	_, ca3Cert := mk("OCSP CA 3")

	r := &revocation.Responder{Name: "统一 OCSP", Path: "unified", SignerType: "ca", SignerRef: ca1.UUID,
		CAUUIDs: []string{ca1.UUID, ca2.UUID}, Enabled: true}
	if err := rev.SaveResponder(ctx, r); err != nil {
		t.Fatalf("保存响应服务失败: %v", err)
	}
	if err := rev.SaveResponder(ctx, &revocation.Responder{Name: "x", Path: "Bad Path", SignerType: "ca", SignerRef: ca1.UUID, CAUUIDs: []string{ca1.UUID}}); err == nil {
		t.Error("非法路径应拒绝")
	}

	query := func(issuer *x509.Certificate, serial int64) *ocsp.Response {
		t.Helper()
		req, err := ocsp.CreateRequest(&x509.Certificate{SerialNumber: big.NewInt(serial)}, issuer, nil)
		if err != nil {
			t.Fatal(err)
		}
		der, err := rev.Respond(ctx, r, req)
		if err != nil {
			t.Fatalf("响应失败: %v", err)
		}
		resp, err := ocsp.ParseResponse(der, nil)
		if err != nil {
			t.Fatalf("解析响应失败: %v", err)
		}
		return resp
	}

	if resp := query(ca2Cert, 12345); resp.Status != ocsp.Unknown {
		t.Errorf("未登记序列号应为 unknown，实际 %d", resp.Status)
	}
	if err := caSvc.RevokeCert(ctx, ca2.UUID, "12345", 1); err != nil {
		t.Fatal(err)
	}
	resp := query(ca2Cert, 12345)
	if resp.Status != ocsp.Revoked || resp.RevocationReason != 1 {
		t.Errorf("已吊销序列号应为 revoked，实际 %d/%d", resp.Status, resp.RevocationReason)
	}
	if resp.Certificate == nil {
		t.Error("签名者不是颁发者时应附带签名证书")
	}

	// 不在负责列表中的 CA：unauthorized
	req, _ := ocsp.CreateRequest(&x509.Certificate{SerialNumber: big.NewInt(1)}, ca3Cert, nil)
	der, _ := rev.Respond(ctx, r, req)
	if string(der) != string(ocsp.UnauthorizedErrorResponse) {
		t.Error("未负责的 CA 应返回 unauthorized")
	}
}

func TestPromoCouponSubscriptionRedeem(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)
	ctx := context.Background()
	svc := promo.NewService(db)
	env, autoTmpl, _ := newFlowEnvWithDB(t, db)
	_ = env
	u1 := createTestUser(t, db, "promo1@test.com")
	u2 := createTestUser(t, db, "promo2@test.com")

	// 优惠码：9 折封顶 5 元，总量 1，每人 1 次
	c := &promo.Coupon{Code: "save10", DiscountType: "percent", DiscountValue: 10, MaxDiscountCents: 500, TotalLimit: 1, PerUserLimit: 1, Enabled: true}
	if err := svc.SaveCoupon(ctx, c); err != nil {
		t.Fatal(err)
	}
	if d, _, err := svc.PreviewCoupon(ctx, "SAVE10", u1, "ssl", 10000); err != nil || d != 500 {
		t.Errorf("折扣应封顶 500 分，实际 %d err=%v", d, err)
	}
	if _, err := svc.ConsumeCoupon(ctx, "save10", u1, "ORDER-1", "ssl", 1000); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ConsumeCoupon(ctx, "save10", u2, "ORDER-2", "ssl", 1000); err == nil {
		t.Error("总量用尽后应拒绝")
	}
	svc.ReleaseCoupon(ctx, "ORDER-1")
	if _, err := svc.ConsumeCoupon(ctx, "save10", u2, "ORDER-3", "ssl", 1000); err != nil {
		t.Errorf("归还后应可再次使用: %v", err)
	}

	// 订阅：1 张额度，吊销释放额度
	// 单证有效期必须落在颁发模板允许列表内
	bad := &promo.Plan{Code: "bad", Name: "非法有效期", PeriodDays: 30, Enabled: true,
		Items: []promo.PlanItem{{CertApplyTmplUUID: autoTmpl, Quota: 1, ValidDays: 90}}}
	if err := svc.SavePlan(ctx, bad); err == nil {
		t.Error("单证有效期不在颁发模板允许列表内应被拒绝")
	}
	plan := &promo.Plan{Code: "team", Name: "团队版", PeriodDays: 30, Enabled: true, RevokeReleaseQuota: true,
		Items: []promo.PlanItem{{CertApplyTmplUUID: autoTmpl, Quota: 1, ValidDays: 365}}}
	if err := svc.SavePlan(ctx, plan); err != nil {
		t.Fatal(err)
	}
	sub, err := svc.Grant(ctx, u1, plan.UUID, "admin", "ref-1")
	if err != nil || !sub.Active(time.Now()) {
		t.Fatalf("发放订阅失败: %v", err)
	}
	if again, _ := svc.Grant(ctx, u1, plan.UUID, "admin", "ref-1"); again.UUID != sub.UUID {
		t.Error("相同来源重复发放应幂等")
	}
	item, unlock, err := svc.ReserveQuota(ctx, sub.UUID, u1, autoTmpl)
	if err != nil || item.ValidDays != 365 {
		t.Fatalf("应可占用额度: %v", err)
	}
	order, err := env.wf.CreateSubscriptionOrder(ctx, u1, sub.UUID, autoTmpl, "p@test.com", item.ValidDays, "{}")
	if err != nil {
		t.Fatal(err)
	}
	app := &storage.CertApplication{OrderUUID: order.UUID, UserUUID: u1, SubjectJSON: `{"CN":"sub.example.com"}`,
		SANJSON: `{"dns":["sub.example.com"]}`, KeyType: "ec256"}
	if _, issueErr, err := env.wf.SubmitApplication(ctx, app); err != nil || issueErr != nil {
		t.Fatalf("订阅申请失败: %v / %v", err, issueErr)
	}
	unlock()
	if _, _, err := svc.ReserveQuota(ctx, sub.UUID, u1, autoTmpl); err == nil {
		t.Error("额度用尽后应拒绝")
	}
	got, _ := env.wf.GetApplication(ctx, app.UUID)
	cert, _ := storage.NewCertRepo(db).GetByUUID(ctx, got.CertUUID)
	if cert.NotAfter == nil || cert.NotAfter.Sub(time.Now()) > 366*24*time.Hour {
		t.Errorf("订阅应覆盖有效期为 365 天，实际 %v", cert.NotAfter)
	}
	storage.NewCertRepo(db).Revoke(ctx, cert.UUID, 4) //nolint:errcheck
	if _, unlock2, err := svc.ReserveQuota(ctx, sub.UUID, u1, autoTmpl); err != nil {
		t.Errorf("吊销后应释放额度: %v", err)
	} else {
		unlock2()
	}

	// 兑换码：余额
	codes, err := svc.GenerateRedeemCodes(ctx, promo.RedeemCode{BatchName: "b1", GrantType: "balance", BalanceCents: 1000, MaxUses: 2}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Redeem(ctx, strings.ToLower(codes[0].Code), u2); err != nil {
		t.Fatalf("兑换失败: %v", err)
	}
	if _, err := svc.Redeem(ctx, codes[0].Code, u2); err == nil {
		t.Error("同一用户不能重复兑换")
	}
	var bal int64
	db.QueryRowContext(ctx, `SELECT available_cents FROM user_balances WHERE user_uuid = ?`, u2).Scan(&bal) //nolint:errcheck
	if bal != 1000 {
		t.Errorf("余额应为 1000，实际 %d", bal)
	}
}
