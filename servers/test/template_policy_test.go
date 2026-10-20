// Package test - 模板策略解析（ResolvePolicy）与密钥存储模板校验测试。
package test

import (
	"context"
	"strings"
	"testing"

	"github.com/globaltrusts/server-card/internal/issuance"
	"github.com/globaltrusts/server-card/internal/storage"
	"github.com/globaltrusts/server-card/internal/template"
)

func newPolicyFixture(t *testing.T) (*issuance.Service, *storage.IssuanceTemplate, string) {
	t.Helper()
	db := setupServerDB(t)
	svc := issuance.NewService(db)
	ctx := context.Background()

	it := &storage.IssuanceTemplate{
		Name: "策略测试", ValidDays: `[90,365]`, DefaultValidDays: 365,
		AllowedKeyTypes: `["ec256","rsa2048"]`, AllowedCAUUIDs: `[]`, Category: "ssl", Enabled: true,
	}
	if err := svc.CreateIssuanceTemplate(ctx, it); err != nil {
		t.Fatalf("创建颁发模板失败: %v", err)
	}
	const applyUUID = "apply-policy"
	if _, err := db.ExecContext(ctx,
		`INSERT INTO cert_apply_templates
		 (uuid, name, issuance_tmpl_uuid, enabled, require_approval, allow_renewal, description, created_at, updated_at)
		 VALUES (?, '策略开通', ?, 1, 1, 0, '', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`, applyUUID, it.UUID); err != nil {
		t.Fatalf("插入开通模板失败: %v", err)
	}
	return svc, it, applyUUID
}

func TestResolvePolicy_InheritsFromIssuanceTemplate(t *testing.T) {
	t.Parallel()
	svc, it, applyUUID := newPolicyFixture(t)
	ctx := issuance.WithPolicyCache(context.Background())

	p, err := svc.ResolvePolicy(ctx, applyUUID, "", nil)
	if err != nil {
		t.Fatalf("ResolvePolicy 失败: %v", err)
	}
	if p.IssuanceTmpl.UUID != it.UUID {
		t.Errorf("应解析到关联的颁发模板")
	}
	if p.DefaultValidDays != 365 || len(p.ValidDays) != 2 {
		t.Errorf("有效期继承错误: default=%d list=%v", p.DefaultValidDays, p.ValidDays)
	}
	if len(p.KeyTypes) != 2 {
		t.Errorf("密钥算法继承错误: %v", p.KeyTypes)
	}
	if !p.RequireApproval || p.AllowRenewal {
		t.Errorf("审批/续期应来自开通模板: approval=%v renewal=%v", p.RequireApproval, p.AllowRenewal)
	}
	// 签名算法由签发 CA 的密钥类型决定：EC CA 只能 ECDSA 系列，RSA CA 只能 RSA 系列
	ecAlgs := p.SigAlgsForCA("ec256")
	if len(ecAlgs) == 0 {
		t.Fatal("EC CA 应有可用签名算法")
	}
	for _, a := range ecAlgs {
		if !strings.Contains(a, "ECDSA") {
			t.Errorf("ec256 CA 不应出现签名算法 %s", a)
		}
	}
	if len(p.SigAlgsForCA("rsa2048")) == 0 {
		t.Errorf("rsa2048 CA 应有可用签名算法")
	}
	if got := p.SigAlgsForCA(""); got != nil {
		t.Errorf("未知 CA 算法不应给出签名算法: %v", got)
	}
}

func TestResolvePolicy_NarrowingMustStayInRange(t *testing.T) {
	t.Parallel()
	svc, _, applyUUID := newPolicyFixture(t)
	ctx := context.Background()

	// 范围内收窄
	p, err := svc.ResolvePolicy(ctx, applyUUID, "", &issuance.Narrowing{ValidDays: 90, KeyTypes: []string{"ec256"}})
	if err != nil {
		t.Fatalf("范围内收窄应成功: %v", err)
	}
	if p.DefaultValidDays != 90 || len(p.KeyTypes) != 1 || p.KeyTypes[0] != "ec256" {
		t.Errorf("收窄结果不正确: %d %v", p.DefaultValidDays, p.KeyTypes)
	}

	// 超出范围
	if _, err := svc.ResolvePolicy(ctx, applyUUID, "", &issuance.Narrowing{ValidDays: 30}); err == nil {
		t.Error("有效期超出颁发模板范围应被拒绝")
	}
	if _, err := svc.ResolvePolicy(ctx, applyUUID, "", &issuance.Narrowing{KeyTypes: []string{"sm2"}}); err == nil {
		t.Error("密钥算法超出颁发模板范围应被拒绝")
	}
}

func TestResolvePolicy_ValidateSelection(t *testing.T) {
	t.Parallel()
	svc, _, applyUUID := newPolicyFixture(t)
	p, err := svc.ResolvePolicy(context.Background(), applyUUID, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.ValidateSelection("", "ec256", "", 90); err != nil {
		t.Errorf("合法选择被拒绝: %v", err)
	}
	if err := p.ValidateSelection("", "rsa4096", "", 0); err == nil {
		t.Error("不允许的密钥算法应被拒绝")
	}
	if err := p.ValidateSelection("", "ec256", "SM2WithSM3", 0); err == nil {
		t.Error("指定签名算法但未给出 CA 算法时应被拒绝")
	}
	if err := p.ValidateSelectionWithCA("", "ec256", "ec256", "ECDSA_SHA256", 0); err != nil {
		t.Errorf("EC CA 用 ECDSA_SHA256 应合法: %v", err)
	}
	if err := p.ValidateSelectionWithCA("", "ec256", "ec256", "SHA256_RSA", 0); err == nil {
		t.Error("EC CA 不能用 RSA 签名算法")
	}
	if err := p.ValidateSelectionWithCA("", "ec256", "rsa2048", "", 0); err != nil {
		t.Errorf("EC CA 给 RSA 证书签名是允许的（签名算法由 CA 决定）: %v", err)
	}
	if err := p.ValidateSelectionWithCA("", "sm2", "ec256", "", 0); err == nil {
		t.Error("SM2 CA 只能签发 SM2 证书")
	}
	if err := p.ValidateSelection("", "ec256", "", 4000); err == nil {
		t.Error("超过 3650 天应被拒绝")
	}
}

func TestResolvePolicy_MissingTemplates(t *testing.T) {
	t.Parallel()
	svc, _, _ := newPolicyFixture(t)
	ctx := context.Background()
	if _, err := svc.ResolvePolicy(ctx, "no-such-apply", "", nil); err == nil {
		t.Error("开通模板不存在应报错")
	}
	if _, err := svc.ResolvePolicy(ctx, "", "", nil); err == nil {
		t.Error("两个模板都未指定应报错")
	}
}

// SM2 CA 只能签 SM2 证书，保存颁发模板时就要拦住混用。
func TestIssuanceTemplate_SM2CANotMixed(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)
	svc := issuance.NewService(db)
	ctx := context.Background()

	if _, err := db.ExecContext(ctx,
		`INSERT INTO cas (uuid, name, cert_pem, private_enc, status, not_before, not_after, key_type)
		 VALUES ('sm2-ca', 'SM2 CA', 'x', x'00', 'active', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'sm2')`); err != nil {
		t.Skipf("无法直接插入 CA 行（表结构不同）: %v", err)
	}

	bad := &storage.IssuanceTemplate{
		Name: "混用", ValidDays: `[365]`, AllowedKeyTypes: `["sm2","ec256"]`,
		AllowedCAUUIDs: `["sm2-ca"]`, Category: "ssl",
	}
	if err := svc.CreateIssuanceTemplate(ctx, bad); err == nil {
		t.Error("SM2 CA 与 ec256 混用应被拒绝")
	}
	good := &storage.IssuanceTemplate{
		Name: "纯国密", ValidDays: `[365]`, AllowedKeyTypes: `["sm2"]`,
		AllowedSigAlgs: `["SM2WithSM3"]`, AllowedCAUUIDs: `["sm2-ca"]`, DefaultCAUUID: "sm2-ca", Category: "ssl",
	}
	if err := svc.CreateIssuanceTemplate(ctx, good); err != nil {
		t.Errorf("纯国密模板应可创建: %v", err)
	}
	p, err := svc.ResolvePolicy(ctx, "", good.UUID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.AllowsPKCS12("sm2") {
		t.Error("SM2 证书不应提供 PKCS#12")
	}
	if got := p.SigAlgsForCA("sm2"); len(got) != 1 || got[0] != "SM2WithSM3" {
		t.Errorf("SM2 CA 只能搭配 SM2WithSM3，实际 %v", got)
	}
}

func TestKeyStorageTemplateValidate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		tmpl     storage.KeyStorageTemplate
		hardware bool
		wantErr  string
	}{
		{"文件下载自动不限次数", storage.KeyStorageTemplate{Name: "a", StorageMethods: storage.StorageFileDownload}, false, ""},
		{"未选存储方式", storage.KeyStorageTemplate{Name: "a"}, false, "存储方式"},
		{"硬件区域禁止文件下载", storage.KeyStorageTemplate{Name: "a", StorageMethods: storage.StorageFileDownload}, true, "不可导出"},
		{"硬件区域禁止云备份", storage.KeyStorageTemplate{Name: "a", StorageMethods: storage.StorageCloudCard, CloudBackup: true}, true, "云端备份"},
		{"智能卡生成需要卡下发方式", storage.KeyStorageTemplate{Name: "a", StorageMethods: storage.StorageFileDownload, KeyGenLocation: storage.KeyGenCard}, false, "智能卡"},
		{"自带 CSR 不能下载私钥", storage.KeyStorageTemplate{Name: "a", StorageMethods: storage.StorageFileDownload, KeyGenLocation: storage.KeyGenCSR}, false, "CSR"},
		{"下载格式非法", storage.KeyStorageTemplate{Name: "a", StorageMethods: storage.StorageFileDownload, DownloadFormats: `["jks"]`}, false, "下载格式"},
		{"下发次数不能为0", storage.KeyStorageTemplate{Name: "a", StorageMethods: storage.StorageCloudCard, CloudBackup: true, AllowReissue: true, MaxReissueCount: 0}, false, "不能为 0"},
		{"下发不限次数合法", storage.KeyStorageTemplate{Name: "a", StorageMethods: storage.StorageCloudCard, CloudBackup: true, AllowReissue: true, MaxReissueCount: -1}, false, ""},
		{"虚拟卡必须选等级", storage.KeyStorageTemplate{Name: "a", StorageMethods: storage.StorageVirtualCard}, false, "安全等级"},
		{"高安全不可备份", storage.KeyStorageTemplate{Name: "a", StorageMethods: storage.StorageVirtualCard, SecurityLevel: storage.SecurityHigh, CloudBackup: true}, false, "高安全"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tmpl := tt.tmpl
			err := template.Validate(&tmpl, tt.hardware)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Errorf("不应报错: %v", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Errorf("期望错误包含 %q，实际 %v", tt.wantErr, err)
			}
		})
	}
}

func TestKeyStorageTemplate_FileDownloadForcesUnlimited(t *testing.T) {
	t.Parallel()
	tmpl := storage.KeyStorageTemplate{Name: "a", StorageMethods: storage.StorageFileDownload, MaxReissueCount: 3}
	if err := template.Validate(&tmpl, false); err != nil {
		t.Fatal(err)
	}
	if !tmpl.CloudBackup || !tmpl.AllowReissue || tmpl.MaxReissueCount != -1 {
		t.Errorf("文件下载应自动启用云备份并不限次数: %+v", tmpl)
	}
}

func TestKeyStorageTemplate_DeleteReferencedRejected(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)
	tsvc := template.NewService(db)
	isvc := issuance.NewService(db)
	ctx := context.Background()

	ks := &storage.KeyStorageTemplate{Name: "ks", StorageMethods: storage.StorageFileDownload}
	if err := tsvc.Create(ctx, ks); err != nil {
		t.Fatalf("创建密钥存储模板失败: %v", err)
	}
	it := &storage.IssuanceTemplate{
		Name: "引用 ks", ValidDays: `[365]`, AllowedKeyTypes: `["ec256"]`, AllowedCAUUIDs: `[]`,
		KeyStorageTmplUUID: ks.UUID, Category: "ssl",
	}
	if err := isvc.CreateIssuanceTemplate(ctx, it); err != nil {
		t.Fatalf("创建颁发模板失败: %v", err)
	}
	if err := tsvc.Delete(ctx, ks.UUID); err == nil {
		t.Error("被颁发模板引用的密钥存储模板不应能删除")
	}
	// 被开通模板引用的颁发模板同样不能删除
	if _, err := db.ExecContext(ctx,
		`INSERT INTO cert_apply_templates (uuid, name, issuance_tmpl_uuid, enabled, created_at, updated_at)
		 VALUES ('a1', 'a', ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`, it.UUID); err != nil {
		t.Fatal(err)
	}
	if err := isvc.DeleteIssuanceTemplate(ctx, it.UUID); err == nil {
		t.Error("被开通模板引用的颁发模板不应能删除")
	}
}
