// Package test 提供 servers 的集成测试。
package test

import (
	"context"
	"testing"

	"github.com/globaltrusts/server-card/internal/issuance"
	"github.com/globaltrusts/server-card/internal/storage"
)

func TestIssuanceTemplateCRUD(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)

	svc := issuance.NewService(db)
	ctx := context.Background()

	tests := []struct {
		name    string
		tmpl    *storage.IssuanceTemplate
		wantErr bool
	}{
		{
			name: "创建有效颁发模板",
			tmpl: &storage.IssuanceTemplate{
				Name:            "标准 TLS 证书",
				IsCA:            false,
				ValidDays:       `[365,730]`,
				AllowedKeyTypes: `["ec256","rsa2048"]`,
				AllowedCAUUIDs:  `[]`,
				PriceCents:      100,
				Stock:           -1,
				Category:        "tls",
				Enabled:         true,
			},
			wantErr: false,
		},
		{
			name: "创建 CA 颁发模板",
			tmpl: &storage.IssuanceTemplate{
				Name:            "中间 CA 模板",
				IsCA:            true,
				PathLen:         0,
				ValidDays:       `[3650]`,
				AllowedKeyTypes: `["rsa4096"]`,
				AllowedCAUUIDs:  `[]`,
				Category:        "ca",
				Enabled:         true,
			},
			wantErr: false,
		},
		{
			name:    "创建名称为空的模板应失败",
			tmpl:    &storage.IssuanceTemplate{Name: ""},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := svc.CreateIssuanceTemplate(ctx, tt.tmpl)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateIssuanceTemplate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.tmpl.UUID == "" {
				t.Error("CreateIssuanceTemplate() 未生成 UUID")
			}
		})
	}
}

func TestIssuanceTemplateGetAndList(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)

	svc := issuance.NewService(db)
	ctx := context.Background()

	// 创建两个模板
	tmpl1 := &storage.IssuanceTemplate{
		Name: "TLS 模板", Category: "tls", Enabled: true,
		ValidDays: `[365]`, AllowedKeyTypes: `["ec256"]`, AllowedCAUUIDs: `[]`,
	}
	tmpl2 := &storage.IssuanceTemplate{
		Name: "代码签名模板", Category: "codesign", Enabled: false,
		ValidDays: `[365]`, AllowedKeyTypes: `["rsa2048"]`, AllowedCAUUIDs: `[]`,
	}
	if err := svc.CreateIssuanceTemplate(ctx, tmpl1); err != nil {
		t.Fatalf("创建模板1失败: %v", err)
	}
	if err := svc.CreateIssuanceTemplate(ctx, tmpl2); err != nil {
		t.Fatalf("创建模板2失败: %v", err)
	}

	// 按 UUID 查询
	got, err := svc.GetIssuanceTemplate(ctx, tmpl1.UUID)
	if err != nil {
		t.Fatalf("GetIssuanceTemplate() 失败: %v", err)
	}
	if got.Name != tmpl1.Name {
		t.Errorf("Name 不匹配: got %q, want %q", got.Name, tmpl1.Name)
	}

	// 查询所有
	all, err := svc.ListIssuanceTemplates(ctx, "", false)
	if err != nil {
		t.Fatalf("ListIssuanceTemplates() 失败: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("ListIssuanceTemplates() 返回 %d 个，期望 2", len(all))
	}

	// 仅查询启用的
	enabled, err := svc.ListIssuanceTemplates(ctx, "", true)
	if err != nil {
		t.Fatalf("ListIssuanceTemplates(enabledOnly) 失败: %v", err)
	}
	if len(enabled) != 1 {
		t.Errorf("ListIssuanceTemplates(enabledOnly) 返回 %d 个，期望 1", len(enabled))
	}

	// 按分类查询
	byCategory, err := svc.ListIssuanceTemplates(ctx, "tls", false)
	if err != nil {
		t.Fatalf("ListIssuanceTemplates(category) 失败: %v", err)
	}
	if len(byCategory) != 1 {
		t.Errorf("ListIssuanceTemplates(category=tls) 返回 %d 个，期望 1", len(byCategory))
	}
}

func TestIssuanceTemplateDelete(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)

	svc := issuance.NewService(db)
	ctx := context.Background()

	tmpl := &storage.IssuanceTemplate{
		Name: "待删除模板", Category: "custom", Enabled: true,
		ValidDays: `[365]`, AllowedKeyTypes: `["ec256"]`, AllowedCAUUIDs: `[]`,
	}
	if err := svc.CreateIssuanceTemplate(ctx, tmpl); err != nil {
		t.Fatalf("创建模板失败: %v", err)
	}

	if err := svc.DeleteIssuanceTemplate(ctx, tmpl.UUID); err != nil {
		t.Fatalf("DeleteIssuanceTemplate() 失败: %v", err)
	}

	if _, err := svc.GetIssuanceTemplate(ctx, tmpl.UUID); err == nil {
		t.Error("删除后查询应返回错误")
	}
}

func TestSubjectTemplateCRUD(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)

	svc := issuance.NewService(db)
	ctx := context.Background()

	tmpl := &storage.SubjectTemplate{
		Name:   "标准主体模板",
		Fields: `[{"name":"CN","required":true},{"name":"O","required":false}]`,
	}
	if err := svc.CreateSubjectTemplate(ctx, tmpl); err != nil {
		t.Fatalf("CreateSubjectTemplate() 失败: %v", err)
	}
	if tmpl.UUID == "" {
		t.Fatal("UUID 未生成")
	}

	list, err := svc.ListSubjectTemplates(ctx)
	if err != nil {
		t.Fatalf("ListSubjectTemplates() 失败: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("ListSubjectTemplates() 返回 %d 个，期望 1", len(list))
	}

	if err := svc.DeleteSubjectTemplate(ctx, tmpl.UUID); err != nil {
		t.Fatalf("DeleteSubjectTemplate() 失败: %v", err)
	}
	list, _ = svc.ListSubjectTemplates(ctx)
	if len(list) != 0 {
		t.Error("删除后列表应为空")
	}
}

func TestExtensionTemplateCRUD(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)

	svc := issuance.NewService(db)
	ctx := context.Background()

	tmpl := &storage.ExtensionTemplate{
		Name:               "标准 SAN 模板",
		MaxDNS:             10,
		MaxEmail:           5,
		MaxIP:              5,
		MaxURI:             3,
		RequireDNSVerify:   true,
		RequireEmailVerify: false,
	}
	if err := svc.CreateExtensionTemplate(ctx, tmpl); err != nil {
		t.Fatalf("CreateExtensionTemplate() 失败: %v", err)
	}

	list, err := svc.ListExtensionTemplates(ctx)
	if err != nil {
		t.Fatalf("ListExtensionTemplates() 失败: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("ListExtensionTemplates() 返回 %d 个，期望 1", len(list))
	}
	if !list[0].RequireDNSVerify {
		t.Error("RequireDNSVerify 应为 true")
	}
}

func TestKeyUsageTemplateCRUD(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)

	svc := issuance.NewService(db)
	ctx := context.Background()

	tmpl := &storage.KeyUsageTemplate{
		Name:         "TLS 密钥用途",
		KeyUsage:     5, // digitalSignature | keyEncipherment
		ExtKeyUsages: `["serverAuth","clientAuth"]`,
	}
	if err := svc.CreateKeyUsageTemplate(ctx, tmpl); err != nil {
		t.Fatalf("CreateKeyUsageTemplate() 失败: %v", err)
	}

	list, err := svc.ListKeyUsageTemplates(ctx)
	if err != nil {
		t.Fatalf("ListKeyUsageTemplates() 失败: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("ListKeyUsageTemplates() 返回 %d 个，期望 1", len(list))
	}
	if list[0].KeyUsage != 5 {
		t.Errorf("KeyUsage = %d，期望 5", list[0].KeyUsage)
	}

	if err := svc.DeleteKeyUsageTemplate(ctx, tmpl.UUID); err != nil {
		t.Fatalf("DeleteKeyUsageTemplate() 失败: %v", err)
	}
}
