// Package test 提供 servers 的集成测试。
package test

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/globaltrusts/server-card/internal/storage"
	"github.com/globaltrusts/server-card/internal/verification"
)

// verificationCodeRe 匹配验证码邮件正文中的 6 位数字验证码。
var verificationCodeRe = regexp.MustCompile(`验证码：(\d{6})`)

// captureMailer 是测试用 Mailer：把邮件正文送入 channel 供断言读取。
// verification.Service 通过 goroutine 异步发信，因此用带缓冲 channel + 超时等待。
type captureMailer struct {
	mailCh chan string
}

func (m *captureMailer) Send(_, _, body string) error {
	select {
	case m.mailCh <- body:
	default:
	}
	return nil
}

func TestVerificationSubjectInfoCRUD(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)

	svc := verification.NewService(db)
	ctx := context.Background()
	userUUID := createTestUser(t, db, "subject@test.com")
	adminUUID := createTestUser(t, db, "admin-subject@test.com")

	// 创建主体信息
	// 未关联模板的主体信息一律进入人工审核
	info := &storage.SubjectInfo{
		UserUUID:    userUUID,
		FieldValues: `{"CN":"张三","O":"测试公司"}`,
	}
	if err := svc.CreateSubjectInfo(ctx, info); err != nil {
		t.Fatalf("CreateSubjectInfo() 失败: %v", err)
	}
	if info.UUID == "" {
		t.Fatal("UUID 未生成")
	}
	if info.Status != "pending" {
		t.Errorf("初始状态应为 pending，got %q", info.Status)
	}

	// 查询列表
	list, err := svc.ListSubjectInfos(ctx, userUUID)
	if err != nil {
		t.Fatalf("ListSubjectInfos() 失败: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("ListSubjectInfos() 返回 %d 个，期望 1", len(list))
	}

	// 管理员审核通过
	if err := svc.ApproveSubjectInfo(ctx, info.UUID, adminUUID); err != nil {
		t.Fatalf("ApproveSubjectInfo() 失败: %v", err)
	}

	// 验证状态已更新
	list, _ = svc.ListSubjectInfos(ctx, userUUID)
	if list[0].Status != "approved" {
		t.Errorf("审核后状态应为 approved，got %q", list[0].Status)
	}
	if list[0].ReviewedBy != adminUUID {
		t.Errorf("ReviewedBy = %q，期望 %q", list[0].ReviewedBy, adminUUID)
	}
}

func TestVerificationSubjectInfoReject(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)

	svc := verification.NewService(db)
	ctx := context.Background()
	userUUID := createTestUser(t, db, "subject-reject@test.com")
	adminUUID := createTestUser(t, db, "admin-reject@test.com")

	info := &storage.SubjectInfo{
		UserUUID:    userUUID,
		FieldValues: `{"CN":"无效主体"}`,
	}
	if err := svc.CreateSubjectInfo(ctx, info); err != nil {
		t.Fatalf("CreateSubjectInfo() 失败: %v", err)
	}

	if err := svc.RejectSubjectInfo(ctx, info.UUID, adminUUID); err != nil {
		t.Fatalf("RejectSubjectInfo() 失败: %v", err)
	}

	list, _ := svc.ListSubjectInfos(ctx, userUUID)
	if list[0].Status != "rejected" {
		t.Errorf("拒绝后状态应为 rejected，got %q", list[0].Status)
	}
}

func TestVerificationExtensionInfoCreate(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)

	svc := verification.NewService(db)
	ctx := context.Background()
	userUUID := createTestUser(t, db, "ext@test.com")

	tests := []struct {
		name       string
		info       *storage.ExtensionInfo
		wantMethod string
		wantErr    bool
	}{
		{
			name: "创建域名验证请求",
			info: &storage.ExtensionInfo{
				UserUUID: userUUID,
				InfoType: "domain",
				Value:    "example.com",
			},
			wantMethod: "txt",
			wantErr:    false,
		},
		{
			name: "创建邮箱验证请求",
			info: &storage.ExtensionInfo{
				UserUUID: userUUID,
				InfoType: "email",
				Value:    "user@example.com",
			},
			wantMethod: "email",
			wantErr:    false,
		},
		{
			name: "创建 IP 验证请求",
			info: &storage.ExtensionInfo{
				UserUUID: userUUID,
				InfoType: "ip",
				Value:    "192.168.1.1",
			},
			wantMethod: "http",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := svc.CreateExtensionInfo(ctx, tt.info)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateExtensionInfo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if tt.info.UUID == "" {
					t.Error("UUID 未生成")
				}
				if tt.info.VerifyToken == "" {
					t.Error("VerifyToken 未生成")
				}
				if tt.info.VerifyMethod != tt.wantMethod {
					t.Errorf("VerifyMethod = %q，期望 %q", tt.info.VerifyMethod, tt.wantMethod)
				}
				if tt.info.VerifyStatus != "pending" {
					t.Errorf("初始状态应为 pending，got %q", tt.info.VerifyStatus)
				}
			}
		})
	}
}

func TestVerificationEmailCode(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)

	capture := &captureMailer{mailCh: make(chan string, 1)}
	svc := verification.NewService(db)
	svc.SetMailer(capture)
	ctx := context.Background()
	userUUID := createTestUser(t, db, "emailcode@test.com")

	// 创建邮箱验证请求
	info := &storage.ExtensionInfo{
		UserUUID: userUUID,
		InfoType: "email",
		Value:    "verify@example.com",
	}
	if err := svc.CreateExtensionInfo(ctx, info); err != nil {
		t.Fatalf("CreateExtensionInfo() 失败: %v", err)
	}

	// 验证码只以 SHA-256 形式入库，因此从异步发出的邮件正文中提取（模拟真实用户查收邮件）
	var body string
	select {
	case body = <-capture.mailCh:
	case <-time.After(3 * time.Second):
		t.Fatal("未在超时时间内收到验证码邮件")
	}
	m := verificationCodeRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("邮件正文中未找到 6 位验证码: %q", body)
	}
	correctCode := m[1]

	wrongCode := "000000"
	if correctCode == wrongCode {
		wrongCode = "111111"
	}

	tests := []struct {
		name    string
		code    string
		wantErr bool
	}{
		{"正确验证码", correctCode, false},
		{"错误验证码", wrongCode, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 注意：正确验证码只能用一次，错误的先测
			if tt.wantErr {
				err := svc.VerifyEmailCode(ctx, info.UUID, tt.code)
				if err == nil {
					t.Error("错误验证码应返回错误")
				}
			}
		})
	}

	// 最后用正确验证码验证
	if err := svc.VerifyEmailCode(ctx, info.UUID, correctCode); err != nil {
		t.Fatalf("正确验证码验证失败: %v", err)
	}

	// 验证状态已更新
	list, _ := svc.ListExtensionInfos(ctx, userUUID)
	if len(list) == 0 {
		t.Fatal("扩展信息列表为空")
	}
	if list[0].VerifyStatus != "verified" {
		t.Errorf("验证后状态应为 verified，got %q", list[0].VerifyStatus)
	}
}

func TestVerificationExtensionInfoDelete(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)

	svc := verification.NewService(db)
	ctx := context.Background()
	userUUID := createTestUser(t, db, "extdelete@test.com")

	info := &storage.ExtensionInfo{
		UserUUID: userUUID,
		InfoType: "domain",
		Value:    "delete.example.com",
	}
	if err := svc.CreateExtensionInfo(ctx, info); err != nil {
		t.Fatalf("CreateExtensionInfo() 失败: %v", err)
	}

	if err := svc.DeleteExtensionInfo(ctx, info.UUID); err != nil {
		t.Fatalf("DeleteExtensionInfo() 失败: %v", err)
	}

	list, _ := svc.ListExtensionInfos(ctx, userUUID)
	if len(list) != 0 {
		t.Error("删除后列表应为空")
	}
}
