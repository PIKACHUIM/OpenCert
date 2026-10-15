// Package test 提供 servers 的集成测试。
package test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/globaltrusts/server-card/internal/ca"
	"github.com/globaltrusts/server-card/internal/storage"
)

// setupServerDB 创建临时文件 SQLite 测试数据库。
// 数据库通过 t.Cleanup 关闭（而不是返回的清理函数），确保父测试中所有
// t.Parallel() 子测试全部结束后才释放连接，否则子测试会命中
// "sql: database is closed"。
// 另外不使用 ":memory:"：在 database/sql 连接池下每个连接都是独立的内存库，
// 并行子测试会因取到新连接而报 "no such table"。
func setupServerDB(t *testing.T) *storage.DB {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "server-test.db"), "")
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// testMasterKey 是测试用主密钥（AES-256 要求恰好 32 字节）。
var testMasterKey = []byte("test-master-key-32bytes-padding!")

func TestCACreate(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)

	svc := ca.NewService(db, testMasterKey)
	ctx := context.Background()

	tests := []struct {
		name    string
		ca      *storage.CA
		wantErr bool
	}{
		{
			name: "创建有效 CA",
			ca: &storage.CA{
				Name:       "测试根 CA",
				CertPEM:    "-----BEGIN CERTIFICATE-----\nMIIBxxx\n-----END CERTIFICATE-----",
				PrivateEnc: []byte("encrypted-private-key"),
				NotBefore:  time.Now(),
				NotAfter:   time.Now().Add(10 * 365 * 24 * time.Hour),
			},
			wantErr: false,
		},
		{
			name: "创建中间 CA（带父 UUID）",
			ca: &storage.CA{
				Name:       "测试中间 CA",
				CertPEM:    "-----BEGIN CERTIFICATE-----\nMIIByyy\n-----END CERTIFICATE-----",
				PrivateEnc: []byte("encrypted-private-key-2"),
				ParentUUID: "parent-uuid-placeholder",
				NotBefore:  time.Now(),
				NotAfter:   time.Now().Add(5 * 365 * 24 * time.Hour),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := svc.Create(ctx, tt.ca)
			if (err != nil) != tt.wantErr {
				t.Errorf("Create() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.ca.UUID == "" {
				t.Error("Create() 未生成 UUID")
			}
		})
	}
}

func TestCAGetByUUID(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)

	svc := ca.NewService(db, testMasterKey)
	ctx := context.Background()

	// 先创建一个 CA
	caObj := &storage.CA{
		Name:       "查询测试 CA",
		CertPEM:    "-----BEGIN CERTIFICATE-----\nMIIBtest\n-----END CERTIFICATE-----",
		PrivateEnc: []byte("enc-key"),
		NotBefore:  time.Now(),
		NotAfter:   time.Now().Add(365 * 24 * time.Hour),
	}
	if err := svc.Create(ctx, caObj); err != nil {
		t.Fatalf("创建 CA 失败: %v", err)
	}

	// 查询存在的 CA
	got, err := svc.GetByUUID(ctx, caObj.UUID)
	if err != nil {
		t.Fatalf("GetByUUID() 失败: %v", err)
	}
	if got.Name != caObj.Name {
		t.Errorf("Name 不匹配: got %q, want %q", got.Name, caObj.Name)
	}

	// 查询不存在的 CA
	_, err = svc.GetByUUID(ctx, "non-existent-uuid")
	if err == nil {
		t.Error("查询不存在的 CA 应返回错误")
	}
}

func TestCAList(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)

	svc := ca.NewService(db, testMasterKey)
	ctx := context.Background()

	// 创建多个 CA
	for i := 0; i < 3; i++ {
		c := &storage.CA{
			Name:       "CA-" + string(rune('A'+i)),
			CertPEM:    "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
			PrivateEnc: []byte("enc"),
			NotBefore:  time.Now(),
			NotAfter:   time.Now().Add(365 * 24 * time.Hour),
		}
		if err := svc.Create(ctx, c); err != nil {
			t.Fatalf("创建 CA 失败: %v", err)
		}
	}

	cas, err := svc.List(ctx)
	if err != nil {
		t.Fatalf("List() 失败: %v", err)
	}
	if len(cas) != 3 {
		t.Errorf("List() 返回 %d 个 CA，期望 3 个", len(cas))
	}
}

func TestCAUpdate(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)

	svc := ca.NewService(db, testMasterKey)
	ctx := context.Background()

	caObj := &storage.CA{
		Name:       "原始名称",
		CertPEM:    "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
		PrivateEnc: []byte("enc"),
		NotBefore:  time.Now(),
		NotAfter:   time.Now().Add(365 * 24 * time.Hour),
	}
	if err := svc.Create(ctx, caObj); err != nil {
		t.Fatalf("创建 CA 失败: %v", err)
	}

	if err := svc.Update(ctx, caObj.UUID, "新名称", "active"); err != nil {
		t.Fatalf("Update() 失败: %v", err)
	}

	got, _ := svc.GetByUUID(ctx, caObj.UUID)
	if got.Name != "新名称" {
		t.Errorf("Update() 后 Name = %q，期望 %q", got.Name, "新名称")
	}
}

func TestCADelete(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)

	svc := ca.NewService(db, testMasterKey)
	ctx := context.Background()

	caObj := &storage.CA{
		Name:       "待删除 CA",
		CertPEM:    "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
		PrivateEnc: []byte("enc"),
		NotBefore:  time.Now(),
		NotAfter:   time.Now().Add(365 * 24 * time.Hour),
	}
	if err := svc.Create(ctx, caObj); err != nil {
		t.Fatalf("创建 CA 失败: %v", err)
	}

	// 删除无签发记录的 CA 应成功
	if err := svc.Delete(ctx, caObj.UUID); err != nil {
		t.Fatalf("Delete() 失败: %v", err)
	}

	// 再次查询应返回错误
	if _, err := svc.GetByUUID(ctx, caObj.UUID); err == nil {
		t.Error("删除后查询应返回错误")
	}
}

func TestCARevokeCert(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)

	svc := ca.NewService(db, testMasterKey)
	ctx := context.Background()

	caObj := &storage.CA{
		Name:       "吊销测试 CA",
		CertPEM:    "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
		PrivateEnc: []byte("enc"),
		NotBefore:  time.Now(),
		NotAfter:   time.Now().Add(365 * 24 * time.Hour),
	}
	if err := svc.Create(ctx, caObj); err != nil {
		t.Fatalf("创建 CA 失败: %v", err)
	}

	tests := []struct {
		name         string
		serialNumber string
		reason       int
		wantErr      bool
	}{
		{"吊销证书 - 原因 0（未指定）", "aabbccdd01", 0, false},
		{"吊销证书 - 原因 1（密钥泄露）", "aabbccdd02", 1, false},
		{"重复吊销同一序列号", "aabbccdd01", 0, false}, // INSERT OR IGNORE，不报错
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			err := svc.RevokeCert(ctx, caObj.UUID, tt.serialNumber, tt.reason)
			if (err != nil) != tt.wantErr {
				t.Errorf("RevokeCert() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}

	// 验证吊销列表
	revoked, err := svc.ListRevokedCerts(ctx, caObj.UUID)
	if err != nil {
		t.Fatalf("ListRevokedCerts() 失败: %v", err)
	}
	if len(revoked) != 2 {
		t.Errorf("吊销列表数量 = %d，期望 2", len(revoked))
	}
}
