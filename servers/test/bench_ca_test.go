// Package test - server-card 关键路径性能基准。
//
// 覆盖 CA 自签 + 证书签发等高代价路径，作为
// "安全审计与基准测试自动化"任务的执行目标。
//
// 运行：
//
//	cd servers && go test -bench=. -benchmem -run=^$ ./test/...
package test

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/globaltrusts/server-card/internal/ca"
	"github.com/globaltrusts/server-card/internal/storage"
)

// benchOpenDB 打开一个内存 SQLite，用于 benchmark（与 setupServerDB 等价但接收 *testing.B）。
func benchOpenDB(b *testing.B) (*storage.DB, func()) {
	b.Helper()
	db, err := storage.Open(":memory:", "")
	if err != nil {
		b.Fatalf("storage.Open: %v", err)
	}
	return db, func() { db.Close() }
}

// BenchmarkCA_CreateSelfSignedCA_EC256 测量自签 EC256 CA 的耗时。
func BenchmarkCA_CreateSelfSignedCA_EC256(b *testing.B) {
	db, cleanup := benchOpenDB(b)
	defer cleanup()
	svc := ca.NewService(db, testMasterKey)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := svc.CreateSelfSignedCA(context.Background(),
			"bench-root",
			pkix.Name{CommonName: "Bench Root"},
			"ec256",
			1,
		); err != nil {
			b.Fatalf("CreateSelfSignedCA: %v", err)
		}
	}
}

// BenchmarkCA_IssueCert_EC256 测量使用 EC256 CA 签发 EC256 终端证书的耗时。
func BenchmarkCA_IssueCert_EC256(b *testing.B) {
	db, cleanup := benchOpenDB(b)
	defer cleanup()
	svc := ca.NewService(db, testMasterKey)

	caObj, err := svc.CreateSelfSignedCA(context.Background(),
		"BenchRootCA",
		pkix.Name{CommonName: "Bench Root CA"},
		"ec256",
		1,
	)
	if err != nil {
		b.Fatalf("CreateSelfSignedCA: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := svc.IssueCert(context.Background(), &ca.IssueRequest{
			CAUUID:    caObj.UUID,
			Subject:   pkix.Name{CommonName: "bench.example.com"},
			KeyType:   "ec256",
			ValidDays: 90,
			KeyUsage:  x509.KeyUsageDigitalSignature,
			DNSNames:  []string{"bench.example.com"},
		}); err != nil {
			b.Fatalf("IssueCert: %v", err)
		}
	}
}
