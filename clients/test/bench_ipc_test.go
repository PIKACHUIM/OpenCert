// Package storage_test - benchmark：IPC handler 关键路径性能基准。
//
// 覆盖 Digest / GenerateRandom 高频操作，作为 roadmap 中
// "安全审计与基准测试自动化"任务的执行目标。
//
// 运行：
//
//	cd clients && go test -bench=. -benchmem -run=^$ ./test/...
package storage_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/globaltrusts/client-card/internal/card"
	"github.com/globaltrusts/client-card/internal/card/local"
	"github.com/globaltrusts/client-card/internal/ipc"
	"github.com/globaltrusts/client-card/internal/storage"
	"github.com/globaltrusts/client-card/pkg/pkcs11types"
)

// benchSetupIPC 为 benchmark 启动一个 IPC 服务器，返回 sockPath 与 cleanup。
// 与 setupIPCServer(t *testing.T) 等价，但接受 *testing.B。
func benchSetupIPC(b *testing.B) (string, func()) {
	b.Helper()
	if runtime.GOOS == "windows" {
		b.Skip("Unix Socket benchmark 跳过 Windows")
	}

	f, err := os.CreateTemp("", "ipc-bench-*.db")
	if err != nil {
		b.Fatal(err)
	}
	f.Close()

	db, err := storage.Open(f.Name())
	if err != nil {
		os.Remove(f.Name())
		b.Fatal(err)
	}

	userRepo := storage.NewUserRepo(db)
	cardRepo := storage.NewCardRepo(db)
	certRepo := storage.NewCertRepo(db)
	user := &storage.User{
		UserType: storage.UserTypeLocal, DisplayName: "bench", Email: "b@t", Enabled: true,
	}
	ctx := context.Background()
	if err := userRepo.Create(ctx, user); err != nil {
		b.Fatal(err)
	}
	testCard, err := local.CreateCard(ctx, cardRepo, user.UUID, "bench-card", "pin", "", "")
	if err != nil {
		b.Fatal(err)
	}

	mgr := card.NewManager()
	slot := local.New(pkcs11types.SlotID(1), testCard, certRepo)
	mgr.RegisterSlot(slot)

	sockPath := filepath.Join(os.TempDir(), "ipc-bench-"+b.Name()+".sock")
	os.Remove(sockPath)

	srv := ipc.NewServer(sockPath)
	handler := ipc.NewPKCSHandler(mgr)
	handler.Register(srv)

	if err := srv.Start(); err != nil {
		b.Fatalf("启动 IPC 服务器失败: %v", err)
	}
	time.Sleep(20 * time.Millisecond)

	return sockPath, func() {
		srv.Stop()
		db.Close()
		os.Remove(f.Name())
		os.Remove(sockPath)
	}
}

// benchDial 建立一条到 IPC 服务器的连接。
func benchDial(b *testing.B, sockPath string) net.Conn {
	b.Helper()
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		b.Fatalf("连接失败: %v", err)
	}
	return conn
}

// benchCall 发送一个 IPC 请求并接收响应（不打印日志，专为 benchmark 优化）。
func benchCall(b *testing.B, conn net.Conn, cmd ipc.CmdCode, payload []byte) *ipc.Frame {
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := ipc.WriteFrame(conn, cmd, payload); err != nil {
		b.Fatalf("WriteFrame: %v", err)
	}
	frame, err := ipc.ReadFrame(conn)
	if err != nil {
		b.Fatalf("ReadFrame: %v", err)
	}
	return frame
}

// BenchmarkIPCDigestSHA256 通过 IPC 完整往返计算 SHA-256，
// 反映 driver→client 整链的吞吐能力上限。
func BenchmarkIPCDigestSHA256(b *testing.B) {
	sockPath, cleanup := benchSetupIPC(b)
	defer cleanup()

	conn := benchDial(b, sockPath)
	defer conn.Close()

	// 建立会话
	openFrame := benchCall(b, conn, ipc.CmdOpenSession, []byte(`{"slot_id":1,"flags":4}`))
	openResp, err := ipc.ParseResponse(openFrame.Payload)
	if err != nil {
		b.Fatal(err)
	}
	var openData map[string]json.RawMessage
	json.Unmarshal(openResp.Data, &openData)
	var sid uint32
	json.Unmarshal(openData["session_handle"], &sid)

	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i)
	}

	initPayload, _ := json.Marshal(map[string]interface{}{
		"session_id": sid,
		"mechanism":  testCkmSHA256,
	})
	digestPayload, _ := json.Marshal(map[string]interface{}{
		"session_id": sid,
		"data":       data,
	})

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchCall(b, conn, ipc.CmdDigestInit, initPayload)
		f := benchCall(b, conn, ipc.CmdDigest, digestPayload)
		resp, _ := ipc.ParseResponse(f.Payload)
		if resp.RV != uint32(pkcs11types.CKR_OK) {
			b.Fatalf("Digest 失败: rv=0x%X", resp.RV)
		}
	}
	b.SetBytes(int64(len(data)))
}

// BenchmarkIPCGenerateRandom256 测量 IPC GenerateRandom 256B 单次往返延迟。
func BenchmarkIPCGenerateRandom256(b *testing.B) {
	sockPath, cleanup := benchSetupIPC(b)
	defer cleanup()

	conn := benchDial(b, sockPath)
	defer conn.Close()

	openFrame := benchCall(b, conn, ipc.CmdOpenSession, []byte(`{"slot_id":1,"flags":4}`))
	openResp, _ := ipc.ParseResponse(openFrame.Payload)
	var openData map[string]json.RawMessage
	json.Unmarshal(openResp.Data, &openData)
	var sid uint32
	json.Unmarshal(openData["session_handle"], &sid)

	payload, _ := json.Marshal(map[string]interface{}{
		"session_id": sid,
		"length":     uint32(256),
	})

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		f := benchCall(b, conn, ipc.CmdGenerateRandom, payload)
		resp, _ := ipc.ParseResponse(f.Payload)
		if resp.RV != uint32(pkcs11types.CKR_OK) {
			b.Fatalf("rv=0x%X", resp.RV)
		}
	}
	b.SetBytes(256)
}

// BenchmarkLocalSHA256Baseline 是不经过 IPC 的本地 SHA-256 基线，
// 用作 BenchmarkIPCDigestSHA256 的吞吐量对比基准。
func BenchmarkLocalSHA256Baseline(b *testing.B) {
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = sha256.Sum256(data)
	}
	b.SetBytes(int64(len(data)))
}

// ---- benchmark 专用 helper（与 *testing.T 版本对应） ----

func setupIPCServerB(b *testing.B) (string, func()) {
	b.Helper()
	t := &testingTBShim{TB: b}
	return setupIPCServer(t)
}

func ipcConnB(b *testing.B, sockPath string) (interface {
	SetDeadline(time interface{}) error
	Close() error
}, func()) {
	b.Helper()
	t := &testingTBShim{TB: b}
	c, closeFn := ipcConn(t, sockPath)
	return ipcConnAdapter{c}, closeFn
}

func ipcCallConnB(b *testing.B, conn interface{}, cmd ipc.CmdCode, payload []byte) *ipc.Frame {
	b.Helper()
	t := &testingTBShim{TB: b}
	if a, ok := conn.(ipcConnAdapter); ok {
		return ipcCallConn(t, a.real(), cmd, payload)
	}
	b.Fatalf("ipcCallConnB: 不支持的 conn 类型 %T", conn)
	return nil
}

func mustParseRespB(b *testing.B, frame *ipc.Frame) *ipc.Response {
	b.Helper()
	resp, err := ipc.ParseResponse(frame.Payload)
	if err != nil {
		b.Fatalf("解析响应失败: %v", err)
	}
	return resp
}

func mustExtractUint32B(b *testing.B, data []byte, key string) uint32 {
	b.Helper()
	if len(data) == 0 {
		return 0
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		b.Fatalf("extractUint32: %v", err)
	}
	raw, ok := m[key]
	if !ok {
		return 0
	}
	var v uint32
	if err := json.Unmarshal(raw, &v); err != nil {
		b.Fatalf("extractUint32 %s: %v", key, err)
	}
	return v
}

func mustJSONB(b *testing.B, v interface{}) []byte {
	b.Helper()
	out, err := json.Marshal(v)
	if err != nil {
		b.Fatalf("json.Marshal: %v", err)
	}
	return out
}
