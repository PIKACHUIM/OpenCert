package storage_test

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/globaltrusts/client-card/internal/card"
	"github.com/globaltrusts/client-card/internal/card/local"
	"github.com/globaltrusts/client-card/internal/ipc"
	"github.com/globaltrusts/client-card/internal/storage"
	"github.com/globaltrusts/client-card/pkg/pkcs11types"
)

// setupIPCServer 创建测试用 IPC 服务器，返回 socket 路径和清理函数。
func setupIPCServer(t *testing.T) (string, func()) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Unix Socket 测试跳过 Windows")
	}

	// 创建临时数据库
	f, err := os.CreateTemp("", "ipc-test-*.db")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	db, err := storage.Open(f.Name())
	if err != nil {
		os.Remove(f.Name())
		t.Fatal(err)
	}

	// 创建测试用户和卡片
	ctx := context.Background()
	userRepo := storage.NewUserRepo(db)
	cardRepo := storage.NewCardRepo(db)
	certRepo := storage.NewCertRepo(db)

	user := &storage.User{
		UserType:    storage.UserTypeLocal,
		DisplayName: "IPC 测试用户",
		Email:       "ipc@test.com",
		Enabled:     true,
	}
	if err := userRepo.Create(ctx, user); err != nil {
		t.Fatal(err)
	}

	testCard, err := local.CreateCard(ctx, cardRepo, user.UUID, "IPC 测试卡片", "ipcpass123", "", "")
	if err != nil {
		t.Fatal(err)
	}

	// 创建 Manager 并注册 Slot
	mgr := card.NewManager()
	slot := local.New(pkcs11types.SlotID(1), testCard, certRepo)
	mgr.RegisterSlot(slot)

	// 创建 IPC 服务器（Unix Socket）
	sockPath := filepath.Join(os.TempDir(), "ipc-test-"+t.Name()+".sock")
	os.Remove(sockPath) // 清理残留

	srv := ipc.NewServer(sockPath)
	handler := ipc.NewPKCSHandler(mgr)
	handler.Register(srv)

	if err := srv.Start(); err != nil {
		t.Fatalf("启动 IPC 服务器失败: %v", err)
	}

	// 等待服务器就绪
	time.Sleep(50 * time.Millisecond)

	return sockPath, func() {
		srv.Stop()
		db.Close()
		os.Remove(f.Name())
		os.Remove(sockPath)
	}
}

// ipcConn 建立一个持久 IPC 连接，返回连接和关闭函数。
func ipcConn(t *testing.T, sockPath string) (net.Conn, func()) {
	t.Helper()
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("连接 IPC 服务器失败: %v", err)
	}
	return conn, func() { conn.Close() }
}

// ipcCallConn 在已有连接上发送 IPC 请求并接收响应。
func ipcCallConn(t *testing.T, conn net.Conn, cmd ipc.CmdCode, payload []byte) *ipc.Frame {
	t.Helper()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := ipc.WriteFrame(conn, cmd, payload); err != nil {
		t.Fatalf("发送 IPC 帧失败: %v", err)
	}
	frame, err := ipc.ReadFrame(conn)
	if err != nil {
		t.Fatalf("读取 IPC 响应失败: %v", err)
	}
	return frame
}

// ipcCall 发送 IPC 请求并接收响应（每次新建连接，适用于无状态命令）。
func ipcCall(t *testing.T, sockPath string, cmd ipc.CmdCode, payload []byte) *ipc.Frame {
	t.Helper()
	conn, closeConn := ipcConn(t, sockPath)
	defer closeConn()
	return ipcCallConn(t, conn, cmd, payload)
}

// ---- GetSlotList ----

func TestIPCGetSlotList(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix Socket 测试跳过 Windows")
	}

	sockPath, cleanup := setupIPCServer(t)
	defer cleanup()

	payload := []byte(`{"token_present":false}`)
	frame := ipcCall(t, sockPath, ipc.CmdGetSlotList, payload)

	// 解析响应
	resp := parseIPCResponse(t, frame)
	if resp.RV != uint32(pkcs11types.CKR_OK) {
		t.Errorf("GetSlotList rv 错误: got 0x%X, want 0x%X", resp.RV, pkcs11types.CKR_OK)
	}
}

// ---- OpenSession + CloseSession ----

func TestIPCOpenCloseSession(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix Socket 测试跳过 Windows")
	}

	sockPath, cleanup := setupIPCServer(t)
	defer cleanup()

	// 使用同一连接完成 OpenSession + CloseSession
	conn, closeConn := ipcConn(t, sockPath)
	defer closeConn()

	// OpenSession
	openFrame := ipcCallConn(t, conn, ipc.CmdOpenSession, []byte(`{"slot_id":1,"flags":4}`))
	openResp := parseIPCResponse(t, openFrame)
	if openResp.RV != uint32(pkcs11types.CKR_OK) {
		t.Fatalf("OpenSession 失败: rv=0x%X", openResp.RV)
	}

	// 从响应中提取 session_id
	sessionHandle := extractUint32(t, openResp.Data, "session_id")
	if sessionHandle == 0 {
		t.Fatal("session_id 为 0")
	}

	// CloseSession
	closePayload := []byte(`{"session_id":` + uint32Str(sessionHandle) + `}`)
	closeFrame := ipcCallConn(t, conn, ipc.CmdCloseSession, closePayload)
	closeResp := parseIPCResponse(t, closeFrame)
	if closeResp.RV != uint32(pkcs11types.CKR_OK) {
		t.Errorf("CloseSession 失败: rv=0x%X", closeResp.RV)
	}
}

// ---- Login + FindObjects ----

func TestIPCLoginAndFindObjects(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix Socket 测试跳过 Windows")
	}

	sockPath, cleanup := setupIPCServer(t)
	defer cleanup()

	// 使用同一连接完成所有有状态操作
	conn, closeConn := ipcConn(t, sockPath)
	defer closeConn()

	// OpenSession
	openFrame := ipcCallConn(t, conn, ipc.CmdOpenSession, []byte(`{"slot_id":1,"flags":4}`))
	openResp := parseIPCResponse(t, openFrame)
	if openResp.RV != uint32(pkcs11types.CKR_OK) {
		t.Fatalf("OpenSession 失败: rv=0x%X", openResp.RV)
	}
	sessionHandle := extractUint32(t, openResp.Data, "session_id")

	// Login（正确密码）
	loginPayload := []byte(`{"session_id":` + uint32Str(sessionHandle) + `,"user_type":1,"pin":"ipcpass123"}`)
	loginFrame := ipcCallConn(t, conn, ipc.CmdLogin, loginPayload)
	loginResp := parseIPCResponse(t, loginFrame)
	if loginResp.RV != uint32(pkcs11types.CKR_OK) {
		t.Fatalf("Login 失败: rv=0x%X", loginResp.RV)
	}

	// FindObjectsInit
	findInitPayload := []byte(`{"session_id":` + uint32Str(sessionHandle) + `,"template":[]}`)
	findInitFrame := ipcCallConn(t, conn, ipc.CmdFindObjectsInit, findInitPayload)
	findInitResp := parseIPCResponse(t, findInitFrame)
	t.Logf("FindObjectsInit rv=0x%X", findInitResp.RV)

	// FindObjects
	findPayload := []byte(`{"session_id":` + uint32Str(sessionHandle) + `,"max_count":10}`)
	findFrame := ipcCallConn(t, conn, ipc.CmdFindObjects, findPayload)
	findResp := parseIPCResponse(t, findFrame)
	t.Logf("FindObjects rv=0x%X, data=%s", findResp.RV, findResp.Data)

	// FindObjectsFinal
	findFinalPayload := []byte(`{"session_id":` + uint32Str(sessionHandle) + `}`)
	ipcCallConn(t, conn, ipc.CmdFindObjectsFinal, findFinalPayload)
}

// ---- Login 错误密码 ----

func TestIPCLoginWrongPIN(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix Socket 测试跳过 Windows")
	}

	sockPath, cleanup := setupIPCServer(t)
	defer cleanup()

	conn, closeConn := ipcConn(t, sockPath)
	defer closeConn()

	openFrame := ipcCallConn(t, conn, ipc.CmdOpenSession, []byte(`{"slot_id":1,"flags":4}`))
	openResp := parseIPCResponse(t, openFrame)
	sessionHandle := extractUint32(t, openResp.Data, "session_id")

	// 错误密码
	loginPayload := []byte(`{"session_id":` + uint32Str(sessionHandle) + `,"user_type":1,"pin":"wrongpassword"}`)
	loginFrame := ipcCallConn(t, conn, ipc.CmdLogin, loginPayload)
	loginResp := parseIPCResponse(t, loginFrame)
	if loginResp.RV == uint32(pkcs11types.CKR_OK) {
		t.Error("错误密码不应该登录成功")
	}
	t.Logf("错误密码 Login rv=0x%X（预期非 0）", loginResp.RV)
}

// ---- 未知命令 ----

func TestIPCUnknownCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix Socket 测试跳过 Windows")
	}

	sockPath, cleanup := setupIPCServer(t)
	defer cleanup()

	// 发送未知命令码 0xFFFF
	frame := ipcCall(t, sockPath, ipc.CmdCode(0xFFFF), []byte(`{}`))
	resp := parseIPCResponse(t, frame)
	// 应返回 CKR_FUNCTION_NOT_SUPPORTED = 0x54
	if resp.RV != 0x54 {
		t.Errorf("未知命令应返回 0x54: got 0x%X", resp.RV)
	}
}

// ---- 帧协议测试 ----

func TestIPCFrameProtocol(t *testing.T) {
	// 测试 WriteFrame / ReadFrame 的往返一致性
	pr, pw := net.Pipe()
	defer pr.Close()
	defer pw.Close()

	testPayload := []byte(`{"test":"hello","num":42}`)
	done := make(chan struct{})

	go func() {
		defer close(done)
		if err := ipc.WriteFrame(pw, ipc.CmdGetSlotList, testPayload); err != nil {
			t.Errorf("WriteFrame 失败: %v", err)
		}
	}()

	frame, err := ipc.ReadFrame(pr)
	<-done

	if err != nil {
		t.Fatalf("ReadFrame 失败: %v", err)
	}
	if frame.Cmd != ipc.CmdGetSlotList {
		t.Errorf("命令码不匹配: got 0x%X, want 0x%X", frame.Cmd, ipc.CmdGetSlotList)
	}
	if string(frame.Payload) != string(testPayload) {
		t.Errorf("Payload 不匹配: got %q, want %q", frame.Payload, testPayload)
	}
}

// ---- 辅助函数 ----

// parseIPCResponse 解析 IPC 响应帧中的 Response 结构。
func parseIPCResponse(t *testing.T, frame *ipc.Frame) *ipc.Response {
	t.Helper()
	resp, err := ipc.ParseResponse(frame.Payload)
	if err != nil {
		t.Fatalf("解析 IPC 响应失败: %v", err)
	}
	return resp
}

// extractUint32 从 JSON RawMessage 中提取 uint32 字段。
func extractUint32(t *testing.T, data []byte, key string) uint32 {
	t.Helper()
	if len(data) == 0 {
		return 0
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		t.Logf("extractUint32: 解析 JSON 失败: %v", err)
		return 0
	}
	raw, ok := m[key]
	if !ok {
		return 0
	}
	var v uint32
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Logf("extractUint32: 解析字段 %q 失败: %v", key, err)
		return 0
	}
	return v
}

// uint32Str 将 uint32 转为字符串。
func uint32Str(v uint32) string {
	return strconv.FormatUint(uint64(v), 10)
}
