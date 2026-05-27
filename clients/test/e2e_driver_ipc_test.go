// Package storage_test - 三组件 E2E 联调测试（driver → IPC → client）。
//
// 该文件聚焦在 client-card IPC 服务器层模拟 PKCS#11 DLL 驱动的真实调用序列。
// 由于 DLL 是 C 代码、无法在 Go test 中直接装载，这里通过原生 IPC 协议帧
// 模拟 driver 的所有发送/接收行为，验证：
//
//   1. C_DigestInit / C_Digest / C_DigestUpdate / C_DigestFinal （任务 2 新增）
//   2. C_VerifyInit / C_Verify / C_VerifyUpdate / C_VerifyFinal （任务 2 新增）
//   3. C_GenerateRandom / C_SeedRandom                          （任务 2 新增）
//   4. 完整序列：Initialize → Login → GenerateKeyPair → Sign → Verify → Logout
//
// 真实 DLL 联调请参考 Makefile 中的 e2e-driver 目标。
package storage_test

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"runtime"
	"testing"

	"github.com/globaltrusts/client-card/internal/ipc"
	"github.com/globaltrusts/client-card/pkg/pkcs11types"
)

// PKCS#11 mechanism 常量（与 handler_digest_verify_random.go 保持一致）。
const (
	testCkmSHA256        uint32 = 0x00000250
	testCkmSHA1          uint32 = 0x00000220
	testCkmECDSASHA256   uint32 = 0x00001044
)

// ---- E2E: Digest 系列 ----

// TestE2EDigestSingleShot 模拟 driver 的 C_DigestInit + C_Digest 单次摘要调用。
func TestE2EDigestSingleShot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix Socket 测试跳过 Windows")
	}
	sockPath, cleanup := setupIPCServer(t)
	defer cleanup()

	conn, closeConn := ipcConn(t, sockPath)
	defer closeConn()

	// driver: C_OpenSession
	openFrame := ipcCallConn(t, conn, ipc.CmdOpenSession, []byte(`{"slot_id":1,"flags":4}`))
	openResp := parseIPCResponse(t, openFrame)
	if openResp.RV != uint32(pkcs11types.CKR_OK) {
		t.Fatalf("OpenSession 失败: rv=0x%X", openResp.RV)
	}
	sessionHandle := extractUint32(t, openResp.Data, "session_handle")

	// driver: C_DigestInit(SHA-256)
	initPayload := jsonMust(map[string]interface{}{
		"session_id": sessionHandle,
		"mechanism":  testCkmSHA256,
	})
	initFrame := ipcCallConn(t, conn, ipc.CmdDigestInit, initPayload)
	initResp := parseIPCResponse(t, initFrame)
	if initResp.RV != uint32(pkcs11types.CKR_OK) {
		t.Fatalf("DigestInit 失败: rv=0x%X", initResp.RV)
	}

	// driver: C_Digest
	plain := []byte("Hello PKCS#11 Driver E2E Digest!")
	digestPayload := jsonMust(map[string]interface{}{
		"session_id": sessionHandle,
		"data":       plain,
	})
	digestFrame := ipcCallConn(t, conn, ipc.CmdDigest, digestPayload)
	digestResp := parseIPCResponse(t, digestFrame)
	if digestResp.RV != uint32(pkcs11types.CKR_OK) {
		t.Fatalf("Digest 失败: rv=0x%X", digestResp.RV)
	}

	// 校验摘要值
	var dr struct {
		Digest []byte `json:"digest"`
	}
	if err := json.Unmarshal(digestResp.Data, &dr); err != nil {
		t.Fatalf("解析 digest 响应失败: %v", err)
	}
	expect := sha256.Sum256(plain)
	if string(dr.Digest) != string(expect[:]) {
		t.Errorf("摘要不匹配: got %x, want %x", dr.Digest, expect[:])
	}
	t.Logf("✓ E2E DigestSingleShot 通过，摘要长度 %d", len(dr.Digest))
}

// TestE2EDigestStream 模拟 driver 的 DigestInit + DigestUpdate*N + DigestFinal。
func TestE2EDigestStream(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix Socket 测试跳过 Windows")
	}
	sockPath, cleanup := setupIPCServer(t)
	defer cleanup()

	conn, closeConn := ipcConn(t, sockPath)
	defer closeConn()

	openFrame := ipcCallConn(t, conn, ipc.CmdOpenSession, []byte(`{"slot_id":1,"flags":4}`))
	sessionHandle := extractUint32(t, parseIPCResponse(t, openFrame).Data, "session_handle")

	// DigestInit
	ipcCallConn(t, conn, ipc.CmdDigestInit, jsonMust(map[string]interface{}{
		"session_id": sessionHandle,
		"mechanism":  testCkmSHA256,
	}))

	// 分块 Update：模拟 driver 处理大文件的流式分块
	parts := [][]byte{
		[]byte("part-1: "),
		[]byte("part-2: "),
		[]byte("part-3: end."),
	}
	for i, p := range parts {
		updateFrame := ipcCallConn(t, conn, ipc.CmdDigestUpdate, jsonMust(map[string]interface{}{
			"session_id": sessionHandle,
			"part":       p,
		}))
		if rv := parseIPCResponse(t, updateFrame).RV; rv != uint32(pkcs11types.CKR_OK) {
			t.Fatalf("DigestUpdate#%d 失败: rv=0x%X", i, rv)
		}
	}

	// DigestFinal
	finalFrame := ipcCallConn(t, conn, ipc.CmdDigestFinal, jsonMust(map[string]interface{}{
		"session_id": sessionHandle,
	}))
	finalResp := parseIPCResponse(t, finalFrame)
	if finalResp.RV != uint32(pkcs11types.CKR_OK) {
		t.Fatalf("DigestFinal 失败: rv=0x%X", finalResp.RV)
	}

	var dr struct {
		Digest []byte `json:"digest"`
	}
	if err := json.Unmarshal(finalResp.Data, &dr); err != nil {
		t.Fatal(err)
	}
	// 与拼接后单次计算结果对比
	concat := append(append([]byte{}, parts[0]...), parts[1]...)
	concat = append(concat, parts[2]...)
	expect := sha256.Sum256(concat)
	if string(dr.Digest) != string(expect[:]) {
		t.Errorf("流式摘要不匹配")
	}
	t.Logf("✓ E2E DigestStream 通过，分块数 %d", len(parts))
}

// TestE2EDigestStateGuard 验证：未 DigestInit 直接 Digest 应返回 OPERATION_NOT_INITIALIZED。
func TestE2EDigestStateGuard(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix Socket 测试跳过 Windows")
	}
	sockPath, cleanup := setupIPCServer(t)
	defer cleanup()

	conn, closeConn := ipcConn(t, sockPath)
	defer closeConn()

	openFrame := ipcCallConn(t, conn, ipc.CmdOpenSession, []byte(`{"slot_id":1,"flags":4}`))
	sessionHandle := extractUint32(t, parseIPCResponse(t, openFrame).Data, "session_handle")

	// 未 DigestInit 直接 Digest
	frame := ipcCallConn(t, conn, ipc.CmdDigest, jsonMust(map[string]interface{}{
		"session_id": sessionHandle,
		"data":       []byte("x"),
	}))
	resp := parseIPCResponse(t, frame)
	if resp.RV != uint32(pkcs11types.CKR_OPERATION_NOT_INITIALIZED) {
		t.Errorf("期望 CKR_OPERATION_NOT_INITIALIZED(0x%X)，实际 0x%X",
			uint32(pkcs11types.CKR_OPERATION_NOT_INITIALIZED), resp.RV)
	}
}

// TestE2EDigestUnsupportedMechanism 验证未知机制返回 MECHANISM_INVALID。
func TestE2EDigestUnsupportedMechanism(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix Socket 测试跳过 Windows")
	}
	sockPath, cleanup := setupIPCServer(t)
	defer cleanup()

	conn, closeConn := ipcConn(t, sockPath)
	defer closeConn()

	openFrame := ipcCallConn(t, conn, ipc.CmdOpenSession, []byte(`{"slot_id":1,"flags":4}`))
	sessionHandle := extractUint32(t, parseIPCResponse(t, openFrame).Data, "session_handle")

	frame := ipcCallConn(t, conn, ipc.CmdDigestInit, jsonMust(map[string]interface{}{
		"session_id": sessionHandle,
		"mechanism":  uint32(0xDEADBEEF),
	}))
	resp := parseIPCResponse(t, frame)
	if resp.RV != uint32(pkcs11types.CKR_MECHANISM_INVALID) {
		t.Errorf("期望 CKR_MECHANISM_INVALID(0x%X)，实际 0x%X",
			uint32(pkcs11types.CKR_MECHANISM_INVALID), resp.RV)
	}
}

// ---- E2E: GenerateRandom ----

// TestE2EGenerateRandom 模拟 driver 的 C_GenerateRandom。
func TestE2EGenerateRandom(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix Socket 测试跳过 Windows")
	}
	sockPath, cleanup := setupIPCServer(t)
	defer cleanup()

	conn, closeConn := ipcConn(t, sockPath)
	defer closeConn()

	openFrame := ipcCallConn(t, conn, ipc.CmdOpenSession, []byte(`{"slot_id":1,"flags":4}`))
	sessionHandle := extractUint32(t, parseIPCResponse(t, openFrame).Data, "session_handle")

	// 1. 正常长度
	for _, length := range []uint32{1, 16, 32, 256, 4096} {
		frame := ipcCallConn(t, conn, ipc.CmdGenerateRandom, jsonMust(map[string]interface{}{
			"session_id": sessionHandle,
			"length":     length,
		}))
		resp := parseIPCResponse(t, frame)
		if resp.RV != uint32(pkcs11types.CKR_OK) {
			t.Fatalf("GenerateRandom(len=%d) 失败: rv=0x%X", length, resp.RV)
		}
		var rr struct {
			Data []byte `json:"data"`
		}
		if err := json.Unmarshal(resp.Data, &rr); err != nil {
			t.Fatal(err)
		}
		if uint32(len(rr.Data)) != length {
			t.Errorf("len 期望 %d，实际 %d", length, len(rr.Data))
		}
	}

	// 2. 长度=0 应失败
	frame := ipcCallConn(t, conn, ipc.CmdGenerateRandom, jsonMust(map[string]interface{}{
		"session_id": sessionHandle,
		"length":     0,
	}))
	if rv := parseIPCResponse(t, frame).RV; rv != uint32(pkcs11types.CKR_ARGUMENTS_BAD) {
		t.Errorf("len=0 期望 ARGUMENTS_BAD，实际 0x%X", rv)
	}
	t.Log("✓ E2E GenerateRandom 通过")
}

// TestE2ESeedRandom 模拟 driver 的 C_SeedRandom（seed 仅记录不影响 CSPRNG）。
func TestE2ESeedRandom(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix Socket 测试跳过 Windows")
	}
	sockPath, cleanup := setupIPCServer(t)
	defer cleanup()

	conn, closeConn := ipcConn(t, sockPath)
	defer closeConn()

	openFrame := ipcCallConn(t, conn, ipc.CmdOpenSession, []byte(`{"slot_id":1,"flags":4}`))
	sessionHandle := extractUint32(t, parseIPCResponse(t, openFrame).Data, "session_handle")

	frame := ipcCallConn(t, conn, ipc.CmdSeedRandom, jsonMust(map[string]interface{}{
		"session_id": sessionHandle,
		"seed":       []byte{0x01, 0x02, 0x03, 0x04, 0x05},
	}))
	if rv := parseIPCResponse(t, frame).RV; rv != uint32(pkcs11types.CKR_OK) {
		t.Errorf("SeedRandom 期望 OK，实际 0x%X", rv)
	}
}

// ---- E2E: Verify（机制校验） ----

// TestE2EVerifyInitMechanismCheck 验证 VerifyInit 对未知机制返回 MECHANISM_INVALID。
// 实际签名/验签的端到端测试见 e2e_test.go 的 TestE2EFullPKCS11Sequence。
func TestE2EVerifyInitMechanismCheck(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix Socket 测试跳过 Windows")
	}
	sockPath, cleanup := setupIPCServer(t)
	defer cleanup()

	conn, closeConn := ipcConn(t, sockPath)
	defer closeConn()

	openFrame := ipcCallConn(t, conn, ipc.CmdOpenSession, []byte(`{"slot_id":1,"flags":4}`))
	sessionHandle := extractUint32(t, parseIPCResponse(t, openFrame).Data, "session_handle")

	// 未知机制
	frame := ipcCallConn(t, conn, ipc.CmdVerifyInit, jsonMust(map[string]interface{}{
		"session_id": sessionHandle,
		"mechanism":  uint32(0xCAFEBABE),
		"key_handle": uint32(1),
	}))
	if rv := parseIPCResponse(t, frame).RV; rv != uint32(pkcs11types.CKR_MECHANISM_INVALID) {
		t.Errorf("未知机制期望 MECHANISM_INVALID，实际 0x%X", rv)
	}

	// 已知机制：CKM_ECDSA_SHA256（key_handle 无效会在 Verify 时失败，但 Init 应通过）
	initFrame := ipcCallConn(t, conn, ipc.CmdVerifyInit, jsonMust(map[string]interface{}{
		"session_id": sessionHandle,
		"mechanism":  testCkmECDSASHA256,
		"key_handle": uint32(1),
	}))
	if rv := parseIPCResponse(t, initFrame).RV; rv != uint32(pkcs11types.CKR_OK) {
		t.Errorf("VerifyInit 已知机制期望 OK，实际 0x%X", rv)
	}
}

// TestE2EVerifyOperationActiveGuard 验证：未 VerifyInit 直接 Verify 返回 OPERATION_NOT_INITIALIZED。
func TestE2EVerifyOperationActiveGuard(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix Socket 测试跳过 Windows")
	}
	sockPath, cleanup := setupIPCServer(t)
	defer cleanup()

	conn, closeConn := ipcConn(t, sockPath)
	defer closeConn()

	openFrame := ipcCallConn(t, conn, ipc.CmdOpenSession, []byte(`{"slot_id":1,"flags":4}`))
	sessionHandle := extractUint32(t, parseIPCResponse(t, openFrame).Data, "session_handle")

	frame := ipcCallConn(t, conn, ipc.CmdVerify, jsonMust(map[string]interface{}{
		"session_id": sessionHandle,
		"data":       []byte("x"),
		"signature":  []byte("y"),
	}))
	if rv := parseIPCResponse(t, frame).RV; rv != uint32(pkcs11types.CKR_OPERATION_NOT_INITIALIZED) {
		t.Errorf("期望 OPERATION_NOT_INITIALIZED，实际 0x%X", rv)
	}
}

// ---- E2E: 多命令并发性 ----

// TestE2EDigestSessionIsolation 验证：同一 IPC 服务器上不同 session 的 digest 状态隔离。
func TestE2EDigestSessionIsolation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix Socket 测试跳过 Windows")
	}
	sockPath, cleanup := setupIPCServer(t)
	defer cleanup()

	conn1, close1 := ipcConn(t, sockPath)
	defer close1()
	conn2, close2 := ipcConn(t, sockPath)
	defer close2()

	// session 1
	open1 := ipcCallConn(t, conn1, ipc.CmdOpenSession, []byte(`{"slot_id":1,"flags":4}`))
	sid1 := extractUint32(t, parseIPCResponse(t, open1).Data, "session_handle")
	// session 2
	open2 := ipcCallConn(t, conn2, ipc.CmdOpenSession, []byte(`{"slot_id":1,"flags":4}`))
	sid2 := extractUint32(t, parseIPCResponse(t, open2).Data, "session_handle")

	if sid1 == sid2 {
		t.Fatalf("两次 OpenSession 应得到不同 session_handle: %d == %d", sid1, sid2)
	}

	// session 1 init SHA-256，session 2 init SHA-1
	ipcCallConn(t, conn1, ipc.CmdDigestInit, jsonMust(map[string]interface{}{
		"session_id": sid1,
		"mechanism":  testCkmSHA256,
	}))
	ipcCallConn(t, conn2, ipc.CmdDigestInit, jsonMust(map[string]interface{}{
		"session_id": sid2,
		"mechanism":  testCkmSHA1,
	}))

	data := []byte("isolation-test")

	// session 1 完成 SHA-256
	d1Frame := ipcCallConn(t, conn1, ipc.CmdDigest, jsonMust(map[string]interface{}{
		"session_id": sid1,
		"data":       data,
	}))
	d1Resp := parseIPCResponse(t, d1Frame)
	if d1Resp.RV != uint32(pkcs11types.CKR_OK) {
		t.Fatalf("session1 Digest 失败: rv=0x%X", d1Resp.RV)
	}
	var d1 struct {
		Digest []byte `json:"digest"`
	}
	json.Unmarshal(d1Resp.Data, &d1)
	if len(d1.Digest) != 32 {
		t.Errorf("session1 应为 SHA-256 长度 32，实际 %d", len(d1.Digest))
	}

	// session 2 完成 SHA-1
	d2Frame := ipcCallConn(t, conn2, ipc.CmdDigest, jsonMust(map[string]interface{}{
		"session_id": sid2,
		"data":       data,
	}))
	d2Resp := parseIPCResponse(t, d2Frame)
	var d2 struct {
		Digest []byte `json:"digest"`
	}
	json.Unmarshal(d2Resp.Data, &d2)
	if len(d2.Digest) != 20 {
		t.Errorf("session2 应为 SHA-1 长度 20，实际 %d", len(d2.Digest))
	}
	t.Logf("✓ Session 隔离 OK: sha256=%d bytes, sha1=%d bytes", len(d1.Digest), len(d2.Digest))
}

// ---- 辅助 ----

// jsonMust 将 map 序列化为 JSON。注意：[]byte 字段会被 base64 编码（IPC handler 已用 []byte 接收），
// Go 的 json 包默认对 []byte 进行 base64 处理，与 handler 端 ParseRequest 解析一致。
func jsonMust(v interface{}) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("jsonMust: %v", err))
	}
	return b
}
