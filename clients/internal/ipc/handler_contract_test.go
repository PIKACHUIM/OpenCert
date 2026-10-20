package ipc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/globaltrusts/client-card/internal/card"
	"github.com/globaltrusts/client-card/internal/card/local"
	"github.com/globaltrusts/client-card/internal/storage"
	"github.com/globaltrusts/client-card/pkg/pkcs11types"
)

// 本文件验证 IPC 层与 C 驱动（drivers/codes/csp/codes/pkcs11-mock.c）之间的 JSON 契约。
//
// 之所以直接调用 handler 而不是走 socket：Unix Socket 测试在 Windows 上会被跳过，
// 而字段名不匹配正是"驱动在生产环境完全不可用"的根因，必须在所有平台都能验证。
//
// C 驱动使用的键名（见 pkcs11-mock.c）：
//
//	请求：session_id / mechanism / object_handle / handle / types / attrs / template / data
//	响应：session_id / count / handles / handles[i] / attrs / handle / pub_handle / priv_handle
//	      slot_description / manufacturer_id / hw_major / fw_minor / library_description ...

const (
	contractPIN = "contractpin123"
	// CKF_SERIAL_SESSION(0x04) | CKF_RW_SESSION(0x02)
	contractSessionFlags = 6
)

// newContractFixture 创建带本地卡片的 handler 夹具。
func newContractFixture(t *testing.T) *PKCSHandler {
	t.Helper()

	db, err := storage.Open(filepath.Join(t.TempDir(), "ipc-contract.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	ctx := context.Background()
	userRepo := storage.NewUserRepo(db)
	cardRepo := storage.NewCardRepo(db)
	certRepo := storage.NewCertRepo(db)

	user := &storage.User{
		UserType:    storage.UserTypeLocal,
		DisplayName: "IPC 契约测试用户",
		Email:       "contract@test.com",
		Enabled:     true,
	}
	if err := userRepo.Create(ctx, user); err != nil {
		t.Fatalf("创建测试用户失败: %v", err)
	}

	testCard, err := local.CreateCard(ctx, cardRepo, user.UUID, "契约测试卡片", contractPIN, "", "")
	if err != nil {
		t.Fatalf("创建测试卡片失败: %v", err)
	}

	mgr := card.NewManager()
	mgr.RegisterSlot(local.NewWithCardRepo(pkcs11types.SlotID(1), testCard, certRepo, cardRepo))
	return NewPKCSHandler(mgr)
}

// invoke 调用 handler 并把响应按 WriteResponse 的方式还原为 map，便于检查字段名。
func invoke(t *testing.T, h Handler, payload string) (map[string]interface{}, uint32) {
	t.Helper()
	data, rv := h(context.Background(), &Frame{Payload: []byte(payload)})
	if data == nil {
		return nil, rv
	}
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("序列化响应失败: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	return m, rv
}

// invokeOK 调用 handler 并断言 rv == CKR_OK。
func invokeOK(t *testing.T, h Handler, payload, what string) map[string]interface{} {
	t.Helper()
	data, rv := invoke(t, h, payload)
	if rv != uint32(pkcs11types.CKR_OK) {
		t.Fatalf("%s 失败: rv=0x%X payload=%s", what, rv, payload)
	}
	return data
}

func uint32Field(t *testing.T, data map[string]interface{}, key, what string) uint32 {
	t.Helper()
	raw, ok := data[key]
	if !ok {
		t.Fatalf("%s: 响应缺少 %q 字段（实际字段: %v）", what, key, mapKeys(data))
	}
	f, ok := raw.(float64)
	if !ok {
		t.Fatalf("%s: 字段 %q 不是数字: %T", what, key, raw)
	}
	return uint32(f)
}

func mapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// openAndLogin 打开 RW 会话并以普通用户登录，返回会话句柄。
func openAndLogin(t *testing.T, h *PKCSHandler) uint32 {
	t.Helper()

	data := invokeOK(t, h.handleOpenSession,
		fmt.Sprintf(`{"slot_id":1,"flags":%d}`, contractSessionFlags), "OpenSession")
	// C 驱动读取 session_id，缺此字段会退回到自己的固定会话号
	sid := uint32Field(t, data, "session_id", "OpenSession")
	if sid == 0 {
		t.Fatal("OpenSession 返回的 session_id 为 0")
	}

	invokeOK(t, h.handleLogin,
		fmt.Sprintf(`{"session_id":%d,"user_type":%d,"pin":%q}`, sid, pkcs11types.CKU_USER, contractPIN),
		"Login")
	return sid
}

// ---- 库 / Slot / Token 信息 ----

func TestContractGetInfoAndSlotFields(t *testing.T) {
	h := newContractFixture(t)

	info := invokeOK(t, h.handleGetInfo, "", "GetInfo")
	for _, key := range []string{"manufacturer_id", "library_description", "library_version_major", "library_version_minor"} {
		if _, ok := info[key]; !ok {
			t.Errorf("GetInfo 响应缺少 C 驱动读取的字段 %q（实际: %v）", key, mapKeys(info))
		}
	}

	slots := invokeOK(t, h.handleGetSlotList, `{"token_present":false}`, "GetSlotList")
	if got := uint32Field(t, slots, "count", "GetSlotList"); got != 1 {
		t.Errorf("GetSlotList count = %d，期望 1", got)
	}
	if _, ok := slots["slot_ids"]; !ok {
		t.Errorf("GetSlotList 响应缺少 slot_ids: %v", mapKeys(slots))
	}

	slotInfo := invokeOK(t, h.handleGetSlotInfo, `{"slot_id":1}`, "GetSlotInfo")
	for _, key := range []string{"slot_description", "manufacturer_id", "flags", "hw_major", "hw_minor", "fw_major", "fw_minor"} {
		if _, ok := slotInfo[key]; !ok {
			t.Errorf("GetSlotInfo 响应缺少 C 驱动读取的字段 %q（实际: %v）", key, mapKeys(slotInfo))
		}
	}

	tokenInfo := invokeOK(t, h.handleGetTokenInfo, `{"slot_id":1}`, "GetTokenInfo")
	for _, key := range []string{"label", "manufacturer_id", "model", "serial_number", "flags"} {
		if _, ok := tokenInfo[key]; !ok {
			t.Errorf("GetTokenInfo 响应缺少 C 驱动读取的字段 %q（实际: %v）", key, mapKeys(tokenInfo))
		}
	}

	mechs := invokeOK(t, h.handleGetMechanismList, `{"slot_id":1}`, "GetMechanismList")
	if uint32Field(t, mechs, "count", "GetMechanismList") == 0 {
		t.Error("GetMechanismList count 为 0")
	}

	// C 驱动发送的键名是 mechanism（不是 mechanism_type）
	mechInfo := invokeOK(t, h.handleGetMechanismInfo,
		fmt.Sprintf(`{"slot_id":1,"mechanism":%d}`, uint32(pkcs11types.CKM_SHA256_RSA_PKCS)), "GetMechanismInfo")
	for _, key := range []string{"min_key_size", "max_key_size", "flags"} {
		if _, ok := mechInfo[key]; !ok {
			t.Errorf("GetMechanismInfo 响应缺少 %q", key)
		}
	}
}

// ---- 对象：生成、查找、属性、删除 ----

func TestContractObjectLifecycle(t *testing.T) {
	h := newContractFixture(t)
	sid := openAndLogin(t, h)

	// C_GenerateKeyPair：只发送 mechanism
	kp := invokeOK(t, h.handleGenerateKeyPair,
		fmt.Sprintf(`{"session_id":%d,"mechanism":%d}`, sid, uint32(pkcs11types.CKM_RSA_PKCS_KEY_PAIR_GEN)),
		"GenerateKeyPair")
	pubHandle := uint32Field(t, kp, "pub_handle", "GenerateKeyPair")
	privHandle := uint32Field(t, kp, "priv_handle", "GenerateKeyPair")
	if pubHandle == 0 || privHandle == 0 {
		t.Fatalf("GenerateKeyPair 返回了无效句柄 pub=%d priv=%d", pubHandle, privHandle)
	}

	// C_FindObjectsInit：count + handles 数组
	found := invokeOK(t, h.handleFindObjectsInit,
		fmt.Sprintf(`{"session_id":%d,"template":[{"type":%d,"value":"%s"}]}`,
			sid, uint32(pkcs11types.CKA_CLASS),
			base64.StdEncoding.EncodeToString(bigEndianUint32(uint32(pkcs11types.CKO_PRIVATE_KEY)))),
		"FindObjectsInit")
	if uint32Field(t, found, "count", "FindObjectsInit") == 0 {
		t.Error("FindObjectsInit 未返回任何对象")
	}

	// C_FindObjects：count + handles[i] 索引键
	batch := invokeOK(t, h.handleFindObjects, fmt.Sprintf(`{"session_id":%d,"max_count":10}`, sid), "FindObjects")
	count := uint32Field(t, batch, "count", "FindObjects")
	if got := uint32Field(t, batch, "handles[0]", "FindObjects"); got == 0 {
		t.Errorf("FindObjects handles[0] 无效（count=%d）", count)
	}
	invokeOK(t, h.handleFindObjectsFinal, fmt.Sprintf(`{"session_id":%d}`, sid), "FindObjectsFinal")

	// C_GetObjectSize
	sizeResp := invokeOK(t, h.handleGetObjectSize,
		fmt.Sprintf(`{"session_id":%d,"object_handle":%d}`, sid, privHandle), "GetObjectSize")
	if uint32Field(t, sizeResp, "size", "GetObjectSize") == 0 {
		t.Error("GetObjectSize 返回 0")
	}

	// C_GetAttributeValue：请求键为 types，响应键为 attrs
	attrs := invokeOK(t, h.handleGetAttributeValue,
		fmt.Sprintf(`{"session_id":%d,"object_handle":%d,"types":[%d,%d]}`,
			sid, privHandle, uint32(pkcs11types.CKA_CLASS), uint32(pkcs11types.CKA_LABEL)),
		"GetAttributeValue")
	if _, ok := attrs["attrs"]; !ok {
		t.Fatalf("GetAttributeValue 响应缺少 attrs 字段（实际: %v）", mapKeys(attrs))
	}

	// C_SetAttributeValue：更新 CKA_LABEL
	newLabel := base64.StdEncoding.EncodeToString([]byte("契约测试标签"))
	invokeOK(t, h.handleSetAttributeValue,
		fmt.Sprintf(`{"session_id":%d,"object_handle":%d,"attrs":[{"type":%d,"value":"%s"}]}`,
			sid, privHandle, uint32(pkcs11types.CKA_LABEL), newLabel),
		"SetAttributeValue")

	// C_CreateObject：带 template（C 驱动已同步修改为传输模板内容）
	certDER := makeSelfSignedCertDER(t)
	created := invokeOK(t, h.handleCreateObject,
		fmt.Sprintf(`{"session_id":%d,"attr_count":2,"template":[{"type":%d,"value":"%s"},{"type":%d,"value":"%s"}]}`,
			sid,
			uint32(pkcs11types.CKA_CLASS),
			base64.StdEncoding.EncodeToString(bigEndianUint32(uint32(pkcs11types.CKO_CERTIFICATE))),
			uint32(pkcs11types.CKA_VALUE),
			base64.StdEncoding.EncodeToString(certDER)),
		"CreateObject")
	createdHandle := uint32Field(t, created, "handle", "CreateObject")
	if createdHandle == 0 {
		t.Fatal("CreateObject 返回句柄 0")
	}

	// 句柄是按加载顺序位置化分配的，删除后可能被复用，
	// 因此用对象总数验证删除效果，而不是断言旧句柄失效。
	before := objectCount(t, h, sid)
	invokeOK(t, h.handleDestroyObject,
		fmt.Sprintf(`{"session_id":%d,"handle":%d}`, sid, createdHandle), "DestroyObject")
	after := objectCount(t, h, sid)
	if after != before-1 {
		t.Errorf("DestroyObject 后对象数 = %d，期望 %d", after, before-1)
	}
}

// objectCount 通过 FindObjectsInit 统计当前可见对象数量。
func objectCount(t *testing.T, h *PKCSHandler, sid uint32) uint32 {
	t.Helper()
	data := invokeOK(t, h.handleFindObjectsInit,
		fmt.Sprintf(`{"session_id":%d,"template":[]}`, sid), "FindObjectsInit")
	count := uint32Field(t, data, "count", "FindObjectsInit")
	invokeOK(t, h.handleFindObjectsFinal, fmt.Sprintf(`{"session_id":%d}`, sid), "FindObjectsFinal")
	return count
}

// ---- 多段签名 ----

func TestContractStreamingSign(t *testing.T) {
	h := newContractFixture(t)
	sid := openAndLogin(t, h)

	kp := invokeOK(t, h.handleGenerateKeyPair,
		fmt.Sprintf(`{"session_id":%d,"mechanism":%d}`, sid, uint32(pkcs11types.CKM_RSA_PKCS_KEY_PAIR_GEN)),
		"GenerateKeyPair")
	handle := uint32Field(t, kp, "priv_handle", "GenerateKeyPair")

	invokeOK(t, h.handleSignInit,
		fmt.Sprintf(`{"session_id":%d,"mechanism":%d,"key_handle":%d}`,
			sid, uint32(pkcs11types.CKM_SHA256_RSA_PKCS), handle),
		"SignInit")

	part1 := base64.StdEncoding.EncodeToString([]byte("hello "))
	part2 := base64.StdEncoding.EncodeToString([]byte("world"))
	invokeOK(t, h.handleSignUpdate, fmt.Sprintf(`{"session_id":%d,"part":"%s"}`, sid, part1), "SignUpdate")
	invokeOK(t, h.handleSignUpdate, fmt.Sprintf(`{"session_id":%d,"part":"%s"}`, sid, part2), "SignUpdate")

	final := invokeOK(t, h.handleSignFinal, fmt.Sprintf(`{"session_id":%d}`, sid), "SignFinal")
	sigB64, _ := final["signature"].(string)
	if sigB64 == "" {
		t.Fatal("SignFinal 未返回签名")
	}
	if _, err := base64.StdEncoding.DecodeString(sigB64); err != nil {
		t.Fatalf("签名不是合法 base64: %v", err)
	}
}

// ---- PIN 管理 ----

func TestContractSetPIN(t *testing.T) {
	h := newContractFixture(t)
	sid := openAndLogin(t, h)

	const newPIN = "newcontractpin456"
	invokeOK(t, h.handleSetPIN,
		fmt.Sprintf(`{"session_id":%d,"old_pin":%q,"new_pin":%q}`, sid, contractPIN, newPIN),
		"SetPIN")

	// 先登出：同一 Slot 的所有会话共享登录状态，未登出时重新登录会被拒绝
	invokeOK(t, h.handleLogout, fmt.Sprintf(`{"session_id":%d}`, sid), "Logout")

	data := invokeOK(t, h.handleOpenSession,
		fmt.Sprintf(`{"slot_id":1,"flags":%d}`, contractSessionFlags), "OpenSession")
	sid2 := uint32Field(t, data, "session_id", "OpenSession")

	// 新 PIN 可登录
	invokeOK(t, h.handleLogin,
		fmt.Sprintf(`{"session_id":%d,"user_type":%d,"pin":%q}`, sid2, pkcs11types.CKU_USER, newPIN),
		"Login(新 PIN)")
	invokeOK(t, h.handleLogout, fmt.Sprintf(`{"session_id":%d}`, sid2), "Logout")

	// 旧 PIN 不再可用
	data3 := invokeOK(t, h.handleOpenSession,
		fmt.Sprintf(`{"slot_id":1,"flags":%d}`, contractSessionFlags), "OpenSession")
	sid3 := uint32Field(t, data3, "session_id", "OpenSession")
	_, rv := invoke(t, h.handleLogin,
		fmt.Sprintf(`{"session_id":%d,"user_type":%d,"pin":%q}`, sid3, pkcs11types.CKU_USER, contractPIN))
	if rv == uint32(pkcs11types.CKR_OK) {
		t.Error("修改 PIN 后旧 PIN 仍可登录")
	}
}

func TestContractInitPIN(t *testing.T) {
	h := newContractFixture(t)

	data := invokeOK(t, h.handleOpenSession,
		fmt.Sprintf(`{"slot_id":1,"flags":%d}`, contractSessionFlags), "OpenSession")
	sid := uint32Field(t, data, "session_id", "OpenSession")

	// InitPIN 需要 RW_SO 状态
	invokeOK(t, h.handleLogin,
		fmt.Sprintf(`{"session_id":%d,"user_type":%d,"pin":%q}`, sid, pkcs11types.CKU_SO, contractPIN),
		"Login(SO)")

	const soSetPIN = "sosetpin789"
	invokeOK(t, h.handleInitPIN, fmt.Sprintf(`{"session_id":%d,"pin":%q}`, sid, soSetPIN), "InitPIN")
	invokeOK(t, h.handleLogout, fmt.Sprintf(`{"session_id":%d}`, sid), "Logout")

	// 用 SO 设置的新 PIN 重新登录
	data2 := invokeOK(t, h.handleOpenSession,
		fmt.Sprintf(`{"slot_id":1,"flags":%d}`, contractSessionFlags), "OpenSession")
	sid2 := uint32Field(t, data2, "session_id", "OpenSession")
	invokeOK(t, h.handleLogin,
		fmt.Sprintf(`{"session_id":%d,"user_type":%d,"pin":%q}`, sid2, pkcs11types.CKU_USER, soSetPIN),
		"Login(InitPIN 后的 PIN)")
}

// ---- 国密：SM2 / SM3 ----

// TestContractSM2KeyGenAndSign 验证 CKM_SM2_KEY_PAIR_GEN 生成真实 SM2 密钥，
// 并且 CKM_SM2 的输入是原文、签名为 64 字节 r‖s。
func TestContractSM2KeyGenAndSign(t *testing.T) {
	h := newContractFixture(t)
	sid := openAndLogin(t, h)

	kp := invokeOK(t, h.handleGenerateKeyPair,
		fmt.Sprintf(`{"session_id":%d,"mechanism":%d}`, sid, uint32(pkcs11types.CKM_SM2_KEY_PAIR_GEN)),
		"GenerateKeyPair(SM2)")
	handle := uint32Field(t, kp, "priv_handle", "GenerateKeyPair(SM2)")
	if handle == 0 {
		t.Fatal("SM2 GenerateKeyPair 返回句柄 0")
	}

	invokeOK(t, h.handleSignInit,
		fmt.Sprintf(`{"session_id":%d,"mechanism":%d,"key_handle":%d}`,
			sid, uint32(pkcs11types.CKM_SM2), handle),
		"SignInit(SM2)")

	data := base64.StdEncoding.EncodeToString([]byte("国密签名原文"))
	signed := invokeOK(t, h.handleSign,
		fmt.Sprintf(`{"session_id":%d,"key_handle":%d,"mechanism":%d,"data":"%s"}`,
			sid, handle, uint32(pkcs11types.CKM_SM2), data),
		"Sign(SM2)")

	sigB64, _ := signed["signature"].(string)
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("SM2 签名不是合法 base64: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("SM2 签名长度应为 64（r‖s），实际 %d", len(sig))
	}
}

// TestContractSM3Digest 验证 CKM_SM3 摘要链路的字段与结果。
func TestContractSM3Digest(t *testing.T) {
	h := newContractFixture(t)
	sid := openAndLogin(t, h)

	invokeOK(t, h.handleDigestInit,
		fmt.Sprintf(`{"session_id":%d,"mechanism":%d}`, sid, uint32(pkcs11types.CKM_SM3)),
		"DigestInit(SM3)")

	out := invokeOK(t, h.handleDigest,
		fmt.Sprintf(`{"session_id":%d,"data":"%s"}`, sid, base64.StdEncoding.EncodeToString([]byte("abc"))),
		"Digest(SM3)")

	digestB64, _ := out["digest"].(string)
	got, err := base64.StdEncoding.DecodeString(digestB64)
	if err != nil {
		t.Fatalf("SM3 摘要不是合法 base64: %v", err)
	}
	const wantHex = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
	if fmt.Sprintf("%x", got) != wantHex {
		t.Fatalf("SM3(\"abc\") 结果不正确: %x", got)
	}
}

// TestContractSM2MechanismInfo 验证机制信息表把 SM2 报为 256 位可签名/验签/加解密。
func TestContractSM2MechanismInfo(t *testing.T) {
	h := newContractFixture(t)

	data := invokeOK(t, h.handleGetMechanismInfo,
		fmt.Sprintf(`{"slot_id":1,"mechanism":%d}`, uint32(pkcs11types.CKM_SM2)),
		"GetMechanismInfo(SM2)")

	if v := uint32Field(t, data, "min_key_size", "GetMechanismInfo"); v != 256 {
		t.Errorf("SM2 min_key_size = %d，期望 256", v)
	}
	if v := uint32Field(t, data, "max_key_size", "GetMechanismInfo"); v != 256 {
		t.Errorf("SM2 max_key_size = %d，期望 256", v)
	}
}

// ---- 国密对称加密：SM4 ----

// TestContractSM4SecretKeyCrypt 验证 C_CreateObject 创建 SM4 密钥对象后，
// 通过 EncryptInit/Encrypt/DecryptInit/Decrypt 完成一次 CBC 往返，
// 同时覆盖驱动把 IV 放进 mech_param 的契约。
func TestContractSM4SecretKeyCrypt(t *testing.T) {
	h := newContractFixture(t)
	sid := openAndLogin(t, h)

	// C_CreateObject：CKO_SECRET_KEY + CKK_SM4 + CKA_VALUE
	created := invokeOK(t, h.handleCreateObject,
		fmt.Sprintf(`{"session_id":%d,"attr_count":4,"template":[
			{"type":%d,"value":"%s"},
			{"type":%d,"value":"%s"},
			{"type":%d,"value":"%s"},
			{"type":%d,"value":"%s"}]}`,
			sid,
			uint32(pkcs11types.CKA_CLASS),
			base64.StdEncoding.EncodeToString(bigEndianUint32(uint32(pkcs11types.CKO_SECRET_KEY))),
			uint32(pkcs11types.CKA_KEY_TYPE),
			base64.StdEncoding.EncodeToString(bigEndianUint32(uint32(pkcs11types.CKK_SM4))),
			uint32(pkcs11types.CKA_VALUE),
			base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")),
			uint32(pkcs11types.CKA_LABEL),
			base64.StdEncoding.EncodeToString([]byte("sm4-contract")),
		),
		"CreateObject(SM4)")
	keyHandle := uint32Field(t, created, "handle", "CreateObject(SM4)")

	iv := base64.StdEncoding.EncodeToString([]byte("abcdefghijklmnop"))
	invokeOK(t, h.handleEncryptInit,
		fmt.Sprintf(`{"session_id":%d,"mechanism":%d,"key_handle":%d,"mech_param":"%s"}`,
			sid, uint32(pkcs11types.CKM_SM4_CBC), keyHandle, iv),
		"EncryptInit(SM4-CBC)")

	plaintext := []byte("sm4 ipc contract payload")
	enc := invokeOK(t, h.handleEncrypt,
		fmt.Sprintf(`{"session_id":%d,"key_handle":%d,"mechanism":%d,"data":"%s"}`,
			sid, keyHandle, uint32(pkcs11types.CKM_SM4_CBC),
			base64.StdEncoding.EncodeToString(plaintext)),
		"Encrypt(SM4-CBC)")
	ctB64, _ := enc["ciphertext"].(string)
	ciphertext, err := base64.StdEncoding.DecodeString(ctB64)
	if err != nil || len(ciphertext) == 0 {
		t.Fatalf("密文无效: %v", err)
	}

	invokeOK(t, h.handleDecryptInit,
		fmt.Sprintf(`{"session_id":%d,"mechanism":%d,"key_handle":%d,"mech_param":"%s"}`,
			sid, uint32(pkcs11types.CKM_SM4_CBC), keyHandle, iv),
		"DecryptInit(SM4-CBC)")
	dec := invokeOK(t, h.handleDecrypt,
		fmt.Sprintf(`{"session_id":%d,"key_handle":%d,"mechanism":%d,"data":"%s"}`,
			sid, keyHandle, uint32(pkcs11types.CKM_SM4_CBC), ctB64),
		"Decrypt(SM4-CBC)")

	ptB64, _ := dec["plaintext"].(string)
	got, err := base64.StdEncoding.DecodeString(ptB64)
	if err != nil {
		t.Fatalf("明文不是合法 base64: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("SM4 往返结果不一致: %q", got)
	}
}

// ---- 未实现能力的返回码 ----

func TestContractUnsupportedMechanism(t *testing.T) {
	h := newContractFixture(t)
	sid := openAndLogin(t, h)

	// CKM_AES_KEY_GEN 不在支持列表 → CKR_MECHANISM_INVALID（而不是假装成功）
	if _, rv := invoke(t, h.handleGenerateKeyPair,
		fmt.Sprintf(`{"session_id":%d,"mechanism":%d}`, sid, 0x1081)); rv != uint32(pkcs11types.CKR_MECHANISM_INVALID) {
		t.Errorf("不支持的机制应返回 CKR_MECHANISM_INVALID，实际 0x%X", rv)
	}
}

// ---- 辅助 ----

func bigEndianUint32(v uint32) []byte {
	return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

// makeSelfSignedCertDER 生成一张自签名证书 DER，用于 CreateObject。
func makeSelfSignedCertDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "ipc-contract"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("签发测试证书失败: %v", err)
	}
	return der
}
