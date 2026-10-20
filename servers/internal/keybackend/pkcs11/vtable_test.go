package pkcs11

import (
	"testing"
	"unsafe"
)

// TestFunctionTableAgainstExports 交叉校验 CK_FUNCTION_LIST 的布局假设：
// 函数表中每个 C_* 项的地址必须与模块导出的同名符号地址完全一致。
//
// 这是对「函数表序号 + 头部偏移」假设最直接的验证，可避免因布局猜错
// 而在真实 HSM 上调用到错误函数（甚至崩溃）。
func TestFunctionTableAgainstExports(t *testing.T) {
	path := testModulePath(t)

	m, err := LoadModule(path)
	if err != nil {
		t.Fatalf("加载模块失败: %v", err)
	}
	defer ReleaseModule(path)

	list := m.table
	if list == nil {
		t.Fatal("函数表指针为空")
	}
	offset, detected := m.Layout()
	t.Logf("函数表布局：头部偏移=%d 已识别=%v（%s）", offset, detected, m.LayoutNote())

	expected := map[int]string{
		ordInitialize:       "C_Initialize",
		ordFinalize:         "C_Finalize",
		ordGetInfo:          "C_GetInfo",
		4:                   "C_GetFunctionList",
		ordGetSlotList:      "C_GetSlotList",
		ordGetSlotInfo:      "C_GetSlotInfo",
		ordGetTokenInfo:     "C_GetTokenInfo",
		ordGetMechanismList: "C_GetMechanismList",
		ordGetMechanismInfo: "C_GetMechanismInfo",
		ordOpenSession:      "C_OpenSession",
		ordCloseSession:     "C_CloseSession",
		ordLogin:            "C_Login",
		ordLogout:           "C_Logout",
		ordCreateObject:     "C_CreateObject",
		ordDestroyObject:    "C_DestroyObject",
		ordGetAttributeVal:  "C_GetAttributeValue",
		ordFindObjectsInit:  "C_FindObjectsInit",
		ordFindObjects:      "C_FindObjects",
		ordFindObjectsFinal: "C_FindObjectsFinal",
		ordDecryptInit:      "C_DecryptInit",
		ordDecrypt:          "C_Decrypt",
		ordSignInit:         "C_SignInit",
		ordSign:             "C_Sign",
		ordGenerateKeyPair:  "C_GenerateKeyPair",
	}

	checked := 0
	for ord, name := range expected {
		want, err := lookupSymbol(m.handle, name)
		if err != nil || want == 0 {
			// 模块可能未按名字导出该函数（规范只要求导出 C_GetFunctionList），跳过比对
			continue
		}
		got := *(*uintptr)(unsafe.Add(list, uintptr(offset)+uintptr(ord-1)*unsafe.Sizeof(uintptr(0))))
		if got != want {
			t.Errorf("函数表第 %d 项应为 %s（0x%X），实际为 0x%X —— 函数表布局假设不成立",
				ord, name, want, got)
		}
		checked++
	}
	if checked == 0 {
		t.Skip("该模块未按名字导出 C_* 符号，无法交叉校验")
	}
	if !detected {
		t.Errorf("模块导出了 %d 个 C_* 符号，但未能自动判定函数表布局", checked)
	}
	t.Logf("已交叉校验 %d 个函数表项", checked)
}
