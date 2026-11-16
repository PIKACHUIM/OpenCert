//go:build windows

package backup

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// 本文件提供 DPAPI 解密原语。当前只支持“当前进程身份”作用域。
// VSC 卡片数据由 LocalService 写入，普通管理员身份无法解开；
// 完整的 .tsb 还原还需要借用 SYSTEM 令牌后再调用本函数（下一步实现）。

var (
	crypt32DLL             = windows.NewLazySystemDLL("crypt32.dll")
	kernel32DLL            = windows.NewLazySystemDLL("kernel32.dll")
	procCryptUnprotectData = crypt32DLL.NewProc("CryptUnprotectData")
	procCryptProtectData   = crypt32DLL.NewProc("CryptProtectData")
	procLocalFree          = kernel32DLL.NewProc("LocalFree")
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

// unprotectDPAPI 解密当前用户作用域的 DPAPI blob。
func unprotectDPAPI(blob []byte) ([]byte, error) {
	if len(blob) == 0 {
		return nil, fmt.Errorf("DPAPI blob 为空")
	}
	in := dataBlob{cbData: uint32(len(blob)), pbData: &blob[0]}
	var out dataBlob
	result, _, _ := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&in)),
		0,
		0,
		0,
		0,
		0x1, // CRYPTPROTECT_UI_FORBIDDEN
		uintptr(unsafe.Pointer(&out)),
	)
	if result == 0 {
		return nil, fmt.Errorf("DPAPI 解密失败（当前身份无权解开该卡数据，可能需要 SYSTEM 令牌）")
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.pbData)))
	if out.pbData == nil || out.cbData == 0 {
		return nil, fmt.Errorf("DPAPI 解密返回空数据")
	}
	data := make([]byte, out.cbData)
	copy(data, unsafe.Slice(out.pbData, out.cbData))
	return data, nil
}

// protectDPAPI 用当前身份重新加密明文，供还原时写回目标机。
func protectDPAPI(plain []byte) ([]byte, error) {
	if len(plain) == 0 {
		return nil, fmt.Errorf("DPAPI 明文为空")
	}
	in := dataBlob{cbData: uint32(len(plain)), pbData: &plain[0]}
	var out dataBlob
	result, _, _ := procCryptProtectData.Call(
		uintptr(unsafe.Pointer(&in)),
		0, 0, 0, 0, 0x1,
		uintptr(unsafe.Pointer(&out)),
	)
	if result == 0 {
		return nil, fmt.Errorf("DPAPI 重新加密失败")
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.pbData)))
	data := make([]byte, out.cbData)
	copy(data, unsafe.Slice(out.pbData, out.cbData))
	return data, nil
}
