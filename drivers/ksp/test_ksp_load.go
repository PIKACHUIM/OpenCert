//go:build windows

package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	ncrypt              = syscall.NewLazyDLL("ncrypt.dll")
	procOpenStorageProv = ncrypt.NewProc("NCryptOpenStorageProvider")
	procFreeObject      = ncrypt.NewProc("NCryptFreeObject")

	kernel32     = syscall.NewLazyDLL("kernel32.dll")
	procLoadLib  = kernel32.NewProc("LoadLibraryW")
	procGetProc  = kernel32.NewProc("GetProcAddress")
	procFreeLib  = kernel32.NewProc("FreeLibrary")
)

func main() {
	fmt.Println("=== OpenCert KSP Diagnostic Tool ===")
	fmt.Println()

	// Test 1: 直接加载 DLL
	fmt.Println("[1] Direct DLL load test...")
	dllPath, _ := syscall.UTF16PtrFromString(`C:\WINDOWS\System32\OpenCertKSP.dll`)
	h, _, err := procLoadLib.Call(uintptr(unsafe.Pointer(dllPath)))
	if h == 0 {
		fmt.Printf("    [FAIL] LoadLibrary failed: %v\n", err)
		return
	}
	fmt.Printf("    [OK] DLL loaded at 0x%X\n", h)

	// Test 2: 获取导出函数
	fmt.Println("[2] GetProcAddress test...")
	funcName, _ := syscall.BytePtrFromString("GetKeyStorageInterface")
	addr, _, err := procGetProc.Call(h, uintptr(unsafe.Pointer(funcName)))
	if addr == 0 {
		fmt.Printf("    [FAIL] GetProcAddress failed: %v\n", err)
		procFreeLib.Call(h)
		return
	}
	fmt.Printf("    [OK] GetKeyStorageInterface at 0x%X\n", addr)

	// Test 3: 调用 GetKeyStorageInterface
	fmt.Println("[3] Calling GetKeyStorageInterface...")
	provName, _ := syscall.UTF16PtrFromString("OpenCert Key Storage Provider")
	var pTable uintptr
	ret, _, _ := syscall.SyscallN(addr,
		uintptr(unsafe.Pointer(provName)),
		uintptr(unsafe.Pointer(&pTable)),
		0,
	)
	fmt.Printf("    NTSTATUS: 0x%08X\n", ret)
	if ret == 0 {
		fmt.Printf("    [OK] Function table at 0x%X\n", pTable)
		if pTable != 0 {
			// 读取 Version (BCRYPT_INTERFACE_VERSION = {USHORT Major, USHORT Minor})
			ver := (*[2]uint16)(unsafe.Pointer(pTable))
			fmt.Printf("    Version: %d.%d\n", ver[0], ver[1])
			// 读取第一个函数指针 (OpenProvider)
			ptrs := (*[30]uintptr)(unsafe.Pointer(pTable))
			fmt.Printf("    OpenProvider func ptr: 0x%X\n", ptrs[1])
		}
	} else {
		fmt.Printf("    [FAIL] GetKeyStorageInterface returned error\n")
	}

	procFreeLib.Call(h)

	// Test 4: 通过 NCrypt API 打开
	fmt.Println()
	fmt.Println("[4] NCryptOpenStorageProvider test...")
	var hProv uintptr
	provNameNCrypt, _ := syscall.UTF16PtrFromString("OpenCert Key Storage Provider")
	r, _, _ := procOpenStorageProv.Call(
		uintptr(unsafe.Pointer(&hProv)),
		uintptr(unsafe.Pointer(provNameNCrypt)),
		0,
	)
	fmt.Printf("    SECURITY_STATUS: 0x%08X\n", r)
	if r == 0 {
		fmt.Printf("    [OK] Provider handle: 0x%X\n", hProv)
		procFreeObject.Call(hProv)
	} else {
		fmt.Printf("    [FAIL] NCryptOpenStorageProvider failed\n")
		// 常见错误码
		switch r {
		case 0x80090013:
			fmt.Println("    Error: NTE_BAD_PROVIDER - 提供程序无效")
			fmt.Println("    可能原因:")
			fmt.Println("      - DLL 的 GetKeyStorageInterface 返回了错误的函数表")
			fmt.Println("      - 函数表的 Version 字段不正确")
			fmt.Println("      - 函数表中的函数指针为 NULL")
		case 0x80090035:
			fmt.Println("    Error: NTE_DEVICE_NOT_FOUND")
		}
	}

	fmt.Println()
	fmt.Println("=== Done ===")
}
