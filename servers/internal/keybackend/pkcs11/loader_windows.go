//go:build windows

package pkcs11

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// loadLibrary 加载 PKCS#11 动态库（Windows）。
func loadLibrary(path string) (uintptr, error) {
	h, err := windows.LoadLibrary(path)
	if err != nil {
		// 常见原因：位数不匹配（32 位模块 / 64 位进程）
		if errno, ok := err.(windows.Errno); ok {
			switch errno {
			case 193:
				return 0, fmt.Errorf("模块位数与进程不匹配（请使用 64 位 PKCS#11 模块）")
			case 126:
				return 0, fmt.Errorf("找不到依赖的动态库（请确认厂商驱动已完整安装）")
			}
		}
		return 0, err
	}
	return uintptr(h), nil
}

// lookupSymbol 获取导出符号地址。
func lookupSymbol(handle uintptr, name string) (uintptr, error) {
	addr, err := windows.GetProcAddress(windows.Handle(handle), name)
	if err != nil {
		return 0, err
	}
	return addr, nil
}

// releaseLibrary 卸载动态库。
func releaseLibrary(handle uintptr) {
	if handle != 0 {
		_ = windows.FreeLibrary(windows.Handle(handle))
	}
}
