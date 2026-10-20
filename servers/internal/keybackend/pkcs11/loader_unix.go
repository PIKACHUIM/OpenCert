//go:build !windows

package pkcs11

import (
	"fmt"

	"github.com/ebitengine/purego"
)

// loadLibrary 加载 PKCS#11 动态库（Linux/macOS/BSD，基于 purego，无需 cgo）。
func loadLibrary(path string) (uintptr, error) {
	h, err := purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		return 0, err
	}
	if h == 0 {
		return 0, fmt.Errorf("dlopen 返回空句柄")
	}
	return h, nil
}

// lookupSymbol 获取导出符号地址。
func lookupSymbol(handle uintptr, name string) (uintptr, error) {
	return purego.Dlsym(handle, name)
}

// releaseLibrary 卸载动态库。
func releaseLibrary(handle uintptr) {
	if handle != 0 {
		_ = purego.Dlclose(handle)
	}
}
