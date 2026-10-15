package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// pkcs11LibraryName 返回当前平台下 PKCS#11 驱动的文件名。
func pkcs11LibraryName() string {
	switch runtime.GOOS {
	case "windows":
		return "pkcs11-mock.dll"
	case "darwin":
		return "libpkcs11-mock.dylib"
	default:
		return "libpkcs11-mock.so"
	}
}

// findPKCS11Library 在可执行文件同级目录与常见构建产物目录中查找 PKCS#11 驱动。
func findPKCS11Library() (string, error) {
	name := pkcs11LibraryName()

	var dirs []string
	if exe, err := os.Executable(); err == nil {
		base := filepath.Dir(exe)
		dirs = append(dirs,
			base,
			filepath.Join(base, "drivers"),
			filepath.Join(base, "bin"),
			filepath.Join(base, "..", "drivers", "build", "Release"),
			filepath.Join(base, "..", "drivers", "build"),
		)
	}
	if wd, err := os.Getwd(); err == nil {
		dirs = append(dirs, wd)
	}

	for _, dir := range dirs {
		candidate := filepath.Join(dir, name)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("未找到 %s，请先构建 PKCS#11 驱动并放到程序同目录", name)
}
