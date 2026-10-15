//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"
)

// registerPKCS11Mock 通过 regsvr32 把 pkcs11-mock.dll 注册到系统。
// 该操作需要管理员权限，权限不足时返回带指引的错误。
func registerPKCS11Mock() (string, error) {
	lib, err := findPKCS11Library()
	if err != nil {
		return "", err
	}

	cmd := exec.Command("regsvr32", "/s", lib)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		detail := strings.TrimSpace(string(out))
		if detail == "" {
			detail = err.Error()
		}
		return "", fmt.Errorf("regsvr32 注册失败（请以管理员身份运行）：%s", detail)
	}
	return "已注册 PKCS#11 驱动：" + lib, nil
}

// openPath 用资源管理器打开文件或目录。
func openPath(path string) error {
	return exec.Command("cmd", "/c", "start", "", path).Start()
}

// openURL 用系统默认浏览器打开链接。
func openURL(u string) error {
	return exec.Command("rundll32", "url.dll,FileProtocolHandler", u).Start()
}
