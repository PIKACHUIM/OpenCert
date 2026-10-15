//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// registerPKCS11Mock 通过 modutil 把驱动注册到 NSS 数据库（Firefox / Chromium 使用）。
func registerPKCS11Mock() (string, error) {
	lib, err := findPKCS11Library()
	if err != nil {
		return "", err
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("获取用户目录失败: %w", err)
	}

	dbdir := filepath.Join(home, ".pki", "nssdb")
	if err := os.MkdirAll(dbdir, 0o700); err != nil {
		return "", fmt.Errorf("创建目录失败: %w", err)
	}

	cmd := exec.Command("modutil",
		"-add", "OpenCert",
		"-libfile", lib,
		"-dbdir", "sql:"+dbdir,
		"-force",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		detail := strings.TrimSpace(string(out))
		if detail == "" {
			detail = err.Error()
		}
		return "", fmt.Errorf("modutil 注册失败（需安装 libnss3-tools）：%s", detail)
	}
	return "已注册 PKCS#11 驱动：" + lib, nil
}

// openPath 用系统默认程序打开文件或目录。
func openPath(path string) error {
	return exec.Command("xdg-open", path).Start()
}

// openURL 用系统默认浏览器打开链接。
func openURL(u string) error {
	return exec.Command("xdg-open", u).Start()
}
