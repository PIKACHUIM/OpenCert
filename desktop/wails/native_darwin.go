//go:build darwin

package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

// registerPKCS11Mock 把驱动复制到 macOS 的 tokend 目录（尽力而为，失败不阻断使用）。
func registerPKCS11Mock() (string, error) {
	lib, err := findPKCS11Library()
	if err != nil {
		return "", err
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("获取用户目录失败: %w", err)
	}

	destDir := filepath.Join(home, "Library", "Security", "tokend")
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return "", fmt.Errorf("创建目录失败: %w", err)
	}

	dest := filepath.Join(destDir, filepath.Base(lib))
	if err := copyFile(lib, dest); err != nil {
		return "", fmt.Errorf("复制驱动失败: %w", err)
	}
	return "已复制 PKCS#11 驱动到：" + dest, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

// openPath 用访达打开文件或目录。
func openPath(path string) error {
	return exec.Command("open", path).Start()
}

// openURL 用系统默认浏览器打开链接。
func openURL(u string) error {
	return exec.Command("open", u).Start()
}
