//go:build windows

package fido

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

// RuntimeStatus 描述本机 FIDO 虚拟设备运行环境。
type RuntimeStatus struct {
	DriverInstalled bool   `json:"driver_installed"`
	ExePath         string `json:"exe_path,omitempty"`
	Version         string `json:"version,omitempty"`
	Message         string `json:"message"`
}

// FindFIDOGo 在已知位置查找 fido-go.exe（参考项目 TPMSmartCard 随包分发）。
func FindFIDOGo() string {
	candidates := []string{}
	if custom := os.Getenv("OPENCERT_FIDO_EXE"); custom != "" {
		candidates = append(candidates, custom)
	}
	for _, base := range []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)"), os.Getenv("ProgramData")} {
		if base == "" {
			continue
		}
		candidates = append(candidates,
			filepath.Join(base, "TPMSmartCard", "Fido", "fido-go.exe"),
			filepath.Join(base, "TPMSmartCard", "fido-go.exe"),
		)
	}
	for _, base := range installLocations() {
		candidates = append(candidates,
			filepath.Join(base, "Fido", "fido-go.exe"),
			filepath.Join(base, "fido-go.exe"),
		)
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(dir, "Fido", "fido-go.exe"),
			filepath.Join(dir, "fido-go.exe"),
		)
	}
	for _, path := range candidates {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}
	return ""
}

// installLocations 从卸载表里读取 TPMSmartCard 的安装目录，覆盖自定义安装路径。
func installLocations() []string {
	roots := []struct {
		root registry.Key
		path string
	}{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`},
	}
	var out []string
	for _, r := range roots {
		k, err := registry.OpenKey(r.root, r.path, registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			continue
		}
		names, err := k.ReadSubKeyNames(-1)
		k.Close()
		if err != nil {
			continue
		}
		for _, name := range names {
			sub, err := registry.OpenKey(r.root, r.path+`\`+name, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			display, _, _ := sub.GetStringValue("DisplayName")
			location, _, _ := sub.GetStringValue("InstallLocation")
			sub.Close()
			if location == "" {
				continue
			}
			if strings.Contains(strings.ToLower(display), "tpmsmartcard") || strings.Contains(strings.ToLower(display), "tpm smart card") {
				out = append(out, location)
			}
		}
	}
	return out
}

// DriverInstalled 检查 usbip 虚拟总线驱动是否已安装（ROOT\VHCI_UDE 或 USBIPWIN\VHCI）。
func DriverInstalled() bool {
	for _, key := range []string{
		`SYSTEM\CurrentControlSet\Enum\ROOT\VHCI_UDE`,
		`SYSTEM\CurrentControlSet\Enum\USBIPWIN\VHCI`,
	} {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
		if err == nil {
			k.Close()
			return true
		}
	}
	return false
}

// Inspect 汇总 FIDO 运行环境，不修改系统。
func Inspect() RuntimeStatus {
	status := RuntimeStatus{DriverInstalled: DriverInstalled()}
	status.ExePath = FindFIDOGo()
	if !status.DriverInstalled {
		status.Message = "未安装 usbip 虚拟总线驱动（需先安装 TPMSmartCard 的 Fido/usbip 驱动）"
		return status
	}
	if status.ExePath == "" {
		status.Message = "未找到 fido-go.exe（可设置 OPENCERT_FIDO_EXE 指向它）"
		return status
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, status.ExePath, "-version").CombinedOutput()
	if err != nil {
		status.Message = fmt.Sprintf("fido-go.exe 无法运行: %v", err)
		return status
	}
	status.Version = strings.TrimSpace(string(out))
	status.Message = "环境就绪（驱动 + fido-go.exe）"
	return status
}
