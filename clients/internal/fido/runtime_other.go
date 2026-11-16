//go:build !windows

package fido

// RuntimeStatus 描述本机 FIDO 虚拟设备运行环境。
type RuntimeStatus struct {
	DriverInstalled bool   `json:"driver_installed"`
	ExePath         string `json:"exe_path,omitempty"`
	Version         string `json:"version,omitempty"`
	Message         string `json:"message"`
}

// Inspect 在非 Windows 平台返回不可用。
func Inspect() RuntimeStatus {
	return RuntimeStatus{Message: "当前平台不支持 usbip 虚拟 FIDO 设备"}
}
