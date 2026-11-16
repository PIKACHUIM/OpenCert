//go:build !windows

package tpmsc

import "fmt"

// TPMStatus 描述本机 TPM 的可用状态。
type TPMStatus struct {
	Available     bool
	Version       string
	InterfaceType uint32
	Admin         bool
}

// GetTPMStatus 在非 Windows 平台不可用。
func GetTPMStatus() (*TPMStatus, error) {
	return &TPMStatus{Available: false}, fmt.Errorf("当前平台不支持 TPM 状态检测")
}
