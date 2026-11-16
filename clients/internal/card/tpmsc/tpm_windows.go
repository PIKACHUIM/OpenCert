//go:build windows

package tpmsc

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TPMStatus 描述本机 TPM 的可用状态。
type TPMStatus struct {
	Available     bool
	Version       string
	InterfaceType uint32
	Admin         bool
}

type tpmDeviceInfo struct {
	StructSize    uint32
	Version       uint32
	InterfaceType uint32
	ImpRevision   uint32
}

var (
	tbsDLL                = windows.NewLazySystemDLL("tbs.dll")
	procTbsiGetDeviceInfo = tbsDLL.NewProc("Tbsi_GetDeviceInfo")
)

// GetTPMStatus 通过 TBS 读取本机 TPM 版本。失败时返回 Available=false 与原因。
func GetTPMStatus() (*TPMStatus, error) {
	if err := procTbsiGetDeviceInfo.Find(); err != nil {
		return &TPMStatus{Available: false, Admin: IsRunningAsAdmin()}, fmt.Errorf("系统未提供 TBS 接口，无法读取 TPM 状态")
	}
	info := tpmDeviceInfo{StructSize: uint32(unsafe.Sizeof(tpmDeviceInfo{}))}
	result, _, _ := procTbsiGetDeviceInfo.Call(
		uintptr(info.StructSize),
		uintptr(unsafe.Pointer(&info)),
	)
	if result == 0 {
		return &TPMStatus{Available: false, Admin: IsRunningAsAdmin()}, fmt.Errorf("读取 TPM 状态失败（TBS 返回 0）")
	}
	major := byte(info.Version)
	minor := byte(info.Version >> 8)
	return &TPMStatus{
		Available:     true,
		Version:       fmt.Sprintf("%d.%d", major, minor),
		InterfaceType: info.InterfaceType,
		Admin:         IsRunningAsAdmin(),
	}, nil
}
