//go:build windows

package tpmsc

import (
	"fmt"
	"strings"
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
	procSCardListReaders  = winscardDLL.NewProc("SCardListReadersW")
)

// GetTPMStatus 通过 TBS 读取本机 TPM 版本。失败时返回 Available=false 与原因。
func GetTPMStatus() (*TPMStatus, error) {
	if err := procTbsiGetDeviceInfo.Find(); err != nil {
		if name, ok := findVSCReader(); ok {
			return &TPMStatus{Available: true, Version: "2.0 (VSC " + name + ")", Admin: IsRunningAsAdmin()}, nil
		}
		return &TPMStatus{Available: false, Admin: IsRunningAsAdmin()}, fmt.Errorf("系统未提供 TBS 接口，且未发现 TPM 虚拟读卡器")
	}
	info := tpmDeviceInfo{StructSize: uint32(unsafe.Sizeof(tpmDeviceInfo{}))}
	result, _, _ := procTbsiGetDeviceInfo.Call(
		uintptr(info.StructSize),
		uintptr(unsafe.Pointer(&info)),
	)
	if result == 0 {
		// 本机可能缺少 TBS 服务但 TPM 与 VSC 仍然可用（实测 Win10 VM 存在这种情况）。
		// 已发布的 TPM 虚拟读卡器是 TPM 可用的直接证据。
		if name, ok := findVSCReader(); ok {
			return &TPMStatus{Available: true, Version: "2.0 (VSC " + name + ")", Admin: IsRunningAsAdmin()}, nil
		}
		return &TPMStatus{Available: false, Admin: IsRunningAsAdmin()}, fmt.Errorf("读取 TPM 状态失败（TBS 不可用，且未发现 TPM 虚拟读卡器）")
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

// findVSCReader 通过 PC/SC 查找已发布的 TPM 虚拟智能卡读卡器。
func findVSCReader() (string, bool) {
	var ctx uintptr
	if r, _, _ := procSCardEstablishContext.Call(scardScopeUser, 0, 0, uintptr(unsafe.Pointer(&ctx))); uint32(r) != scardSuccess {
		return "", false
	}
	defer procSCardReleaseContext.Call(ctx)

	var needed uint32
	if r, _, _ := procSCardListReaders.Call(ctx, 0, 0, uintptr(unsafe.Pointer(&needed))); uint32(r) != scardSuccess || needed == 0 {
		return "", false
	}
	buf := make([]uint16, needed)
	if r, _, _ := procSCardListReaders.Call(ctx, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&needed))); uint32(r) != scardSuccess {
		return "", false
	}
	// 多字符串：reader\0reader\0\0
	start := 0
	for i, v := range buf {
		if v != 0 {
			continue
		}
		if i == start {
			break
		}
		name := windows.UTF16ToString(buf[start:i])
		start = i + 1
		if strings.Contains(strings.ToLower(name), "virtual smart card") {
			return name, true
		}
	}
	return "", false
}
