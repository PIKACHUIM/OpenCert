//go:build windows

package backup

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	advapi32DLL             = windows.NewLazySystemDLL("advapi32.dll")
	procImpersonateLoggedOn = advapi32DLL.NewProc("ImpersonateLoggedOnUser")
	procRevertToSelf        = advapi32DLL.NewProc("RevertToSelf")
)

// withSystemToken 临时借用 SYSTEM 身份执行 fn，用于解开 LocalService 写入的 DPAPI blob。
//
// 需要管理员权限；借用前启用 SeDebugPrivilege，借用后立即 RevertToSelf。
func withSystemToken(fn func() error) error {
	pid, err := findProcess("winlogon.exe")
	if err != nil {
		return err
	}
	proc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return fmt.Errorf("打开 winlogon 进程失败（需要管理员权限）: %w", err)
	}
	defer windows.CloseHandle(proc)

	var token windows.Token
	if err := windows.OpenProcessToken(proc, windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY, &token); err != nil {
		return fmt.Errorf("打开 winlogon 令牌失败: %w", err)
	}
	defer token.Close()

	var dup windows.Token
	if err := windows.DuplicateTokenEx(token, windows.TOKEN_ALL_ACCESS, nil,
		windows.SecurityImpersonation, windows.TokenImpersonation, &dup); err != nil {
		return fmt.Errorf("复制 SYSTEM 令牌失败: %w", err)
	}
	defer dup.Close()

	if result, _, _ := procImpersonateLoggedOn.Call(uintptr(dup)); result == 0 {
		return fmt.Errorf("切换到 SYSTEM 身份失败")
	}
	defer procRevertToSelf.Call()
	return fn()
}

func findProcess(name string) (uint32, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, fmt.Errorf("枚举进程失败: %w", err)
	}
	defer windows.CloseHandle(snapshot)
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snapshot, &entry); err != nil {
		return 0, fmt.Errorf("枚举进程失败: %w", err)
	}
	for {
		if windows.UTF16ToString(entry.ExeFile[:]) == name {
			return entry.ProcessID, nil
		}
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			return 0, fmt.Errorf("未找到 %s 进程", name)
		}
	}
}
