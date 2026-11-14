// Package tpmsc 提供 Microsoft TPM Virtual Smart Card（tpmvscmgr.exe）的受限管理帮助。
// 当前版本未实现安全交互凭据创建与 Windows CNG/CAPI 密码学 Provider，
// 因此不会创建或宣称可用的 TPM VSC。
//
// 参考文档：
//   - https://learn.microsoft.com/en-us/windows/security/identity-protection/virtual-smart-cards/virtual-smart-card-deploy-virtual-smart-cards
//   - https://learn.microsoft.com/en-us/windows/security/identity-protection/virtual-smart-cards/virtual-smart-card-tpmvscmgr
package tpmsc

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// PINPolicy 定义 PIN 策略配置。
// 参考 Microsoft 文档最低要求：最小长度 8，最大长度 127。
type PINPolicy struct {
	MinLen       int  // 最小 PIN 长度（默认 8）
	MaxLen       int  // 最大 PIN 长度（默认 127）
	UpperCase    bool // 允许大写字母
	LowerCase    bool // 允许小写字母
	Digits       bool // 允许数字
	SpecialChars bool // 允许特殊字符
}

// DefaultPINPolicy 返回 Microsoft 推荐的默认 PIN 策略。
func DefaultPINPolicy() PINPolicy {
	return PINPolicy{
		MinLen:       8,
		MaxLen:       127,
		UpperCase:    true,
		LowerCase:    true,
		Digits:       true,
		SpecialChars: true,
	}
}

// CreateCardArgs 是创建 TPM Virtual Smart Card 的参数。
type CreateCardArgs struct {
	// Name 是虚拟智能卡读卡器名称（必填）
	Name string
}

// CreateCardResult 是虚拟智能卡创建结果，不包含 PIN、PUK 或 AdminKey。
type CreateCardResult struct {
	ReaderName string
	InstanceID string
}

// ValidatePIN 验证 PIN 是否符合策略要求。
func ValidatePIN(pin string, policy PINPolicy) error {
	if len(pin) < policy.MinLen {
		return fmt.Errorf("PIN 长度不足：最少 %d 位，当前 %d 位", policy.MinLen, len(pin))
	}
	if len(pin) > policy.MaxLen {
		return fmt.Errorf("PIN 长度超限：最多 %d 位，当前 %d 位", policy.MaxLen, len(pin))
	}
	return nil
}

// ErrProvisioningNotImplemented 表示尚未实现安全的 VSC 凭据初始化与密码学接入。
var ErrProvisioningNotImplemented = errors.New("TPM VSC 安全创建尚未实现；未执行创建")

// CreateCard 在安全交互式 PIN/PUK/AdminKey 和 CNG/CAPI Provider 接入前拒绝创建。
func CreateCard(_ context.Context, args CreateCardArgs) (*CreateCardResult, error) {
	if strings.TrimSpace(args.Name) == "" {
		return nil, fmt.Errorf("虚拟智能卡名称不能为空")
	}
	return nil, ErrProvisioningNotImplemented
}

// DeleteCard 不可恢复地销毁指定 TPM VSC；只能由获得明确用户确认的管理流程调用。
// OpenCert 不会自动调用此函数，删除本地卡片记录也不会触发硬件销毁。
func DeleteCard(ctx context.Context, instanceID string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("TPM Virtual Smart Card 仅支持 Windows 平台")
	}
	instanceID = strings.TrimSpace(instanceID)
	if !strings.HasPrefix(strings.ToUpper(instanceID), "ROOT\\SMARTCARDREADER\\") ||
		strings.Count(instanceID, "\\") != 2 {
		return fmt.Errorf("无效的 TPM VSC 实例 ID")
	}

	cmd := exec.CommandContext(ctx, "tpmvscmgr.exe", "destroy", "/instance", instanceID)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("删除虚拟智能卡失败: %w\n输出: %s", err, string(output))
	}
	return nil
}

// IsAvailable 仅检查 tpmvscmgr.exe 是否可执行，不代表 TPM 就绪或 VSC 密码学能力已接入。
func IsAvailable() bool {
	if runtime.GOOS != "windows" {
		return false
	}
	_, err := exec.LookPath("tpmvscmgr.exe")
	return err == nil
}

// IsRunningAsAdmin 检查当前进程是否以管理员权限运行。
// 通过执行 "net session" 命令来判断——该命令仅在管理员权限下可成功执行。
func IsRunningAsAdmin() bool {
	if runtime.GOOS != "windows" {
		return false
	}
	cmd := exec.Command("net", "session")
	err := cmd.Run()
	return err == nil
}
