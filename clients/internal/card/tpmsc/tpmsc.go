// Package tpmsc 封装 Microsoft TPM Virtual Smart Card（tpmvscmgr.exe）的管理操作。
//
// Microsoft TPM Virtual Smart Card 利用 Windows TPM 芯片创建虚拟智能卡，
// 密钥由 TPM 硬件保护，永远不可导出。
//
// 参考文档：
//   - https://learn.microsoft.com/en-us/windows/security/identity-protection/virtual-smart-cards/virtual-smart-card-deploy-virtual-smart-cards
//   - https://learn.microsoft.com/en-us/windows/security/identity-protection/virtual-smart-cards/virtual-smart-card-tpmvscmgr
package tpmsc

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"runtime"
	"strings"
	"time"
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

// CreateCardResult 是创建结果。
type CreateCardResult struct {
	// ReaderName 是创建的虚拟智能卡读卡器名称
	ReaderName string
	// AdminKey 是管理密钥（DEFAULT 模式为 48 字节全 0x01-0x08 循环）
	AdminKey string
	// PUK 是 PUK 解锁码（DEFAULT 模式为 12345678）
	PUK string
	// PIN 是初始 PIN 码（DEFAULT 模式为 12345678）
	PIN string
	// InstanceID 是虚拟智能卡实例 ID（从 tpmvscmgr 输出解析）
	InstanceID string
	// Output 是 tpmvscmgr.exe 的命令行输出（用于调试）
	Output string
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

// CreateCard 调用 tpmvscmgr.exe 创建 Microsoft TPM Virtual Smart Card。
// 仅在 Windows 平台可用，且需要管理员权限。
//
// 注意：tpmvscmgr.exe 的 PROMPT 模式会弹出 Windows GUI 对话框，不支持 stdin pipe。
// 因此使用 DEFAULT 模式创建（PIN=12345678, AdminKey=48个FF, PUK=12345678），
// 创建成功后用户需要通过 Windows 智能卡管理修改 PIN。
//
// 命令格式：
//
//	tpmvscmgr.exe create /name <name> /AdminKey DEFAULT /PIN DEFAULT /PUK DEFAULT /generate
func CreateCard(ctx context.Context, args CreateCardArgs) (*CreateCardResult, error) {
	if runtime.GOOS != "windows" {
		return nil, fmt.Errorf("TPM Virtual Smart Card 仅支持 Windows 平台")
	}
	if !IsRunningAsAdmin() {
		return nil, fmt.Errorf("创建 TPM Virtual Smart Card 需要管理员权限，请以管理员身份运行程序")
	}

	if args.Name == "" {
		return nil, fmt.Errorf("虚拟智能卡名称不能为空")
	}

	result := &CreateCardResult{
		ReaderName: args.Name,
		// DEFAULT 模式的默认值
		AdminKey: "010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708", // 48 字节默认 AdminKey
		PUK:      "12345678",
		PIN:      "12345678",
	}

	// 为命令执行设置 120 秒超时（tpmvscmgr.exe 可能需要较长时间）
	cmdCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	// 直接调用 tpmvscmgr.exe，由 Go 的 os/exec 负责将含空格的 name 参数正确转义。
	// 不再使用 `cmd /c "chcp 65001 && tpmvscmgr ..."`，因为 cmd /c 在嵌套引号场景下
	// 会吞掉内层引号，导致 `/name "My Card"` 变成 `/name My Card`，从而出现类似
	// "Unknown parameter: Card" 的错误。
	cmdArgs := []string{
		"create",
		"/name", args.Name,
		"/AdminKey", "DEFAULT",
		"/PIN", "DEFAULT",
		"/PUK", "DEFAULT",
		"/generate",
	}
	cmd := exec.CommandContext(cmdCtx, "tpmvscmgr.exe", cmdArgs...)

	log.Printf("[TPMSC] 执行命令: tpmvscmgr.exe %s", strings.Join(cmdArgs, " "))

	// 直接获取输出（DEFAULT 模式无需 stdin 交互）
	output, err := cmd.CombinedOutput()
	combinedOutput := string(output)
	log.Printf("[TPMSC] 命令输出:\n%s", combinedOutput)

	if err != nil {
		if cmdCtx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("执行 tpmvscmgr.exe 超时（120秒）\n输出: %s", combinedOutput)
		}
		return nil, fmt.Errorf("执行 tpmvscmgr.exe 失败: %w\n输出: %s", err, combinedOutput)
	}

	// 解析输出获取实例 ID
	result.InstanceID = parseInstanceID(combinedOutput)
	result.Output = combinedOutput

	log.Printf("[TPMSC] 创建成功: ReaderName=%s, InstanceID=%s", result.ReaderName, result.InstanceID)
	return result, nil
}

// DeleteCard 删除 TPM Virtual Smart Card。
func DeleteCard(ctx context.Context, instanceID string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("TPM Virtual Smart Card 仅支持 Windows 平台")
	}
	if instanceID == "" {
		return fmt.Errorf("实例 ID 不能为空")
	}

	cmd := exec.CommandContext(ctx, "tpmvscmgr.exe", "destroy", "/instance", instanceID)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("删除虚拟智能卡失败: %w\n输出: %s", err, string(output))
	}
	return nil
}

// IsAvailable 检查当前系统是否支持 TPM Virtual Smart Card。
// 需要 Windows 平台且 tpmvscmgr.exe 可用。
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

// parseInstanceID 从 tpmvscmgr.exe 输出中解析实例 ID。
// 输出格式示例：
//
//	TpmVscMgr.exe: Successfully created virtual smart card.
//	Device Instance ID: ROOT\SMARTCARDREADER\0000
func parseInstanceID(output string) string {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(strings.ToLower(line), "device instance id") ||
			strings.Contains(strings.ToLower(line), "instance id") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}
