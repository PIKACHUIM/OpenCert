// Package tpmsc provides secure TPM Virtual Smart Card lifecycle management on Windows.
// Smart Card KSP, PKCS#11 token operations and PIN/PUK management remain unsupported.
//
// 参考文档：
//   - https://learn.microsoft.com/en-us/windows/security/identity-protection/virtual-smart-cards/virtual-smart-card-deploy-virtual-smart-cards
//   - https://learn.microsoft.com/en-us/windows/security/identity-protection/virtual-smart-cards/virtual-smart-card-tpmvscmgr
package tpmsc

import (
	"bytes"
	"context"
	"encoding/hex"
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

// CreateCardArgs contains one-time credentials used only during VSC provisioning.
type CreateCardArgs struct {
	Name     string
	PIN      string
	PUK      string
	AdminKey string // 48 hexadecimal characters; never persisted or logged
}

// CreateCardResult contains non-secret VSC identity and discovery status.
type CreateCardResult struct {
	ReaderName string
	InstanceID string
	NeedReboot bool
}

// SmartCardKSPProviderName is the Windows CNG provider used for TPM VSC key containers.
const SmartCardKSPProviderName = "Microsoft Smart Card Key Storage Provider"

// SmartCardKSPContainerName builds the fully-qualified reader/container name used by CNG.
func SmartCardKSPContainerName(readerName, containerName string) string {
	return "\\\\.\\" + readerName + "\\" + containerName
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

// ErrProvisioningNotImplemented indicates the current platform has no VSC management backend.
var (
	ErrProvisioningNotImplemented = errors.New("当前平台未实现 TPM VSC 管理接口")
	ErrUserCancelled              = errors.New("TPM VSC 管理操作已取消")
	ErrRebootRequired             = errors.New("TPM VSC 操作已提交，需重启后完成")
	ErrReaderUnavailable          = errors.New("TPM VSC reader 当前不可用")
)

// ValidateCreateCardArgs validates secrets before the caller stores a provisioning intent.
func ValidateCreateCardArgs(args CreateCardArgs) error {
	if strings.TrimSpace(args.Name) == "" || strings.ContainsRune(args.Name, 0) {
		return fmt.Errorf("虚拟智能卡名称不能为空或包含 NUL")
	}
	if err := ValidatePIN(args.PIN, DefaultPINPolicy()); err != nil {
		return err
	}
	if err := validatePrintableASCII(args.PIN, "PIN"); err != nil {
		return err
	}
	if args.PUK != "" {
		if err := ValidatePIN(args.PUK, DefaultPINPolicy()); err != nil {
			return fmt.Errorf("PUK 无效: %w", err)
		}
		if err := validatePrintableASCII(args.PUK, "PUK"); err != nil {
			return err
		}
	}
	adminKey, err := hex.DecodeString(args.AdminKey)
	if err != nil || len(adminKey) != 24 {
		return fmt.Errorf("AdminKey 必须是 48 位十六进制字符串（24 字节）")
	}
	defer zeroBytes(adminKey)
	if bytes.Equal(adminKey[:8], adminKey[8:16]) || bytes.Equal(adminKey[:8], adminKey[16:]) ||
		bytes.Equal(adminKey[8:16], adminKey[16:]) {
		return fmt.Errorf("AdminKey 必须使用三个不同的 8 字节密钥分组")
	}
	return nil
}

// CreateCard creates a TPM VSC through the platform management interface.
func CreateCard(ctx context.Context, args CreateCardArgs) (*CreateCardResult, error) {
	args.Name = strings.TrimSpace(args.Name)
	if err := ValidateCreateCardArgs(args); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return createCardPlatform(ctx, args)
}

func validatePrintableASCII(value, label string) error {
	for _, b := range []byte(value) {
		if b < 0x20 || b > 0x7e {
			return fmt.Errorf("%s 仅支持可打印 ASCII 字符", label)
		}
	}
	return nil
}

func zeroBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

// DestroyCard irreversibly destroys a TPM VSC; callers must require explicit user confirmation.
func DestroyCard(ctx context.Context, instanceID string) (bool, error) {
	if runtime.GOOS != "windows" {
		return false, fmt.Errorf("TPM Virtual Smart Card 仅支持 Windows 平台")
	}
	instanceID = strings.TrimSpace(instanceID)
	if !isValidInstanceID(instanceID) {
		return false, fmt.Errorf("无效的 TPM VSC 实例 ID")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return destroyCardPlatform(ctx, instanceID)
}

// DeleteCard destroys a VSC and reports when Windows has queued the operation for reboot.
func DeleteCard(ctx context.Context, instanceID string) error {
	needReboot, err := DestroyCard(ctx, instanceID)
	if err != nil {
		return err
	}
	if needReboot {
		return ErrRebootRequired
	}
	return nil
}

// DiscoverReaderName resolves a VSC device instance ID to its current Smart Card reader name.
func DiscoverReaderName(ctx context.Context, instanceID string) (string, error) {
	instanceID = strings.TrimSpace(instanceID)
	if !isValidInstanceID(instanceID) {
		return "", fmt.Errorf("无效的 TPM VSC 实例 ID")
	}
	return discoverReaderNamePlatform(ctx, instanceID)
}

func isValidInstanceID(value string) bool {
	return strings.HasPrefix(strings.ToUpper(strings.TrimSpace(value)), "ROOT\\SMARTCARDREADER\\") &&
		strings.Count(value, "\\") == 2
}

// IsAvailable reports whether the Windows VSC management backend is compiled in.
// It does not verify TPM readiness, administrator approval, or Smart Card KSP support.
func IsAvailable() bool {
	return runtime.GOOS == "windows"
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
