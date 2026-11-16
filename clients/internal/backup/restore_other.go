//go:build !windows

package backup

import (
	"context"
	"errors"
)

// RestoreFiles 在非 Windows 平台不可用。
func RestoreFiles(context.Context, map[string][]byte) error {
	return errors.New("当前平台不支持 TPM VSC 还原")
}

// Diagnosis 是还原后的三层自检结果。
type Diagnosis struct {
	DeviceRegistry bool
	PCPKeyCount    int
	StoreFileCount int
	DPAPIError     string
}

// Diagnose 在非 Windows 平台返回空结果。
func Diagnose() Diagnosis { return Diagnosis{} }
