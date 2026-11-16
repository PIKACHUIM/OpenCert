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
