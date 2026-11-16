//go:build !windows

package backup

import (
	"context"
	"errors"
)

// CollectCard 在非 Windows 平台不可用。
func CollectCard(context.Context, string) (map[string][]byte, *Manifest, error) {
	return nil, nil, errors.New("当前平台不支持 TPM VSC 备份")
}

// RestoreRegistry 在非 Windows 平台不可用。
func RestoreRegistry(context.Context, []byte) error {
	return errors.New("当前平台不支持 TPM VSC 注册表还原")
}
