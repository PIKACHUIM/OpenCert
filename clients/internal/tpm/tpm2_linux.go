//go:build linux

// Package tpm - Linux 默认后端；真实 TPM2 /dev/tpmrm0 Provider 尚未接入。
package tpm

func newPlatformProvider() (Provider, error) {
	return nil, ErrNotAvailable
}
