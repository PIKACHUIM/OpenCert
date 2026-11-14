//go:build darwin && !cgo

// Package tpm - macOS 无 CGO 默认后端；Secure Enclave Provider 尚未接入。
package tpm

func newPlatformProvider() (Provider, error) {
	return nil, ErrNotAvailable
}
