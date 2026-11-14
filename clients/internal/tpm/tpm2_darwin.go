//go:build darwin && cgo

// Package tpm - macOS 默认后端（CGO 启用时）；Secure Enclave Provider 尚未接入。
package tpm

func newPlatformProvider() (Provider, error) {
	return nil, ErrNotAvailable
}
