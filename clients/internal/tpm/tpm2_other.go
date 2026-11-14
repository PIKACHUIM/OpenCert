//go:build !linux && !windows && !darwin

// Package tpm - 其它平台尚未接入真实 TPM Provider。
package tpm

func newPlatformProvider() (Provider, error) {
	return nil, ErrNotAvailable
}
