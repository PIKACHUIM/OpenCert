//go:build !linux && !windows && !darwin

// Package tpm - 其它平台：复用 SoftwareStub，保证可用。
package tpm

func newPlatformProvider() (Provider, error) {
	return NewSoftwareStub()
}
