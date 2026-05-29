//go:build darwin && !cgo

// Package tpm - macOS 无 CGO 退化后端：直接复用 SoftwareStub。
package tpm

func newPlatformProvider() (Provider, error) {
	return NewSoftwareStub()
}
