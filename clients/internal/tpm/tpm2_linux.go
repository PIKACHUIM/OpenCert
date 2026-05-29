//go:build linux

// Package tpm - Linux 默认后端。
//
// 当前阶段：直接复用 SoftwareStub。
// 后续将在此接入 github.com/google/go-tpm + /dev/tpmrm0 实现真 TPM2。
package tpm

func newPlatformProvider() (Provider, error) {
	return NewSoftwareStub()
}
