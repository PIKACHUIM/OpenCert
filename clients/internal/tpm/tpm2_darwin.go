//go:build darwin && cgo

// Package tpm - macOS 默认后端（CGO 启用时）。
//
// 当前阶段：直接复用 SoftwareStub。
// 后续可改为 Secure Enclave / Keychain（需要 Apple Developer ID 与 Hardened Runtime）。
package tpm

func newPlatformProvider() (Provider, error) {
	return NewSoftwareStub()
}
