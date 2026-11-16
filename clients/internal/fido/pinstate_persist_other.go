//go:build !windows

package fido

// NewPersistentPINState 在非 Windows 平台退化为内存状态。
func NewPersistentPINState(string) *PINState { return NewPINState(nil) }
