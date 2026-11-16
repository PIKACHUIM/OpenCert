//go:build !windows

package tpmsc

import "context"

// ChangePIN 在非 Windows 平台不可用。
func ChangePIN(context.Context, string, string, string) error {
	return ErrPINBackendUnavailable
}

// UnblockPIN 在非 Windows 平台不可用。
func UnblockPIN(context.Context, string, string, string) error {
	return ErrPINBackendUnavailable
}
