//go:build !windows

package fido

import (
	"context"
	"errors"
)

// Listen 在非 Windows 平台不可用。
func Listen(context.Context, Handler) error {
	return errors.New("当前平台未实现 FIDO IPC 管道")
}
