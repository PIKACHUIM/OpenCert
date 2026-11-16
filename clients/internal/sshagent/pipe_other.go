//go:build !windows

package sshagent

import (
	"context"
	"errors"
)

// Pipeline 在非 Windows 平台不可用。
func Listen(context.Context, Backend) error {
	return errors.New("当前平台未实现 SSH agent 管道")
}
