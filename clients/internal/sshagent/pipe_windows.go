//go:build windows

package sshagent

import (
	"context"
	"errors"
	"fmt"

	"github.com/Microsoft/go-winio"
)

// PipeName 是 OpenSSH 客户端默认连接的命名管道。
const PipeName = `\\.\pipe\openssh-ssh-agent`

// Listen 在 OpenSSH 标准管道上提供服务，直到 ctx 取消。
func Listen(ctx context.Context, backend Backend) error {
	ln, err := winio.ListenPipe(PipeName, nil)
	if err != nil {
		return fmt.Errorf("监听 %s 失败（可能已有 ssh-agent 占用）: %w", PipeName, err)
	}
	defer ln.Close()
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, winio.ErrPipeListenerClosed) {
				return nil
			}
			return err
		}
		go func() { _ = Serve(conn, backend) }()
	}
}
