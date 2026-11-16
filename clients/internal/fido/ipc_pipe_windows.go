//go:build windows

package fido

import (
	"context"
	"errors"
	"fmt"

	"github.com/Microsoft/go-winio"
)

// PipeName 是 fido-go.exe 连接的命名管道。
const PipeName = `\\.\pipe\TPMFIDO`

// Listen 在 \\.\pipe\TPMFIDO 上处理 fido-go 的请求，直到 ctx 取消。
func Listen(ctx context.Context, handler Handler) error {
	ln, err := winio.ListenPipe(PipeName, nil)
	if err != nil {
		return fmt.Errorf("监听 %s 失败（可能已有其它 FIDO 服务占用）: %w", PipeName, err)
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
		go func() { _ = Serve(conn, handler) }()
	}
}
