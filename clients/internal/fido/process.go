package fido

import (
	"context"
	"fmt"
	"os/exec"
	"sync"
)

// Process 是受管的 fido-go.exe 进程。
type Process struct {
	cmd  *exec.Cmd
	once sync.Once
}

// StartProcess 启动 fido-go.exe；调用方负责在退出时 Stop。
func StartProcess(ctx context.Context, exePath string) (*Process, error) {
	if exePath == "" {
		return nil, fmt.Errorf("fido-go.exe 路径为空")
	}
	cmd := exec.Command(exePath)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("启动 fido-go.exe 失败: %w", err)
	}
	go func() {
		<-ctx.Done()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}()
	go func() { _ = cmd.Wait() }()
	return &Process{cmd: cmd}, nil
}

// Stop 结束进程，可重复调用。
func (p *Process) Stop() {
	p.once.Do(func() {
		if p.cmd.Process != nil {
			_ = p.cmd.Process.Kill()
		}
	})
}
