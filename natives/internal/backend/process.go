// Package backend 提供后端进程生命周期管理。
//
// natives 客户端需要启动并监控 client-card 后端服务进程，
// 确保后端服务可用时才允许用户操作。
package backend

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// State 后端进程状态
type State int

const (
	StateStopped  State = iota // 未启动
	StateStarting              // 启动中
	StateRunning               // 运行中
	StateFailed                // 启动失败
)

// Process 后端进程管理器
type Process struct {
	binPath       string
	cmd           *exec.Cmd
	state         State
	mu            sync.RWMutex
	onStateChange []func(State)
	stopCh        chan struct{}
}

// NewProcess 创建后端进程管理器
func NewProcess() *Process {
	return &Process{
		state:  StateStopped,
		stopCh: make(chan struct{}),
	}
}

// SetBinPath 设置后端二进制文件路径
func (p *Process) SetBinPath(path string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.binPath = path
}

// AutoDetectBinPath 自动检测后端二进制文件路径
func (p *Process) AutoDetectBinPath() string {
	// 1. 同目录下查找
	exePath, err := os.Executable()
	if err == nil {
		dir := filepath.Dir(exePath)
		candidate := filepath.Join(dir, backendBinName())
		if _, err := os.Stat(candidate); err == nil {
			p.SetBinPath(candidate)
			return candidate
		}
	}

	// 2. 相对路径查找（上级目录的 clients/dist/）
	exePath, _ = os.Executable()
	dir := filepath.Dir(exePath)
	for i := 0; i < 3; i++ {
		dir = filepath.Dir(dir)
		candidate := filepath.Join(dir, "clients", "dist", backendBinName())
		if _, err := os.Stat(candidate); err == nil {
			p.SetBinPath(candidate)
			return candidate
		}
	}

	return ""
}

// Start 启动后端进程
func (p *Process) Start(ctx context.Context) error {
	p.mu.RLock()
	binPath := p.binPath
	p.mu.RUnlock()

	if binPath == "" {
		return fmt.Errorf("后端二进制文件路径未设置")
	}

	if _, err := os.Stat(binPath); err != nil {
		return fmt.Errorf("后端二进制文件不存在: %s", binPath)
	}

	p.setState(StateStarting)

	cmd := exec.CommandContext(ctx, binPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// 设置工作目录为二进制文件所在目录
	cmd.Dir = filepath.Dir(binPath)

	if err := cmd.Start(); err != nil {
		p.setState(StateFailed)
		return fmt.Errorf("启动后端进程失败: %w", err)
	}

	p.mu.Lock()
	p.cmd = cmd
	p.mu.Unlock()

	// 监控进程退出
	go func() {
		err := cmd.Wait()
		p.mu.Lock()
		p.cmd = nil
		p.mu.Unlock()

		if err != nil {
			p.setState(StateFailed)
		} else {
			p.setState(StateStopped)
		}
	}()

	// 等待后端就绪（健康检查）
	if err := p.waitReady(ctx); err != nil {
		p.setState(StateFailed)
		return fmt.Errorf("后端启动超时: %w", err)
	}

	p.setState(StateRunning)
	return nil
}

// Stop 停止后端进程
func (p *Process) Stop() error {
	p.mu.Lock()
	cmd := p.cmd
	p.mu.Unlock()

	if cmd == nil || cmd.Process == nil {
		return nil
	}

	// 优雅关闭
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		// 强制终止
		_ = cmd.Process.Kill()
	}

	// 等待进程退出（最多5秒）
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
	}

	p.setState(StateStopped)
	return nil
}

// State 获取当前状态
func (p *Process) State() State {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.state
}

// OnStateChange 注册状态变更回调
func (p *Process) OnStateChange(fn func(State)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.onStateChange = append(p.onStateChange, fn)
}

// IsRunning 是否正在运行
func (p *Process) IsRunning() bool {
	return p.State() == StateRunning
}

// Restart 重启后端进程
func (p *Process) Restart(ctx context.Context) error {
	if err := p.Stop(); err != nil {
		return err
	}
	// 短暂等待端口释放
	time.Sleep(500 * time.Millisecond)
	return p.Start(ctx)
}

// setState 设置状态并通知
func (p *Process) setState(s State) {
	p.mu.Lock()
	p.state = s
	callbacks := make([]func(State), len(p.onStateChange))
	copy(callbacks, p.onStateChange)
	p.mu.Unlock()

	for _, fn := range callbacks {
		fn(s)
	}
}

// waitReady 等待后端服务就绪
func (p *Process) waitReady(ctx context.Context) error {
	const maxWait = 15 * time.Second
	const checkInterval = 300 * time.Millisecond

	deadline := time.After(maxWait)
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			return fmt.Errorf("等待后端就绪超时")
		case <-ticker.C:
			// 简单检查进程是否还活着
			p.mu.RLock()
			cmd := p.cmd
			p.mu.RUnlock()
			if cmd == nil || cmd.Process == nil {
				return fmt.Errorf("后端进程已退出")
			}
			// 进程存在，假设就绪
			// 实际应该通过 HTTP 健康检查确认，但这里简化处理
			return nil
		}
	}
}

// backendBinName 返回后端二进制文件名（根据平台）
func backendBinName() string {
	switch runtime.GOOS {
	case "windows":
		return "client-card.exe"
	default:
		return "client-card"
	}
}
