// Package appcore 提供应用程序核心逻辑，管理全局状态和生命周期。
package appcore

import (
	"context"
	"fmt"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/dialog"

	"github.com/globaltrusts/native-client/internal/api"
	"github.com/globaltrusts/native-client/internal/backend"
	"github.com/globaltrusts/native-client/internal/config"
	"github.com/globaltrusts/native-client/internal/i18n"
)

// State 应用状态
type State int

const (
	StateDisconnected State = iota // 未连接
	StateConnecting               // 连接中
	StateConnected                // 已连接（已登录）
	StateBackendOffline           // 后端离线
)

// App 应用程序核心
type App struct {
	fyneApp fyne.App
	window  fyne.Window
	client  *api.Client
	backend *backend.Process
	state   State
	token   *api.AuthToken
	mu      sync.RWMutex

	// 状态变更回调
	onStateChange []func(State)
}

// New 创建应用实例
func New(fyneApp fyne.App) *App {
	cfg := config.Get()
	proc := backend.NewProcess()
	proc.AutoDetectBinPath()

	return &App{
		fyneApp: fyneApp,
		client:  api.NewClient(cfg.BackendURL),
		backend: proc,
		state:   StateDisconnected,
	}
}

// StartBackend 启动后端进程
func (a *App) StartBackend(ctx context.Context) error {
	if a.backend == nil {
		return fmt.Errorf("后端进程管理器未初始化")
	}
	return a.backend.Start(ctx)
}

// StopBackend 停止后端进程
func (a *App) StopBackend() error {
	if a.backend == nil {
		return nil
	}
	return a.backend.Stop()
}

// BackendState 获取后端进程状态
func (a *App) BackendState() backend.State {
	if a.backend == nil {
		return backend.StateStopped
	}
	return a.backend.State()
}

// FyneApp 返回底层的fyne.App实例
func (a *App) FyneApp() fyne.App {
	return a.fyneApp
}

// SetWindow 设置主窗口
func (a *App) SetWindow(w fyne.Window) {
	a.window = w
}

// Client 获取 API 客户端
func (a *App) Client() *api.Client {
	return a.client
}

// State 获取当前状态
func (a *App) State() State {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.state
}

// Token 获取当前认证令牌
func (a *App) Token() *api.AuthToken {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.token
}

// IsLoggedIn 是否已登录
func (a *App) IsLoggedIn() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.state == StateConnected && a.token != nil
}

// OnStateChange 注册状态变更回调
func (a *App) OnStateChange(fn func(State)) {
	a.onStateChange = append(a.onStateChange, fn)
}

// setState 设置状态并通知
func (a *App) setState(s State) {
	a.mu.Lock()
	a.state = s
	a.mu.Unlock()
	for _, fn := range a.onStateChange {
		fn(s)
	}
}

// CheckBackend 检查后端状态
func (a *App) CheckBackend() {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_, err := a.client.Health(ctx)
		if err != nil {
			a.setState(StateBackendOffline)
		} else if a.token == nil {
			a.setState(StateDisconnected)
		}
		// 如果已登录，保持 StateConnected
	}()
}

// Connect 连接后端（检查健康状态）
func (a *App) Connect() error {
	a.setState(StateConnecting)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := a.client.Health(ctx)
	if err != nil {
		a.setState(StateBackendOffline)
		return err
	}

	a.setState(StateDisconnected)
	return nil
}

// Login 本地登录
func (a *App) Login(username, password string) error {
	a.setState(StateConnecting)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	token, err := a.client.Login(ctx, &api.LoginRequest{
		Username: username,
		Password: password,
	})
	if err != nil {
		a.setState(StateDisconnected)
		return err
	}

	a.mu.Lock()
	a.token = token
	a.mu.Unlock()
	a.setState(StateConnected)
	return nil
}

// LoginWith2FA 本地登录（含2FA）
func (a *App) LoginWith2FA(username, password, totpCode string) error {
	a.setState(StateConnecting)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	token, err := a.client.Login(ctx, &api.LoginRequest{
		Username: username,
		Password: password,
		TOTPCode: totpCode,
	})
	if err != nil {
		a.setState(StateDisconnected)
		return err
	}

	a.mu.Lock()
	a.token = token
	a.mu.Unlock()
	a.setState(StateConnected)
	return nil
}

// CloudLogin 云端登录
func (a *App) CloudLogin(cloudURL, username, password string) error {
	a.setState(StateConnecting)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	token, err := a.client.CloudLogin(ctx, &api.CloudLoginRequest{
		CloudURL: cloudURL,
		Username: username,
		Password: password,
	})
	if err != nil {
		a.setState(StateDisconnected)
		return err
	}

	a.mu.Lock()
	a.token = token
	a.mu.Unlock()
	a.setState(StateConnected)
	return nil
}

// Logout 注销
func (a *App) Logout() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_ = a.client.Logout(ctx)
	a.mu.Lock()
	a.token = nil
	a.mu.Unlock()
	a.setState(StateDisconnected)
}

// ShowError 显示错误对话框
func (a *App) ShowError(err error) {
	if a.window != nil {
		dialog.ShowError(err, a.window)
	}
}

// ShowInfo 显示信息对话框
func (a *App) ShowInfo(title, message string) {
	if a.window != nil {
		dialog.ShowInformation(title, message, a.window)
	}
}

// UpdateBackendURL 更新后端地址
func (a *App) UpdateBackendURL(url string) {
	a.mu.Lock()
	a.client = api.NewClient(url)
	a.token = nil
	a.mu.Unlock()
	a.setState(StateDisconnected)
}

// StateText 状态文本
func (a *App) StateText() string {
	switch a.State() {
	case StateConnected:
		token := a.Token()
		if token != nil {
			loginType := i18n.T("card.local")
			if token.CloudURL != "" {
				loginType = token.CloudURL
			}
			user := token.Username
			if user == "" {
				user = token.CloudUser
			}
			return fmt.Sprintf("%s: %s [%s]", i18n.T("tray.connected"), user, loginType)
		}
		return i18n.T("tray.connected")
	case StateConnecting:
		return i18n.T("app.connecting")
	case StateBackendOffline:
		return i18n.T("tray.backend_offline")
	default:
		return i18n.T("tray.disconnected")
	}
}
