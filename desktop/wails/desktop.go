package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/globaltrusts/client-card/configs"
	"github.com/globaltrusts/client-card/pkg/app"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

const (
	appName          = "OpenCert Manager"
	singleInstanceID = "com.globaltrusts.opencert.manager"

	// backendStopWait 是退出/重启后端时等待 IPC 上未完成操作的最长时间。
	backendStopWait = 10 * time.Second
	// defaultAPIPort 与 clients/configs 的默认端口保持一致。
	defaultAPIPort = 1026
)

// Desktop 是 Wails 桌面端应用对象：负责内嵌后端生命周期、托盘与原生能力。
// 导出的方法会通过 Wails 绑定暴露给前端（window.go.main.Desktop.*）。
type Desktop struct {
	// ctx 为 Wails 运行时上下文，OnStartup 之后才可用。
	ctx context.Context

	mu         sync.Mutex
	backend    *app.Instance // 内嵌后端；连接已有服务时为 nil
	backendErr error
	apiURL     string // 实际使用的后端地址（内嵌或已存在的本地服务）
	external   bool   // true 表示连接的是本机已运行的其它 client-card 实例
	logFile    string

	proxy    *proxyHandler
	tray     *trayController
	quitting atomic.Bool
}

// NewDesktop 创建桌面端对象（此时尚未启动后端）。
func NewDesktop() *Desktop {
	return &Desktop{proxy: newProxyHandler()}
}

// ---- Wails 生命周期 ----

// onStartup 在 WebView 创建完成后调用：初始化日志、启动托盘与内嵌后端。
func (d *Desktop) onStartup(ctx context.Context) {
	d.ctx = ctx
	d.initLogger()

	// 托盘与后端并行启动：后端初始化（TPM 探测、数据库迁移等）可能耗时数百毫秒，
	// 期间窗口由反向代理返回的等待页兜底，不会白屏。
	d.tray = newTrayController(d)
	d.tray.start()

	go d.startBackend(ctx)
}

// onShutdown 在应用退出时调用：停止托盘与内嵌后端。
func (d *Desktop) onShutdown(context.Context) {
	d.quitting.Store(true)

	if d.tray != nil {
		d.tray.stop()
	}

	d.mu.Lock()
	inst := d.backend
	d.backend = nil
	d.mu.Unlock()

	if inst != nil {
		slog.Info("正在关闭内嵌后端...")
		inst.Stop(backendStopWait)
		slog.Info("内嵌后端已关闭")
	}
}

// onBeforeClose 拦截窗口关闭：托盘可用时最小化到托盘，否则真正退出。
func (d *Desktop) onBeforeClose(ctx context.Context) bool {
	if d.quitting.Load() {
		return false
	}
	// 托盘不可用时隐藏窗口会让用户无法再次唤起，此时按常规退出处理
	if d.tray == nil || !d.tray.available() {
		return false
	}
	runtime.WindowHide(ctx)
	return true
}

// onSecondInstance 在检测到第二个实例启动时调用（单实例锁），用于唤起已有窗口。
func (d *Desktop) onSecondInstance(options.SecondInstanceData) {
	d.showWindow()
}

// ---- 后端生命周期 ----

// startBackend 以同进程方式启动本地管理端，并把它挂到反向代理上。
// 若 Named Pipe / REST 端口已被其它 client-card 实例占用（二者都是单例资源），
// 则退化为直接连接该实例，保证桌面端在「服务常驻」场景下同样可用。
func (d *Desktop) startBackend(ctx context.Context) {
	inst, err := app.Start(ctx, app.Options{
		Version:   Version,
		Commit:    Commit,
		BuildTime: BuildTime,
	})
	if err == nil {
		d.mu.Lock()
		d.backend = inst
		d.backendErr = nil
		d.apiURL = inst.HTTPBaseURL()
		d.external = false
		d.mu.Unlock()

		d.attachProxy(inst.HTTPBaseURL())
		slog.Info("内嵌后端已就绪", "addr", inst.Addr())
		return
	}

	if baseURL, ok := detectRunningBackend(); ok {
		slog.Warn("内嵌后端启动失败，改为连接本机已有服务", "url", baseURL, "start_error", err)
		d.mu.Lock()
		d.backend = nil
		d.backendErr = nil
		d.apiURL = baseURL
		d.external = true
		d.mu.Unlock()

		d.attachProxy(baseURL)
		return
	}

	d.mu.Lock()
	d.backend = nil
	d.backendErr = err
	d.apiURL = ""
	d.external = false
	d.mu.Unlock()

	slog.Error("启动内嵌后端失败", "error", err)
	if d.tray != nil {
		d.tray.setStatus(false)
	}
}

// attachProxy 让 AssetServer 反向代理到指定后端，并刷新托盘状态。
func (d *Desktop) attachProxy(baseURL string) {
	if target, err := url.Parse(baseURL); err == nil {
		d.proxy.setTarget(target)
	}
	if d.tray != nil {
		d.tray.setStatus(true)
	}
}

// detectRunningBackend 探测本机是否已有可用的 client-card 服务。
// 配置文件不可读时回退到默认端口 1026。
func detectRunningBackend() (string, bool) {
	host := "127.0.0.1"
	port := defaultAPIPort
	if cfg, err := config.Load(""); err == nil {
		port = cfg.API.Port
		if h := cfg.API.Host; h != "" && h != "0.0.0.0" && h != "::" {
			host = h
		}
	}
	if port <= 0 {
		port = defaultAPIPort
	}
	baseURL := fmt.Sprintf("http://%s:%d", host, port)

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(baseURL + "/api/health")
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false
	}
	return baseURL, true
}

// initLogger 把默认日志输出重定向到数据目录下的日志文件。
// Wails 生产构建是 GUI 子系统，没有标准输出，日志必须落盘才可诊断。
func (d *Desktop) initLogger() {
	logDir := filepath.Join(filepath.Dir(config.ResolveConfigPath()), "logs")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return
	}

	logPath := filepath.Join(logDir, "desktop.log")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	d.mu.Lock()
	d.logFile = logPath
	d.mu.Unlock()

	// 同时写 stderr，便于 `go run` / `wails dev` 时在终端直接观察
	slog.SetDefault(slog.New(slog.NewTextHandler(io.MultiWriter(f, os.Stderr), &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))
	slog.Info(appName+" 桌面端启动中", "version", Version, "commit", Commit, "built", BuildTime, "log", logPath)
}

func (d *Desktop) showWindow() {
	if d.ctx == nil {
		return
	}
	runtime.WindowShow(d.ctx)
	runtime.WindowUnminimise(d.ctx)
}

func (d *Desktop) appContext() context.Context {
	if d.ctx != nil {
		return d.ctx
	}
	return context.Background()
}

// ---- 暴露给前端的绑定方法 ----

// StatusInfo 描述桌面端与后端的当前状态。
type StatusInfo struct {
	Version        string `json:"version"`
	Embedded       bool   `json:"embedded"`
	External       bool   `json:"external"`
	BackendRunning bool   `json:"backendRunning"`
	BackendError   string `json:"backendError,omitempty"`
	APIURL         string `json:"apiUrl"`
	ConfigPath     string `json:"configPath"`
	DataDir        string `json:"dataDir"`
	DatabasePath   string `json:"databasePath"`
	LogFile        string `json:"logFile"`
	TrayAvailable  bool   `json:"trayAvailable"`
}

// Version 返回桌面端版本号。
func (d *Desktop) Version() string { return Version }

// Status 返回桌面端与后端的当前状态。
func (d *Desktop) Status() StatusInfo {
	d.mu.Lock()
	inst, err := d.backend, d.backendErr
	apiURL, external, logFile := d.apiURL, d.external, d.logFile
	d.mu.Unlock()

	info := StatusInfo{
		Version:        Version,
		Embedded:       inst != nil && !external,
		External:       external,
		BackendRunning: apiURL != "",
		APIURL:         apiURL,
		LogFile:        logFile,
	}
	if d.tray != nil {
		info.TrayAvailable = d.tray.available()
	}
	if err != nil {
		info.BackendError = err.Error()
	}
	if inst != nil {
		info.ConfigPath = inst.ConfigPath()
		info.DataDir = inst.DataDir()
		info.DatabasePath = inst.DBPath()
	}
	return info
}

// RestartBackend 停止并重新启动后端，返回重启后的状态。
func (d *Desktop) RestartBackend() (StatusInfo, error) {
	d.mu.Lock()
	old := d.backend
	d.backend = nil
	d.backendErr = nil
	d.apiURL = ""
	d.external = false
	d.mu.Unlock()

	d.proxy.clearTarget()
	if d.tray != nil {
		d.tray.setStatus(false)
	}

	if old != nil {
		slog.Info("重启内嵌后端：正在停止旧实例...")
		old.Stop(backendStopWait)
	}

	defer d.showWindow()
	d.startBackend(d.appContext())

	d.mu.Lock()
	err := d.backendErr
	d.mu.Unlock()

	if err != nil {
		return d.Status(), fmt.Errorf("重启后端失败: %w", err)
	}
	return d.Status(), nil
}

// RegisterPKCS11Mock 把 pkcs11-mock 驱动注册到操作系统（Windows 需要管理员权限）。
func (d *Desktop) RegisterPKCS11Mock() (string, error) {
	return registerPKCS11Mock()
}

// OpenInBrowser 使用系统默认浏览器打开管理界面（用于排查 WebView 显示问题）。
func (d *Desktop) OpenInBrowser() error {
	d.mu.Lock()
	apiURL := d.apiURL
	d.mu.Unlock()
	if apiURL == "" {
		return fmt.Errorf("后端尚未就绪")
	}
	return openURL(apiURL)
}

// OpenDataDir 打开数据目录（配置文件、数据库、日志所在目录）。
func (d *Desktop) OpenDataDir() error {
	dir := filepath.Dir(config.ResolveConfigPath())
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return openPath(dir)
}

// OpenLogFile 打开桌面端运行日志文件。
func (d *Desktop) OpenLogFile() error {
	d.mu.Lock()
	logFile := d.logFile
	d.mu.Unlock()
	if logFile == "" {
		return fmt.Errorf("日志文件尚未初始化")
	}
	return openPath(logFile)
}

// Quit 退出桌面端（会优雅关闭内嵌后端）。
func (d *Desktop) Quit() {
	d.quitting.Store(true)
	if d.ctx != nil {
		runtime.Quit(d.ctx)
	}
}
