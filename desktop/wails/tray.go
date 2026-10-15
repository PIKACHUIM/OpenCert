package main

import (
	"log/slog"
	"sync"
	"sync/atomic"

	"fyne.io/systray"
)

// trayController 封装系统托盘：图标、菜单与状态刷新。
type trayController struct {
	desktop *Desktop

	started  atomic.Bool
	ready    atomic.Bool
	stopCh   chan struct{}
	stopOnce sync.Once

	statusItem *systray.MenuItem
}

func newTrayController(d *Desktop) *trayController {
	return &trayController{desktop: d, stopCh: make(chan struct{})}
}

// available 报告托盘是否已就绪（就绪后才能安全地隐藏窗口到托盘）。
func (t *trayController) available() bool { return t.ready.Load() }

// start 在独立 goroutine 中运行托盘事件循环。
// 创建托盘窗口与运行其消息循环必须在同一个 goroutine（即同一 OS 线程）中完成，
// 因此这里整体放进 goroutine，而不是用 RunWithExternalLoop。
func (t *trayController) start() {
	t.started.Store(true)
	go systray.Run(t.onReady, func() {})
}

// stop 退出托盘事件循环。
func (t *trayController) stop() {
	if !t.started.Load() {
		return
	}
	t.stopOnce.Do(func() { close(t.stopCh) })
	systray.Quit()
}

// setStatus 刷新托盘中的后端状态文案。
func (t *trayController) setStatus(online bool) {
	if !t.ready.Load() || t.statusItem == nil {
		return
	}
	if online {
		t.statusItem.SetTitle("后端：运行中")
		systray.SetTooltip(appName + " — 运行中")
	} else {
		t.statusItem.SetTitle("后端：已停止")
		systray.SetTooltip(appName + " — 后端已停止")
	}
}

// onReady 在托盘就绪后构建菜单。
func (t *trayController) onReady() {
	systray.SetIcon(appIcon())
	systray.SetTooltip(appName)

	showItem := systray.AddMenuItem("显示主窗口", "打开 "+appName+" 主窗口")
	systray.AddSeparator()
	t.statusItem = systray.AddMenuItem("后端：启动中...", "内嵌后端运行状态")
	t.statusItem.Disable()
	restartItem := systray.AddMenuItem("重启后端服务", "重新启动内嵌的本地管理端")
	openBrowserItem := systray.AddMenuItem("在浏览器中打开", "使用系统默认浏览器访问管理界面")
	openDataDirItem := systray.AddMenuItem("打开数据目录", "打开配置文件、数据库与日志所在目录")
	openLogItem := systray.AddMenuItem("查看运行日志", "打开桌面端运行日志")
	registerItem := systray.AddMenuItem("注册 pkcs11-mock 到系统", "把 PKCS#11 驱动注册到操作系统")
	systray.AddSeparator()
	quitItem := systray.AddMenuItem("退出", "退出 "+appName)

	t.ready.Store(true)

	go func() {
		for {
			select {
			case <-t.stopCh:
				return
			case <-showItem.ClickedCh:
				t.desktop.showWindow()
			case <-restartItem.ClickedCh:
				go func() {
					if _, err := t.desktop.RestartBackend(); err != nil {
						slog.Warn("重启后端失败", "error", err)
					}
				}()
			case <-openBrowserItem.ClickedCh:
				if err := t.desktop.OpenInBrowser(); err != nil {
					slog.Warn("打开浏览器失败", "error", err)
				}
			case <-openDataDirItem.ClickedCh:
				if err := t.desktop.OpenDataDir(); err != nil {
					slog.Warn("打开数据目录失败", "error", err)
				}
			case <-openLogItem.ClickedCh:
				if err := t.desktop.OpenLogFile(); err != nil {
					slog.Warn("打开日志文件失败", "error", err)
				}
			case <-registerItem.ClickedCh:
				go func() {
					msg, err := t.desktop.RegisterPKCS11Mock()
					if err != nil {
						slog.Warn("注册 pkcs11-mock 失败", "error", err)
						return
					}
					slog.Info(msg)
				}()
			case <-quitItem.ClickedCh:
				t.desktop.Quit()
				return
			}
		}
	}()
}
