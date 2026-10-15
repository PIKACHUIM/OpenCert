// OpenCert Manager 桌面端（Go + Wails v2）
//
// 与 desktop/ 目录下的 Electron 壳不同，本客户端把本地管理端后端（client-card）
// 以「同进程」方式嵌入，因此只需要发布一个可执行文件：
//
//	Wails WebView 窗口 ──► Wails AssetServer（反向代理）──► 内嵌的 REST API + 前端静态资源
//
// 窗口本身只负责展示，所有业务逻辑由内嵌后端提供；托盘菜单负责窗口、服务状态、
// 重启后端、注册 pkcs11-mock 到系统等原生操作。
package main

import (
	"log"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

// 版本信息，由 ldflags 在构建时注入。
var (
	Version   = "dev"
	BuildTime = "unknown"
	Commit    = "unknown"
)

func main() {
	desktop := NewDesktop()

	err := wails.Run(&options.App{
		Title:     "OpenCert Manager",
		Width:     1280,
		Height:    800,
		MinWidth:  960,
		MinHeight: 600,
		// 与等待页/前端深色主题保持一致，避免窗口出现时闪白
		BackgroundColour: &options.RGBA{R: 13, G: 17, B: 23, A: 255},
		// 前端资源不打进当前二进制，而是反向代理到内嵌后端（默认 127.0.0.1:1026），
		// 从而保证 Web 端与桌面端始终使用同一份构建产物。
		AssetServer: &assetserver.Options{
			Handler: desktop.assetHandler(),
		},
		Bind:          []interface{}{desktop},
		OnStartup:     desktop.onStartup,
		OnShutdown:    desktop.onShutdown,
		OnBeforeClose: desktop.onBeforeClose,
		SingleInstanceLock: &options.SingleInstanceLock{
			UniqueId:               singleInstanceID,
			OnSecondInstanceLaunch: desktop.onSecondInstance,
		},
	})

	if err != nil {
		log.Fatalf("启动 OpenCert Manager 桌面端失败: %v", err)
	}
}
