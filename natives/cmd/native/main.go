// Package main 是 GlobalTrusts 原生客户端的入口。
//
// 本客户端通过 HTTP REST API 连接 client-card 后端服务，
// 提供智能卡管理、证书查看和导入等功能。
package main

import (
	_ "embed"
	"log"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"

	"github.com/globaltrusts/native-client/internal/appcore"
	"github.com/globaltrusts/native-client/internal/config"
	"github.com/globaltrusts/native-client/internal/i18n"
	"github.com/globaltrusts/native-client/internal/ui"
)

//go:embed icon.png
var iconPNG []byte

var keyIcon = fyne.NewStaticResource("key.png", iconPNG)

func main() {
	// 1. 初始化配置
	if err := config.Init(); err != nil {
		log.Printf("配置初始化警告: %v", err)
	}

	cfg := config.Get()

	// 2. 初始化多语言
	i18n.Init(cfg.Language)

	// 3. 创建 Fyne 应用
	fyneApp := app.NewWithID("com.globaltrusts.natives-client")
	fyneApp.SetIcon(keyIcon) // 设置应用图标（托盘图标依赖此设置）

	// 4. 创建应用核心
	application := appcore.New(fyneApp)

	// 5. 创建主窗口
	mainWindow := ui.NewMainWindow(application, fyneApp)

	// 6. 显示窗口并运行
	mainWindow.Show()
	fyneApp.Run()
}