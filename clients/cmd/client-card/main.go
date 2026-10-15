// clients 是虚拟智能卡管理服务。
// 提供 IPC 接口供 pkcs11-mock 调用，以及 REST API 供前端管理。
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/globaltrusts/client-card/configs"
	"github.com/globaltrusts/client-card/pkg/app"
)

// 版本信息，由 ldflags 在构建时注入。
var (
	Version   = "dev"
	BuildTime = "unknown"
	Commit    = "unknown"
)

func main() {
	// 命令行参数
	configPath := flag.String("config", "", "配置文件路径（默认使用用户数据目录）")
	showVersion := flag.Bool("version", false, "显示版本信息")
	flag.Parse()

	if *showVersion {
		fmt.Printf("clients %s (commit: %s, built: %s)\n", Version, Commit, BuildTime)
		os.Exit(0)
	}

	// 先加载配置以确定日志级别（配置本身会在 app.Start 中再次加载并绑定）
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载配置失败: %v\n", err)
		os.Exit(1)
	}
	initLogger(cfg.Log.Level)

	// 等待退出信号
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	inst, err := app.Start(ctx, app.Options{
		ConfigPath: *configPath,
		Version:    Version,
		Commit:     Commit,
		BuildTime:  BuildTime,
	})
	if err != nil {
		slog.Error("启动本地管理端失败", "error", err)
		os.Exit(1)
	}

	<-ctx.Done()

	slog.Info("clients 正在关闭...")
	// 优雅关闭 IPC 服务（等待当前操作完成，最长 10 秒）
	inst.Stop(10 * time.Second)
}

// initLogger 初始化结构化日志。
func initLogger(level string) {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: lvl,
	})
	slog.SetDefault(slog.New(handler))
}
