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
	"github.com/globaltrusts/client-card/internal/api"
	"github.com/globaltrusts/client-card/internal/card"
	"github.com/globaltrusts/client-card/internal/card/cloud"
	"github.com/globaltrusts/client-card/internal/card/local"
	tpm2card "github.com/globaltrusts/client-card/internal/card/tpm2"
	"github.com/globaltrusts/client-card/internal/card/tpmsc"
	"github.com/globaltrusts/client-card/internal/certprop"
	"github.com/globaltrusts/client-card/internal/ipc"
	"github.com/globaltrusts/client-card/internal/storage"
	"github.com/globaltrusts/client-card/internal/tpm"
	"github.com/globaltrusts/client-card/pkg/pkcs11types"
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

	// 加载配置
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载配置失败: %v\n", err)
		os.Exit(1)
	}

	// 绑定完整配置到 api 包，使 PUT /api/settings 可以热更新并写回 YAML
	resolvedCfgPath := *configPath
	if resolvedCfgPath == "" {
		resolvedCfgPath = config.ResolveConfigPath()
	}
	api.BindFullConfig(cfg, resolvedCfgPath)

	// 初始化日志
	initLogger(cfg.Log.Level)

	slog.Info("clients 启动中",
		"version", Version,
		"commit", Commit,
		"api_addr", cfg.API.Addr(),
		"ipc_path", cfg.IPC.IPCPath(),
		"db_path", cfg.Database.Path,
	)

	// 初始化数据库
	db, err := storage.Open(cfg.Database.Path)
	if err != nil {
		slog.Error("初始化数据库失败", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	slog.Info("数据库已连接", "path", cfg.Database.Path)

	// 初始化卡片管理器
	manager := card.NewManager()

	// 从数据库加载所有本地卡片，注册为 Slot
	if err := loadLocalSlots(manager, db); err != nil {
		slog.Warn("加载本地 Slot 失败", "error", err)
	}

	// 启动 IPC 服务
	ipcServer := ipc.NewServer(cfg.IPC.IPCPath())
	pkcsHandler := ipc.NewPKCSHandler(manager)
	pkcsHandler.Register(ipcServer)
	pkcsHandler.RegisterKSPHandlers(ipcServer) // 注册 KSP 专用命令

	if err := ipcServer.Start(); err != nil {
		slog.Error("启动 IPC 服务失败", "error", err)
		os.Exit(1)
	}

	// 启动 REST API 服务
	apiServer := api.NewServer(&cfg.API, manager, db)
	// 注入 IPC 广播回调：卡片增删改后会通知 pkcs11-mock 重新枚举 slot
	apiServer.SetIPCBroadcaster(ipcServer.BroadcastSlotChanged)
	// 注入证书传播器
	propagator := certprop.New()
	apiServer.SetCertPropagator(propagator)
	if err := apiServer.Start(); err != nil {
		slog.Error("启动 REST API 服务失败", "error", err)
		os.Exit(1)
	}

	slog.Info("clients 已就绪，等待连接...")

	// 等待退出信号
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 启动时执行一次证书同步到系统存储，并启动定期同步
	go startCertPropagationLoop(ctx, db, propagator)

	// 启动云端自动定时同步（使用信号上下文，优雅退出时自动停止）
	apiServer.StartAutoSync(ctx)

	<-ctx.Done()

	slog.Info("clients 正在关闭...")

	// 优雅关闭 IPC 服务（等待当前操作完成，最长 10 秒）
	ipcServer.GracefulStop(10 * time.Second)

	// 优雅关闭 API 服务
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := apiServer.Stop(shutdownCtx); err != nil {
		slog.Warn("REST API 关闭超时", "error", err)
	}
}

// loadLocalSlots 从数据库加载所有本地卡片，注册到 Manager。
func loadLocalSlots(manager *card.Manager, db *storage.DB) error {
	ctx := context.Background()
	cardRepo := storage.NewCardRepo(db)
	certRepo := storage.NewCertRepo(db)

	cards, err := cardRepo.ListAll(ctx)
	if err != nil {
		return fmt.Errorf("查询卡片列表失败: %w", err)
	}

	// 初始化 TPM Provider（失败时降级，不影响本地 Slot）
	tpmProv, tpmErr := tpm.NewProvider()
	if tpmErr != nil {
		slog.Warn("TPM2 不可用，TPM2 卡片将无法加载", "error", tpmErr)
	}

	var slotID pkcs11types.SlotID = 1
	for _, c := range cards {
		switch c.SlotType {
		case storage.SlotTypeLocal:
			slot := local.New(slotID, c, certRepo)
			manager.RegisterSlot(slot)
			slog.Info("已注册本地 Slot", "slot_id", slotID, "card", c.CardName)
		case storage.SlotTypeTPM2:
			if tpmProv == nil {
				slog.Warn("跳过 TPM2 卡片（TPM2 不可用）", "card", c.CardName)
				continue
			}
			slot := tpm2card.New(slotID, c, certRepo, tpmProv)
			manager.RegisterSlot(slot)
			slog.Info("已注册 TPM2 Slot", "slot_id", slotID, "card", c.CardName, "platform", tpmProv.PlatformName())
		case storage.SlotTypeCloud:
			if c.CloudURL == "" || c.CloudCardUUID == "" {
				slog.Warn("跳过 Cloud 卡片（缺少 cloud_url 或 cloud_card_uuid）", "card", c.CardName)
				continue
			}
			slot, err := cloud.New(slotID, c, false)
			if err != nil {
				slog.Warn("创建 Cloud Slot 失败，跳过", "card", c.CardName, "error", err)
				continue
			}
			manager.RegisterSlot(slot)
			slog.Info("已注册 Cloud Slot", "slot_id", slotID, "card", c.CardName, "url", c.CloudURL)
		case storage.SlotTypeTPMSC:
			if !tpmsc.IsAvailable() {
				slog.Warn("跳过 TPMSC 卡片（tpmvscmgr.exe 不可用）", "card", c.CardName)
				continue
			}
			slot := tpmsc.New(slotID, c, certRepo)
			manager.RegisterSlot(slot)
			slog.Info("已注册 TPM-VSC Slot", "slot_id", slotID, "card", c.CardName)
		default:
			continue
		}
		slotID++
	}
	return nil
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

// certPropagationInterval 是证书定期同步的间隔时间。
const certPropagationInterval = 5 * time.Minute

// startCertPropagationLoop 启动证书传播循环：
// 1. 启动时立即执行一次全量同步
// 2. 之后每隔 certPropagationInterval 执行一次同步
// 3. ctx 取消时停止循环
func startCertPropagationLoop(ctx context.Context, db *storage.DB, propagator certprop.Propagator) {
	// 启动时立即执行一次
	syncCertsToSystem(db, propagator)

	ticker := time.NewTicker(certPropagationInterval)
	defer ticker.Stop()

	slog.Info("证书传播：定期同步已启动", "interval", certPropagationInterval)

	for {
		select {
		case <-ctx.Done():
			slog.Info("证书传播：定期同步已停止")
			return
		case <-ticker.C:
			syncCertsToSystem(db, propagator)
		}
	}
}

// syncCertsToSystem 将数据库中的证书同步到操作系统证书存储。
// 同时查询 pki_certs 表（PKI 工具签发/导入的证书）和 certificates 表（智能卡上的 X.509 证书）。
func syncCertsToSystem(db *storage.DB, propagator certprop.Propagator) {
	ctx := context.Background()
	pkiCertRepo := storage.NewPKICertRepo(db)
	certRepo := storage.NewCertRepo(db)

	var certInfos []certprop.CertInfo

	// 1. 查询 PKI 证书（pki_certs 表）
	pkiCerts, _, err := pkiCertRepo.List(ctx, 1, 1000)
	if err != nil {
		slog.Warn("证书传播：查询 PKI 证书列表失败", "error", err)
	} else {
		for _, c := range pkiCerts {
			if c.Revoked || c.CertPEM == "" {
				continue
			}
			certInfos = append(certInfos, certprop.CertInfo{
				UUID:       c.UUID,
				CardUUID:   c.CardUUID,
				CommonName: c.CommonName,
				CertPEM:    c.CertPEM,
				HasKey:     c.HasPrivateKey,
				KeyType:    c.KeyType,
			})
		}
	}

	// 2. 查询智能卡证书（certificates 表，仅 X.509 类型）
	scCerts, err := certRepo.ListX509All(ctx)
	if err != nil {
		slog.Warn("证书传播：查询智能卡证书列表失败", "error", err)
	} else {
		for _, c := range scCerts {
			if len(c.CertContent) == 0 {
				continue
			}
			hasKey := len(c.PrivateData) > 0
			certInfos = append(certInfos, certprop.CertInfo{
				UUID:     c.UUID,
				CardUUID: c.CardUUID,
				CertDER:  c.DERContent(),
				HasKey:   hasKey,
				KeyType:  c.KeyType,
			})
		}
	}

	if len(certInfos) == 0 {
		slog.Debug("证书传播：无证书需要同步")
		return
	}

	result, err := propagator.Sync(ctx, certInfos)
	if err != nil {
		slog.Warn("证书传播：同步失败", "error", err)
		return
	}

	// 仅在有实际变更时输出 Info 日志，避免定期同步时刷屏
	if result.Added > 0 || result.Removed > 0 || result.Errors > 0 {
		slog.Info("证书传播：同步完成",
			"added", result.Added,
			"removed", result.Removed,
			"skipped", result.Skipped,
			"errors", result.Errors,
		)
	} else {
		slog.Debug("证书传播：同步完成，无变更", "skipped", result.Skipped)
	}
}
