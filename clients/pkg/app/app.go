// Package app 封装本地管理端（client-card）的完整启动流程。
//
// 之所以把它抽成公开的 pkg 包而不是 internal 包，是为了让仓库内其它 Go module
// （例如 desktop/wails 的 Wails 桌面端）能够通过 go.mod 的 replace 指令直接嵌入
// 同一套后端，实现「单进程、单二进制」的桌面客户端。
//
// 使用方式：
//
//	inst, err := app.Start(ctx, app.Options{})
//	if err != nil { ... }
//	defer inst.Stop(10 * time.Second)
//	// inst.HTTPBaseURL() 即前端地址，例如 http://127.0.0.1:1026
package app

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/globaltrusts/client-card/configs"
	"github.com/globaltrusts/client-card/internal/api"
	"github.com/globaltrusts/client-card/internal/card"
	"github.com/globaltrusts/client-card/internal/card/cloud"
	"github.com/globaltrusts/client-card/internal/card/local"
	tpm2card "github.com/globaltrusts/client-card/internal/card/tpm2"
	"github.com/globaltrusts/client-card/internal/card/tpmsc"
	"github.com/globaltrusts/client-card/internal/certprop"
	"github.com/globaltrusts/client-card/internal/fido"
	"github.com/globaltrusts/client-card/internal/ipc"
	"github.com/globaltrusts/client-card/internal/storage"
	"github.com/globaltrusts/client-card/internal/tpm"
	"github.com/globaltrusts/client-card/pkg/pkcs11types"
)

// CertPropagationInterval 是证书定期同步到操作系统证书存储的间隔时间。
const CertPropagationInterval = 5 * time.Minute

// Options 描述启动本地管理端所需的参数。
type Options struct {
	// ConfigPath 为配置文件路径；为空时使用用户数据目录下的 config.yaml。
	ConfigPath string
	// Version / Commit / BuildTime 仅用于日志输出，由构建时的 ldflags 注入。
	Version   string
	Commit    string
	BuildTime string
}

// Instance 是一个已启动的本地管理端实例（IPC 服务 + REST API + 后台任务）。
type Instance struct {
	cfg       *config.Config
	cfgPath   string
	db        *storage.DB
	ipcServer *ipc.Server
	apiServer *api.Server

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// Start 启动本地管理端。返回时 IPC 与 REST API 均已开始监听，
// 后台任务（证书传播、云端自动同步）已随传入的 ctx 启动。
//
// 任一环节失败都会回滚已分配的资源，并返回描述性错误。
func Start(ctx context.Context, opts Options) (*Instance, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	// 加载配置
	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("加载配置失败: %w", err)
	}

	resolvedCfgPath := opts.ConfigPath
	if resolvedCfgPath == "" {
		resolvedCfgPath = config.ResolveConfigPath()
	}
	// 绑定完整配置到 api 包，使 PUT /api/settings 可以热更新并写回 YAML
	api.BindFullConfig(cfg, resolvedCfgPath)

	slog.Info("clients 启动中",
		"version", opts.Version,
		"commit", opts.Commit,
		"api_addr", cfg.API.Addr(),
		"ipc_path", cfg.IPC.IPCPath(),
		"db_path", cfg.Database.Path,
	)

	// 初始化数据库
	db, err := storage.Open(cfg.Database.Path)
	if err != nil {
		return nil, fmt.Errorf("初始化数据库失败: %w", err)
	}
	slog.Info("数据库已连接", "path", cfg.Database.Path)

	// 失败回滚：关闭数据库
	rollback := func(inner error) (*Instance, error) {
		_ = db.Close()
		return nil, inner
	}

	// 初始化卡片管理器
	manager := card.NewManager()

	// 初始化 TPM Provider（失败时退化为软件 stub，保证 medium/high 仍可使用统一接口）
	tpmProv, tpmErr := tpm.NewProvider()
	if tpmErr != nil {
		slog.Warn("TPM Provider 不可用，将退化为软件 stub", "error", tpmErr)
		fallback, fbErr := tpm.NewSoftwareStub()
		if fbErr != nil {
			slog.Error("软件 stub 初始化失败，medium/high 安全等级将无法使用", "error", fbErr)
		} else {
			tpmProv = fallback
		}
	}
	if tpmProv != nil {
		slog.Info("TPM Provider 已就绪", "platform", tpmProv.PlatformName())
	}

	// 从数据库加载所有本地卡片，注册为 Slot
	if err := loadLocalSlots(manager, db, tpmProv); err != nil {
		slog.Warn("加载本地 Slot 失败", "error", err)
	}

	// 启动 IPC 服务
	ipcServer := ipc.NewServer(cfg.IPC.IPCPath())
	// 初始化 FIDO Store（复用 storage.Certificate 表）
	cardRepo := storage.NewCardRepo(db)
	certRepo := storage.NewCertRepo(db)
	km := local.NewKeyManager(certRepo, cardRepo)
	fidoStore := fido.NewStore(certRepo, cardRepo, km)
	slog.Info("FIDO Store 已初始化")
	pkcsHandler := ipc.NewPKCSHandlerWithOptions(manager, ipc.PKCSHandlerOptions{
		FIDOStore: fidoStore,
		CardRepo:  cardRepo,
		CertRepo:  certRepo,
	})
	pkcsHandler.Register(ipcServer)

	if err := ipcServer.Start(); err != nil {
		return rollback(fmt.Errorf("启动 IPC 服务失败: %w", err))
	}

	// 启动 REST API 服务
	apiServer, err := api.NewServer(&cfg.API, manager, db)
	if err != nil {
		ipcServer.Stop()
		return rollback(fmt.Errorf("初始化 REST API 服务失败: %w", err))
	}
	// 注入 IPC 广播回调：卡片增删改后会通知 pkcs11-mock 重新枚举 slot
	apiServer.SetIPCBroadcaster(ipcServer.BroadcastSlotChanged)
	// 注入 TPM Provider，medium/high 安全等级需要
	apiServer.SetTPMProvider(tpmProv)
	// 注入证书传播器
	propagator := certprop.New()
	apiServer.SetCertPropagator(propagator)

	if err := apiServer.Start(); err != nil {
		ipcServer.Stop()
		return rollback(fmt.Errorf("启动 REST API 服务失败: %w", err))
	}

	inst := &Instance{
		cfg:       cfg,
		cfgPath:   resolvedCfgPath,
		db:        db,
		ipcServer: ipcServer,
		apiServer: apiServer,
	}

	// 后台任务：证书定期同步到系统存储 + 云端自动定时同步
	runCtx, cancel := context.WithCancel(ctx)
	inst.cancel = cancel

	inst.wg.Add(1)
	go func() {
		defer inst.wg.Done()
		startCertPropagationLoop(runCtx, db, propagator)
	}()
	apiServer.StartAutoSync(runCtx)

	slog.Info("clients 已就绪，等待连接...", "api_addr", cfg.API.Addr())
	return inst, nil
}

// Stop 优雅关闭本地管理端：
// 取消后台任务 → 关闭 IPC（最长 timeout）→ 关闭 REST API（最长 5 秒）→ 关闭数据库。
func (i *Instance) Stop(timeout time.Duration) {
	if i == nil {
		return
	}
	if i.cancel != nil {
		i.cancel()
	}
	if i.ipcServer != nil {
		i.ipcServer.GracefulStop(timeout)
	}
	if i.apiServer != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := i.apiServer.Stop(shutdownCtx); err != nil {
			slog.Warn("REST API 关闭超时", "error", err)
		}
		cancel()
	}
	i.wg.Wait()
	if i.db != nil {
		_ = i.db.Close()
	}
}

// Config 返回当前生效的完整配置。
func (i *Instance) Config() *config.Config {
	if i == nil {
		return nil
	}
	return i.cfg
}

// Addr 返回 REST API 的监听地址（host:port）。
func (i *Instance) Addr() string {
	if i == nil || i.cfg == nil {
		return ""
	}
	return i.cfg.API.Addr()
}

// HTTPBaseURL 返回可直接访问的前端地址，例如 http://127.0.0.1:1026。
func (i *Instance) HTTPBaseURL() string {
	if i == nil || i.cfg == nil {
		return ""
	}
	scheme := "http"
	if i.cfg.API.TLSEnabled {
		scheme = "https"
	}
	host := i.cfg.API.Host
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return fmt.Sprintf("%s://%s:%d", scheme, host, i.cfg.API.Port)
}

// ConfigPath 返回实际使用的配置文件路径。
func (i *Instance) ConfigPath() string {
	if i == nil {
		return ""
	}
	return i.cfgPath
}

// DataDir 返回数据目录（认证 Token 等运行时数据）。
func (i *Instance) DataDir() string {
	if i == nil || i.cfg == nil {
		return ""
	}
	return i.cfg.API.DataDir
}

// DBPath 返回 SQLite 数据库文件路径。
func (i *Instance) DBPath() string {
	if i == nil || i.cfg == nil {
		return ""
	}
	return i.cfg.Database.Path
}

// loadLocalSlots 从数据库加载所有本地卡片，注册到 Manager。
func loadLocalSlots(manager *card.Manager, db *storage.DB, tpmProv tpm.Provider) error {
	ctx := context.Background()
	cardRepo := storage.NewCardRepo(db)
	certRepo := storage.NewCertRepo(db)

	cards, err := cardRepo.ListAll(ctx)
	if err != nil {
		return fmt.Errorf("查询卡片列表失败: %w", err)
	}

	var slotID pkcs11types.SlotID = 1
	for _, c := range cards {
		switch c.SlotType {
		case storage.SlotTypeLocal:
			// 本地卡：medium/high 需要 TPM Provider；low 也可注入（无副作用）
			slot := local.NewWithTPM(slotID, c, certRepo, cardRepo, tpmProv)
			manager.RegisterSlot(slot)
			slog.Info("已注册本地 Slot", "slot_id", slotID, "card", c.CardName, "level", c.SecurityLevel)
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

// startCertPropagationLoop 启动证书传播循环：
// 1. 启动时立即执行一次全量同步
// 2. 之后每隔 CertPropagationInterval 执行一次同步
// 3. ctx 取消时停止循环
func startCertPropagationLoop(ctx context.Context, db *storage.DB, propagator certprop.Propagator) {
	// 启动时立即执行一次
	syncCertsToSystem(db, propagator)

	ticker := time.NewTicker(CertPropagationInterval)
	defer ticker.Stop()

	slog.Info("证书传播：定期同步已启动", "interval", CertPropagationInterval)

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
