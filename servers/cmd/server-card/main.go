// servers 是云端智能卡管理服务。
// 提供 REST API 供 clients 的 Cloud Slot 调用。
// 私钥在服务端加密存储，签名/解密操作在服务端执行。
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/globaltrusts/server-card/configs"
	"github.com/globaltrusts/server-card/internal/acme"
	"github.com/globaltrusts/server-card/internal/api"
	"github.com/globaltrusts/server-card/internal/auth"
	"github.com/globaltrusts/server-card/internal/ca"
	"github.com/globaltrusts/server-card/internal/card"
	"github.com/globaltrusts/server-card/internal/ct"
	"github.com/globaltrusts/server-card/internal/issuance"
	"github.com/globaltrusts/server-card/internal/mailer"
	"github.com/globaltrusts/server-card/internal/payment"
	"github.com/globaltrusts/server-card/internal/revocation"
	"github.com/globaltrusts/server-card/internal/storage"
	"github.com/globaltrusts/server-card/internal/template"
	"github.com/globaltrusts/server-card/internal/verification"
	"github.com/globaltrusts/server-card/internal/workflow"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	// 加载配置
	cfg := configs.Load()

	// 初始化日志
	initLogger(cfg.Log.Level)

	slog.Info("servers 启动中", "addr", cfg.API.Addr(), "db", cfg.Database.Path, "db_url", cfg.Database.URL != "")

	// 初始化数据库
	db, err := storage.Open(cfg.Database.Path, cfg.Database.URL)
	if err != nil {
		slog.Error("初始化数据库失败", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	// 初始化服务端主密钥（生产环境应从 HSM 或密钥管理服务获取）
	masterKey, err := loadOrGenerateMasterKey(cfg)
	if err != nil {
		slog.Error("初始化服务端主密钥失败", "error", err)
		os.Exit(1)
	}

	// 初始化各层
	userRepo := storage.NewUserRepo(db)
	cardRepo := storage.NewCardRepo(db)
	certRepo := storage.NewCertRepo(db)
	logRepo := storage.NewLogRepo(db)

	// 首次启动时创建默认管理员账号
	if err := ensureDefaultAdmin(context.Background(), userRepo); err != nil {
		slog.Warn("初始化默认管理员账号失败", "error", err)
	}

	jwtMgr, err := auth.NewManager(cfg.JWT.Secret, cfg.JWT.ExpiryHours)
	if err != nil {
		slog.Error("初始化 JWT Manager 失败", "error", err)
		os.Exit(1)
	}
	cardSvc := card.NewService(cardRepo, certRepo, masterKey)

	// 初始化 CA 管理服务
	caSvc := ca.NewService(db, masterKey)

	// 初始化证书颁发模板服务
	issuanceSvc := issuance.NewService(db)

	// 初始化验证服务
	verifySvc := verification.NewService(db)
	// 注入邮件发送器（SMTP 未启用时自动退化为日志输出）
	verifySvc.SetMailer(mailer.New(cfg.SMTP))

	// 初始化工作流服务（注入 caSvc/issuanceSvc 以支持审批自动签发）
	workflowSvc := workflow.NewService(db, caSvc, issuanceSvc)

	// 初始化支付系统
	paymentRegistry := payment.NewRegistry()
	paymentSvc := payment.NewService(db, paymentRegistry)

	// 加载已启用的支付渠道（PaymentPlugin DB → Registry）。
	// 单个插件加载失败不会阻塞启动，仅打印日志。
	paymentLoader := payment.NewLoader(db, paymentRegistry, cardSvc.DecryptData)
	if loaded, err := paymentLoader.Reload(context.Background()); err != nil {
		slog.Warn("加载支付渠道失败", "error", err)
	} else {
		slog.Info("支付渠道加载完成", "count", len(loaded), "types", loaded)
	}

	// 初始化模板服务
	tmplSvc := template.NewService(db)

	// 初始化吊销服务
	revocationSvc := revocation.NewService(db, caSvc)

	// 初始化 CT 服务
	ctSvc := ct.NewService(db)

	// 初始化 ACME 服务
	acmeSvc := acme.NewService(db)
	// 注入 CA 签发依赖（避免循环依赖）
	acmeSvc.SetCASvc(caSvc)

	// 启动定时任务：关闭超时未支付订单
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			if n, err := paymentSvc.CloseExpiredOrders(context.Background()); err != nil {
				slog.Error("关闭超时订单失败", "error", err)
			} else if n > 0 {
				slog.Info("已关闭超时订单", "count", n)
			}
		}
	}()

	// 启动 API 服务
	svcs := &api.Services{
		CardSvc:       cardSvc,
		CASvc:         caSvc,
		IssuanceSvc:   issuanceSvc,
		VerifySvc:     verifySvc,
		WorkflowSvc:   workflowSvc,
		PaymentSvc:    paymentSvc,
		TmplSvc:       tmplSvc,
		RevocationSvc: revocationSvc,
		CTSvc:         ctSvc,
		ACMESvc:       acmeSvc,
	}
	apiServer := api.NewServer(cfg, db, jwtMgr, svcs, userRepo, logRepo)
	apiServer.SetMailer(mailer.New(cfg.SMTP))
	if err := apiServer.Start(); err != nil {
		slog.Error("启动 API 服务失败", "error", err)
		os.Exit(1)
	}

	slog.Info("servers 已就绪", "addr", cfg.API.Addr())

	// 等待退出信号
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 启动 CRL 定时刷新（使用信号上下文，优雅退出时自动停止）
	revocationSvc.StartCRLRefreshLoop(ctx)

	<-ctx.Done()

	slog.Info("servers 正在关闭...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := apiServer.Stop(shutdownCtx); err != nil {
		slog.Warn("API 服务关闭超时", "error", err)
	}
}

// loadOrGenerateMasterKey 加载或生成服务端主密钥。
// 优先级：1. 环境变量 SERVER_CARD_MASTER_KEY（Base64）
//         2. 配置文件路径（验证文件权限为 0600）
//         3. 自动生成并保存到文件
func loadOrGenerateMasterKey(cfg *configs.Config) ([]byte, error) {
	// 1. 优先从环境变量读取（Base64 编码的 32 字节密钥）
	if envKey := os.Getenv("SERVER_CARD_MASTER_KEY"); envKey != "" {
		key, err := base64.StdEncoding.DecodeString(envKey)
		if err != nil {
			return nil, fmt.Errorf("解码环境变量 SERVER_CARD_MASTER_KEY 失败: %w", err)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("环境变量 SERVER_CARD_MASTER_KEY 长度必须为 32 字节（Base64 编码后 44 字符）")
		}
		slog.Info("已从环境变量加载服务端主密钥")
		return key, nil
	}

	// 2. 从配置文件路径读取
	keyPath := cfg.MasterKeyFile
	if keyPath == "" {
		keyPath = cfg.Database.Path + ".masterkey"
	}

	if data, err := os.ReadFile(keyPath); err == nil {
		if len(data) != 32 {
			return nil, fmt.Errorf("主密钥文件长度错误，期望 32 字节，实际 %d 字节", len(data))
		}
		// 验证文件权限为 0600
		info, err := os.Stat(keyPath)
		if err != nil {
			return nil, fmt.Errorf("获取主密钥文件信息失败: %w", err)
		}
		if info.Mode().Perm() != 0600 {
			slog.Warn("主密钥文件权限不安全，建议设置为 0600", "path", keyPath, "perm", info.Mode().Perm())
		}
		slog.Info("已从文件加载服务端主密钥", "path", keyPath)
		return data, nil
	}

	// 3. 生成新密钥
	slog.Warn("未找到主密钥，正在生成新密钥。生产环境请使用环境变量 SERVER_CARD_MASTER_KEY")
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("生成主密钥失败: %w", err)
	}

	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		return nil, fmt.Errorf("保存主密钥失败: %w", err)
	}

	slog.Info("已生成新的服务端主密钥", "path", keyPath,
		"tip", "生产环境请将密钥内容设置到环境变量 SERVER_CARD_MASTER_KEY（base64 编码）")
	return key, nil
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

	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl})
	slog.SetDefault(slog.New(handler))
}

// ensureDefaultAdmin 首次启动时创建默认管理员账号。
// 默认账号：admin / admin
// 如果 admin 用户已存在则跳过。
func ensureDefaultAdmin(ctx context.Context, userRepo *storage.UserRepo) error {
	const defaultUsername = "admin"
	const defaultPassword = "admin"

	// 检查 admin 是否已存在
	if _, err := userRepo.GetByUsername(ctx, defaultUsername); err == nil {
		// 已存在，跳过
		return nil
	}

	// 生成密码哈希
	hash, err := bcrypt.GenerateFromPassword([]byte(defaultPassword), 13)
	if err != nil {
		return fmt.Errorf("生成密码哈希失败: %w", err)
	}

	admin := &storage.User{
		Username:     defaultUsername,
		DisplayName:  "系统管理员",
		Email:        "admin@opencert.local",
		PasswordHash: string(hash),
		Role:         "admin",
		Enabled:      true,
	}

	if err := userRepo.Create(ctx, admin); err != nil {
		return fmt.Errorf("创建默认管理员失败: %w", err)
	}

	slog.Info("已创建默认管理员账号",
		"username", defaultUsername,
		"password", defaultPassword,
		"tip", "请登录后立即修改密码",
	)
	return nil
}
