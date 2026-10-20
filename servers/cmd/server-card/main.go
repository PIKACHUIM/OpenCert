// servers 是云端智能卡管理服务。
// 提供 REST API 供 clients 的 Cloud Slot 调用。
// 私钥在服务端加密存储，签名/解密操作在服务端执行。
package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/globaltrusts/server-card/configs"
	"github.com/globaltrusts/server-card/internal/acme"
	"github.com/globaltrusts/server-card/internal/api"
	"github.com/globaltrusts/server-card/internal/auth"
	"github.com/globaltrusts/server-card/internal/ca"
	"github.com/globaltrusts/server-card/internal/card"
	"github.com/globaltrusts/server-card/internal/cps"
	"github.com/globaltrusts/server-card/internal/ct"
	"github.com/globaltrusts/server-card/internal/identity"
	"github.com/globaltrusts/server-card/internal/issuance"
	"github.com/globaltrusts/server-card/internal/keybackend"
	// 内置私钥存储后端驱动：TPM（Windows CNG）与 PKCS#11（HSM/USB 令牌）
	_ "github.com/globaltrusts/server-card/internal/keybackend/pkcs11"
	_ "github.com/globaltrusts/server-card/internal/keybackend/tpm"
	"github.com/globaltrusts/server-card/internal/mailer"
	"github.com/globaltrusts/server-card/internal/payment"
	"github.com/globaltrusts/server-card/internal/portal"
	"github.com/globaltrusts/server-card/internal/promo"
	"github.com/globaltrusts/server-card/internal/revocation"
	"github.com/globaltrusts/server-card/internal/storage"
	"github.com/globaltrusts/server-card/internal/template"
	"github.com/globaltrusts/server-card/internal/verification"
	"github.com/globaltrusts/server-card/internal/workflow"
	"golang.org/x/crypto/bcrypt"
)

// 版本信息，由 ldflags 在构建时注入。
var (
	Version   = "dev"
	BuildTime = "unknown"
	Commit    = "unknown"
)

func main() {
	// 加载配置
	cfg := configs.Load()

	// 初始化日志
	initLogger(cfg.Log.Level)

	slog.Info("servers 启动中",
		"version", Version,
		"commit", Commit,
		"built", BuildTime,
		"addr", cfg.API.Addr(),
		"db", cfg.Database.Path,
		"db_url", cfg.Database.URL != "")

	// 生产安全基线：对外监听时不允许使用默认 JWT 密钥（否则任何人都能伪造管理员令牌）
	if !isLoopbackHost(cfg.API.Host) && (cfg.JWT.Secret == defaultJWTSecret || len(cfg.JWT.Secret) < 32) {
		slog.Error("对外监听时必须通过 SERVER_CARD_JWT_SECRET 设置至少 32 位的随机密钥",
			"host", cfg.API.Host)
		os.Exit(1)
	}

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
	if err := ensureDefaultAdmin(context.Background(), userRepo, !isLoopbackHost(cfg.API.Host)); err != nil {
		slog.Warn("初始化默认管理员账号失败", "error", err)
	}

	jwtMgr, err := auth.NewManager(cfg.JWT.Secret, cfg.JWT.ExpiryHours)
	if err != nil {
		slog.Error("初始化 JWT Manager 失败", "error", err)
		os.Exit(1)
	}
	cardSvc := card.NewService(cardRepo, certRepo, masterKey)

	// 私钥存储后端（存储区域）：本地加密 / TPM / HSM（PKCS#11）
	// 外部插件清单用于扩展可扫描到的厂商 PKCS#11 模块（文件不存在时忽略）
	if err := keybackend.LoadPresetFile(cfg.KeyBackendsFile); err != nil {
		slog.Warn("加载私钥后端插件清单失败，将仅使用内置驱动", "error", err, "path", cfg.KeyBackendsFile)
	}
	zoneRepo := storage.NewStorageZoneRepo(db)
	cardSvc.AttachStorageZones(zoneRepo)
	defer cardSvc.Close() //nolint:errcheck // 退出时释放设备会话
	if err := ensureDefaultStorageZone(context.Background(), zoneRepo, cardSvc); err != nil {
		slog.Warn("初始化默认存储区域失败", "error", err)
	}
	// 内置默认数据（幂等）：CA 类颁发模板 + 密钥用途模板、域名验证接口。
	// 已存在同类数据时自动跳过，保证全新安装开箱即用。
	if err := db.EnsureBuiltins(context.Background()); err != nil {
		slog.Warn("初始化内置默认数据失败", "error", err)
	}

	// 初始化 CA 管理服务
	caSvc := ca.NewService(db, masterKey)
	// CA 私钥托管在 HSM/TPM 存储区域时，通过 keybackend 加载签名器
	// （仅支持 RSA/ECDSA：这两类算法是 pkcs11/tpm 驱动当前声明的能力范围，
	// SM2 CA 私钥始终使用本地加密存储，因此用标准库解析证书公钥即可）。
	caSvc.SetSignerLoader(func(ctx context.Context, record *storage.CA) (crypto.Signer, error) {
		if record.StorageZone == "" {
			return nil, fmt.Errorf("CA 私钥未关联存储区域")
		}
		provider, zone, err := cardSvc.OpenZone(ctx, record.StorageZone)
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode([]byte(record.CertPEM))
		if block == nil {
			return nil, fmt.Errorf("CA 证书 PEM 解码失败")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("解析 CA 证书失败: %w", err)
		}
		handle := keybackend.KeyHandle{Driver: zone.DriverID(), Ref: record.KeyRef}
		return keybackend.NewSigner(ctx, provider, handle, cert.PublicKey), nil
	})
	// 创建 CA 时若选择了存储区域，在该区域内生成密钥（本地数据库区域与之前
	// 行为一致：返回 nil signer，调用方按旧路径在内存生成并加密入库）。
	caSvc.SetZoneKeyGenerator(func(ctx context.Context, zoneUUID, keyType string) (
		crypto.PublicKey, string, string, crypto.Signer, error,
	) {
		provider, zone, err := cardSvc.OpenZone(ctx, zoneUUID)
		if err != nil {
			return nil, "", "", nil, err
		}
		driver := zone.DriverID()
		if driver == storage.DriverDatabase {
			// 本地加密存储：退回标准生成路径（CreateCA 内部会走 generateKey/加密入库）。
			return nil, "", "database", nil, ca.ErrUseLocalKeyGen
		}
		kp, err := provider.Generate(ctx, keybackend.KeySpec{KeyType: keyType, Label: "CA:" + zone.Name})
		if err != nil {
			return nil, "", "", nil, fmt.Errorf("存储区域「%s」生成密钥失败: %w", zone.Name, err)
		}
		pub, err := x509.ParsePKIXPublicKey(kp.PublicDER)
		if err != nil {
			return nil, "", "", nil, fmt.Errorf("解析存储区域返回的公钥失败: %w", err)
		}
		handle := keybackend.KeyHandle{Driver: driver, Ref: kp.Ref}
		return pub, kp.Ref, driver, keybackend.NewSigner(ctx, provider, handle, pub), nil
	})
	// 导入外部 CA 私钥：本地加密存储交回 ca 包用主密钥加密入库；
	// 硬件区域导入设备（区域未开启导入或不支持时，provider 会返回明确原因）。
	caSvc.SetZoneKeyImporter(func(ctx context.Context, zoneUUID, keyType string, privDER []byte) (string, string, error) {
		provider, zone, err := cardSvc.OpenZone(ctx, zoneUUID)
		if err != nil {
			return "", "", err
		}
		driver := zone.DriverID()
		if driver == storage.DriverDatabase {
			return "", "database", ca.ErrUseLocalKeyGen
		}
		kp, err := provider.Import(ctx, privDER, keybackend.KeySpec{KeyType: keyType, Label: "CA:" + zone.Name})
		if err != nil {
			return "", "", fmt.Errorf("存储区域「%s」导入私钥失败: %w", zone.Name, err)
		}
		return kp.Ref, driver, nil
	})

	// 系统信息页展示的版本号
	api.ServiceVersion = Version

	// 初始化证书颁发模板服务
	issuanceSvc := issuance.NewService(db)

	// 初始化验证服务（邮件发送器在下面按"后台配置的默认邮件接口"注入）
	verifySvc := verification.NewService(db)

	// 初始化工作流服务（注入 caSvc/issuanceSvc 以支持审批自动签发）
	workflowSvc := workflow.NewService(db, caSvc, issuanceSvc)

	// 初始化门户（官网/商城）服务：商品目录、权威报价与下单编排
	portalSvc := portal.NewService(storage.NewPortalRepo(db), workflowSvc)

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
	// 注入颁发模板服务：签发有效期、允许算法与 CA 统一按模板策略解析
	acmeSvc.SetIssuanceSvc(issuanceSvc)

	// 身份认证接口（SMTP/Resend 邮件、实名回调）：配置用主密钥加密存储
	identityStore := identity.NewStore(db, cardSvc, mailer.New(cfg.SMTP))
	verifySvc.SetProviders(identityStore)
	// 系统邮件：优先使用后台配置并设为默认的邮件接口，未配置时回退到环境变量 SMTP
	if m, err := identityStore.SystemMailer(context.Background()); err == nil {
		verifySvc.SetMailer(m)
	} else {
		slog.Info("未配置邮件接口，验证码邮件将只记录日志", "reason", err)
		verifySvc.SetMailer(mailer.New(configs.SMTPConfig{}))
	}
	// 域名 TLS 验证复用 ACME TLS-ALPN-01 校验
	verifySvc.SetTLSValidator(acmeSvc.ValidateTLSALPN01)

	// 独立 OCSP 响应服务可使用平台内证书（如 OCSP 委托签名证书）作为签名者
	revocationSvc.SetSignerLoader(func(ctx context.Context, certUUID string) (*x509.Certificate, crypto.Signer, error) {
		c, err := certRepo.GetByUUID(ctx, certUUID)
		if err != nil {
			return nil, nil, err
		}
		block, _ := pem.Decode(c.CertContent)
		if block == nil {
			return nil, nil, fmt.Errorf("证书内容不是 PEM 格式")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, err
		}
		if len(c.PrivateData) == 0 {
			return nil, nil, fmt.Errorf("该证书的私钥不在平台内，不能用于签名")
		}
		key, err := cardSvc.DecryptPrivateKey(ctx, c)
		if err != nil {
			return nil, nil, err
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, nil, fmt.Errorf("私钥不支持签名")
		}
		return cert, signer, nil
	})

	// 优惠码 / 订阅 / 兑换码；证书策略页面
	promoSvc := promo.NewService(db)
	portalSvc.SetPromo(promoSvc)
	cpsSvc := cps.NewService(db)

	// 启动定时任务：关闭超时未支付订单（充值订单 + 证书/智能卡/套餐订单，后者归还库存与优惠码）
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			if n, err := paymentSvc.CloseExpiredOrders(context.Background()); err != nil {
				slog.Error("关闭超时订单失败", "error", err)
			} else if n > 0 {
				slog.Info("已关闭超时订单", "count", n)
			}
			if n, err := portalSvc.CloseStaleOrders(context.Background()); err != nil {
				slog.Error("关闭超时证书订单失败", "error", err)
			} else if n > 0 {
				slog.Info("已关闭超时证书订单", "count", n)
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
		PortalSvc:     portalSvc,
		PaymentLoader: paymentLoader,
		IdentityStore: identityStore,
		CPSSvc:        cpsSvc,
		PromoSvc:      promoSvc,
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

// ensureDefaultStorageZone 首次启动时创建默认的「本地加密存储」区域，
// 便于在控制台开卡时直接选择私钥存放位置（历史部署不受影响）。
func ensureDefaultStorageZone(ctx context.Context, repo *storage.StorageZoneRepo, cardSvc *card.Service) error {
	zones, err := repo.List(ctx)
	if err != nil {
		return err
	}
	if len(zones) > 0 {
		return nil
	}
	zone := &storage.StorageZone{
		Name:        "本地加密存储",
		StorageType: string(keybackend.KindDatabase),
		HSMDriver:   storage.DriverDatabase,
		Status:      "active",
	}
	enc, err := cardSvc.EncryptZoneParams(keybackend.Params{})
	if err != nil {
		return err
	}
	zone.ParamsEnc = enc
	if caps, cerr := json.Marshal(cardSvc.ZoneCapabilities(zone)); cerr == nil {
		zone.Capabilities = string(caps)
	}
	if err := repo.Create(ctx, zone); err != nil {
		return err
	}
	slog.Info("已创建默认存储区域", "name", zone.Name, "driver", storage.DriverDatabase, "uuid", zone.UUID)
	return nil
}

// loadOrGenerateMasterKey 加载或生成服务端主密钥。
// 优先级：1. 环境变量 SERVER_CARD_MASTER_KEY（Base64）
//  2. 配置文件路径（验证文件权限为 0600）
//  3. 自动生成并保存到文件
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

// defaultJWTSecret 与 configs 中的缺省值保持一致，用于识别"未修改"的部署。
const defaultJWTSecret = "change-me-in-production-please!!"

// isLoopbackHost 判断监听地址是否仅限本机（本地开发/测试环境）。
func isLoopbackHost(host string) bool {
	switch strings.TrimSpace(host) {
	case "127.0.0.1", "localhost", "::1":
		return true
	}
	return false
}

// ensureDefaultAdmin 首次启动时创建默认管理员账号（admin 已存在则跳过）。
//
// 口令来源优先级：
//  1. 环境变量 SERVER_CARD_ADMIN_PASSWORD（至少 12 位）；
//  2. 本机监听（开发环境）使用 admin，便于本地调试；
//  3. 对外监听（生产环境）自动生成随机口令，仅在首次启动日志中输出一次。
func ensureDefaultAdmin(ctx context.Context, userRepo *storage.UserRepo, production bool) error {
	const defaultUsername = "admin"

	// 检查 admin 是否已存在
	if _, err := userRepo.GetByUsername(ctx, defaultUsername); err == nil {
		// 已存在，跳过
		return nil
	}

	defaultPassword := os.Getenv("SERVER_CARD_ADMIN_PASSWORD")
	switch {
	case defaultPassword != "":
		if len(defaultPassword) < 12 {
			return fmt.Errorf("SERVER_CARD_ADMIN_PASSWORD 至少需要 12 位")
		}
	case production:
		buf := make([]byte, 12)
		if _, err := rand.Read(buf); err != nil {
			return fmt.Errorf("生成初始管理员口令失败: %w", err)
		}
		defaultPassword = base64.RawURLEncoding.EncodeToString(buf)
	default:
		defaultPassword = "admin"
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
