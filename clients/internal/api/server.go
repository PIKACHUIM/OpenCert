package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	config "github.com/globaltrusts/client-card/configs"
	"github.com/globaltrusts/client-card/internal/api/middleware"
	"github.com/globaltrusts/client-card/internal/card"
	"github.com/globaltrusts/client-card/internal/certprop"
	"github.com/globaltrusts/client-card/internal/storage"
	"github.com/globaltrusts/client-card/internal/totp"
	"github.com/globaltrusts/client-card/ui"
)

// Server 是 REST API 服务。
type Server struct {
	cfg         *config.APIConfig
	mux         *http.ServeMux
	httpSrv     *http.Server
	manager     *card.Manager
	db          *storage.DB
	userRepo    *storage.UserRepo
	cardRepo    *storage.CardRepo
	certRepo    *storage.CertRepo
	logRepo     *storage.LogRepo
	auditRepo   *storage.AuditRepo
	authToken   *middleware.AuthToken
	rateLimiter *middleware.RateLimiter
	metrics     *middleware.Metrics
	totpStore   *totp.Store
	// PKI 仓库
	csrRepo     *storage.CSRRepo
	caRepo      *storage.CARepo
	pkiCertRepo *storage.PKICertRepo
	// ipcBroadcast 在卡片增删改后广播 slot_changed 事件；可为 nil。
	ipcBroadcast func(reason string)
	// certPropagator 证书传播器，将证书同步到操作系统证书存储。
	certPropagator certprop.Propagator
}

// NewServer 创建 API 服务实例。
func NewServer(cfg *config.APIConfig, manager *card.Manager, db *storage.DB) *Server {
	s := &Server{
		cfg:         cfg,
		mux:         http.NewServeMux(),
		manager:     manager,
		db:          db,
	userRepo:    storage.NewUserRepo(db),
		cardRepo:    storage.NewCardRepo(db),
		certRepo:    storage.NewCertRepo(db),
		logRepo:     storage.NewLogRepo(db),
		auditRepo:   storage.NewAuditRepo(db),
		rateLimiter: middleware.NewRateLimiter(100),
		metrics:     middleware.NewMetrics(),
		totpStore:   totp.NewStore(db.Conn()),
		csrRepo:     storage.NewCSRRepo(db),
		caRepo:      storage.NewCARepo(db),
		pkiCertRepo: storage.NewPKICertRepo(db),
	}

	// 初始化 TOTP 表
	if err := s.totpStore.InitTable(context.Background()); err != nil {
		slog.Warn("初始化 TOTP 表失败", "error", err)
	}

	// 初始化默认用户（数据库为空时创建 root/root）
	if err := db.Seed(); err != nil {
		slog.Warn("初始化默认用户失败", "error", err)
	}

	// 初始化审计日志表
	if err := s.auditRepo.InitTable(context.Background()); err != nil {
		slog.Warn("初始化审计日志表失败", "error", err)
	}

	// 初始化本地认证 Token
	authToken, err := middleware.NewAuthToken(cfg.DataDir)
	if err != nil {
		slog.Warn("初始化本地认证 Token 失败，API 将不启用认证", "error", err)
	} else {
		s.authToken = authToken
		// 注入 session token 验证函数，使用户登录 token 也能通过认证
		authToken.SetSessionValidator(func(token string) bool {
			return isValidSession(token)
		})
	}

	// 检查绑定地址安全性
	middleware.CheckBindAddress(cfg.Addr())

	s.registerRoutes()
	return s
}

// registerRoutes 注册所有 API 路由。
// 使用 Go 1.22 ServeMux 的方法+路径模式。
func (s *Server) registerRoutes() {
	// 健康检查
	s.mux.HandleFunc("GET /api/health", s.handleHealth)

	// ---- 认证接口（公开，不需要 API Token）----
	s.mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	s.mux.HandleFunc("POST /api/auth/register", s.handleRegister)
	s.mux.HandleFunc("POST /api/auth/cloud-login", s.handleCloudLogin)
	s.mux.HandleFunc("POST /api/auth/refresh", s.handleRefreshToken)
	s.mux.HandleFunc("DELETE /api/auth/logout", s.handleLogout)
	s.mux.HandleFunc("DELETE /api/auth/logout-all", s.handleLogoutAll)
	s.mux.HandleFunc("PUT /api/auth/password", s.handleChangePassword)

	// ---- 当前用户 ----
	s.mux.HandleFunc("GET /api/users/me", s.handleGetMe)
	s.mux.HandleFunc("PUT /api/users/me", s.handleUpdateMe)

	// ---- 用户管理 ----
	s.mux.HandleFunc("GET /api/users", s.handleListUsers)
	s.mux.HandleFunc("POST /api/users", s.handleCreateUser)
	s.mux.HandleFunc("GET /api/users/{uuid}", s.handleGetUser)
	s.mux.HandleFunc("PUT /api/users/{uuid}", s.handleUpdateUser)
	s.mux.HandleFunc("DELETE /api/users/{uuid}", s.handleDeleteUser)

	// ---- 卡片管理 ----
	s.mux.HandleFunc("GET /api/cards", s.handleListCards)
	s.mux.HandleFunc("POST /api/cards", s.handleCreateCard)
	s.mux.HandleFunc("GET /api/cards/{uuid}", s.handleGetCard)
	s.mux.HandleFunc("PUT /api/cards/{uuid}", s.handleUpdateCard)
	s.mux.HandleFunc("DELETE /api/cards/{uuid}", s.handleDeleteCard)
	s.mux.HandleFunc("POST /api/cards/{uuid}/reset-pin", s.handleResetPIN)
	s.mux.HandleFunc("POST /api/cards/{uuid}/reset-puk", s.handleResetPUK)
	s.mux.HandleFunc("POST /api/cards/{uuid}/export", s.handleExportCard)
	s.mux.HandleFunc("POST /api/cards/restore", s.handleRestoreCard)

	// ---- 证书管理 ----
	s.mux.HandleFunc("GET /api/cards/{card_uuid}/certs", s.handleListCerts)
	s.mux.HandleFunc("POST /api/cards/{card_uuid}/certs", s.handleCreateCert)
	s.mux.HandleFunc("POST /api/cards/{card_uuid}/certs/import", s.handleImportCertWithKey)
	s.mux.HandleFunc("GET /api/cards/{card_uuid}/certs/{uuid}", s.handleGetCert)
	s.mux.HandleFunc("DELETE /api/cards/{card_uuid}/certs/{uuid}", s.handleDeleteCert)
	s.mux.HandleFunc("POST /api/cards/{card_uuid}/certs/{uuid}/export", s.handleExportCertKey)
	s.mux.HandleFunc("GET /api/cards/{card_uuid}/certs/{uuid}/detail", s.handleCertDetail)
	s.mux.HandleFunc("POST /api/cards/{card_uuid}/credentials", s.handleCreateCredential)

	// ---- 密钥操作 ----
	s.mux.HandleFunc("POST /api/cards/{card_uuid}/keygen", s.handleKeyGen)

	// ---- 日志查询 ----
	s.mux.HandleFunc("GET /api/logs", s.handleListLogs)

	// ---- 审计日志 ----
	s.mux.HandleFunc("GET /api/audit", s.handleListAuditLogs)
	s.mux.HandleFunc("GET /api/audit/verify", s.handleVerifyAuditIntegrity)

	// ---- Slot 状态 ----
	s.mux.HandleFunc("GET /api/slots", s.handleListSlots)

	// ---- TOTP 管理 ----
	s.mux.HandleFunc("GET /api/cards/{card_uuid}/totp", s.handleListTOTP)
	s.mux.HandleFunc("POST /api/cards/{card_uuid}/totp", s.handleCreateTOTP)
	s.mux.HandleFunc("GET /api/totp/{id}/code", s.handleGetTOTPCode)
	s.mux.HandleFunc("DELETE /api/totp/{id}", s.handleDeleteTOTP)

	// ---- 本地 PKI 工具 ----
	s.mux.HandleFunc("POST /api/pki/selfsign", s.handleSelfSign)
	s.mux.HandleFunc("POST /api/pki/convert", s.handleConvertCert)
	s.mux.HandleFunc("POST /api/pki/parse", s.handleParseCert)

	// CSR 管理
	s.mux.HandleFunc("GET /api/pki/csr", s.handleListCSR)
	s.mux.HandleFunc("POST /api/pki/csr", s.handleCreateCSR)
	s.mux.HandleFunc("GET /api/pki/csr/{uuid}", s.handleGetCSR)
	s.mux.HandleFunc("DELETE /api/pki/csr/{uuid}", s.handleDeleteCSR)
	s.mux.HandleFunc("GET /api/pki/csr/{uuid}/download", s.handleDownloadCSR)

	// CA 管理
	s.mux.HandleFunc("GET /api/pki/ca", s.handleListCA)
	s.mux.HandleFunc("POST /api/pki/ca", s.handleCreateCA)
	s.mux.HandleFunc("POST /api/pki/ca/import", s.handleImportCA)
	s.mux.HandleFunc("GET /api/pki/ca/{uuid}", s.handleGetCA)
	s.mux.HandleFunc("POST /api/pki/ca/{uuid}/revoke", s.handleRevokeCA)
	s.mux.HandleFunc("DELETE /api/pki/ca/{uuid}", s.handleDeleteCA)
	s.mux.HandleFunc("GET /api/pki/ca/{uuid}/export", s.handleExportCA)

	// 证书管理
	s.mux.HandleFunc("GET /api/pki/certs", s.handleListPKICerts)
	s.mux.HandleFunc("POST /api/pki/certs/issue", s.handleIssuePKICert)
	s.mux.HandleFunc("POST /api/pki/certs/selfsign", s.handleSelfSignFromCSR)
	s.mux.HandleFunc("POST /api/pki/certs/import", s.handleImportPKICert)
	s.mux.HandleFunc("GET /api/pki/certs/{uuid}", s.handleGetPKICert)
	s.mux.HandleFunc("DELETE /api/pki/certs/{uuid}", s.handleDeletePKICert)
	s.mux.HandleFunc("DELETE /api/pki/certs/{uuid}/key", s.handleDeletePKICertKey)
	s.mux.HandleFunc("POST /api/pki/certs/{uuid}/export", s.handleExportPKICert)
	s.mux.HandleFunc("POST /api/pki/certs/{uuid}/import-to-card", s.handleImportPKICertToCard)
	s.mux.HandleFunc("POST /api/pki/certs/{uuid}/revoke", s.handleRevokePKICert)

	// 证书传播（同步到操作系统证书存储）
	s.mux.HandleFunc("POST /api/pki/certs/propagate", s.handlePropagateCerts)

	// ---- 应用指标 ----
	s.mux.HandleFunc("GET /metrics", s.metrics.Handler())

	// ---- 云端同步 ----
	s.mux.HandleFunc("POST /api/cloud/sync", s.handleCloudSync)
	s.mux.HandleFunc("GET /api/cloud/status", s.handleCloudStatus)
	s.mux.HandleFunc("POST /api/cloud/deliver", s.handleCloudDeliver)

	// ---- Settings ----
	s.mux.HandleFunc("GET /api/settings", s.handleGetSettings)
	s.mux.HandleFunc("PUT /api/settings", s.handlePutSettings)

	// ---- 前端管理界面（静态文件）----
	// 所有非 /api/ 路径的请求都由前端 SPA 处理
	s.mux.Handle("/", ui.Handler())
}

// Handler 返回 HTTP 处理器，供测试使用。
func (s *Server) Handler() http.Handler {
	return s.buildMiddlewareChain(s.mux)
}

// buildMiddlewareChain 构建中间件链。
// 执行顺序（从外到内）：CORS -> 日志 -> 速率限制 -> 认证 -> RBAC -> 路由
func (s *Server) buildMiddlewareChain(handler http.Handler) http.Handler {
	// RBAC 权限控制
	handler = middleware.RBACMiddleware(handler)
	// 本地认证
	if s.authToken != nil {
		handler = s.authToken.Middleware(handler)
	}
	// 速率限制
	handler = s.rateLimiter.Middleware(handler)
	// 应用指标收集
	handler = middleware.MetricsMiddleware(s.metrics)(handler)
	// 结构化请求日志（含请求 ID）
	handler = middleware.StructuredLogMiddleware(handler)
	// CORS
	handler = corsMiddleware(handler)
	return handler
}

// AuthToken 返回当前认证 Token（供前端内嵌注入使用）。
func (s *Server) AuthToken() string {
	if s.authToken == nil {
		return ""
	}
	return s.authToken.Token()
}

// Start 启动 HTTP 服务。
func (s *Server) Start() error {
	handler := s.buildMiddlewareChain(s.mux)

	s.httpSrv = &http.Server{
		Addr:         s.cfg.Addr(),
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	slog.Info("REST API 服务已启动", "addr", s.cfg.Addr())

	go func() {
		var err error
		if s.cfg.TLSEnabled {
			err = s.httpSrv.ListenAndServeTLS(s.cfg.TLSCert, s.cfg.TLSKey)
		} else {
			err = s.httpSrv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			slog.Error("REST API 服务异常退出", "error", err)
		}
	}()

	return nil
}

// Stop 优雅关闭 HTTP 服务。
func (s *Server) Stop(ctx context.Context) error {
	if s.httpSrv == nil {
		return nil
	}
	return s.httpSrv.Shutdown(ctx)
}

// ---- 中间件 ----

// responseWriter 包装 http.ResponseWriter，捕获状态码。
type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(status int) {
	rw.status = status
	rw.ResponseWriter.WriteHeader(status)
}

// logMiddleware 记录请求日志（含状态码）。
func logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		slog.Debug("API 请求",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.status,
			"duration", time.Since(start),
			"remote", r.RemoteAddr,
		)
	})
}

// corsMiddleware 添加 CORS 头，允许前端跨域访问。
// 仅允许本地来源（127.0.0.1 / localhost），适合桌面应用场景。
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		// 只允许本地来源
		if isLocalOrigin(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		} else if origin == "" {
			// 非浏览器请求（如 curl、测试）直接放行
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Max-Age", "86400")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isLocalOrigin 判断是否为本地来源（localhost / 127.0.0.1）。
func isLocalOrigin(origin string) bool {
	if origin == "" {
		return false
	}
	for _, prefix := range []string{
		"http://localhost",
		"https://localhost",
		"http://127.0.0.1",
		"https://127.0.0.1",
	} {
		if len(origin) >= len(prefix) && origin[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

// ---- 健康检查 ----

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeOK(w, map[string]string{
		"status":  "ok",
		"version": "1.0.0",
		"time":    fmt.Sprintf("%d", time.Now().Unix()),
	})
}

// ---- Slot 状态 ----

func (s *Server) handleListSlots(w http.ResponseWriter, r *http.Request) {
	ids := s.manager.GetSlotList(false)
	type slotItem struct {
		SlotID      uint32 `json:"slot_id"`
		Description string `json:"description"`
		TokenPresent bool  `json:"token_present"`
	}

	items := make([]slotItem, 0, len(ids))
	for _, id := range ids {
		info, err := s.manager.GetSlotInfo(id)
		if err != nil {
			continue
		}
		items = append(items, slotItem{
			SlotID:       uint32(id),
			Description:  info.Description,
			TokenPresent: info.TokenPresent,
		})
	}
	writeOK(w, items)
}

// ---- 审计日志 ----

func (s *Server) handleListAuditLogs(w http.ResponseWriter, r *http.Request) {
	offset, limit := parsePagination(r)
	result, err := s.auditRepo.List(r.Context(), offset, limit)
	if err != nil {
		slog.Error("查询审计日志失败", "error", err)
		writeError(w, http.StatusInternalServerError, "查询审计日志失败")
		return
	}
	writeOK(w, result)
}

func (s *Server) handleVerifyAuditIntegrity(w http.ResponseWriter, r *http.Request) {
	ok, brokenAt, err := s.auditRepo.VerifyIntegrity(r.Context())
	if err != nil {
		slog.Error("验证审计日志完整性失败", "error", err)
		writeError(w, http.StatusInternalServerError, "验证失败")
		return
	}
	writeOK(w, map[string]interface{}{
		"integrity_ok": ok,
		"broken_at_id": brokenAt,
	})
}

// parsePagination 从查询参数中解析分页参数。
func parsePagination(r *http.Request) (offset, limit int) {
	offset = 0
	limit = 20
	if v := r.URL.Query().Get("offset"); v != "" {
		fmt.Sscanf(v, "%d", &offset)
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		fmt.Sscanf(v, "%d", &limit)
	}
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	return
}

// SetIPCBroadcaster 注入 IPC 事件广播回调。
// 由 cmd/client-card/main.go 在启动时调用 apiServer.SetIPCBroadcaster(ipcServer.BroadcastSlotChanged)，
// 之后任何新增/删除/同步卡片的 handler 都可以通过 s.notifySlotChanged() 广播变更事件。
// 若未调用该方法，notifySlotChanged 将静默跳过，不产生任何副作用。
func (s *Server) SetIPCBroadcaster(fn func(reason string)) {
	s.ipcBroadcast = fn
}

// notifySlotChanged 在卡片列表发生变化时广播 slot_changed 事件给所有 pkcs11-mock 客户端。
// reason 取值建议：create / delete / update / sync。
// 异步执行，不阻塞当前请求。
func (s *Server) notifySlotChanged(reason string) {
	if s.ipcBroadcast == nil {
		return
	}
	go s.ipcBroadcast(reason)
}

// SetCertPropagator 注入证书传播器。
// 由 cmd/client-card/main.go 在启动时调用。
func (s *Server) SetCertPropagator(p certprop.Propagator) {
	s.certPropagator = p
}

// propagateCertAdd 在证书新增/导入后，异步将证书传播到系统存储。
func (s *Server) propagateCertAdd(certPEM, certUUID, cardUUID, commonName, keyType string, hasKey bool) {
	if s.certPropagator == nil {
		return
	}
	go func() {
		err := s.certPropagator.Add(context.Background(), certprop.CertInfo{
			UUID:       certUUID,
			CardUUID:   cardUUID,
			CommonName: commonName,
			CertPEM:    certPEM,
			HasKey:     hasKey,
			KeyType:    keyType,
		})
		if err != nil {
			slog.Warn("证书传播到系统存储失败", "uuid", certUUID, "error", err)
		}
	}()
}

// propagateCertRemove 在证书删除后，异步从系统存储中移除。
func (s *Server) propagateCertRemove(certUUID string) {
	if s.certPropagator == nil {
		return
	}
	go func() {
		err := s.certPropagator.Remove(context.Background(), certUUID)
		if err != nil {
			slog.Warn("从系统存储移除证书失败", "uuid", certUUID, "error", err)
		}
	}()
}

// propagateCertAddDER 在智能卡证书导入后，异步将 DER 格式证书传播到系统存储。
func (s *Server) propagateCertAddDER(certDER []byte, certUUID, cardUUID, keyType string, hasKey bool) {
	if s.certPropagator == nil {
		return
	}
	go func() {
		err := s.certPropagator.Add(context.Background(), certprop.CertInfo{
			UUID:     certUUID,
			CardUUID: cardUUID,
			CertDER:  certDER,
			HasKey:   hasKey,
			KeyType:  keyType,
		})
		if err != nil {
			slog.Warn("证书传播到系统存储失败", "uuid", certUUID, "error", err)
		}
	}()
}