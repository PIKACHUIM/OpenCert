// Package api 提供 servers 的 REST API 服务。
package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/globaltrusts/server-card/configs"
	"github.com/globaltrusts/server-card/internal/acme"
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
)

// Services 是所有业务服务的容器，用于简化 NewServer 参数列表。
type Services struct {
	CardSvc       *card.Service
	CASvc         *ca.Service
	IssuanceSvc   *issuance.Service
	VerifySvc     *verification.Service
	WorkflowSvc   *workflow.Service
	PaymentSvc    *payment.Service
	TmplSvc       *template.Service
	RevocationSvc *revocation.Service
	CTSvc         *ct.Service
	ACMESvc       *acme.Service
}

// Server 是 REST API 服务器。
type Server struct {
	cfg           *configs.Config
	httpServer    *http.Server
	db            *storage.DB
	jwtMgr        *auth.Manager
	cardSvc       *card.Service
	caSvc         *ca.Service
	issuanceSvc   *issuance.Service
	verifySvc     *verification.Service
	workflowSvc   *workflow.Service
	userRepo      *storage.UserRepo
	logRepo       *storage.LogRepo
	auditLogRepo  *storage.AuditLogRepo // 审计日志
	paymentSvc    *payment.Service
	tmplSvc       *template.Service
	revocationSvc *revocation.Service
	ctSvc         *ct.Service
	acmeSvc       *acme.Service
	pinSessions   *card.PINSessionStore // PIN 会话令牌存储
	mailer        mailer.Mailer         // 邮件发送器（找回密码等场景）
}

// SetMailer 注入邮件发送器（在服务装配阶段调用）。
func (s *Server) SetMailer(m mailer.Mailer) {
	s.mailer = m
}

// NewServer 创建 API 服务器。
func NewServer(cfg *configs.Config, db *storage.DB, jwtMgr *auth.Manager, svcs *Services, userRepo *storage.UserRepo, logRepo *storage.LogRepo) *Server {
	s := &Server{
		cfg:           cfg,
		db:            db,
		jwtMgr:        jwtMgr,
		cardSvc:       svcs.CardSvc,
		caSvc:         svcs.CASvc,
		issuanceSvc:   svcs.IssuanceSvc,
		verifySvc:     svcs.VerifySvc,
		workflowSvc:   svcs.WorkflowSvc,
		userRepo:      userRepo,
		logRepo:       logRepo,
		auditLogRepo:  storage.NewAuditLogRepo(db),
		paymentSvc:    svcs.PaymentSvc,
		tmplSvc:       svcs.TmplSvc,
		revocationSvc: svcs.RevocationSvc,
		ctSvc:         svcs.CTSvc,
		acmeSvc:       svcs.ACMESvc,
		pinSessions:   card.NewPINSessionStore(card.DefaultPINSessionTTL),
	}

	mux := http.NewServeMux()
	s.registerRoutes(mux)

	s.httpServer = &http.Server{
		Addr:         cfg.API.Addr(),
		Handler:      corsMiddleware(cfg, mux),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	return s
}

// corsMiddleware 处理跨域请求（CORS）。
// 从配置项 SERVER_CARD_ALLOWED_ORIGINS 读取允许的来源白名单。
func corsMiddleware(cfg *configs.Config, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && cfg.IsAllowedOrigin(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-ID, X-Token-Refresh")
			w.Header().Set("Access-Control-Expose-Headers", "X-Request-ID, X-Token-Refresh")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Max-Age", "86400")
		}

		// OPTIONS 预检请求直接返回 200，不继续处理
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// registerRoutes 注册所有路由。
func (s *Server) registerRoutes(mux *http.ServeMux) {
	// 门户首页（静态文件服务，无需认证）
	mux.HandleFunc("GET /", s.handlePortal)

	// 健康检查（无需认证）
	mux.HandleFunc("GET /api/health", s.handleHealth)

	// 认证（无需认证）
	mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	mux.HandleFunc("POST /api/auth/register", s.handleRegister)
	mux.HandleFunc("POST /api/auth/refresh", s.authMiddleware(s.handleRefresh))
	mux.HandleFunc("DELETE /api/auth/logout", s.authMiddleware(s.handleLogout))
	// 找回密码（无需认证）
	mux.HandleFunc("POST /api/auth/forgot-password", s.handleForgotPassword)
	mux.HandleFunc("POST /api/auth/reset-password", s.handleResetPassword)
	// TOTP 二次验证（无需认证，使用 session_token）
	mux.HandleFunc("POST /api/auth/totp-verify", s.handleTOTPVerify)

	// 用户管理（需要认证）
	mux.HandleFunc("GET /api/users/me", s.authMiddleware(s.handleGetProfile))
	mux.HandleFunc("PUT /api/users/me", s.authMiddleware(s.handleUpdateProfile))
	mux.HandleFunc("PUT /api/auth/password", s.authMiddleware(s.handleChangePassword))
	mux.HandleFunc("PUT /api/users/me/pubkey", s.authMiddleware(s.handleUpdatePublicKey))

	// 用户管理（管理员）
	mux.HandleFunc("GET /api/users", s.adminOnly(s.handleListUsers))
	mux.HandleFunc("POST /api/users", s.adminOnly(s.handleCreateUser))
	mux.HandleFunc("PUT /api/users/{uuid}", s.adminOnly(s.handleUpdateUser))
	mux.HandleFunc("DELETE /api/users/{uuid}", s.adminOnly(s.handleDeleteUser))
	mux.HandleFunc("PUT /api/users/{uuid}/role", s.adminOnly(s.handleUpdateUserRole))
	mux.HandleFunc("PUT /api/users/{uuid}/enabled", s.adminOnly(s.handleUpdateUserEnabled))

	// 操作日志查询（需要认证）
	mux.HandleFunc("GET /api/logs", s.authMiddleware(s.handleListLogs))

	// 卡片管理（读取需认证，写入需 user 以上角色）
	mux.HandleFunc("GET /api/cards", s.authMiddleware(s.handleListCards))
	mux.HandleFunc("POST /api/cards", s.writeOnly(s.handleCreateCard))
	mux.HandleFunc("GET /api/cards/{uuid}", s.authMiddleware(s.handleGetCard))
	mux.HandleFunc("DELETE /api/cards/{uuid}", s.writeOnly(s.handleDeleteCard))

	// 证书管理（读取需认证，写入需 user 以上角色）
	mux.HandleFunc("GET /api/cards/{uuid}/certs", s.authMiddleware(s.handleListCerts))
	mux.HandleFunc("POST /api/cards/{uuid}/certs", s.writeOnly(s.handleImportCert))
	mux.HandleFunc("DELETE /api/cards/{uuid}/certs/{cert_uuid}", s.writeOnly(s.handleDeleteCert))

	// 证书增强管理（筛选查询、吊销、分配、续期、导出）
	mux.HandleFunc("GET /api/certs", s.authMiddleware(s.handleListCertsFiltered))
	mux.HandleFunc("POST /api/certs/{uuid}/revoke", s.adminOnly(s.handleRevokeCertByUUID))
	mux.HandleFunc("POST /api/certs/{uuid}/assign", s.adminOnly(s.handleAssignCertToCard))
	mux.HandleFunc("POST /api/certs/{uuid}/renew", s.authMiddleware(s.handleRenewCert))
	mux.HandleFunc("GET /api/certs/{uuid}/export", s.authMiddleware(s.handleExportCert))
	mux.HandleFunc("GET /api/certs/{uuid}/chain", s.authMiddleware(s.handleGetCertChain))
	mux.HandleFunc("GET /api/certs/{uuid}/chain-view", s.authMiddleware(s.handleGetCertChainView))

	// 卡片 PIN/PUK/Admin Key 管理（需要认证）
	mux.HandleFunc("POST /api/cards/{uuid}/verify-pin", s.authMiddleware(s.handleVerifyPIN))
	mux.HandleFunc("DELETE /api/cards/{uuid}/pin-session", s.authMiddleware(s.handleLogoutPINSession))
	mux.HandleFunc("POST /api/cards/{uuid}/unlock-puk", s.authMiddleware(s.handleUnlockWithPUK))
	mux.HandleFunc("POST /api/cards/{uuid}/reset-admin", s.authMiddleware(s.handleResetWithAdminKey))

	// 密钥生成（需要认证）
	mux.HandleFunc("POST /api/cards/{uuid}/keygen", s.authMiddleware(s.handleKeyGen))

	// 云端签名/解密（需要认证）
	mux.HandleFunc("POST /api/cards/{uuid}/sign", s.authMiddleware(s.handleSign))
	mux.HandleFunc("POST /api/cards/{uuid}/decrypt", s.authMiddleware(s.handleDecrypt))

	// 支付系统（需要认证）
	mux.HandleFunc("POST /api/payment/recharge", s.authMiddleware(s.handleCreateRecharge))
	mux.HandleFunc("GET /api/payment/orders", s.authMiddleware(s.handleListOrders))
	mux.HandleFunc("GET /api/payment/balance", s.authMiddleware(s.handleGetBalance))
	mux.HandleFunc("POST /api/payment/refund", s.authMiddleware(s.handleCreateRefund))
	// 支付回调（无需认证，由支付平台调用，内部验签）
	mux.HandleFunc("POST /api/payment/callback/{channel}", s.handlePaymentCallback)

	// 支付插件管理（管理员）
	mux.HandleFunc("GET /api/payment/plugins", s.adminOnly(s.handleListPaymentPlugins))
	mux.HandleFunc("POST /api/payment/plugins", s.adminOnly(s.handleCreatePaymentPlugin))
	mux.HandleFunc("PUT /api/payment/plugins/{uuid}", s.adminOnly(s.handleUpdatePaymentPlugin))
	mux.HandleFunc("DELETE /api/payment/plugins/{uuid}", s.adminOnly(s.handleDeletePaymentPlugin))

	// 退款审批（管理员）
	mux.HandleFunc("GET /api/payment/refunds", s.adminOnly(s.handleListRefunds))
	mux.HandleFunc("POST /api/payment/refund/{uuid}/approve", s.adminOnly(s.handleApproveRefund))
	mux.HandleFunc("POST /api/payment/refund/{uuid}/reject", s.adminOnly(s.handleRejectRefund))

	// 密钥存储类型模板（读取需认证，写入需管理员）
	mux.HandleFunc("GET /api/templates/key-storage", s.authMiddleware(s.handleListKeyStorageTemplates))
	mux.HandleFunc("POST /api/templates/key-storage", s.adminOnly(s.handleCreateKeyStorageTemplate))
	mux.HandleFunc("GET /api/templates/key-storage/{uuid}", s.authMiddleware(s.handleGetKeyStorageTemplate))
	mux.HandleFunc("PUT /api/templates/key-storage/{uuid}", s.adminOnly(s.handleUpdateKeyStorageTemplate))
	mux.HandleFunc("DELETE /api/templates/key-storage/{uuid}", s.adminOnly(s.handleDeleteKeyStorageTemplate))

	// CA 管理（读取需认证，写入需管理员）
	mux.HandleFunc("GET /api/cas", s.authMiddleware(s.handleListCAs))
	mux.HandleFunc("POST /api/cas", s.adminOnly(s.handleCreateCA))
	mux.HandleFunc("POST /api/cas/import", s.adminOnly(s.handleImportCA))
	mux.HandleFunc("GET /api/cas/{uuid}", s.authMiddleware(s.handleGetCA))
	mux.HandleFunc("PUT /api/cas/{uuid}", s.adminOnly(s.handleUpdateCA))
	mux.HandleFunc("DELETE /api/cas/{uuid}", s.adminOnly(s.handleDeleteCA))
	mux.HandleFunc("POST /api/cas/{uuid}/import-chain", s.adminOnly(s.handleImportCAChain))
	mux.HandleFunc("GET /api/cas/{uuid}/chain", s.authMiddleware(s.handleGetCAChain))
	mux.HandleFunc("GET /api/cas/{uuid}/chain-view", s.authMiddleware(s.handleGetCAChainView))
	mux.HandleFunc("GET /api/cas/{uuid}/revoked", s.authMiddleware(s.handleListRevokedCerts))
	mux.HandleFunc("POST /api/cas/{uuid}/revoke", s.adminOnly(s.handleRevokeCert))
	mux.HandleFunc("GET /api/cas/{uuid}/crl", s.handleGetCRL)
	mux.HandleFunc("POST /api/cas/{uuid}/issue", s.adminOnly(s.handleIssueCert))

	// 证书颁发模板管理（读取需认证，写入需管理员）
	mux.HandleFunc("GET /api/templates/issuance", s.authMiddleware(s.handleListIssuanceTemplates))
	mux.HandleFunc("POST /api/templates/issuance", s.adminOnly(s.handleCreateIssuanceTemplate))
	mux.HandleFunc("GET /api/templates/issuance/{uuid}", s.authMiddleware(s.handleGetIssuanceTemplate))
	mux.HandleFunc("PUT /api/templates/issuance/{uuid}", s.adminOnly(s.handleUpdateIssuanceTemplate))
	mux.HandleFunc("DELETE /api/templates/issuance/{uuid}", s.adminOnly(s.handleDeleteIssuanceTemplate))

	// 主体模板管理（管理员）
	mux.HandleFunc("GET /api/templates/subject", s.authMiddleware(s.handleListSubjectTemplates))
	mux.HandleFunc("POST /api/templates/subject", s.adminOnly(s.handleCreateSubjectTemplate))
	mux.HandleFunc("DELETE /api/templates/subject/{uuid}", s.adminOnly(s.handleDeleteSubjectTemplate))

	// 扩展信息模板管理（管理员）
	mux.HandleFunc("GET /api/templates/extension", s.authMiddleware(s.handleListExtensionTemplates))
	mux.HandleFunc("POST /api/templates/extension", s.adminOnly(s.handleCreateExtensionTemplate))
	mux.HandleFunc("DELETE /api/templates/extension/{uuid}", s.adminOnly(s.handleDeleteExtensionTemplate))

	// 密钥用途模板管理（管理员）
	mux.HandleFunc("GET /api/templates/key-usage", s.authMiddleware(s.handleListKeyUsageTemplates))
	mux.HandleFunc("POST /api/templates/key-usage", s.adminOnly(s.handleCreateKeyUsageTemplate))
	mux.HandleFunc("DELETE /api/templates/key-usage/{uuid}", s.adminOnly(s.handleDeleteKeyUsageTemplate))

	// 证书拓展模板管理（管理员）
	mux.HandleFunc("GET /api/templates/cert-ext", s.authMiddleware(s.handleListCertExtTemplates))
	mux.HandleFunc("POST /api/templates/cert-ext", s.adminOnly(s.handleCreateCertExtTemplate))
	mux.HandleFunc("DELETE /api/templates/cert-ext/{uuid}", s.adminOnly(s.handleDeleteCertExtTemplate))

	// 审计日志查询（管理员）
	mux.HandleFunc("GET /api/audit-logs", s.adminOnly(s.handleListAuditLogs))

	// 证书申请模板管理（管理员）
	mux.HandleFunc("GET /api/templates/cert-apply", s.authMiddleware(s.handleListCertApplyTemplates))
	mux.HandleFunc("POST /api/templates/cert-apply", s.adminOnly(s.handleCreateCertApplyTemplate))
	mux.HandleFunc("GET /api/templates/cert-apply/{uuid}", s.authMiddleware(s.handleGetCertApplyTemplate))
	mux.HandleFunc("PUT /api/templates/cert-apply/{uuid}", s.adminOnly(s.handleUpdateCertApplyTemplate))
	mux.HandleFunc("DELETE /api/templates/cert-apply/{uuid}", s.adminOnly(s.handleDeleteCertApplyTemplate))

	// 存储区域管理（管理员）
	mux.HandleFunc("GET /api/storage-zones", s.authMiddleware(s.handleListStorageZones))
	mux.HandleFunc("POST /api/storage-zones", s.adminOnly(s.handleCreateStorageZone))
	mux.HandleFunc("DELETE /api/storage-zones/{uuid}", s.adminOnly(s.handleDeleteStorageZone))

	// OID 管理（管理员）
	mux.HandleFunc("GET /api/oids", s.authMiddleware(s.handleListOIDs))
	mux.HandleFunc("POST /api/oids", s.adminOnly(s.handleCreateOID))
	mux.HandleFunc("DELETE /api/oids/{uuid}", s.adminOnly(s.handleDeleteOID))

	// 元数据接口（静态预置数据，需要认证即可访问）
	mux.HandleFunc("GET /api/meta/subject-fields", s.authMiddleware(s.handleGetSubjectFields))
	mux.HandleFunc("GET /api/meta/predefined-oids", s.authMiddleware(s.handleGetPredefinedOIDs))
	mux.HandleFunc("GET /api/meta/predefined-oids/categories", s.authMiddleware(s.handleListOIDCategories))
	mux.HandleFunc("GET /api/meta/algorithms", s.authMiddleware(s.handleGetAlgorithms))

	// 云端 TOTP 管理（需要认证）- 路径统一为 /api/cloud-totp
	mux.HandleFunc("GET /api/cloud-totp", s.authMiddleware(s.handleListUserTOTPs))
	mux.HandleFunc("POST /api/cloud-totp", s.writeOnly(s.handleCreateUserTOTP))
	mux.HandleFunc("GET /api/cloud-totp/{uuid}/code", s.authMiddleware(s.handleGetTOTPCode))
	mux.HandleFunc("DELETE /api/cloud-totp/{uuid}", s.writeOnly(s.handleDeleteUserTOTP))

	// 登录 TOTP 自主绑定（users.totp_secret）：与云端 TOTP 管理不同，这是登录二次验证
	mux.HandleFunc("GET /api/user/login-totp/status", s.authMiddleware(s.handleLoginTOTPStatus))
	mux.HandleFunc("POST /api/user/login-totp/generate", s.authMiddleware(s.handleGenerateLoginTOTP))
	mux.HandleFunc("POST /api/user/login-totp/bind", s.authMiddleware(s.handleBindLoginTOTP))
	mux.HandleFunc("DELETE /api/user/login-totp", s.authMiddleware(s.handleUnbindLoginTOTP))

	// 主体信息管理（需要认证）
	mux.HandleFunc("GET /api/subject-infos", s.authMiddleware(s.handleListSubjectInfos))
	mux.HandleFunc("POST /api/subject-infos", s.writeOnly(s.handleCreateSubjectInfo))
	mux.HandleFunc("DELETE /api/subject-infos/{uuid}", s.writeOnly(s.handleDeleteSubjectInfo))
	mux.HandleFunc("POST /api/subject-infos/{uuid}/approve", s.adminOnly(s.handleApproveSubjectInfo))
	mux.HandleFunc("POST /api/subject-infos/{uuid}/reject", s.adminOnly(s.handleRejectSubjectInfo))

	// 扩展信息验证（需要认证）
	mux.HandleFunc("GET /api/extension-infos", s.authMiddleware(s.handleListExtensionInfos))
	mux.HandleFunc("POST /api/extension-infos", s.writeOnly(s.handleCreateExtensionInfo))
	mux.HandleFunc("POST /api/extension-infos/{uuid}/verify-dns", s.authMiddleware(s.handleVerifyDNS))
	mux.HandleFunc("POST /api/extension-infos/{uuid}/verify-email", s.authMiddleware(s.handleVerifyEmail))
	mux.HandleFunc("POST /api/extension-infos/{uuid}/verify-http", s.authMiddleware(s.handleVerifyHTTP))
	mux.HandleFunc("DELETE /api/extension-infos/{uuid}", s.writeOnly(s.handleDeleteExtensionInfo))

	// 证书订单与申请（需要认证）
	mux.HandleFunc("POST /api/cert-orders", s.writeOnly(s.handleCreateCertOrder))
	mux.HandleFunc("GET /api/cert-orders", s.authMiddleware(s.handleListCertOrders))
	mux.HandleFunc("GET /api/cert-orders/{uuid}", s.authMiddleware(s.handleGetCertOrder))
	mux.HandleFunc("POST /api/cert-orders/{uuid}/pay", s.writeOnly(s.handlePayCertOrder))
	mux.HandleFunc("POST /api/cert-orders/{uuid}/cancel", s.writeOnly(s.handleCancelCertOrder))
	mux.HandleFunc("POST /api/cert-applications", s.writeOnly(s.handleCreateCertApplication))
	mux.HandleFunc("GET /api/cert-applications", s.authMiddleware(s.handleListCertApplications))
	mux.HandleFunc("POST /api/cert-applications/{uuid}/approve", s.operatorOnly(s.handleApproveCertApplication))
	mux.HandleFunc("POST /api/cert-applications/{uuid}/reject", s.operatorOnly(s.handleRejectCertApplication))

	// 公开服务路由（无需认证，供外部客户端访问）
	mux.HandleFunc("GET /crl/{caUUID}", s.handlePublicCRL)
	mux.HandleFunc("POST /ocsp/{caUUID}", s.handlePublicOCSP)
	mux.HandleFunc("GET /ocsp/{caUUID}", s.handlePublicOCSP)
	mux.HandleFunc("GET /ca/{caUUID}", s.handlePublicCAIssuer)
	// 自定义路径的吊销服务路由（通过 revocation_services 表配置）
	mux.HandleFunc("GET /pki/crl/{path}", s.handlePublicCRLByPath)
	mux.HandleFunc("POST /pki/ocsp/{path}", s.handlePublicOCSPByPath)
	mux.HandleFunc("GET /pki/ocsp/{path}", s.handlePublicOCSPByPath)
	mux.HandleFunc("GET /pki/ca/{path}", s.handlePublicCAIssuerByPath)
	mux.HandleFunc("GET /acme/{path}/directory", s.handleACMEDirectory)
	mux.HandleFunc("HEAD /acme/{path}/new-nonce", s.handleACMENewNonce)
	// ACME 完整协议路由
	mux.HandleFunc("POST /acme/{path}/new-account", s.handleACMENewAccount)
	mux.HandleFunc("POST /acme/{path}/new-order", s.handleACMENewOrder)
	mux.HandleFunc("POST /acme/{path}/acct/{id}", s.handleACMEGetAccount)
	mux.HandleFunc("POST /acme/{path}/order/{id}", s.handleACMEGetOrder)
	mux.HandleFunc("POST /acme/{path}/authz/{id}", s.handleACMEGetAuthorization)
	mux.HandleFunc("POST /acme/{path}/chall/{id}", s.handleACMEChallenge)
	mux.HandleFunc("POST /acme/{path}/finalize/{id}", s.handleACMEFinalize)
	mux.HandleFunc("POST /acme/{path}/cert/{id}", s.handleACMEGetCertificate)
	mux.HandleFunc("POST /ct/submit", s.handleCTSubmit)
	mux.HandleFunc("GET /ct/query", s.handleCTQuery)

	// 公开证书申请（无需认证，门户用户可直接提交）
	mux.HandleFunc("POST /api/public/cert-applications", s.handlePublicCreateCertApplication)
	mux.HandleFunc("GET /api/public/cert-applications/{uuid}", s.handlePublicGetCertApplicationStatus)

	// 吊销服务管理（管理员）
	mux.HandleFunc("GET /api/revocation-services", s.adminOnly(s.handleListRevocationServices))
	mux.HandleFunc("POST /api/revocation-services", s.adminOnly(s.handleCreateRevocationService))
	mux.HandleFunc("DELETE /api/revocation-services/{uuid}", s.adminOnly(s.handleDeleteRevocationService))

	// ACME 配置管理（管理员）
	mux.HandleFunc("GET /api/acme-configs", s.adminOnly(s.handleListACMEConfigs))
	mux.HandleFunc("POST /api/acme-configs", s.adminOnly(s.handleCreateACMEConfig))
	mux.HandleFunc("DELETE /api/acme-configs/{uuid}", s.adminOnly(s.handleDeleteACMEConfig))

	// CT 记录管理（需要认证）
	mux.HandleFunc("GET /api/ct-entries", s.authMiddleware(s.handleListCTEntries))
	mux.HandleFunc("DELETE /api/ct-entries/{uuid}", s.adminOnly(s.handleDeleteCTEntry))
}

// Start 启动 HTTP 服务。
func (s *Server) Start() error {
	slog.Info("servers API 服务启动", "addr", s.cfg.API.Addr())
	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("API 服务异常退出", "error", err)
		}
	}()
	return nil
}

// Stop 优雅关闭 HTTP 服务。
func (s *Server) Stop(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

// ---- 认证中间件 ----

// authMiddleware 验证 JWT Token，将 Claims 注入 context。
func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := extractBearerToken(r)
		if token == "" {
			writeError(w, http.StatusUnauthorized, "缺少认证 Token")
			return
		}

		claims, err := s.jwtMgr.Verify(token)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "Token 无效或已过期")
			return
		}

		// 检查 Token 是否即将过期，提示客户端刷新
		if s.jwtMgr.NeedsRefresh(claims) {
			w.Header().Set("X-Token-Refresh", "true")
		}

		ctx := context.WithValue(r.Context(), claimsKey{}, claims)
		next(w, r.WithContext(ctx))
	}
}

// adminOnly 仅允许 super_admin 或 admin 角色访问的中间件。
func (s *Server) adminOnly(next http.HandlerFunc) http.HandlerFunc {
	return s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		claims := claimsFromCtx(r.Context())
		if !auth.IsAdmin(claims.Role) {
			writeError(w, http.StatusForbidden, "需要管理员权限")
			return
		}
		next(w, r)
	})
}

// operatorOnly 仅允许 super_admin/admin/operator 角色访问的中间件。
func (s *Server) operatorOnly(next http.HandlerFunc) http.HandlerFunc {
	return s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		claims := claimsFromCtx(r.Context())
		if !auth.IsOperatorOrAbove(claims.Role) {
			writeError(w, http.StatusForbidden, "需要操作员或以上权限")
			return
		}
		next(w, r)
	})
}

// writeOnly 仅允许非 readonly 角色访问（readonly 被拒绝），需先经过 authMiddleware。
func (s *Server) writeOnly(next http.HandlerFunc) http.HandlerFunc {
	return s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		claims := claimsFromCtx(r.Context())
		if !auth.CanWrite(claims.Role) {
			writeError(w, http.StatusForbidden, "只读用户无权执行此操作")
			return
		}
		next(w, r)
	})
}

// checkPINSession 校验 X-PIN-Session 令牌与当前卡片 UUID 和用户 UUID 是否匹配。
// 校验失败时写回 401，并返回 false；若卡片未设置 PIN（即未启用 PIN 保护）则直接放行。
// 注意：需在 authMiddleware 之后调用，ctx 中必须已有 claims。
func (s *Server) checkPINSession(w http.ResponseWriter, r *http.Request, cardUUID string) bool {
	claims := claimsFromCtx(r.Context())

	// 若卡片未设置 PIN，跳过校验（兼容历史卡片）
	c, err := s.cardSvc.GetCard(r.Context(), cardUUID, claims.UserUUID)
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return false
	}
	if len(c.PINData) == 0 {
		return true
	}

	token := r.Header.Get("X-PIN-Session")
	if _, err := s.pinSessions.Verify(token, cardUUID, claims.UserUUID); err != nil {
		w.Header().Set("X-PIN-Required", "true")
		writeError(w, http.StatusUnauthorized, err.Error())
		return false
	}
	return true
}

// ---- 工具函数 ----

type claimsKey struct{}

func claimsFromCtx(ctx context.Context) *auth.Claims {
	return ctx.Value(claimsKey{}).(*auth.Claims)
}

func extractBearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return h[7:]
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// scheme 返回请求的协议（http 或 https）。
func scheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		return proto
	}
	return "http"
}