// Package middleware 提供 REST API 中间件。
package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Principal 表示通过认证的调用方身份。
type Principal struct {
	UserUUID  string
	Role      Role
	TokenType string
}

// SessionValidator 验证 session token 并返回调用方身份。
type SessionValidator func(token string) (Principal, bool)

// AuthToken 管理本地 API 认证 Token。
type AuthToken struct {
	token            string
	mu               sync.RWMutex
	filePath         string
	sessionValidator SessionValidator // 可选：验证用户登录 session token
}

// NewAuthToken 创建并初始化本地认证 Token。
// 启动时生成随机 Token 并写入受保护的本地文件（权限 0600）。
func NewAuthToken(dataDir string) (*AuthToken, error) {
	at := &AuthToken{
		filePath: filepath.Join(dataDir, ".api_token"),
	}

	// 生成 32 字节随机 Token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("生成认证 Token 失败: %w", err)
	}
	at.token = hex.EncodeToString(tokenBytes)

	// 写入文件，权限 0600（仅所有者可读写）
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("创建数据目录失败: %w", err)
	}
	if err := os.WriteFile(at.filePath, []byte(at.token), 0600); err != nil {
		return nil, fmt.Errorf("写入 Token 文件失败: %w", err)
	}

	slog.Info("本地认证 Token 已生成", "path", at.filePath)
	return at, nil
}

// SetSessionValidator 注入 session token 验证函数。
// 调用后，中间件会同时接受用户登录 session token 作为有效凭证。
func (at *AuthToken) SetSessionValidator(v SessionValidator) {
	at.mu.Lock()
	defer at.mu.Unlock()
	at.sessionValidator = v
}

// Token 返回当前认证 Token。
func (at *AuthToken) Token() string {
	at.mu.RLock()
	defer at.mu.RUnlock()
	return at.token
}

// Middleware 返回认证中间件。
// 检查 Authorization: Bearer <token> 头，支持：
//  1. 本地 API Token（启动时生成）
//  2. 用户登录 session token
func (at *AuthToken) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 跳过不需要认证的路径
		if IsPublicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// OPTIONS 预检请求跳过认证
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		principal, errMsg := at.authenticate(r.Header.Get("Authorization"))
		if errMsg != "" {
			writeUnauthorized(w, errMsg)
			return
		}

		ctx := SetUserContext(r.Context(), principal.UserUUID, principal.Role)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Protect 包装一个处理器，要求请求携带本地 API Token 或有效 session。
// 用于 /metrics 这类不在 /api/ 前缀下、因而不会被全局认证中间件覆盖的端点，
// 避免监控指标对同机任意进程（或改绑外网地址后的任意主机）完全开放。
func (at *AuthToken) Protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, errMsg := at.authenticate(r.Header.Get("Authorization")); errMsg != "" {
			writeUnauthorized(w, errMsg)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// authenticate 解析 Authorization 头并返回调用方身份。
// 返回的 errMsg 非空表示认证失败，由调用方写入 401 响应。
func (at *AuthToken) authenticate(authHeader string) (Principal, string) {
	if authHeader == "" {
		return Principal{}, "缺少 Authorization 头"
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return Principal{}, "Authorization 格式错误，期望 Bearer <token>"
	}
	token := parts[1]

	// 优先验证用户 session token
	at.mu.RLock()
	validator := at.sessionValidator
	at.mu.RUnlock()
	if validator != nil {
		if principal, ok := validator(token); ok {
			return principal, ""
		}
	}

	// 本地 API Token 仅代表受限的本机系统调用方，不授予用户角色。
	if token == at.Token() {
		return Principal{Role: RoleSystem, TokenType: "local"}, ""
	}
	return Principal{}, "Token 无效"
}

// IsPublicPath 判断是否为公开路径（不需要认证）。
// 公开路径同时也不受 RBAC 约束：认证中间件不会为它们注入用户角色，
// 若 RBAC 仍按 fail-closed 处理会把登录接口与前端静态资源一并拒绝。
func IsPublicPath(path string) bool {
	// 健康检查
	if path == "/api/health" {
		return true
	}
	// 认证接口（登录、注册等）
	if strings.HasPrefix(path, "/api/auth/") {
		return true
	}
	// 非 API 路径（前端静态资源）
	if !strings.HasPrefix(path, "/api/") {
		return true
	}
	return false
}

// CheckBindAddress 检查绑定地址是否安全。
// 如果不是 127.0.0.1，输出安全警告。
func CheckBindAddress(addr string) {
	if !strings.HasPrefix(addr, "127.0.0.1:") && !strings.HasPrefix(addr, "localhost:") {
		slog.Warn("⚠️ REST API 绑定到非本地地址，存在安全风险",
			"addr", addr,
			"建议", "生产环境请绑定到 127.0.0.1")
	}
}

func writeUnauthorized(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	fmt.Fprintf(w, `{"code":401,"message":"%s"}`, msg)
}
