package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/globaltrusts/client-card/internal/storage"
)

// ---- Session 管理（内存存储）----

// session 表示一个登录会话。
type session struct {
	UserUUID  string
	Username  string
	Role      string
	ExpiresAt time.Time
}

var (
	sessionMu sync.RWMutex
	sessions  = make(map[string]*session) // token -> session
)

// newSessionToken 生成随机 Token 并存储 session。
func newSessionToken(u *storage.User) string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	token := hex.EncodeToString(b)

	sessionMu.Lock()
	sessions[token] = &session{
		UserUUID:  u.UUID,
		Username:  u.Username,
		Role:      u.Role,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	sessionMu.Unlock()
	return token
}

// getSession 根据 Token 获取 session（自动过期清理）。
func getSession(token string) *session {
	sessionMu.RLock()
	s, ok := sessions[token]
	sessionMu.RUnlock()
	if !ok || time.Now().After(s.ExpiresAt) {
		sessionMu.Lock()
		delete(sessions, token)
		sessionMu.Unlock()
		return nil
	}
	return s
}

// deleteSession 删除 session（登出）。
func deleteSession(token string) {
	sessionMu.Lock()
	delete(sessions, token)
	sessionMu.Unlock()
}

// isValidSession 检查 token 是否为有效的登录 session（供中间件使用）。
func isValidSession(token string) bool {
	return getSession(token) != nil
}

// authTokenResponse 是登录/注册成功的响应体。
type authTokenResponse struct {
	Token     string `json:"token"`
	UserUUID  string `json:"user_uuid"`
	Username  string `json:"username"`
	Role      string `json:"role"`
	ExpiresAt string `json:"expires_at"`
}

// ---- 登录 POST /api/auth/login ----

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		TOTPCode string `json:"totp_code"` // 2FA 验证码（启用 2FA 时必填）
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	if req.Username == "" {
		writeError(w, http.StatusBadRequest, "用户名不能为空")
		return
	}

	user, err := s.userRepo.GetByUsername(r.Context(), req.Username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "查询用户失败")
		return
	}
	if user == nil {
		writeError(w, http.StatusUnauthorized, "用户名或密码错误")
		return
	}

	// 免密码登录模式：只验证 2FA，不验证密码
	if user.PasswordlessEnabled && user.TwoFAEnabled {
		if req.TOTPCode == "" {
			// 返回特殊状态码告知前端需要 2FA 验证码
			writeJSON(w, http.StatusPreconditionRequired, Response{
				Code:    428,
				Message: "需要 2FA 验证码（免密码模式）",
				Data: map[string]interface{}{
					"require_2fa":  true,
					"passwordless": true,
				},
			})
			return
		}
		if !s.verifyTOTP(user.TwoFASecret, req.TOTPCode) {
			writeError(w, http.StatusUnauthorized, "2FA 验证码错误")
			return
		}
	} else {
		// 标准模式：必须验证密码
		if req.Password == "" {
			writeError(w, http.StatusBadRequest, "密码不能为空")
			return
		}
		if !verifyPassword(req.Password, user.PasswordHash) {
			writeError(w, http.StatusUnauthorized, "用户名或密码错误")
			return
		}

		// 2FA 启用时还需验证 TOTP 码
		if user.TwoFAEnabled {
			if req.TOTPCode == "" {
				// 密码正确，但需要 2FA
				writeJSON(w, http.StatusPreconditionRequired, Response{
					Code:    428,
					Message: "需要 2FA 验证码",
					Data: map[string]interface{}{
						"require_2fa":  true,
						"passwordless": false,
					},
				})
				return
			}
			if !s.verifyTOTP(user.TwoFASecret, req.TOTPCode) {
				writeError(w, http.StatusUnauthorized, "2FA 验证码错误")
				return
			}
		}
	}

	if !user.Enabled {
		writeError(w, http.StatusForbidden, "账号已被禁用")
		return
	}

	token := newSessionToken(user)
	writeOK(w, authTokenResponse{
		Token:     token,
		UserUUID:  user.UUID,
		Username:  user.Username,
		Role:      user.Role,
		ExpiresAt: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	})
}

// ---- 注册 POST /api/auth/register ----

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username    string `json:"username"`
		Password    string `json:"password"`
		Email       string `json:"email"`
		DisplayName string `json:"display_name"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	if req.Username == "" || req.Password == "" || req.DisplayName == "" {
		writeError(w, http.StatusBadRequest, "username、password、display_name 不能为空")
		return
	}
	if len(req.Username) < 3 {
		writeError(w, http.StatusBadRequest, "用户名至少3位")
		return
	}
	if len(req.Password) < 8 {
		writeError(w, http.StatusBadRequest, "密码至少8位")
		return
	}

	// 检查用户名是否已存在
	existing, err := s.userRepo.GetByUsername(r.Context(), req.Username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "查询用户失败")
		return
	}
	if existing != nil {
		writeError(w, http.StatusConflict, "用户名已存在")
		return
	}

	hash, err := hashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "密码处理失败")
		return
	}

	user := &storage.User{
		UserType:     storage.UserTypeLocal,
		Role:         "user",
		Username:     req.Username,
		DisplayName:  req.DisplayName,
		Email:        req.Email,
		Enabled:      true,
		PasswordHash: hash,
	}
	if err := s.userRepo.Create(r.Context(), user); err != nil {
		writeError(w, http.StatusInternalServerError, "创建用户失败: "+err.Error())
		return
	}

	token := newSessionToken(user)
	writeJSON(w, http.StatusCreated, Response{Code: 0, Message: "ok", Data: authTokenResponse{
		Token:     token,
		UserUUID:  user.UUID,
		Username:  user.Username,
		Role:      user.Role,
		ExpiresAt: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	}})
}

// ---- 刷新 Token POST /api/auth/refresh ----

func (s *Server) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	token := extractBearerToken(r)
	if token == "" {
		writeError(w, http.StatusUnauthorized, "缺少 Token")
		return
	}
	sess := getSession(token)
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "Token 无效或已过期")
		return
	}

	user, err := s.userRepo.GetByUUID(r.Context(), sess.UserUUID)
	if err != nil || user == nil {
		writeError(w, http.StatusUnauthorized, "用户不存在")
		return
	}

	// 删除旧 Token，生成新 Token
	deleteSession(token)
	newToken := newSessionToken(user)
	writeOK(w, authTokenResponse{
		Token:     newToken,
		UserUUID:  user.UUID,
		Username:  user.Username,
		Role:      user.Role,
		ExpiresAt: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	})
}

// ---- 登出 DELETE /api/auth/logout ----

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	token := extractBearerToken(r)
	if token != "" {
		deleteSession(token)
	}
	writeOK(w, nil)
}

// ---- 修改密码 PUT /api/auth/password ----

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	token := extractBearerToken(r)
	sess := getSession(token)
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "未登录")
		return
	}

	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	if len(req.NewPassword) < 8 {
		writeError(w, http.StatusBadRequest, "新密码至少8位")
		return
	}

	user, err := s.userRepo.GetByUUID(r.Context(), sess.UserUUID)
	if err != nil || user == nil {
		writeError(w, http.StatusUnauthorized, "用户不存在")
		return
	}
	if !verifyPassword(req.OldPassword, user.PasswordHash) {
		writeError(w, http.StatusUnauthorized, "原密码错误")
		return
	}

	hash, err := hashPassword(req.NewPassword)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "密码处理失败")
		return
	}
	user.PasswordHash = hash
	if err := s.userRepo.Update(r.Context(), user); err != nil {
		writeError(w, http.StatusInternalServerError, "更新密码失败")
		return
	}
	writeOK(w, nil)
}

// ---- 获取当前用户 GET /api/users/me ----

func (s *Server) handleGetMe(w http.ResponseWriter, r *http.Request) {
	token := extractBearerToken(r)
	sess := getSession(token)
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "未登录")
		return
	}

	user, err := s.userRepo.GetByUUID(r.Context(), sess.UserUUID)
	if err != nil || user == nil {
		writeError(w, http.StatusUnauthorized, "用户不存在")
		return
	}
	writeOK(w, user)
}

// ---- 更新当前用户 PUT /api/users/me ----

func (s *Server) handleUpdateMe(w http.ResponseWriter, r *http.Request) {
	token := extractBearerToken(r)
	sess := getSession(token)
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "未登录")
		return
	}

	user, err := s.userRepo.GetByUUID(r.Context(), sess.UserUUID)
	if err != nil || user == nil {
		writeError(w, http.StatusUnauthorized, "用户不存在")
		return
	}

	var req struct {
		DisplayName string `json:"display_name"`
		Email       string `json:"email"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	if req.DisplayName != "" {
		user.DisplayName = req.DisplayName
	}
	if req.Email != "" {
		user.Email = req.Email
	}
	if err := s.userRepo.Update(r.Context(), user); err != nil {
		writeError(w, http.StatusInternalServerError, "更新用户失败")
		return
	}
	writeOK(w, user)
}

// extractBearerToken 从请求头提取 Bearer Token。
func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if len(auth) > 7 && auth[:7] == "Bearer " {
		return auth[7:]
	}
	return ""
}

// ---- 多账号：云端登录与全量登出 ----

// cloudLoginDoer 抽象出"POST 云端 /api/auth/login"的行为，方便单元测试注入 mock。
// 默认实现基于 net/http，单测可通过 SetCloudLoginDoer 注入自定义实现。
type cloudLoginDoer func(ctx context.Context, cloudURL, username, password string) (*cloudLoginResp, error)

// cloudLoginResp 是云端 /api/auth/login 响应体。
// 兼容 {token,user_uuid,username,role} 和被 {code,message,data} 包裹两种格式。
type cloudLoginResp struct {
	Token    string `json:"token"`
	UserUUID string `json:"user_uuid"`
	Username string `json:"username"`
	Role     string `json:"role"`
}

// defaultCloudLoginDoer 通过 HTTP 真实请求云端。
func defaultCloudLoginDoer(ctx context.Context, cloudURL, username, password string) (*cloudLoginResp, error) {
	if cloudURL == "" {
		return nil, fmt.Errorf("cloud_url 不能为空")
	}
	body, err := json.Marshal(map[string]string{"username": username, "password": password})
	if err != nil {
		return nil, err
	}
	url := strings.TrimRight(cloudURL, "/") + "/api/auth/login"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("连接云端失败: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取云端响应失败: %w", err)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("云端拒绝登录 [%d]: %s", resp.StatusCode, string(data))
	}

	// 优先尝试 {code,message,data} 包裹
	var wrapper struct {
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Data    *cloudLoginResp `json:"data"`
	}
	if err := json.Unmarshal(data, &wrapper); err == nil && wrapper.Data != nil && wrapper.Data.Token != "" {
		if wrapper.Code != 0 {
			return nil, fmt.Errorf("云端响应错误: %s", wrapper.Message)
		}
		return wrapper.Data, nil
	}
	// 否则按扁平结构解析
	var flat cloudLoginResp
	if err := json.Unmarshal(data, &flat); err != nil {
		return nil, fmt.Errorf("解析云端响应失败: %w", err)
	}
	if flat.Token == "" {
		return nil, fmt.Errorf("云端未返回 token")
	}
	return &flat, nil
}

// cloudLoginDoerHolder 使用原子变量持有当前 doer，便于单测替换后恢复。
var cloudLoginDoerHolder cloudLoginDoer = defaultCloudLoginDoer

// SetCloudLoginDoer 允许单元测试注入自定义云端登录实现，返回旧实现用于还原。
func SetCloudLoginDoer(d cloudLoginDoer) cloudLoginDoer {
	old := cloudLoginDoerHolder
	if d != nil {
		cloudLoginDoerHolder = d
	}
	return old
}

// handleCloudLogin POST /api/auth/cloud-login
// 接收 {cloud_url, username, password}，调用云端登录后，
// 把账号以 UserType=cloud 形式落到本地 users 表（以 cloud_url|username 去重），
// 并生成一个本地 session token 返回，供多账号 Store 使用。
func (s *Server) handleCloudLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CloudURL string `json:"cloud_url"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	req.CloudURL = strings.TrimSpace(req.CloudURL)
	req.Username = strings.TrimSpace(req.Username)
	if req.CloudURL == "" || req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "cloud_url、username、password 不能为空")
		return
	}

	// 调用云端登录
	cloud, err := cloudLoginDoerHolder(r.Context(), req.CloudURL, req.Username, req.Password)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "云端登录失败: "+err.Error())
		return
	}

	// 以 "cloud:<host>:<username>" 作为本地用户名，确保唯一且可辨识
	localUsername := buildCloudLocalUsername(req.CloudURL, req.Username)

	existing, err := s.userRepo.GetByUsername(r.Context(), localUsername)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "查询用户失败: "+err.Error())
		return
	}

	var user *storage.User
	if existing == nil {
		user = &storage.User{
			UserType:    storage.UserTypeCloud,
			Role:        "user",
			Username:    localUsername,
			DisplayName: req.Username + "@" + hostOf(req.CloudURL),
			Email:       "",
			Enabled:     true,
			CloudURL:    req.CloudURL,
			AuthToken:   []byte(cloud.Token),
		}
		if err := s.userRepo.Create(r.Context(), user); err != nil {
			writeError(w, http.StatusInternalServerError, "创建云端账号记录失败: "+err.Error())
			return
		}
	} else {
		existing.UserType = storage.UserTypeCloud
		existing.CloudURL = req.CloudURL
		existing.AuthToken = []byte(cloud.Token)
		existing.Enabled = true
		if err := s.userRepo.Update(r.Context(), existing); err != nil {
			writeError(w, http.StatusInternalServerError, "更新云端账号记录失败: "+err.Error())
			return
		}
		user = existing
	}

	// 生成本地 session token（24h 有效）
	localToken := newSessionToken(user)

	writeOK(w, map[string]interface{}{
		"token":      localToken,
		"user_uuid":  user.UUID,
		"username":   user.Username,
		"role":       user.Role,
		"user_type":  string(user.UserType),
		"cloud_url":  req.CloudURL,
		"cloud_user": req.Username,
		"expires_at": time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	})
}

// handleLogoutAll DELETE /api/auth/logout-all
// 清空所有 session（仅用于调试/多账号一键全部退出；不影响用户记录本身）。
func (s *Server) handleLogoutAll(w http.ResponseWriter, r *http.Request) {
	sessionMu.Lock()
	count := len(sessions)
	sessions = make(map[string]*session)
	sessionMu.Unlock()
	writeOK(w, map[string]int{"cleared": count})
}

// buildCloudLocalUsername 构造本地用户名形如 "cloud:<host>:<username>"。
func buildCloudLocalUsername(cloudURL, username string) string {
	return "cloud:" + hostOf(cloudURL) + ":" + username
}

// hostOf 尝试从 URL 提取 host:port，失败则原样返回。
func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	return u.Host
}