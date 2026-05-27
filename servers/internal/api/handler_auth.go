package api

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/globaltrusts/server-card/internal/auth"
	"github.com/globaltrusts/server-card/internal/storage"
	"golang.org/x/crypto/bcrypt"
)

// ---- 认证处理器 ----

func (s *Server) handlePortal(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, "web/index.html")
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "service": "servers"})
}

// LoginRequest 是登录请求体。
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}

	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "用户名和密码不能为空")
		return
	}

	user, err := s.userRepo.GetByUsername(r.Context(), req.Username)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "用户名或密码错误")
		return
	}

	if !user.Enabled {
		writeError(w, http.StatusForbidden, "账号已禁用")
		return
	}

	// 检查是否被锁定
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		writeError(w, http.StatusTooManyRequests, fmt.Sprintf("账号已锁定，请在 %s 后重试", user.LockedUntil.Format("15:04:05")))
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		// 登录失败，递增失败计数（5次锁定15分钟）
		s.userRepo.IncrementFailedAttempts(r.Context(), user.UUID, 5, 15*time.Minute) //nolint:errcheck
		writeError(w, http.StatusUnauthorized, "用户名或密码错误")
		return
	}

	// 登录成功，重置失败计数
	s.userRepo.ResetFailedAttempts(r.Context(), user.UUID) //nolint:errcheck

	// 如果用户绑定了 TOTP，返回 session_token 要求二次验证
	if user.TOTPSecret != "" {
		sessionToken, err := totpSessionStore.create(user.UUID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "生成会话 Token 失败")
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"require_totp":  true,
			"session_token": sessionToken,
		})
		return
	}

	token, _, err := s.jwtMgr.Sign(user.UUID, user.Username, user.Role)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "生成 Token 失败")
		return
	}

	// 记录登录日志
	s.logRepo.Create(r.Context(), &storage.Log{ //nolint:errcheck
		UserUUID:  user.UUID,
		Action:    "login",
		IPAddr:    r.RemoteAddr,
		UserAgent: r.UserAgent(),
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"token":     token,
		"user_uuid": user.UUID,
		"username":  user.Username,
		"role":      user.Role,
	})
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	token, _, err := s.jwtMgr.Refresh(claims)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "刷新 Token 失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

// RegisterRequest 是注册请求体。
type RegisterRequest struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}

	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "用户名和密码不能为空")
		return
	}
	if len(req.Password) < 8 {
		writeError(w, http.StatusBadRequest, "密码长度不能少于8位")
		return
	}
	if req.Email == "" {
		writeError(w, http.StatusBadRequest, "邮箱不能为空")
		return
	}

	// 检查用户名唯一性
	if _, err := s.userRepo.GetByUsername(r.Context(), req.Username); err == nil {
		writeError(w, http.StatusConflict, "用户名已存在")
		return
	}

	// 检查邮箱唯一性
	if _, err := s.userRepo.GetByEmail(r.Context(), req.Email); err == nil {
		writeError(w, http.StatusConflict, "邮箱已被注册")
		return
	}

	// 密码哈希（bcrypt cost=13）
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), 13)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "密码加密失败")
		return
	}

	user := &storage.User{
		Username:     req.Username,
		DisplayName:  req.DisplayName,
		Email:        req.Email,
		PasswordHash: string(hash),
		Role:         "user",
		Enabled:      true,
	}

	if err := s.userRepo.Create(r.Context(), user); err != nil {
		writeError(w, http.StatusInternalServerError, "创建用户失败: "+err.Error())
		return
	}

	// 记录注册日志
	s.logRepo.Create(r.Context(), &storage.Log{ //nolint:errcheck
		UserUUID: user.UUID,
		Action:   "register",
		IPAddr:   r.RemoteAddr,
	})

	// 注册成功后自动签发 token，与 login 返回格式一致
	token, _, err := s.jwtMgr.Sign(user.UUID, user.Username, user.Role)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "生成 Token 失败")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"token":     token,
		"user_uuid": user.UUID,
		"username":  user.Username,
		"role":      user.Role,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())

	// 将当前 Token 加入黑名单
	if claims.ExpiresAt != nil {
		s.jwtMgr.Revoke(claims.ID, claims.ExpiresAt.Time)
	}

	s.logRepo.Create(r.Context(), &storage.Log{ //nolint:errcheck
		UserUUID: claims.UserUUID,
		Action:   "logout",
		IPAddr:   r.RemoteAddr,
	})

	writeJSON(w, http.StatusOK, map[string]string{"message": "已登出"})
}

// ---- 找回密码 ----

// passwordResetStore 存储密码重置验证码（内存缓存，生产环境应使用 Redis）。
var passwordResetStore = &resetCodeStore{
	codes: make(map[string]*resetCode),
}

type resetCode struct {
	code      string
	expiresAt time.Time
}

type resetCodeStore struct {
	mu    sync.Mutex
	codes map[string]*resetCode // key: email
}

func (s *resetCodeStore) set(email, code string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[email] = &resetCode{
		code:      code,
		expiresAt: time.Now().Add(15 * time.Minute),
	}
}

func (s *resetCodeStore) verify(email, code string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	rc, ok := s.codes[email]
	if !ok {
		return false
	}
	if time.Now().After(rc.expiresAt) {
		delete(s.codes, email)
		return false
	}
	if rc.code != code {
		return false
	}
	delete(s.codes, email)
	return true
}

// generate6DigitCode 生成 6 位随机数字验证码。
func generate6DigitCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// ForgotPasswordRequest 是找回密码请求体。
type ForgotPasswordRequest struct {
	Email string `json:"email"`
}

func (s *Server) handleForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req ForgotPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if req.Email == "" {
		writeError(w, http.StatusBadRequest, "邮箱不能为空")
		return
	}

	// 查询用户是否存在（不泄露用户是否存在，统一返回成功）
	user, err := s.userRepo.GetByEmail(r.Context(), req.Email)
	if err == nil && user != nil {
		code, err := generate6DigitCode()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "生成验证码失败")
			return
		}
		passwordResetStore.set(req.Email, code)

		// 通过 mailer 发送验证码邮件
		if s.mailer != nil {
			subject := "OpenCert Platform — 密码重置验证码"
			body := fmt.Sprintf(
				"您好，%s：\n\n您正在重置 OpenCert Platform 账号密码。\n\n验证码：%s\n\n该验证码 5 分钟内有效，请勿泄露给他人。\n如非本人操作，请忽略此邮件。\n\n—— OpenCert Platform",
				user.DisplayName, code,
			)
			if err := s.mailer.Send(req.Email, subject, body); err != nil {
				slog.Warn("发送密码重置邮件失败", "email", req.Email, "error", err)
			}
		}

		// 审计日志（不记录明文验证码到日志，仅记录操作）
		s.logRepo.Create(r.Context(), &storage.Log{ //nolint:errcheck
			UserUUID: user.UUID,
			Action:   "forgot_password:email_sent",
			IPAddr:   r.RemoteAddr,
		})
	}

	// 无论用户是否存在，统一返回成功（防止用户枚举）
	writeJSON(w, http.StatusOK, map[string]string{"message": "如果该邮箱已注册，验证码将发送到您的邮箱"})
}

// ResetPasswordRequest 是重置密码请求体。
type ResetPasswordRequest struct {
	Email    string `json:"email"`
	Code     string `json:"code"`
	Password string `json:"new_password"`
}

func (s *Server) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	var req ResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if req.Email == "" || req.Code == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "邮箱、验证码和新密码不能为空")
		return
	}
	if len(req.Password) < 8 {
		writeError(w, http.StatusBadRequest, "新密码长度不能少于8位")
		return
	}

	// 验证验证码
	if !passwordResetStore.verify(req.Email, req.Code) {
		writeError(w, http.StatusBadRequest, "验证码无效或已过期")
		return
	}

	// 查询用户
	user, err := s.userRepo.GetByEmail(r.Context(), req.Email)
	if err != nil {
		writeError(w, http.StatusBadRequest, "用户不存在")
		return
	}

	// 生成新密码哈希
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), 13)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "密码加密失败")
		return
	}

	if err := s.userRepo.UpdatePassword(r.Context(), user.UUID, string(hash)); err != nil {
		writeError(w, http.StatusInternalServerError, "更新密码失败")
		return
	}

	// 使该用户所有 JWT Token 失效（通过更新 token 版本号）
	s.jwtMgr.RevokeAllForUser(user.UUID)

	s.logRepo.Create(r.Context(), &storage.Log{ //nolint:errcheck
		UserUUID: user.UUID,
		Action:   "reset_password",
		IPAddr:   r.RemoteAddr,
	})

	writeJSON(w, http.StatusOK, map[string]string{"message": "密码已重置，请重新登录"})
}

// ---- TOTP 二次验证 ----

// totpSessionStore 存储 TOTP 登录会话（内存缓存）。
var totpSessionStore = &sessionStore{
	sessions: make(map[string]*totpSession),
}

type totpSession struct {
	userUUID  string
	expiresAt time.Time
}

type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]*totpSession // key: session_token
}

func (s *sessionStore) create(userUUID string) (string, error) {
	token, err := generateSecureToken()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[token] = &totpSession{
		userUUID:  userUUID,
		expiresAt: time.Now().Add(5 * time.Minute),
	}
	return token, nil
}

func (s *sessionStore) consume(token string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[token]
	if !ok {
		return "", false
	}
	delete(s.sessions, token)
	if time.Now().After(sess.expiresAt) {
		return "", false
	}
	return sess.userUUID, true
}

func generateSecureToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

// TOTPVerifyRequest 是 TOTP 二次验证请求体。
type TOTPVerifyRequest struct {
	SessionToken string `json:"session_token"`
	Code         string `json:"code"`
}

func (s *Server) handleTOTPVerify(w http.ResponseWriter, r *http.Request) {
	var req TOTPVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if req.SessionToken == "" || req.Code == "" {
		writeError(w, http.StatusBadRequest, "session_token 和验证码不能为空")
		return
	}

	// 从会话中获取用户 UUID
	userUUID, ok := totpSessionStore.consume(req.SessionToken)
	if !ok {
		writeError(w, http.StatusUnauthorized, "会话已过期，请重新登录")
		return
	}

	// 获取用户信息
	user, err := s.userRepo.GetByUUID(r.Context(), userUUID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "用户不存在")
		return
	}

	// 检查账号锁定
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		writeError(w, http.StatusTooManyRequests, fmt.Sprintf("账号已锁定，请在 %s 后重试", user.LockedUntil.Format("15:04:05")))
		return
	}

	// 验证 TOTP 码（从 users.totp_secret 字段读取加密的登录 TOTP 密钥并验证）
	if !s.verifyLoginTOTPCode(r.Context(), userUUID, req.Code) {
		// 记录失败次数，连续 5 次失败锁定账号 15 分钟
		s.userRepo.IncrementFailedAttempts(r.Context(), userUUID, 5, 15*time.Minute) //nolint:errcheck
		writeError(w, http.StatusUnauthorized, "TOTP 验证码错误")
		return
	}

	// 验证成功，重置失败计数
	s.userRepo.ResetFailedAttempts(r.Context(), userUUID) //nolint:errcheck

	token, _, err := s.jwtMgr.Sign(user.UUID, user.Username, user.Role)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "生成 Token 失败")
		return
	}

	s.logRepo.Create(r.Context(), &storage.Log{ //nolint:errcheck
		UserUUID:  user.UUID,
		Action:    "login_totp",
		IPAddr:    r.RemoteAddr,
		UserAgent: r.UserAgent(),
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"token":     token,
		"user_uuid": user.UUID,
		"username":  user.Username,
		"role":      user.Role,
	})
}

// ---- 个人信息处理器 ----

func (s *Server) handleGetProfile(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	user, err := s.userRepo.GetByUUID(r.Context(), claims.UserUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, user)
}

// UpdateProfileRequest 是更新个人信息请求体。
type UpdateProfileRequest struct {
	DisplayName string `json:"display_name"`
	Email       string `json:"email"`
}

func (s *Server) handleUpdateProfile(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	var req UpdateProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}

	if err := s.userRepo.UpdateProfile(r.Context(), claims.UserUUID, req.DisplayName, req.Email); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "个人信息已更新"})
}

// ChangePasswordRequest 是修改密码请求体。
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	var req ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}

	if req.OldPassword == "" || req.NewPassword == "" {
		writeError(w, http.StatusBadRequest, "旧密码和新密码不能为空")
		return
	}
	if len(req.NewPassword) < 8 {
		writeError(w, http.StatusBadRequest, "新密码长度不能少于8位")
		return
	}

	user, err := s.userRepo.GetByUUID(r.Context(), claims.UserUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	// 验证旧密码
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.OldPassword)); err != nil {
		writeError(w, http.StatusUnauthorized, "旧密码错误")
		return
	}

	// 生成新密码哈希
	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), 13)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "密码加密失败")
		return
	}

	if err := s.userRepo.UpdatePassword(r.Context(), claims.UserUUID, string(hash)); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.logRepo.Create(r.Context(), &storage.Log{ //nolint:errcheck
		UserUUID: claims.UserUUID,
		Action:   "change_password",
		IPAddr:   r.RemoteAddr,
	})

	writeJSON(w, http.StatusOK, map[string]string{"message": "密码已修改"})
}

// UpdatePublicKeyRequest 是更新公钥请求体。
type UpdatePublicKeyRequest struct {
	PublicKey []byte `json:"public_key"` // DER 编码的公钥
}

func (s *Server) handleUpdatePublicKey(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	var req UpdatePublicKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}

	if len(req.PublicKey) == 0 {
		writeError(w, http.StatusBadRequest, "公钥不能为空")
		return
	}

	if err := s.userRepo.UpdatePublicKey(r.Context(), claims.UserUUID, req.PublicKey); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.logRepo.Create(r.Context(), &storage.Log{ //nolint:errcheck
		UserUUID: claims.UserUUID,
		Action:   "update_pubkey",
		IPAddr:   r.RemoteAddr,
	})

	writeJSON(w, http.StatusOK, map[string]string{"message": "公钥已更新"})
}

// ---- 用户管理（管理员）----

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	keyword := r.URL.Query().Get("keyword")
	page, pageSize := parsePagination(r)

	users, total, err := s.userRepo.ListUsers(r.Context(), keyword, page, pageSize)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"users": users,
		"total": total,
		"page":  page,
	})
}

// CreateUserRequest 是管理员创建用户请求体。
type CreateUserRequest struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Role        string `json:"role"`
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if req.Username == "" || req.Password == "" || req.Email == "" {
		writeError(w, http.StatusBadRequest, "用户名、密码和邮箱不能为空")
		return
	}
	if len(req.Password) < 8 {
		writeError(w, http.StatusBadRequest, "密码长度不能少于8位")
		return
	}
	if req.Role == "" {
		req.Role = "user"
	}

	// 检查唯一性
	if _, err := s.userRepo.GetByUsername(r.Context(), req.Username); err == nil {
		writeError(w, http.StatusConflict, "用户名已存在")
		return
	}
	if _, err := s.userRepo.GetByEmail(r.Context(), req.Email); err == nil {
		writeError(w, http.StatusConflict, "邮箱已被注册")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), 13)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "密码加密失败")
		return
	}

	user := &storage.User{
		Username:     req.Username,
		DisplayName:  req.DisplayName,
		Email:        req.Email,
		PasswordHash: string(hash),
		Role:         req.Role,
		Enabled:      true,
	}
	if err := s.userRepo.Create(r.Context(), user); err != nil {
		writeError(w, http.StatusInternalServerError, "创建用户失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, user)
}

// UpdateUserRequest 是更新用户信息请求体。
type UpdateUserRequest struct {
	DisplayName string `json:"display_name"`
	Email       string `json:"email"`
	Password    string `json:"password"` // 可选，不为空时更新密码
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	targetUUID := r.PathValue("uuid")
	var req UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}

	if err := s.userRepo.UpdateProfile(r.Context(), targetUUID, req.DisplayName, req.Email); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// 如果提供了新密码，更新密码
	if req.Password != "" {
		if len(req.Password) < 8 {
			writeError(w, http.StatusBadRequest, "密码长度不能少于8位")
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), 13)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "密码加密失败")
			return
		}
		if err := s.userRepo.UpdatePassword(r.Context(), targetUUID, string(hash)); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "用户信息已更新"})
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	targetUUID := r.PathValue("uuid")

	// 拒绝删除自身账号
	if targetUUID == claims.UserUUID {
		writeError(w, http.StatusBadRequest, "不能删除自身账号")
		return
	}

	if err := s.userRepo.Delete(r.Context(), targetUUID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "用户已删除"})
}

// UpdateUserRoleRequest 是更新用户角色请求体。
type UpdateUserRoleRequest struct {
	Role string `json:"role"` // admin/user/readonly
}

func (s *Server) handleUpdateUserRole(w http.ResponseWriter, r *http.Request) {
	targetUUID := r.PathValue("uuid")
	var req UpdateUserRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if req.Role != "admin" && req.Role != "user" && req.Role != "readonly" {
		writeError(w, http.StatusBadRequest, "角色必须为 admin/user/readonly")
		return
	}

	if err := s.userRepo.UpdateRole(r.Context(), targetUUID, req.Role); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "用户角色已更新"})
}

// UpdateUserEnabledRequest 是启用/禁用用户请求体。
type UpdateUserEnabledRequest struct {
	Enabled bool `json:"enabled"`
}

func (s *Server) handleUpdateUserEnabled(w http.ResponseWriter, r *http.Request) {
	targetUUID := r.PathValue("uuid")
	var req UpdateUserEnabledRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}

	if err := s.userRepo.UpdateEnabled(r.Context(), targetUUID, req.Enabled); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	msg := "用户已禁用"
	if req.Enabled {
		msg = "用户已启用"
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": msg})
}

// ---- 操作日志查询 ----

func (s *Server) handleListLogs(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	page, pageSize := parsePagination(r)

	// 非管理员只能查看自己的日志
	userUUID := r.URL.Query().Get("user_uuid")
	if !auth.IsAdmin(claims.Role) {
		userUUID = claims.UserUUID
	}

	action := r.URL.Query().Get("action")
	startTime := r.URL.Query().Get("start_time")
	endTime := r.URL.Query().Get("end_time")

	logs, total, err := s.logRepo.List(r.Context(), userUUID, action, startTime, endTime, page, pageSize)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"logs":  logs,
		"total": total,
		"page":  page,
	})
}

// parsePagination 解析分页参数。
func parsePagination(r *http.Request) (page, pageSize int) {
	page = 1
	pageSize = 20
	if p := r.URL.Query().Get("page"); p != "" {
		if v, err := parseInt(p); err == nil && v > 0 {
			page = v
		}
	}
	if ps := r.URL.Query().Get("page_size"); ps != "" {
		if v, err := parseInt(ps); err == nil && v > 0 && v <= 100 {
			pageSize = v
		}
	}
	return
}

func parseInt(s string) (int, error) {
	var v int
	_, err := fmt.Sscanf(s, "%d", &v)
	return v, err
}
