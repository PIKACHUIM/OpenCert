package api

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// ---- 登录 TOTP 自主绑定（users.totp_secret 字段）----
//
// 与 handler_totp.go 中的 user_totps 表管理不同，此处操作的是 users.totp_secret 字段，
// 该字段专门用于登录二次验证。用户自主生成密钥、扫码绑定、解绑。
//
// 流程：
//   1) POST /api/user/login-totp/generate → 生成密钥并返回 otpauth://，密钥暂存到 pendingBindings（5 分钟）
//   2) POST /api/user/login-totp/bind     → 提交 6 位 TOTP 验证码确认，通过后加密落库 users.totp_secret
//   3) DELETE /api/user/login-totp        → 需要当前 TOTP 验证，解绑
//   4) GET /api/user/login-totp/status    → 查询绑定状态

// pendingTOTPBinding 是待绑定的 TOTP 密钥（已生成但未确认）。
type pendingTOTPBinding struct {
	UserUUID  string
	Secret    string // Base32 原文
	CreatedAt time.Time
}

// 进程内待绑定密钥缓存，默认 5 分钟过期。
var (
	pendingBindMu       sync.Mutex
	pendingBindings     = make(map[string]*pendingTOTPBinding) // key: userUUID
	pendingBindLifetime = 5 * time.Minute
)

// getPendingBinding 读取并返回未过期的待绑定密钥。
func getPendingBinding(userUUID string) (*pendingTOTPBinding, bool) {
	pendingBindMu.Lock()
	defer pendingBindMu.Unlock()
	b, ok := pendingBindings[userUUID]
	if !ok {
		return nil, false
	}
	if time.Since(b.CreatedAt) > pendingBindLifetime {
		delete(pendingBindings, userUUID)
		return nil, false
	}
	return b, true
}

// setPendingBinding 写入待绑定密钥。
func setPendingBinding(userUUID, secret string) {
	pendingBindMu.Lock()
	defer pendingBindMu.Unlock()
	pendingBindings[userUUID] = &pendingTOTPBinding{
		UserUUID:  userUUID,
		Secret:    secret,
		CreatedAt: time.Now(),
	}
}

// deletePendingBinding 删除待绑定密钥。
func deletePendingBinding(userUUID string) {
	pendingBindMu.Lock()
	defer pendingBindMu.Unlock()
	delete(pendingBindings, userUUID)
}

// generateTOTPSecret 生成 20 字节随机密钥的 Base32 编码。
func generateTOTPSecret() (string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("生成随机字节失败: %w", err)
	}
	// 使用无填充 Base32，便于直接写入 otpauth URL
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw), nil
}

// buildOTPAuthURL 构造 otpauth://totp/ URL（RFC 6238，供认证器 App 扫码）。
func buildOTPAuthURL(issuer, account, secret string) string {
	label := url.PathEscape(fmt.Sprintf("%s:%s", issuer, account))
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	return fmt.Sprintf("otpauth://totp/%s?%s", label, q.Encode())
}

// handleGenerateLoginTOTP 生成登录 TOTP 密钥（未落库）。
// POST /api/user/login-totp/generate
// 响应体: { secret, otpauth_url, expires_in }
func (s *Server) handleGenerateLoginTOTP(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())

	// 已绑定时不允许再次生成（需先解绑）
	user, err := s.userRepo.GetByUUID(r.Context(), claims.UserUUID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if user.TOTPSecret != "" {
		writeError(w, http.StatusConflict, "已绑定登录 TOTP，请先解绑")
		return
	}

	secret, err := generateTOTPSecret()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	setPendingBinding(claims.UserUUID, secret)

	issuer := "PKCS11Driver"
	if s.cfg != nil && s.cfg.SMTP.FromName != "" {
		issuer = s.cfg.SMTP.FromName
	}
	otpauthURL := buildOTPAuthURL(issuer, user.Username, secret)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"secret":       secret,
		"otpauth_url":  otpauthURL,
		"issuer":       issuer,
		"account":      user.Username,
		"algorithm":    "SHA1",
		"digits":       6,
		"period":       30,
		"expires_in":   int(pendingBindLifetime.Seconds()),
	})
}

// BindLoginTOTPRequest 是绑定登录 TOTP 的请求体。
type BindLoginTOTPRequest struct {
	Code string `json:"code"` // 6 位 TOTP 验证码
}

// handleBindLoginTOTP 确认绑定登录 TOTP。
// POST /api/user/login-totp/bind
// 需 generate 生成待绑定密钥 + 提交一次有效验证码后，将密钥加密写入 users.totp_secret。
func (s *Server) handleBindLoginTOTP(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())

	var req BindLoginTOTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if req.Code == "" {
		writeError(w, http.StatusBadRequest, "验证码不能为空")
		return
	}

	binding, ok := getPendingBinding(claims.UserUUID)
	if !ok {
		writeError(w, http.StatusBadRequest, "未生成待绑定密钥或已过期，请重新生成")
		return
	}

	// 用待绑定密钥验证一次 TOTP（容差 ±1 窗口）
	now := time.Now().Unix()
	counter := now / 30
	matched := false
	for _, c := range []int64{counter - 1, counter, counter + 1} {
		expected, err := computeTOTP(binding.Secret, c, 6, "SHA1")
		if err == nil && expected == req.Code {
			matched = true
			break
		}
	}
	if !matched {
		writeError(w, http.StatusUnauthorized, "TOTP 验证码错误")
		return
	}

	// 加密并写入 users.totp_secret
	secretEnc, err := s.cardSvc.EncryptData([]byte(binding.Secret))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "加密 TOTP 密钥失败")
		return
	}
	// 以 Base64 形式存入 TEXT 字段（兼容 users 表定义）
	encStr := base64.StdEncoding.EncodeToString(secretEnc)

	if _, err := s.db.ExecContext(r.Context(),
		`UPDATE users SET totp_secret = ?, updated_at = ? WHERE uuid = ?`,
		encStr, time.Now(), claims.UserUUID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// 绑定成功后清理待绑定缓存
	deletePendingBinding(claims.UserUUID)
	writeJSON(w, http.StatusOK, map[string]string{"message": "登录 TOTP 绑定成功"})
}

// UnbindLoginTOTPRequest 是解绑登录 TOTP 的请求体。
type UnbindLoginTOTPRequest struct {
	Code string `json:"code"` // 需提交当前 TOTP 验证码，避免未授权解绑
}

// handleUnbindLoginTOTP 解绑登录 TOTP。
// DELETE /api/user/login-totp
// 需要当前 TOTP 验证码，避免未授权解绑。
func (s *Server) handleUnbindLoginTOTP(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())

	var req UnbindLoginTOTPRequest
	_ = json.NewDecoder(r.Body).Decode(&req) // 可能为空 body

	user, err := s.userRepo.GetByUUID(r.Context(), claims.UserUUID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if user.TOTPSecret == "" {
		writeError(w, http.StatusBadRequest, "未绑定登录 TOTP")
		return
	}
	if req.Code == "" {
		writeError(w, http.StatusBadRequest, "需提交当前 TOTP 验证码以完成解绑")
		return
	}

	// 校验当前 TOTP 验证码
	if !s.verifyLoginTOTPCode(r.Context(), claims.UserUUID, req.Code) {
		writeError(w, http.StatusUnauthorized, "TOTP 验证码错误")
		return
	}

	if _, err := s.db.ExecContext(r.Context(),
		`UPDATE users SET totp_secret = '', updated_at = ? WHERE uuid = ?`,
		time.Now(), claims.UserUUID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "登录 TOTP 已解绑"})
}

// handleLoginTOTPStatus 查询登录 TOTP 绑定状态。
// GET /api/user/login-totp/status
func (s *Server) handleLoginTOTPStatus(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	user, err := s.userRepo.GetByUUID(r.Context(), claims.UserUUID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{
		"bound": user.TOTPSecret != "",
	})
}

// verifyLoginTOTPCode 用 users.totp_secret 验证登录 TOTP 码（容差 ±1 窗口）。
// 这是与 verifyUserTOTPCode（验证 user_totps 表条目）不同的登录专用验证器。
func (s *Server) verifyLoginTOTPCode(ctx context.Context, userUUID, code string) bool {
	var encStr string
	err := s.db.QueryRowContext(ctx,
		`SELECT totp_secret FROM users WHERE uuid = ?`, userUUID).Scan(&encStr)
	if err != nil || encStr == "" {
		return false
	}
	secretEnc, err := base64.StdEncoding.DecodeString(encStr)
	if err != nil {
		return false
	}
	secretBytes, err := s.cardSvc.DecryptData(secretEnc)
	if err != nil {
		return false
	}

	now := time.Now().Unix()
	counter := now / 30
	for _, c := range []int64{counter - 1, counter, counter + 1} {
		expected, err := computeTOTP(string(secretBytes), c, 6, "SHA1")
		if err == nil && expected == code {
			return true
		}
	}
	return false
}
