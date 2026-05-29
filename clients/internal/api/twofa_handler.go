package api

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/globaltrusts/client-card/internal/totp"
)

// ---- 2FA (TOTP) API ----

// handleEnable2FA POST /api/users/{uuid}/2fa/enable
// 生成 TOTP 密钥，返回 otpauth URI 和 Base32 密钥供用户绑定验证器。
// 此时不立即启用，需要用户用 verify 接口验证第一个 OTP 码后才正式启用。
func (s *Server) handleEnable2FA(w http.ResponseWriter, r *http.Request) {
	userUUID := r.PathValue("uuid")

	// 权限检查：只能操作自己或管理员操作他人
	if err := s.check2FAPermission(r, userUUID); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}

	user, err := s.userRepo.GetByUUID(r.Context(), userUUID)
	if err != nil || user == nil {
		writeError(w, http.StatusNotFound, "用户不存在")
		return
	}

	if user.TwoFAEnabled {
		writeError(w, http.StatusBadRequest, "2FA 已启用，如需重新绑定请先禁用")
		return
	}

	// 生成 20 字节随机密钥
	secretBytes := make([]byte, 20)
	if _, err := rand.Read(secretBytes); err != nil {
		writeError(w, http.StatusInternalServerError, "生成密钥失败")
		return
	}
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secretBytes)

	// 暂存密钥到用户记录（但不启用），等 verify 成功后才启用
	user.TwoFASecret = secret
	user.UpdatedAt = time.Now()
	if err := s.userRepo.Update(r.Context(), user); err != nil {
		writeError(w, http.StatusInternalServerError, "保存密钥失败: "+err.Error())
		return
	}

	// 构造 otpauth URI
	issuer := "OpenCert"
	account := user.Username
	otpURI := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		issuer, account, secret, issuer)

	writeOK(w, map[string]interface{}{
		"secret":  secret,
		"otp_uri": otpURI,
		"issuer":  issuer,
		"account": account,
	})
}

// handleVerify2FA POST /api/users/{uuid}/2fa/verify
// 验证 OTP 码并正式启用 2FA。
func (s *Server) handleVerify2FA(w http.ResponseWriter, r *http.Request) {
	userUUID := r.PathValue("uuid")

	if err := s.check2FAPermission(r, userUUID); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if req.Code == "" {
		writeError(w, http.StatusBadRequest, "验证码不能为空")
		return
	}

	user, err := s.userRepo.GetByUUID(r.Context(), userUUID)
	if err != nil || user == nil {
		writeError(w, http.StatusNotFound, "用户不存在")
		return
	}

	if user.TwoFASecret == "" {
		writeError(w, http.StatusBadRequest, "请先调用 enable 接口生成密钥")
		return
	}

	// 验证 OTP
	if !s.verifyTOTP(user.TwoFASecret, req.Code) {
		writeError(w, http.StatusBadRequest, "验证码错误，请确认验证器时间同步")
		return
	}

	// 验证通过，正式启用 2FA
	user.TwoFAEnabled = true
	user.UpdatedAt = time.Now()
	if err := s.userRepo.Update(r.Context(), user); err != nil {
		writeError(w, http.StatusInternalServerError, "启用 2FA 失败: "+err.Error())
		return
	}

	slog.Info("用户启用 2FA", "uuid", userUUID, "username", user.Username)
	writeOK(w, map[string]string{"status": "enabled"})
}

// handleDisable2FA POST /api/users/{uuid}/2fa/disable
// 禁用 2FA，需要验证当前密码或 OTP 码。
func (s *Server) handleDisable2FA(w http.ResponseWriter, r *http.Request) {
	userUUID := r.PathValue("uuid")

	if err := s.check2FAPermission(r, userUUID); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}

	var req struct {
		Password string `json:"password"` // 密码验证（二选一）
		Code     string `json:"code"`     // OTP 验证（二选一）
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}

	user, err := s.userRepo.GetByUUID(r.Context(), userUUID)
	if err != nil || user == nil {
		writeError(w, http.StatusNotFound, "用户不存在")
		return
	}

	if !user.TwoFAEnabled {
		writeError(w, http.StatusBadRequest, "2FA 未启用")
		return
	}

	// 验证身份（密码或 OTP 码）
	verified := false
	if req.Code != "" {
		verified = s.verifyTOTP(user.TwoFASecret, req.Code)
	}
	if !verified && req.Password != "" {
		verified = verifyPassword(req.Password, user.PasswordHash)
	}
	if !verified {
		writeError(w, http.StatusForbidden, "身份验证失败：请提供正确的密码或 2FA 验证码")
		return
	}

	// 禁用 2FA
	user.TwoFAEnabled = false
	user.TwoFASecret = ""
	user.PasswordlessEnabled = false
	user.UpdatedAt = time.Now()
	if err := s.userRepo.Update(r.Context(), user); err != nil {
		writeError(w, http.StatusInternalServerError, "禁用 2FA 失败: "+err.Error())
		return
	}

	slog.Info("用户禁用 2FA", "uuid", userUUID, "username", user.Username)
	writeOK(w, map[string]string{"status": "disabled"})
}

// handleTogglePasswordless POST /api/users/{uuid}/2fa/passwordless
// 切换免密码登录模式（需要 2FA 已启用）。
func (s *Server) handleTogglePasswordless(w http.ResponseWriter, r *http.Request) {
	userUUID := r.PathValue("uuid")

	if err := s.check2FAPermission(r, userUUID); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}

	user, err := s.userRepo.GetByUUID(r.Context(), userUUID)
	if err != nil || user == nil {
		writeError(w, http.StatusNotFound, "用户不存在")
		return
	}

	if !user.TwoFAEnabled {
		writeError(w, http.StatusBadRequest, "免密码登录需要先启用 2FA")
		return
	}

	user.PasswordlessEnabled = req.Enabled
	user.UpdatedAt = time.Now()
	if err := s.userRepo.Update(r.Context(), user); err != nil {
		writeError(w, http.StatusInternalServerError, "更新失败: "+err.Error())
		return
	}

	writeOK(w, map[string]interface{}{"passwordless_enabled": user.PasswordlessEnabled})
}

// handle2FAStatus GET /api/users/{uuid}/2fa/status
// 获取 2FA 状态。
func (s *Server) handle2FAStatus(w http.ResponseWriter, r *http.Request) {
	userUUID := r.PathValue("uuid")

	user, err := s.userRepo.GetByUUID(r.Context(), userUUID)
	if err != nil || user == nil {
		writeError(w, http.StatusNotFound, "用户不存在")
		return
	}

	writeOK(w, map[string]interface{}{
		"two_fa_enabled":       user.TwoFAEnabled,
		"passwordless_enabled": user.PasswordlessEnabled,
	})
}

// ---- 内部方法 ----

// verifyTOTP 验证 TOTP 码（允许前后 1 个周期的偏差）。
func (s *Server) verifyTOTP(secret, code string) bool {
	secretBytes, err := totp.DecodeSecret(secret)
	if err != nil {
		return false
	}

	now := time.Now()
	// 验证当前周期和前后各 1 个周期（容忍 30 秒时间偏差）
	for _, offset := range []int{-1, 0, 1} {
		t := now.Add(time.Duration(offset*30) * time.Second)
		expected, err := totp.GenerateTOTP(secretBytes, t, 30, 6, totp.AlgorithmSHA1)
		if err != nil {
			continue
		}
		if strings.TrimSpace(code) == expected {
			return true
		}
	}
	return false
}

// check2FAPermission 检查 2FA 操作权限（只能操作自己或管理员操作他人）。
func (s *Server) check2FAPermission(r *http.Request, targetUUID string) error {
	token := extractBearerToken(r)
	sess := getSession(token)
	if sess == nil {
		return fmt.Errorf("未登录")
	}
	if sess.UserUUID == targetUUID {
		return nil // 操作自己
	}
	// 检查是否为管理员
	user, _ := s.userRepo.GetByUUID(r.Context(), sess.UserUUID)
	if user != nil && user.Role == "admin" {
		return nil
	}
	return fmt.Errorf("无权操作其他用户的 2FA 设置")
}
