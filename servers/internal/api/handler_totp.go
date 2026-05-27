package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/globaltrusts/server-card/internal/auth"
	"github.com/globaltrusts/server-card/internal/storage"
)

// ---- 云端 TOTP 处理器 ----

func (s *Server) handleListUserTOTPs(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	rows, err := s.db.QueryContext(r.Context(),
		`SELECT uuid, user_uuid, issuer, account, algorithm, digits, period, created_at FROM user_totps WHERE user_uuid = ? ORDER BY created_at DESC`,
		claims.UserUUID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	var totps []map[string]interface{}
	for rows.Next() {
		var id, userUUID, issuer, account, algorithm string
		var digits, period int
		var createdAt time.Time
		if err := rows.Scan(&id, &userUUID, &issuer, &account, &algorithm, &digits, &period, &createdAt); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		totps = append(totps, map[string]interface{}{
			"uuid": id, "issuer": issuer, "account": account,
			"algorithm": algorithm, "digits": digits, "period": period, "created_at": createdAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"totps": totps, "total": len(totps)})
}

func (s *Server) handleCreateUserTOTP(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	var req struct {
		Issuer    string `json:"issuer"`
		Account   string `json:"account"`
		Secret    string `json:"secret"`
		Algorithm string `json:"algorithm"`
		Digits    int    `json:"digits"`
		Period    int    `json:"period"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if req.Secret == "" {
		writeError(w, http.StatusBadRequest, "TOTP 密钥不能为空")
		return
	}
	if req.Algorithm == "" {
		req.Algorithm = "SHA1"
	}
	if req.Digits == 0 {
		req.Digits = 6
	}
	if req.Period == 0 {
		req.Period = 30
	}

	// 使用主密钥 AES-256-GCM 加密 TOTP 密钥
	secretEnc, err := s.cardSvc.EncryptData([]byte(req.Secret))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "加密 TOTP 密钥失败")
		return
	}

	totpUUID := uuid.New().String()
	_, err = s.db.ExecContext(r.Context(),
		`INSERT INTO user_totps (uuid, user_uuid, issuer, account, secret_enc, algorithm, digits, period, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		totpUUID, claims.UserUUID, req.Issuer, req.Account, storage.Base64Bytes(secretEnc),
		req.Algorithm, req.Digits, req.Period, time.Now(), time.Now())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"uuid": totpUUID, "message": "TOTP 已添加"})
}

func (s *Server) handleGetTOTPCode(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	totpUUID := r.PathValue("uuid")

	var secretEnc storage.Base64Bytes
	var algorithm string
	var digits, period int
	var userUUID string
	err := s.db.QueryRowContext(r.Context(),
		`SELECT user_uuid, secret_enc, algorithm, digits, period FROM user_totps WHERE uuid = ?`,
		totpUUID).Scan(&userUUID, &secretEnc, &algorithm, &digits, &period)
	if err != nil {
		writeError(w, http.StatusNotFound, "TOTP 条目不存在")
		return
	}

	// 权限检查：只有所有者可以获取验证码
	if userUUID != claims.UserUUID && !auth.IsAdmin(claims.Role) {
		writeError(w, http.StatusForbidden, "无权访问此 TOTP 条目")
		return
	}

	// 解密 TOTP 密钥
	secretBytes, err := s.cardSvc.DecryptData(secretEnc)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "解密 TOTP 密钥失败")
		return
	}

	// 计算当前时间窗口的验证码
	now := time.Now().Unix()
	counter := now / int64(period)
	remaining := int64(period) - (now % int64(period))

	currentCode, err := computeTOTP(string(secretBytes), counter, digits, algorithm)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "计算 TOTP 验证码失败: "+err.Error())
		return
	}
	prevCode, _ := computeTOTP(string(secretBytes), counter-1, digits, algorithm)
	nextCode, _ := computeTOTP(string(secretBytes), counter+1, digits, algorithm)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"uuid":      totpUUID,
		"code":      currentCode,
		"prev_code": prevCode,
		"next_code": nextCode,
		"remaining": remaining,
		"period":    period,
		"algorithm": algorithm,
		"digits":    digits,
	})
}

func (s *Server) handleDeleteUserTOTP(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	totpUUID := r.PathValue("uuid")
	_, err := s.db.ExecContext(r.Context(),
		`DELETE FROM user_totps WHERE uuid = ? AND user_uuid = ?`, totpUUID, claims.UserUUID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "TOTP 已删除"})
}

// computeTOTP 计算 TOTP 验证码（RFC 6238）。
func computeTOTP(secret string, counter int64, digits int, algorithm string) (string, error) {
	secret = strings.ToUpper(strings.TrimSpace(secret))
	if n := len(secret) % 8; n != 0 {
		secret += strings.Repeat("=", 8-n)
	}
	key, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", fmt.Errorf("解码 TOTP 密钥失败: %w", err)
	}

	msg := make([]byte, 8)
	binary.BigEndian.PutUint64(msg, uint64(counter))

	var h hash.Hash
	switch strings.ToUpper(algorithm) {
	case "SHA256":
		h = hmac.New(sha256.New, key)
	case "SHA512":
		h = hmac.New(sha512.New, key)
	default:
		h = hmac.New(sha1.New, key)
	}
	h.Write(msg)
	sum := h.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	binCode := (int64(sum[offset]&0x7f) << 24) |
		(int64(sum[offset+1]&0xff) << 16) |
		(int64(sum[offset+2]&0xff) << 8) |
		int64(sum[offset+3]&0xff)

	mod := int64(math.Pow10(digits))
	code := binCode % mod
	return fmt.Sprintf("%0*d", digits, code), nil
}

// verifyUserTOTPCode 验证用户的 TOTP 验证码（支持前后 1 个时间窗口容差）。
func (s *Server) verifyUserTOTPCode(ctx context.Context, userUUID, code string) bool {
	rows, err := s.db.QueryContext(ctx,
		`SELECT secret_enc, algorithm, digits, period FROM user_totps WHERE user_uuid = ? LIMIT 1`,
		userUUID)
	if err != nil {
		return false
	}
	defer rows.Close()

	if !rows.Next() {
		return false
	}

	var secretEnc storage.Base64Bytes
	var algorithm string
	var digits, period int
	if err := rows.Scan(&secretEnc, &algorithm, &digits, &period); err != nil {
		return false
	}

	secretBytes, err := s.cardSvc.DecryptData(secretEnc)
	if err != nil {
		return false
	}

	now := time.Now().Unix()
	counter := now / int64(period)
	for _, c := range []int64{counter - 1, counter, counter + 1} {
		expected, err := computeTOTP(string(secretBytes), c, digits, algorithm)
		if err == nil && expected == code {
			return true
		}
	}
	return false
}