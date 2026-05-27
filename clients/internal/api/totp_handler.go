package api

import (
	"net/http"
	"time"

	"github.com/globaltrusts/client-card/internal/card/local"
	"github.com/globaltrusts/client-card/internal/crypto"
	"github.com/globaltrusts/client-card/internal/totp"
)

// ---- TOTP 管理 Handler ----

// handleListTOTP GET /api/cards/{card_uuid}/totp
func (s *Server) handleListTOTP(w http.ResponseWriter, r *http.Request) {
	cardUUID := r.PathValue("card_uuid")
	entries, err := s.totpStore.ListByCard(r.Context(), cardUUID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "查询 TOTP 列表失败: "+err.Error())
		return
	}
	if entries == nil {
		entries = []totp.Entry{}
	}
	writeOK(w, entries)
}

// handleCreateTOTP POST /api/cards/{card_uuid}/totp
func (s *Server) handleCreateTOTP(w http.ResponseWriter, r *http.Request) {
	cardUUID := r.PathValue("card_uuid")

	var req struct {
		// 方式一：手动输入
		Issuer    string `json:"issuer"`
		Account   string `json:"account"`
		Secret    string `json:"secret"`    // Base32 编码密钥
		Algorithm string `json:"algorithm"` // SHA1/SHA256/SHA512
		Digits    int    `json:"digits"`    // 6 或 8
		Period    int    `json:"period"`    // 秒
		OTPType   string `json:"otp_type"`  // totp 或 hotp
		// 方式二：otpauth URI
		URI string `json:"uri"` // otpauth://totp/...
		// 卡片密码（用于加密密钥）
		CardPassword string `json:"card_password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	var entry *totp.Entry
	var secretStr string

	if req.URI != "" {
		// 从 otpauth URI 解析
		var err error
		entry, secretStr, err = totp.ParseOTPAuthURI(req.URI)
		if err != nil {
			writeError(w, http.StatusBadRequest, "解析 otpauth URI 失败: "+err.Error())
			return
		}
		entry.CardUUID = cardUUID
	} else {
		// 手动输入
		if req.Secret == "" {
			writeError(w, http.StatusBadRequest, "secret 不能为空")
			return
		}
		secretStr = req.Secret

		algo := totp.AlgorithmSHA1
		if req.Algorithm != "" {
			algo = totp.Algorithm(req.Algorithm)
		}
		digits := 6
		if req.Digits == 8 {
			digits = 8
		}
		period := 30
		if req.Period > 0 {
			period = req.Period
		}
		otpType := totp.TypeTOTP
		if req.OTPType == "hotp" {
			otpType = totp.TypeHOTP
		}

		entry = &totp.Entry{
			CardUUID:  cardUUID,
			OTPType:   otpType,
			Issuer:    req.Issuer,
			Account:   req.Account,
			Algorithm: algo,
			Digits:    digits,
			Period:    period,
		}
	}

	// 解码 Base32 密钥
	secretBytes, err := totp.DecodeSecret(secretStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "密钥 Base32 解码失败: "+err.Error())
		return
	}
	defer totp.ZeroBytes(secretBytes)

	// 使用智能卡主密钥加密 TOTP 密钥
	card, err := s.cardRepo.GetByUUID(r.Context(), cardUUID)
	if err != nil || card == nil {
		writeError(w, http.StatusNotFound, "卡片不存在")
		return
	}

	// 用卡片密码解锁主密钥
	slot := local.New(0, card, s.certRepo)
	if err := slot.Login(r.Context(), 1, req.CardPassword); err != nil {
		writeError(w, http.StatusUnauthorized, "卡片密码错误")
		return
	}
	defer slot.Logout(r.Context())

	masterKey := slot.MasterKey()
	if masterKey == nil {
		writeError(w, http.StatusInternalServerError, "获取主密钥失败")
		return
	}
	defer crypto.ZeroBytes(masterKey)

	salt, err := crypto.GenerateRandomBytes(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "生成盐值失败")
		return
	}

	// 用 HMAC(masterKey, salt) 派生 AES 密钥加密
	encKey := crypto.HMACSHA256(masterKey, salt)
	defer crypto.ZeroBytes(encKey)

	secretEnc, err := crypto.EncryptAES256GCM(encKey, secretBytes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "加密 TOTP 密钥失败")
		return
	}

	// 存储
	if err := s.totpStore.Create(r.Context(), entry, secretEnc, salt); err != nil {
		writeError(w, http.StatusInternalServerError, "保存 TOTP 条目失败: "+err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, Response{Code: 0, Message: "ok", Data: entry})
}

// handleGetTOTPCode GET /api/totp/{id}/code
func (s *Server) handleGetTOTPCode(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	cardPassword := r.URL.Query().Get("card_password")
	if cardPassword == "" {
		writeError(w, http.StatusBadRequest, "需要提供 card_password 参数")
		return
	}

	entry, secretEnc, secretSalt, err := s.totpStore.GetByUUID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "查询 TOTP 条目失败: "+err.Error())
		return
	}
	if entry == nil {
		writeError(w, http.StatusNotFound, "TOTP 条目不存在")
		return
	}

	// 获取卡片并解锁主密钥
	card, err := s.cardRepo.GetByUUID(r.Context(), entry.CardUUID)
	if err != nil || card == nil {
		writeError(w, http.StatusNotFound, "卡片不存在")
		return
	}

	slot := local.New(0, card, s.certRepo)
	if err := slot.Login(r.Context(), 1, cardPassword); err != nil {
		writeError(w, http.StatusUnauthorized, "卡片密码错误")
		return
	}
	defer slot.Logout(r.Context())

	masterKey := slot.MasterKey()
	if masterKey == nil {
		writeError(w, http.StatusInternalServerError, "获取主密钥失败")
		return
	}
	defer crypto.ZeroBytes(masterKey)

	// 用 HMAC(masterKey, salt) 派生 AES 密钥解密
	encKey := crypto.HMACSHA256(masterKey, secretSalt)
	defer crypto.ZeroBytes(encKey)

	secretBytes, err := crypto.DecryptAES256GCM(encKey, secretEnc)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "卡片密码错误或密钥解密失败")
		return
	}
	defer totp.ZeroBytes(secretBytes)

	var code string
	switch entry.OTPType {
	case totp.TypeHOTP:
		// HOTP：使用当前计数器生成，然后递增
		code, err = totp.GenerateHOTP(secretBytes, entry.Counter, entry.Digits, entry.Algorithm)
		if err == nil {
			_, _ = s.totpStore.IncrementCounter(r.Context(), id)
		}
	default:
		// TOTP：使用当前时间生成
		code, err = totp.GenerateTOTP(secretBytes, time.Now(), entry.Period, entry.Digits, entry.Algorithm)
	}

	if err != nil {
		writeError(w, http.StatusInternalServerError, "生成验证码失败: "+err.Error())
		return
	}

	writeOK(w, map[string]interface{}{
		"code":      code,
		"remaining": totp.RemainingSeconds(entry.Period),
		"period":    entry.Period,
	})
}

// handleDeleteTOTP DELETE /api/totp/{id}
func (s *Server) handleDeleteTOTP(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.totpStore.Delete(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, "删除 TOTP 条目失败: "+err.Error())
		return
	}
	writeOK(w, nil)
}
