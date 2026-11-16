package api

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/globaltrusts/client-card/internal/card/local"
	"github.com/globaltrusts/client-card/internal/card/tpmsc"
	"github.com/globaltrusts/client-card/internal/storage"
	"github.com/globaltrusts/client-card/internal/tpm"
)

// ---- 用户管理 Handler ----

// handleListUsers GET /api/users
func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.userRepo.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "查询用户列表失败: "+err.Error())
		return
	}
	writeOK(w, users)
}

// handleCreateUser POST /api/users
func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserType    string `json:"user_type"`
		DisplayName string `json:"display_name"`
		Email       string `json:"email"`
		Password    string `json:"password"`
		CloudURL    string `json:"cloud_url"`
		Role        string `json:"role"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	if req.DisplayName == "" {
		writeError(w, http.StatusBadRequest, "display_name 不能为空")
		return
	}

	user := &storage.User{
		UserType:    storage.UserType(req.UserType),
		DisplayName: req.DisplayName,
		Email:       req.Email,
		CloudURL:    req.CloudURL,
		Role:        req.Role,
		Enabled:     true,
	}

	if user.UserType == "" {
		user.UserType = storage.UserTypeLocal
	}

	// 本地用户需要密码
	if user.UserType == storage.UserTypeLocal && req.Password != "" {
		hash, err := hashPassword(req.Password)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "密码哈希失败")
			return
		}
		user.PasswordHash = hash
	}

	if err := s.userRepo.Create(r.Context(), user); err != nil {
		writeError(w, http.StatusInternalServerError, "创建用户失败: "+err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, Response{Code: 0, Message: "ok", Data: user})
}

// handleGetUser GET /api/users/{uuid}
func (s *Server) handleGetUser(w http.ResponseWriter, r *http.Request) {
	userUUID := r.PathValue("uuid")
	user, err := s.userRepo.GetByUUID(r.Context(), userUUID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if user == nil {
		writeError(w, http.StatusNotFound, "用户不存在")
		return
	}
	writeOK(w, user)
}

// handleUpdateUser PUT /api/users/{uuid}
func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	userUUID := r.PathValue("uuid")

	user, err := s.userRepo.GetByUUID(r.Context(), userUUID)
	if err != nil || user == nil {
		writeError(w, http.StatusNotFound, "用户不存在")
		return
	}

	var req struct {
		DisplayName string `json:"display_name"`
		Email       string `json:"email"`
		Enabled     *bool  `json:"enabled"`
		CloudURL    string `json:"cloud_url"`
		Password    string `json:"password"`
		Role        string `json:"role"`
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
	if req.Enabled != nil {
		user.Enabled = *req.Enabled
	}
	if req.CloudURL != "" {
		user.CloudURL = req.CloudURL
	}
	if req.Role != "" {
		user.Role = req.Role
	}
	if req.Password != "" {
		hash, err := hashPassword(req.Password)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "密码哈希失败")
			return
		}
		user.PasswordHash = hash
	}

	if err := s.userRepo.Update(r.Context(), user); err != nil {
		writeError(w, http.StatusInternalServerError, "更新用户失败: "+err.Error())
		return
	}
	writeOK(w, user)
}

// handleDeleteUser DELETE /api/users/{uuid}
func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	userUUID := r.PathValue("uuid")
	if err := s.userRepo.Delete(r.Context(), userUUID); err != nil {
		// 区分"不存在"和"内部错误"
		if isNotFoundErr(err) {
			writeError(w, http.StatusNotFound, "用户不存在")
			return
		}
		writeError(w, http.StatusInternalServerError, "删除用户失败: "+err.Error())
		return
	}
	writeOK(w, nil)
}

// ---- 卡片管理 Handler ----

// handleListCards GET /api/cards
func (s *Server) handleListCards(w http.ResponseWriter, r *http.Request) {
	userUUID := r.URL.Query().Get("user_uuid")

	var (
		cards []*storage.Card
		err   error
	)
	if userUUID != "" {
		cards, err = s.cardRepo.ListByUser(r.Context(), userUUID)
	} else {
		cards, err = s.cardRepo.ListAll(r.Context())
	}

	if err != nil {
		writeError(w, http.StatusInternalServerError, "查询卡片列表失败: "+err.Error())
		return
	}

	// 查询每张卡片的证书类型统计
	certStats, _ := s.certRepo.CountGroupedByCard(r.Context())

	// 构建带统计信息的响应
	type cardWithStats struct {
		*storage.Card
		CertStats *storage.CertStats `json:"cert_stats"`
	}
	items := make([]cardWithStats, 0, len(cards))
	for _, c := range cards {
		stats := certStats[c.UUID]
		if stats == nil {
			stats = &storage.CertStats{}
		}
		items = append(items, cardWithStats{Card: c, CertStats: stats})
	}

	writeOK(w, items)
}

// handleCreateCard POST /api/cards
func (s *Server) handleCreateCard(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SlotType      string `json:"slot_type"`
		CardName      string `json:"card_name"`
		UserUUID      string `json:"user_uuid"`
		UserPassword  string `json:"user_password"` // 必填，验证用户身份
		CardPassword  string `json:"card_password"` // 可选
		PIN           string `json:"pin"`           // 必填，用于加密主密钥
		PUK           string `json:"puk"`           // 可选，未提供时自动生成
		AdminKey      string `json:"admin_key"`     // 可选，未提供时自动生成
		ExpiresAt     string `json:"expires_at"`    // RFC3339 格式
		Remark        string `json:"remark"`
		SecurityLevel string `json:"security_level"` // 安全等级：high / medium / low（可选，默认 low）
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	if req.CardName == "" || req.UserUUID == "" || req.PIN == "" || req.UserPassword == "" {
		writeError(w, http.StatusBadRequest, "card_name、user_uuid、pin、user_password 不能为空")
		return
	}

	// 验证用户存在并校验密码
	user, err := s.userRepo.GetByUUID(r.Context(), req.UserUUID)
	if err != nil || user == nil {
		writeError(w, http.StatusBadRequest, "用户不存在")
		return
	}
	if !verifyPassword(req.UserPassword, user.PasswordHash) {
		writeError(w, http.StatusForbidden, "用户密码错误")
		return
	}

	// ---- 解析并校验安全等级 ----
	// 前端默认 low；TPMSC 会在安全创建与密码学 Provider 接入前明确拒绝。
	secLevel := storage.SecurityLevel(strings.ToLower(strings.TrimSpace(req.SecurityLevel)))
	switch secLevel {
	case storage.SecurityLevelHigh, storage.SecurityLevelMedium, storage.SecurityLevelLow:
		// ok
	case "":
		secLevel = storage.SecurityLevelLow
	default:
		writeError(w, http.StatusBadRequest, "security_level 仅支持 high / medium / low")
		return
	}

	if storage.SlotType(req.SlotType) == storage.SlotTypeTPMSC {
		if strings.TrimSpace(req.SecurityLevel) != "" && secLevel != storage.SecurityLevelHigh {
			writeError(w, http.StatusBadRequest, "TPM VSC 固定使用 high 安全等级")
			return
		}
		s.handleCreateTPMSCCard(w, r, req.UserUUID, req.CardName, req.PIN, req.PUK, req.AdminKey, req.Remark, req.ExpiresAt)
		return
	}

	// medium / high 都需要 TPM Provider；缺失时给出明确错误，避免落库后再失败。
	if secLevel == storage.SecurityLevelMedium && !tpm.SupportsHardwareNV(s.tpmProvider) {
		writeError(w, http.StatusNotImplemented, tpm.ErrHardwareNVUnavailable.Error())
		return
	}
	if secLevel == storage.SecurityLevelHigh && !tpm.SupportsHardwareKeyGeneration(s.tpmProvider) {
		writeError(w, http.StatusNotImplemented, tpm.ErrHardwareKeyGenerationNotAvailable.Error())
		return
	}

	// 调用三级凭据版本；未提供 PUK/AdminKey 时自动生成并在响应中一次性返回
	result, err := local.CreateCardWithCredsAndTPM(r.Context(), s.cardRepo, s.tpmProvider, local.CreateCardArgs{
		UserUUID:      req.UserUUID,
		CardName:      req.CardName,
		CardPassword:  req.CardPassword,
		PIN:           req.PIN,
		PUK:           req.PUK,
		AdminKey:      req.AdminKey,
		GeneratePUK:   req.PUK == "",
		GenerateAdmin: req.AdminKey == "",
		SecurityLevel: secLevel,
		Remark:        req.Remark,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "创建卡片失败: "+err.Error())
		return
	}
	card := result.Card

	// 设置过期时间
	if req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err == nil {
			card.ExpiresAt = &t
			s.cardRepo.Update(r.Context(), card)
		}
	}

	// Slot 变更广播
	s.notifySlotChanged("create")

	// 响应体包含卡片及一次性明文 PUK / AdminKey（调用方必须保存）
	writeJSON(w, http.StatusCreated, Response{Code: 0, Message: "ok", Data: map[string]interface{}{
		"card":      card,
		"puk":       result.PUK,      // 仅自动生成时非空
		"admin_key": result.AdminKey, // 仅自动生成时非空
		"pin":       result.PIN,      // 仅自动生成时非空
	}})
}

func (s *Server) handleCreateTPMSCCard(w http.ResponseWriter, r *http.Request, userUUID, cardName, pin, puk, adminKey, remark, expiresAt string) {
	if !tpmsc.IsAvailable() {
		writeError(w, http.StatusNotImplemented, "当前系统没有 TPM VSC 管理工具")
		return
	}
	args := tpmsc.CreateCardArgs{Name: cardName, PIN: pin, PUK: puk, AdminKey: adminKey}
	if err := tpmsc.ValidateCreateCardArgs(args); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	card := &storage.Card{
		UUID: newUUID(), SlotType: storage.SlotTypeTPMSC, CardName: cardName,
		UserUUID: userUUID, Enabled: true, SecurityLevel: storage.SecurityLevelHigh,
		Remark: remark, TPMSCState: storage.TPMSCStateProvisioning,
	}
	if expiresAt != "" {
		expiry, err := time.Parse(time.RFC3339, expiresAt)
		if err != nil {
			writeError(w, http.StatusBadRequest, "expires_at 必须为 RFC3339 格式")
			return
		}
		card.ExpiresAt = &expiry
	}
	if err := s.cardRepo.Create(r.Context(), card); err != nil {
		writeError(w, http.StatusInternalServerError, "保存 VSC 创建意图失败: "+err.Error())
		return
	}

	result, err := tpmsc.CreateCard(r.Context(), args)
	if err != nil {
		if errors.Is(err, tpmsc.ErrProvisioningNotImplemented) || errors.Is(err, tpmsc.ErrUserCancelled) {
			_ = s.cardRepo.Delete(context.WithoutCancel(r.Context()), card.UUID)
			status := http.StatusNotImplemented
			if errors.Is(err, tpmsc.ErrUserCancelled) {
				status = http.StatusForbidden
			}
			writeError(w, status, err.Error())
			return
		}
		card.TPMSCState = storage.TPMSCStateProvisioningUnknown
		_ = s.cardRepo.Update(context.WithoutCancel(r.Context()), card)
		writeError(w, http.StatusServiceUnavailable, "VSC 创建结果待核实；请勿重试创建。卡片记录 UUID: "+card.UUID+"; "+err.Error())
		return
	}

	card.TPMSCInstanceID = result.InstanceID
	card.TPMSCReaderName = result.ReaderName
	switch {
	case result.NeedReboot:
		card.TPMSCState = storage.TPMSCStatePendingReboot
	case result.ReaderName == "":
		card.TPMSCState = storage.TPMSCStateReaderUnavailable
	default:
		card.TPMSCState = storage.TPMSCStateReady
	}
	if err := s.cardRepo.Update(context.WithoutCancel(r.Context()), card); err != nil {
		writeError(w, http.StatusInternalServerError, "TPM VSC 已创建但保存设备实例 ID 失败；请保存 InstanceID 并联系管理员: "+result.InstanceID)
		return
	}
	s.notifySlotChanged("create")
	writeJSON(w, http.StatusCreated, Response{Code: 0, Message: "ok", Data: map[string]interface{}{
		"card": card, "instance_id": result.InstanceID, "reader_name": result.ReaderName,
		"need_reboot": result.NeedReboot,
	}})
}

// handleGetCard GET /api/cards/{uuid}
func (s *Server) handleGetCard(w http.ResponseWriter, r *http.Request) {
	cardUUID := r.PathValue("uuid")
	card, err := s.cardRepo.GetByUUID(r.Context(), cardUUID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if card == nil {
		writeError(w, http.StatusNotFound, "卡片不存在")
		return
	}
	writeOK(w, card)
}

// handleUpdateCard PUT /api/cards/{uuid}
func (s *Server) handleUpdateCard(w http.ResponseWriter, r *http.Request) {
	cardUUID := r.PathValue("uuid")
	card, err := s.cardRepo.GetByUUID(r.Context(), cardUUID)
	if err != nil || card == nil {
		writeError(w, http.StatusNotFound, "卡片不存在")
		return
	}

	var req struct {
		CardName          *string `json:"card_name"`
		ExpiresAt         *string `json:"expires_at"`
		Remark            *string `json:"remark"`
		Enabled           *bool   `json:"enabled"`
		FIDOEnabled       *bool   `json:"fido_enabled"`
		TOTPEnabled       *bool   `json:"totp_enabled"`
		CredentialEnabled *bool   `json:"credential_enabled"`
		PINTimeout        *int    `json:"pin_timeout"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	if req.CardName != nil && *req.CardName != "" {
		card.CardName = *req.CardName
	}
	if req.Remark != nil {
		card.Remark = *req.Remark
	}
	if req.Enabled != nil {
		card.Enabled = *req.Enabled
	}
	if req.FIDOEnabled != nil {
		card.FIDOEnabled = *req.FIDOEnabled
	}
	if req.TOTPEnabled != nil {
		card.TOTPEnabled = *req.TOTPEnabled
	}
	if req.CredentialEnabled != nil {
		card.CredentialEnabled = *req.CredentialEnabled
	}
	if req.PINTimeout != nil {
		card.PINTimeout = *req.PINTimeout
	}
	if req.ExpiresAt != nil {
		if *req.ExpiresAt == "" {
			// 空字符串表示永不过期
			card.ExpiresAt = nil
		} else {
			// 支持多种格式：RFC3339、YYYY-MM-DD
			var t time.Time
			var parseErr error
			for _, layout := range []string{time.RFC3339, "2006-01-02", "2006-01-02T15:04:05"} {
				t, parseErr = time.Parse(layout, *req.ExpiresAt)
				if parseErr == nil {
					break
				}
			}
			if parseErr == nil {
				card.ExpiresAt = &t
			}
		}
	}

	if err := s.cardRepo.Update(r.Context(), card); err != nil {
		writeError(w, http.StatusInternalServerError, "更新卡片失败: "+err.Error())
		return
	}
	writeOK(w, card)
}

// handleDeleteCard DELETE /api/cards/{uuid}
// 请求体：{user_uuid, user_password}
func (s *Server) handleDeleteCard(w http.ResponseWriter, r *http.Request) {
	cardUUID := r.PathValue("uuid")

	var req struct {
		UserUUID     string `json:"user_uuid"`
		UserPassword string `json:"user_password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	if req.UserUUID == "" || req.UserPassword == "" {
		writeError(w, http.StatusBadRequest, "user_uuid 和 user_password 不能为空")
		return
	}

	// 验证用户密码
	user, err := s.userRepo.GetByUUID(r.Context(), req.UserUUID)
	if err != nil || user == nil {
		writeError(w, http.StatusBadRequest, "用户不存在")
		return
	}
	if !verifyPassword(req.UserPassword, user.PasswordHash) {
		writeError(w, http.StatusForbidden, "用户密码错误")
		return
	}

	card, err := s.cardRepo.GetByUUID(r.Context(), cardUUID)
	if err != nil || card == nil {
		writeError(w, http.StatusNotFound, "卡片不存在")
		return
	}
	if card.UserUUID != req.UserUUID {
		writeError(w, http.StatusForbidden, "无权删除其他用户的卡片")
		return
	}
	if card.SlotType == storage.SlotTypeTPMSC {
		if card.TPMSCInstanceID == "" {
			writeError(w, http.StatusConflict, "VSC 实例 ID 缺失或创建状态待核实；拒绝删除本地记录")
			return
		}
		if card.TPMSCState == storage.TPMSCStateDestroyPendingReboot {
			_, discoverErr := tpmsc.DiscoverReaderName(r.Context(), card.TPMSCInstanceID)
			if errors.Is(discoverErr, tpmsc.ErrReaderUnavailable) {
				if err := s.cardRepo.Delete(context.WithoutCancel(r.Context()), cardUUID); err != nil {
					writeError(w, http.StatusInternalServerError, "清理已销毁的 VSC 记录失败: "+err.Error())
					return
				}
				s.notifySlotChanged("delete")
				writeOK(w, nil)
				return
			}
			if discoverErr != nil {
				writeError(w, http.StatusServiceUnavailable, "重启后无法确认 TPM VSC 状态: "+discoverErr.Error())
				return
			}
		}
		needReboot, destroyErr := tpmsc.DestroyCard(r.Context(), card.TPMSCInstanceID)
		if destroyErr != nil {
			writeError(w, http.StatusInternalServerError, "销毁 TPM VSC 失败: "+destroyErr.Error())
			return
		}
		if needReboot {
			card.TPMSCState = storage.TPMSCStateDestroyPendingReboot
			if err := s.cardRepo.Update(context.WithoutCancel(r.Context()), card); err != nil {
				writeError(w, http.StatusInternalServerError, "销毁已提交但保存重启状态失败: "+err.Error())
				return
			}
			writeJSON(w, http.StatusAccepted, Response{Code: 0, Message: "需要重启后完成 VSC 销毁", Data: map[string]bool{"need_reboot": true}})
			return
		}
	}

	if err := s.cardRepo.Delete(r.Context(), cardUUID); err != nil {
		if isNotFoundErr(err) {
			writeError(w, http.StatusNotFound, "卡片不存在")
			return
		}
		writeError(w, http.StatusInternalServerError, "删除卡片失败: "+err.Error())
		return
	}
	// Slot 变更广播
	s.notifySlotChanged("delete")
	writeOK(w, nil)
}

// ---- PIN / PUK / AdminKey 三级凭据：重置接口 ----

// handleResetPIN POST /api/cards/{uuid}/reset-pin
// 使用 PUK 或 AdminKey 重置 PIN。请求体：{puk?, admin_key?, new_pin}
func (s *Server) handleResetPIN(w http.ResponseWriter, r *http.Request) {
	cardUUID := r.PathValue("uuid")
	card, err := s.cardRepo.GetByUUID(r.Context(), cardUUID)
	if err != nil || card == nil {
		writeError(w, http.StatusNotFound, "卡片不存在")
		return
	}

	var req struct {
		PUK      string `json:"puk"`
		AdminKey string `json:"admin_key"`
		NewPIN   string `json:"new_pin"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	if card.SlotType == storage.SlotTypeTPMSC {
		if req.AdminKey != "" || req.PUK == "" {
			writeError(w, http.StatusBadRequest, "VSC 仅支持使用 PUK 解锁 PIN；AdminKey challenge-response 尚未接入")
			return
		}
		s.resetTPMSCPIN(w, r, card, req.PUK, req.NewPIN)
		return
	}
	if rejectUnsupportedTPMSC(w, card.SlotType, "PIN 重置") {
		return
	}

	if req.NewPIN == "" {
		writeError(w, http.StatusBadRequest, "new_pin 不能为空")
		return
	}
	if req.PUK == "" && req.AdminKey == "" {
		writeError(w, http.StatusBadRequest, "需要提供 puk 或 admin_key")
		return
	}

	keyType := "puk"
	secret := req.PUK
	if req.AdminKey != "" {
		keyType = "admin"
		secret = req.AdminKey
	}

	if err := local.ResetPIN(r.Context(), s.cardRepo, card, keyType, secret, req.NewPIN); err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	writeOK(w, map[string]string{"status": "pin_reset_ok"})
}

// handleChangePIN POST /api/cards/{uuid}/pin/change
// 仅 TPM VSC 支持：使用当前 PIN 直接修改 PIN。请求体：{old_pin, new_pin}
func (s *Server) handleChangePIN(w http.ResponseWriter, r *http.Request) {
	cardUUID := r.PathValue("uuid")
	card, err := s.cardRepo.GetByUUID(r.Context(), cardUUID)
	if err != nil || card == nil {
		writeError(w, http.StatusNotFound, "卡片不存在")
		return
	}
	if card.SlotType != storage.SlotTypeTPMSC {
		writeError(w, http.StatusBadRequest, "只有 Windows TPM VSC 支持直接修改 PIN；本地卡请使用 PIN 重置")
		return
	}
	var req struct {
		OldPIN string `json:"old_pin"`
		NewPIN string `json:"new_pin"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	if req.OldPIN == "" || req.NewPIN == "" {
		writeError(w, http.StatusBadRequest, "old_pin 和 new_pin 不能为空")
		return
	}
	if err := s.ensureTPMSCReady(card); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if err := tpmsc.ChangePIN(r.Context(), card.TPMSCReaderName, req.OldPIN, req.NewPIN); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeOK(w, map[string]string{"status": "pin_changed"})
}

func (s *Server) resetTPMSCPIN(w http.ResponseWriter, r *http.Request, card *storage.Card, puk, newPIN string) {
	if newPIN == "" {
		writeError(w, http.StatusBadRequest, "new_pin 不能为空")
		return
	}
	if err := s.ensureTPMSCReady(card); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if err := tpmsc.UnblockPIN(r.Context(), card.TPMSCReaderName, puk, newPIN); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeOK(w, map[string]string{"status": "pin_unblocked"})
}

// ensureTPMSCReady 确认 VSC 已创建且读卡器可用，避免把不可用状态误报成 PIN 错误。
func (s *Server) ensureTPMSCReady(card *storage.Card) error {
	if card.TPMSCInstanceID == "" {
		return fmt.Errorf("该卡片没有可用的 VSC 实例，无法执行 PIN 操作")
	}
	if card.TPMSCState != storage.TPMSCStateReady || card.TPMSCReaderName == "" {
		return fmt.Errorf("VSC 当前状态为 %q，读卡器不可用；请先重启并刷新卡片状态", card.TPMSCState)
	}
	return nil
}

// handleResetPUK POST /api/cards/{uuid}/reset-puk
// 仅 AdminKey 可重置 PUK。请求体：{admin_key, new_puk}
func (s *Server) handleResetPUK(w http.ResponseWriter, r *http.Request) {
	cardUUID := r.PathValue("uuid")
	card, err := s.cardRepo.GetByUUID(r.Context(), cardUUID)
	if err != nil || card == nil {
		writeError(w, http.StatusNotFound, "卡片不存在")
		return
	}
	if rejectUnsupportedTPMSC(w, card.SlotType, "PUK 重置") {
		return
	}

	var req struct {
		AdminKey   string `json:"admin_key"`
		CurrentPIN string `json:"current_pin"`
		NewPUK     string `json:"new_puk"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	if req.AdminKey == "" || req.NewPUK == "" {
		writeError(w, http.StatusBadRequest, "admin_key 与 new_puk 不能为空")
		return
	}

	if err := local.ResetPUK(r.Context(), s.cardRepo, card, req.AdminKey, req.CurrentPIN, req.NewPUK); err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	writeOK(w, map[string]string{"status": "puk_reset_ok"})
}

// handleExportCard POST /api/cards/{uuid}/export
// 导出智能卡为 .ocs 文件。请求体：{password?, admin_key?}
func (s *Server) handleExportCard(w http.ResponseWriter, r *http.Request) {
	cardUUID := r.PathValue("uuid")

	var req struct {
		UserUUID     string `json:"user_uuid"`
		UserPassword string `json:"user_password"`
		Password     string `json:"password"`
		AdminKey     string `json:"admin_key"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	if req.UserUUID == "" || req.UserPassword == "" {
		writeError(w, http.StatusBadRequest, "user_uuid 和 user_password 不能为空")
		return
	}

	// 验证用户密码
	user, err := s.userRepo.GetByUUID(r.Context(), req.UserUUID)
	if err != nil || user == nil {
		writeError(w, http.StatusBadRequest, "用户不存在")
		return
	}
	if !verifyPassword(req.UserPassword, user.PasswordHash) {
		writeError(w, http.StatusForbidden, "用户密码错误")
		return
	}

	card, err := s.cardRepo.GetByUUID(r.Context(), cardUUID)
	if err != nil || card == nil {
		writeError(w, http.StatusNotFound, "卡片不存在")
		return
	}
	if rejectUnsupportedTPMSC(w, card.SlotType, "导出卡片") {
		return
	}

	ocsData, err := local.ExportCard(r.Context(), s.cardRepo, s.certRepo, local.ExportCardRequest{
		CardUUID: cardUUID,
		Password: req.Password,
		AdminKey: req.AdminKey,
	})
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=\"card-"+cardUUID+".ocs\"")
	w.WriteHeader(http.StatusOK)
	w.Write(ocsData)
}

// handleRestoreCard POST /api/cards/restore
// 从 .ocs 文件恢复智能卡。请求体：{ocs_data (base64), password, user_uuid}
func (s *Server) handleRestoreCard(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OCSDataB64   string `json:"ocs_data"`
		Password     string `json:"password"`
		UserUUID     string `json:"user_uuid"`
		UserPassword string `json:"user_password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	if req.OCSDataB64 == "" || req.Password == "" || req.UserUUID == "" || req.UserPassword == "" {
		writeError(w, http.StatusBadRequest, "ocs_data、password、user_uuid 和 user_password 不能为空")
		return
	}

	// 验证用户密码
	user, err := s.userRepo.GetByUUID(r.Context(), req.UserUUID)
	if err != nil || user == nil {
		writeError(w, http.StatusBadRequest, "用户不存在")
		return
	}
	if !verifyPassword(req.UserPassword, user.PasswordHash) {
		writeError(w, http.StatusForbidden, "用户密码错误")
		return
	}

	ocsData, err := base64.StdEncoding.DecodeString(req.OCSDataB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "ocs_data base64 解码失败")
		return
	}

	card, err := local.RestoreCard(r.Context(), s.cardRepo, s.certRepo, local.RestoreCardRequest{
		OCSData:  ocsData,
		Password: req.Password,
		UserUUID: req.UserUUID,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, Response{
		Code:    0,
		Message: "卡片恢复成功",
		Data:    card,
	})
}
