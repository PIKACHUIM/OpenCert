package api

import (
	"encoding/base64"
	"net/http"
	"time"

	"github.com/globaltrusts/client-card/internal/card/local"
	"github.com/globaltrusts/client-card/internal/card/tpmsc"
	"github.com/globaltrusts/client-card/internal/storage"
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
		SlotType     string `json:"slot_type"`
		CardName     string `json:"card_name"`
		UserUUID     string `json:"user_uuid"`
		UserPassword string `json:"user_password"` // 必填，验证用户身份
		CardPassword string `json:"card_password"` // 可选
		PIN          string `json:"pin"`           // 必填，用于加密主密钥
		PUK          string `json:"puk"`           // 可选，未提供时自动生成
		AdminKey     string `json:"admin_key"`     // 可选，未提供时自动生成
		ExpiresAt    string `json:"expires_at"`    // RFC3339 格式
		Remark       string `json:"remark"`
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

	// ---- 根据 slot_type 分发创建逻辑 ----
	switch storage.SlotType(req.SlotType) {
	case storage.SlotTypeTPMSC:
		s.handleCreateTPMSCCard(w, r, req.UserUUID, req.CardName, req.PIN, req.Remark)
		return
	default:
		// local / tpm2 / cloud 走原有逻辑
	}

	// 调用三级凭据版本；未提供 PUK/AdminKey 时自动生成并在响应中一次性返回
	result, err := local.CreateCardWithCreds(r.Context(), s.cardRepo, local.CreateCardArgs{
		UserUUID:      req.UserUUID,
		CardName:      req.CardName,
		CardPassword:  req.CardPassword,
		PIN:           req.PIN,
		PUK:           req.PUK,
		AdminKey:      req.AdminKey,
		GeneratePUK:   req.PUK == "",
		GenerateAdmin: req.AdminKey == "",
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
		"puk":       result.PUK,       // 仅自动生成时非空
		"admin_key": result.AdminKey,  // 仅自动生成时非空
		"pin":       result.PIN,       // 仅自动生成时非空
	}})
}

// handleCreateTPMSCCard 处理 Microsoft TPM Virtual Smart Card 的创建。
// 使用 DEFAULT 模式非交互式创建（PIN=12345678），创建后提示用户修改 PIN。
func (s *Server) handleCreateTPMSCCard(w http.ResponseWriter, r *http.Request, userUUID, cardName, pin, remark string) {
	// 检查平台可用性
	if !tpmsc.IsAvailable() {
		writeError(w, http.StatusBadRequest, "当前系统不支持 TPM Virtual Smart Card（需要 Windows 且 tpmvscmgr.exe 可用）")
		return
	}

	// 调用 tpmvscmgr.exe 创建虚拟智能卡（DEFAULT 模式，无需 stdin 交互）
	vscResult, err := tpmsc.CreateCard(r.Context(), tpmsc.CreateCardArgs{
		Name: cardName,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "创建 TPM Virtual Smart Card 失败: "+err.Error())
		return
	}

	// 在数据库中记录卡片信息
	card := &storage.Card{
		UUID:          newUUID(),
		SlotType:      storage.SlotTypeTPMSC,
		CardName:      cardName,
		UserUUID:      userUUID,
		SecurityLevel: storage.SecurityLevelHigh, // TPM VSC 固定高安全性
		Remark:        remark,
		PINRetries:    5, // Microsoft 默认 PIN 重试次数
	}

	if err := s.cardRepo.Create(r.Context(), card); err != nil {
		writeError(w, http.StatusInternalServerError, "保存卡片记录失败: "+err.Error())
		return
	}

	// Slot 变更广播
	s.notifySlotChanged("create")

	// 响应：返回卡片信息和一次性 AdminKey/PUK/PIN
	writeJSON(w, http.StatusCreated, Response{Code: 0, Message: "ok", Data: map[string]interface{}{
		"card":        card,
		"pin":         vscResult.PIN,        // 默认 PIN（12345678），提示用户修改
		"puk":         vscResult.PUK,        // 默认 PUK（12345678）
		"admin_key":   vscResult.AdminKey,   // 默认 AdminKey
		"instance_id": vscResult.InstanceID,  // Windows 设备实例 ID
		"reader_name": vscResult.ReaderName,  // 虚拟读卡器名称
		"output":      vscResult.Output,      // 命令行输出（调试用）
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
		CardName  string `json:"card_name"`
		ExpiresAt string `json:"expires_at"`
		Remark    string `json:"remark"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	if req.CardName != "" {
		card.CardName = req.CardName
	}
	if req.Remark != "" {
		card.Remark = req.Remark
	}
	if req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err == nil {
			card.ExpiresAt = &t
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

// handleResetPUK POST /api/cards/{uuid}/reset-puk
// 仅 AdminKey 可重置 PUK。请求体：{admin_key, new_puk}
func (s *Server) handleResetPUK(w http.ResponseWriter, r *http.Request) {
	cardUUID := r.PathValue("uuid")
	card, err := s.cardRepo.GetByUUID(r.Context(), cardUUID)
	if err != nil || card == nil {
		writeError(w, http.StatusNotFound, "卡片不存在")
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
	if req.AdminKey == "" || req.NewPUK == "" || req.CurrentPIN == "" {
		writeError(w, http.StatusBadRequest, "admin_key、current_pin 与 new_puk 不能为空")
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