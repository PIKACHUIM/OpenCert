// Package api - fido_handler.go：FIDO2/WebAuthn 凭据管理 API。
//
// 路由：
//
//	GET    /api/cards/{card_uuid}/fido          - 列出 FIDO 凭据
//	POST   /api/cards/{card_uuid}/fido          - 创建 FIDO 凭据
//	GET    /api/cards/{card_uuid}/fido/{uuid}   - 获取单条 FIDO 凭据
//	DELETE /api/cards/{card_uuid}/fido/{uuid}   - 删除 FIDO 凭据
//	POST   /api/cards/{card_uuid}/fido/{uuid}/secret  - 解密查看私密数据
//	POST   /api/cards/{card_uuid}/fido/{uuid}/counter - 递增签名计数器
package api

import (
	"encoding/base64"
	"log/slog"
	"net/http"

	"github.com/globaltrusts/client-card/internal/card/local"
	"github.com/globaltrusts/client-card/internal/fido"
)

// ---- FIDO 凭据 Handler ----

// handleListFIDO GET /api/cards/{card_uuid}/fido
// 列出指定卡片下的所有 FIDO 凭据（不含私密数据）。
func (s *Server) handleListFIDO(w http.ResponseWriter, r *http.Request) {
	cardUUID := r.PathValue("card_uuid")

	store := s.newFIDOStore()
	entries, err := store.List(r.Context(), cardUUID)
	if err != nil {
		slog.Error("查询 FIDO 凭据列表失败", "card_uuid", cardUUID, "error", err)
		writeError(w, http.StatusInternalServerError, "查询 FIDO 凭据列表失败: "+err.Error())
		return
	}
	if entries == nil {
		entries = []fido.Entry{}
	}
	writeOK(w, entries)
}

// handleCreateFIDO POST /api/cards/{card_uuid}/fido
//
// 请求体（JSON）：
//
//	{
//	  "rp_id":           "example.com",       // 必填：依赖方 ID
//	  "rp_name":         "Example Corp",      // 可选：依赖方名称
//	  "user_name":       "alice@example.com", // 必填：用户名
//	  "user_display_name": "Alice",           // 可选：用户显示名称
//	  "user_handle":     "<base64url>",       // 可选：用户句柄（留空则随机生成）
//	  "credential_id":   "<uuid>",            // 必填：凭据 ID
//	  "algorithm":       "ES256",             // 可选：签名算法（默认 ES256）
//	  "transports":      ["usb","nfc"],       // 可选：传输方式
//	  "private_key_pem": "-----BEGIN...",     // 可选：私钥 PEM（软件实现时填写）
//	  "key_handle":      "<base64url>",       // 可选：硬件认证器 key handle
//	  "card_password":   "<string>",          // 当有私密数据时必填
//	  "remark":          "<string>"           // 可选：备注
//	}
func (s *Server) handleCreateFIDO(w http.ResponseWriter, r *http.Request) {
	cardUUID := r.PathValue("card_uuid")

	var req struct {
		RPID            string   `json:"rp_id"`
		RPName          string   `json:"rp_name"`
		UserName        string   `json:"user_name"`
		UserDisplayName string   `json:"user_display_name"`
		UserHandle      string   `json:"user_handle"`
		CredentialID    string   `json:"credential_id"`
		Algorithm       string   `json:"algorithm"`
		Transports      []string `json:"transports"`
		PrivateKeyPEM   string   `json:"private_key_pem"`
		KeyHandle       string   `json:"key_handle"`
		PublicKeyDER    string   `json:"public_key_der"` // base64 编码的 DER
		AAGUID          string   `json:"aaguid"`
		CardPassword    string   `json:"card_password"`
		Remark          string   `json:"remark"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	// 构造元数据
	meta := &fido.Meta{
		RPID:            req.RPID,
		RPName:          req.RPName,
		UserName:        req.UserName,
		UserDisplayName: req.UserDisplayName,
		UserHandle:      req.UserHandle,
		CredentialID:    req.CredentialID,
		Algorithm:       req.Algorithm,
		Transports:      req.Transports,
		Counter:         0,
	}
	if meta.Algorithm == "" {
		meta.Algorithm = "ES256"
	}

	// 验证必填字段
	if err := fido.ValidateMeta(meta); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// 构造私密数据（可选）
	var secret *fido.Secret
	hasSecret := req.PrivateKeyPEM != "" || req.KeyHandle != "" || req.PublicKeyDER != ""
	if hasSecret {
		if req.CardPassword == "" {
			writeError(w, http.StatusBadRequest, "存在私密数据时 card_password 不能为空")
			return
		}
		secret = &fido.Secret{
			PrivateKeyPEM: req.PrivateKeyPEM,
			KeyHandle:     req.KeyHandle,
			PublicKeyDER:  req.PublicKeyDER,
			AAGUID:        req.AAGUID,
		}
	}

	// 获取卡片信息
	card, err := s.cardRepo.GetByUUID(r.Context(), cardUUID)
	if err != nil || card == nil {
		writeError(w, http.StatusNotFound, "卡片不存在")
		return
	}

	// 解锁主密钥（有私密数据时才需要）
	var masterKey []byte
	if hasSecret {
		slot := local.New(0, card, s.certRepo)
		if err := slot.Login(r.Context(), 1, req.CardPassword); err != nil {
			writeError(w, http.StatusUnauthorized, "卡片密码错误")
			return
		}
		defer slot.Logout(r.Context())
		masterKey = slot.MasterKey()
		if masterKey == nil {
			writeError(w, http.StatusInternalServerError, "获取主密钥失败")
			return
		}
	}

	store := s.newFIDOStore()
	entry, err := store.Create(r.Context(), cardUUID, meta, secret, masterKey, card)
	if err != nil {
		slog.Error("创建 FIDO 凭据失败", "card_uuid", cardUUID, "error", err)
		writeError(w, http.StatusInternalServerError, "创建 FIDO 凭据失败: "+err.Error())
		return
	}

	slog.Info("创建 FIDO 凭据", "card_uuid", cardUUID, "uuid", entry.UUID, "rp_id", meta.RPID)
	writeJSON(w, http.StatusCreated, Response{Code: 0, Message: "ok", Data: entry})
}

// handleGetFIDO GET /api/cards/{card_uuid}/fido/{uuid}
// 获取单条 FIDO 凭据（不含私密数据）。
func (s *Server) handleGetFIDO(w http.ResponseWriter, r *http.Request) {
	certUUID := r.PathValue("uuid")

	store := s.newFIDOStore()
	entry, err := store.GetByUUID(r.Context(), certUUID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "查询 FIDO 凭据失败: "+err.Error())
		return
	}
	if entry == nil {
		writeError(w, http.StatusNotFound, "FIDO 凭据不存在")
		return
	}
	writeOK(w, entry)
}

// handleDeleteFIDO DELETE /api/cards/{card_uuid}/fido/{uuid}
// 删除 FIDO 凭据。
func (s *Server) handleDeleteFIDO(w http.ResponseWriter, r *http.Request) {
	certUUID := r.PathValue("uuid")

	store := s.newFIDOStore()
	if err := store.Delete(r.Context(), certUUID); err != nil {
		slog.Error("删除 FIDO 凭据失败", "uuid", certUUID, "error", err)
		writeError(w, http.StatusInternalServerError, "删除 FIDO 凭据失败: "+err.Error())
		return
	}

	slog.Info("删除 FIDO 凭据", "uuid", certUUID)
	writeOK(w, nil)
}

// handleGetFIDOSecret POST /api/cards/{card_uuid}/fido/{uuid}/secret
//
// 解密并返回 FIDO 凭据的私密数据（私钥 PEM、key handle 等）。
//
// 请求体（JSON）：
//
//	{ "card_password": "<string>" }
//
// 响应（JSON）：
//
//	{
//	  "private_key_pem": "-----BEGIN...",
//	  "key_handle":      "<base64url>",
//	  "public_key_der":  "<base64>",
//	  "aaguid":          "<base64url>"
//	}
func (s *Server) handleGetFIDOSecret(w http.ResponseWriter, r *http.Request) {
	cardUUID := r.PathValue("card_uuid")
	certUUID := r.PathValue("uuid")

	var req struct {
		CardPassword string `json:"card_password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	if req.CardPassword == "" {
		writeError(w, http.StatusBadRequest, "card_password 不能为空")
		return
	}

	card, err := s.cardRepo.GetByUUID(r.Context(), cardUUID)
	if err != nil || card == nil {
		writeError(w, http.StatusNotFound, "卡片不存在")
		return
	}

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

	store := s.newFIDOStore()
	secret, err := store.GetSecret(r.Context(), certUUID, masterKey, card)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "解密 FIDO 私密数据失败: "+err.Error())
		return
	}

	writeOK(w, secret)
}

// handleIncrFIDOCounter POST /api/cards/{card_uuid}/fido/{uuid}/counter
//
// 递增 FIDO 签名计数器（防重放攻击）。
// 每次使用 FIDO 凭据完成认证后应调用此接口。
//
// 响应（JSON）：
//
//	{ "counter": 42 }
func (s *Server) handleIncrFIDOCounter(w http.ResponseWriter, r *http.Request) {
	certUUID := r.PathValue("uuid")

	store := s.newFIDOStore()
	counter, err := store.IncrementCounter(r.Context(), certUUID)
	if err != nil {
		slog.Error("递增 FIDO 计数器失败", "uuid", certUUID, "error", err)
		writeError(w, http.StatusInternalServerError, "递增计数器失败: "+err.Error())
		return
	}

	writeOK(w, map[string]uint32{"counter": counter})
}

// handleExportFIDOPublicKey GET /api/cards/{card_uuid}/fido/{uuid}/pubkey
//
// 导出 FIDO 凭据的公钥（base64 编码的 DER 格式）。
// 用于在依赖方（RP）注册时提交公钥。
//
// 请求体（JSON）：
//
//	{ "card_password": "<string>" }
//
// 响应（JSON）：
//
//	{ "public_key_der": "<base64>", "algorithm": "ES256" }
func (s *Server) handleExportFIDOPublicKey(w http.ResponseWriter, r *http.Request) {
	cardUUID := r.PathValue("card_uuid")
	certUUID := r.PathValue("uuid")

	var req struct {
		CardPassword string `json:"card_password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	if req.CardPassword == "" {
		writeError(w, http.StatusBadRequest, "card_password 不能为空")
		return
	}

	card, err := s.cardRepo.GetByUUID(r.Context(), cardUUID)
	if err != nil || card == nil {
		writeError(w, http.StatusNotFound, "卡片不存在")
		return
	}

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

	store := s.newFIDOStore()

	// 获取元数据（算法信息）
	entry, err := store.GetByUUID(r.Context(), certUUID)
	if err != nil || entry == nil {
		writeError(w, http.StatusNotFound, "FIDO 凭据不存在")
		return
	}

	// 解密私密数据获取公钥
	secret, err := store.GetSecret(r.Context(), certUUID, masterKey, card)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "解密失败: "+err.Error())
		return
	}

	if secret.PublicKeyDER == "" {
		writeError(w, http.StatusNotFound, "该凭据未存储公钥")
		return
	}

	// 验证 base64 格式
	if _, err := base64.StdEncoding.DecodeString(secret.PublicKeyDER); err != nil {
		writeError(w, http.StatusInternalServerError, "公钥格式错误")
		return
	}

	writeOK(w, map[string]string{
		"public_key_der": secret.PublicKeyDER,
		"algorithm":      entry.Meta.Algorithm,
		"credential_id":  entry.Meta.CredentialID,
	})
}

// ---- 内部辅助 ----

// newFIDOStore 创建 FIDO 存储实例。
func (s *Server) newFIDOStore() *fido.Store {
	km := local.NewKeyManagerWithTPM(s.certRepo, s.cardRepo, s.tpmProvider)
	return fido.NewStore(s.certRepo, s.cardRepo, km)
}
