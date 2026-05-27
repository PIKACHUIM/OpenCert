// Package api - credential_handler.go：通用安全凭据 CRUD（FIDO/Login/Note/Payment/Text 等）。
//
// 与 cert_handler 的区别：
//   - cert_handler 仅处理 X.509 公钥证书（CertContent = DER）
//   - credential_handler 支持任意 cert_type，支持加密 SecretData（PrivateData 字段）
//
// 复用 storage.Certificate 表，避免引入新表与迁移。
package api

import (
	"encoding/base64"
	"net/http"

	"github.com/globaltrusts/client-card/internal/card/local"
	"github.com/globaltrusts/client-card/internal/storage"
)

// handleCreateCredential POST /api/cards/{card_uuid}/credentials
//
// 请求体（JSON）：
//
//	{
//	  "cert_type":     "fido"|"login"|"note"|"payment"|"text",
//	  "key_type":      "fido2"|"login-v1"|...,        // 自由形式标识
//	  "public_meta":   "<base64>",                    // 公开元数据（如登录站点 JSON）
//	  "secret_data":   "<base64>",                    // 私密内容（可选）
//	  "card_password": "<string>",                    // 当 secret_data 非空时必填，用于解锁主密钥
//	  "remark":        "<string>"
//	}
func (s *Server) handleCreateCredential(w http.ResponseWriter, r *http.Request) {
	cardUUID := r.PathValue("card_uuid")

	var req struct {
		CertType     string `json:"cert_type"`
		KeyType      string `json:"key_type"`
		PublicMeta   string `json:"public_meta"`
		SecretData   string `json:"secret_data"`
		CardPassword string `json:"card_password"`
		Remark       string `json:"remark"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	if req.CertType == "" {
		writeError(w, http.StatusBadRequest, "cert_type 不能为空")
		return
	}

	publicMeta, err := decodeBase64Optional(req.PublicMeta)
	if err != nil {
		writeError(w, http.StatusBadRequest, "public_meta 必须是 base64")
		return
	}
	secretData, err := decodeBase64Optional(req.SecretData)
	if err != nil {
		writeError(w, http.StatusBadRequest, "secret_data 必须是 base64")
		return
	}

	// 获取卡片信息（用于安全等级判断）
	card, err := s.cardRepo.GetByUUID(r.Context(), cardUUID)
	if err != nil || card == nil {
		writeError(w, http.StatusNotFound, "卡片不存在")
		return
	}

	// 当存在私密内容时需要解锁主密钥
	var masterKey []byte
	if len(secretData) > 0 {
		if req.CardPassword == "" {
			writeError(w, http.StatusBadRequest, "存在 secret_data 时 card_password 不能为空")
			return
		}
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

	km := local.NewKeyManager(s.certRepo, s.cardRepo)
	cert, err := km.ImportCredential(r.Context(), local.CredentialRequest{
		CardUUID:   cardUUID,
		CertType:   storage.CertType(req.CertType),
		KeyType:    req.KeyType,
		PublicMeta: publicMeta,
		SecretData: secretData,
		Remark:     req.Remark,
	}, masterKey, card)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "创建安全凭据失败: "+err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, Response{Code: 0, Message: "ok", Data: cert})
}

// decodeBase64Optional 允许空字符串返回 nil；非空必须合法 base64。
func decodeBase64Optional(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(s)
}
