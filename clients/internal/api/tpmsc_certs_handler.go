package api

import (
	"encoding/base64"
	"errors"
	"net/http"

	"github.com/globaltrusts/client-card/internal/card/tpmsc"
	"github.com/globaltrusts/client-card/internal/storage"
)

// handleListCardCertificates GET /api/cards/{uuid}/certs/on-card
// 零 OpenSC 口径：枚举 Windows「个人」存储中、密钥挂在指定 VSC 上的证书。
func (s *Server) handleListCardCertificates(w http.ResponseWriter, r *http.Request) {
	card, ok := s.loadTPMSCCard(w, r, "读取卡上证书")
	if !ok {
		return
	}
	certs, err := tpmsc.ListCardCertificates(card.TPMSCReaderName)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeOK(w, certs)
}

// handleImportPFXToCard POST /api/cards/{uuid}/certs/import-pfx
// 请求体：{pfx_b64, password}。密码仅用于本次 certutil 调用，不落库。
func (s *Server) handleImportPFXToCard(w http.ResponseWriter, r *http.Request) {
	card, ok := s.loadTPMSCCard(w, r, "导入 PFX")
	if !ok {
		return
	}
	var req struct {
		PFXB64   string `json:"pfx_b64"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	if req.PFXB64 == "" {
		writeError(w, http.StatusBadRequest, "pfx_b64 不能为空")
		return
	}
	data, err := base64.StdEncoding.DecodeString(req.PFXB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "pfx_b64 不是有效的 base64")
		return
	}
	if len(data) == 0 || len(data) > 8<<20 {
		writeError(w, http.StatusBadRequest, "PFX 大小必须在 1 字节到 8MB 之间")
		return
	}
	if err := tpmsc.ImportPFXToCard(r.Context(), card.TPMSCReaderName, data, req.Password); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeOK(w, map[string]string{"status": "imported"})
}

func (s *Server) loadTPMSCCard(w http.ResponseWriter, r *http.Request, action string) (*storage.Card, bool) {
	cardUUID := r.PathValue("uuid")
	card, err := s.cardRepo.GetByUUID(r.Context(), cardUUID)
	if err != nil || card == nil {
		writeError(w, http.StatusNotFound, "卡片不存在")
		return nil, false
	}
	if card.SlotType != storage.SlotTypeTPMSC {
		writeError(w, http.StatusBadRequest, action+"仅支持 Windows TPM VSC")
		return nil, false
	}
	if err := s.ensureTPMSCReady(card); err != nil {
		if errors.Is(err, tpmsc.ErrReaderUnavailable) {
			writeError(w, http.StatusConflict, err.Error())
			return nil, false
		}
		writeError(w, http.StatusConflict, err.Error())
		return nil, false
	}
	return card, true
}
