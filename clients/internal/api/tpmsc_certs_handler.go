package api

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/http"

	"github.com/globaltrusts/client-card/internal/card/tpmsc"
	"github.com/globaltrusts/client-card/internal/certprop"
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

// handleImportCERToCard POST /api/cards/{uuid}/certs/import-cer
// 把 CA 签发回来的证书绑定到卡上已有密钥容器。请求体：{cert_b64, container_uuid?}
// 不指定 container_uuid 时按公钥匹配该卡片上未过期的内部密钥记录。
func (s *Server) handleImportCERToCard(w http.ResponseWriter, r *http.Request) {
	card, ok := s.loadTPMSCCard(w, r, "导入证书")
	if !ok {
		return
	}
	var req struct {
		CertB64       string `json:"cert_b64"`
		ContainerUUID string `json:"container_uuid"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	if req.CertB64 == "" {
		writeError(w, http.StatusBadRequest, "cert_b64 不能为空")
		return
	}
	raw, err := base64.StdEncoding.DecodeString(req.CertB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "cert_b64 不是有效的 base64")
		return
	}
	certDER, err := decodeCertificateBytes(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	parsed, err := x509.ParseCertificate(certDER)
	if err != nil {
		writeError(w, http.StatusBadRequest, "证书解析失败: "+err.Error())
		return
	}
	record, err := s.matchVSCKeyRecord(r, card, parsed, req.ContainerUUID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	container := tpmsc.SmartCardKSPContainerName(card.TPMSCReaderName, record.UUID)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	if err := s.certPropagator.Add(r.Context(), certprop.CertInfo{
		UUID:         record.UUID,
		CardUUID:     card.UUID,
		CommonName:   parsed.Subject.CommonName,
		CertPEM:      certPEM,
		CertDER:      certDER,
		HasKey:       true,
		KeyType:      record.KeyType,
		KeyProvider:  certprop.SmartCardKSPName,
		KeyContainer: container,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "写入 Windows 证书存储失败: "+err.Error())
		return
	}
	writeOK(w, map[string]string{"status": "cert_bound", "container_uuid": record.UUID})
}

func decodeCertificateBytes(raw []byte) ([]byte, error) {
	if block, _ := pem.Decode(raw); block != nil {
		if block.Type != "CERTIFICATE" {
			return nil, errors.New("PEM 块不是 CERTIFICATE")
		}
		return block.Bytes, nil
	}
	if _, err := x509.ParseCertificate(raw); err == nil {
		return raw, nil
	}
	return nil, errors.New("无法识别的证书格式（支持 PEM/DER 单证书；P7B 请先解包）")
}

func (s *Server) matchVSCKeyRecord(r *http.Request, card *storage.Card, cert *x509.Certificate, containerUUID string) (*storage.Certificate, error) {
	if containerUUID != "" {
		record, err := s.certRepo.GetByUUID(r.Context(), containerUUID)
		if err != nil || record == nil {
			return nil, errors.New("指定的密钥容器不存在")
		}
		if record.CardUUID != card.UUID || record.SlotType != storage.SlotTypeTPMSC || record.CertType != storage.CertTypeInternal {
			return nil, errors.New("指定的容器不是该卡片上的内部密钥")
		}
		return record, nil
	}
	pubDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return nil, errors.New("读取证书公钥失败")
	}
	records, err := s.certRepo.ListByCard(r.Context(), card.UUID)
	if err != nil {
		return nil, errors.New("查询卡片密钥记录失败")
	}
	for _, record := range records {
		if record.SlotType != storage.SlotTypeTPMSC || record.CertType != storage.CertTypeInternal {
			continue
		}
		block, _ := pem.Decode([]byte(record.CertContent))
		if block == nil {
			continue
		}
		if bytes.Equal(block.Bytes, pubDER) {
			return record, nil
		}
	}
	return nil, errors.New("卡上没有与该证书公钥匹配的密钥；请先通过 CSR 生成密钥，或改用 PFX 导入")
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
