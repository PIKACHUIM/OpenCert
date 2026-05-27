package api

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"strconv"

	"github.com/globaltrusts/client-card/internal/card/local"
	"github.com/globaltrusts/client-card/internal/pki"
	"github.com/globaltrusts/client-card/internal/storage"
)

// ---- 证书管理 Handler ----

// certListItem 是证书列表返回的单项，包含解析出的 CN 和 Issuer。
type certListItem struct {
	UUID        string             `json:"uuid"`
	SlotType    storage.SlotType   `json:"slot_type"`
	CardUUID    string             `json:"card_uuid"`
	CertType    storage.CertType   `json:"cert_type"`
	KeyType     string             `json:"key_type"`
	CertContent storage.Base64Bytes `json:"cert_content"`
	Remark      string             `json:"remark"`
	CreatedAt   string             `json:"created_at"`
	UpdatedAt   string             `json:"updated_at"`
	CommonName  string             `json:"common_name"`
	IssuerCN    string             `json:"issuer_cn"`
}

// handleListCerts GET /api/cards/{card_uuid}/certs
func (s *Server) handleListCerts(w http.ResponseWriter, r *http.Request) {
	cardUUID := r.PathValue("card_uuid")
	certs, err := s.certRepo.ListByCard(r.Context(), cardUUID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "查询证书列表失败: "+err.Error())
		return
	}

	// 解析每个证书的 CN 和 Issuer CN
	items := make([]certListItem, 0, len(certs))
	for _, c := range certs {
		item := certListItem{
			UUID:        c.UUID,
			SlotType:    c.SlotType,
			CardUUID:    c.CardUUID,
			CertType:    c.CertType,
			KeyType:     c.KeyType,
			CertContent: c.CertContent,
			Remark:      c.Remark,
			CreatedAt:   c.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			UpdatedAt:   c.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
		}
		// 尝试解析 X.509 证书提取 CN 和 Issuer（使用宽松解析）
		if len(c.CertContent) > 0 {
			if detail, parseErr := local.ParseCertDetail(c.CertContent); parseErr == nil && detail != nil {
				item.CommonName = detail.CommonName
				item.IssuerCN = detail.IssuerCN
			} else {
				// 回退：尝试 DER 宽松解析（处理含非标准 certificate policies 的证书）
				derData := c.DERContent()
				if parsed, e2 := local.ParseCertLenient(derData); e2 == nil {
					item.CommonName = parsed.Subject.CommonName
					item.IssuerCN = parsed.Issuer.CommonName
				}
			}
		}
		items = append(items, item)
	}

	writeOK(w, items)
}

// handleCreateCert POST /api/cards/{card_uuid}/certs
// 用于导入已有证书（公钥/X.509 DER，base64 编码）
func (s *Server) handleCreateCert(w http.ResponseWriter, r *http.Request) {
	cardUUID := r.PathValue("card_uuid")

	var req struct {
		CertType    string `json:"cert_type"`
		KeyType     string `json:"key_type"`
		CertContent string `json:"cert_content"` // base64 DER
		Remark      string `json:"remark"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	certDER, err := base64.StdEncoding.DecodeString(req.CertContent)
	if err != nil {
		writeError(w, http.StatusBadRequest, "cert_content 必须是 base64 编码的 DER 数据")
		return
	}

	certRepo := storage.NewCertRepo(s.db)
	km := local.NewKeyManager(certRepo, s.cardRepo)

	cert, err := km.ImportCertificate(r.Context(), cardUUID, certDER, req.Remark)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "导入证书失败: "+err.Error())
		return
	}

	// 导入成功后，自动传播到系统证书存储
	if cert != nil {
		s.propagateCertAddDER(certDER, cert.UUID, cardUUID, req.KeyType, false)
	}

	writeJSON(w, http.StatusCreated, Response{Code: 0, Message: "ok", Data: cert})
}

// handleGetCert GET /api/cards/{card_uuid}/certs/{uuid}
func (s *Server) handleGetCert(w http.ResponseWriter, r *http.Request) {
	certUUID := r.PathValue("uuid")
	cert, err := s.certRepo.GetByUUID(r.Context(), certUUID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if cert == nil {
		writeError(w, http.StatusNotFound, "证书不存在")
		return
	}
	writeOK(w, cert)
}

// handleDeleteCert DELETE /api/cards/{card_uuid}/certs/{uuid}
func (s *Server) handleDeleteCert(w http.ResponseWriter, r *http.Request) {
	certUUID := r.PathValue("uuid")
	if err := s.certRepo.Delete(r.Context(), certUUID); err != nil {
		writeError(w, http.StatusInternalServerError, "删除证书失败: "+err.Error())
		return
	}
	// 删除后，从系统证书存储中移除
	s.propagateCertRemove(certUUID)
	writeOK(w, nil)
}

// handleExportCertKey POST /api/cards/{card_uuid}/certs/{uuid}/export
// 按安全等级导出证书密钥。请求体：{password, admin_key?, format: "pem"|"pfx"}
func (s *Server) handleExportCertKey(w http.ResponseWriter, r *http.Request) {
	cardUUID := r.PathValue("card_uuid")
	certUUID := r.PathValue("uuid")

	var req struct {
		Password    string `json:"password"`
		AdminKey    string `json:"admin_key"`
		Format      string `json:"format"`       // pem / pfx
		PFXPassword string `json:"pfx_password"` // PFX 文件保护密码
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	// 获取卡片
	card, err := s.cardRepo.GetByUUID(r.Context(), cardUUID)
	if err != nil || card == nil {
		writeError(w, http.StatusNotFound, "卡片不存在")
		return
	}

	// 安全等级检查
	switch card.SecurityLevel {
	case storage.SecurityLevelHigh:
		writeError(w, http.StatusForbidden, "高安全性卡片不允许导出私钥")
		return
	case storage.SecurityLevelMedium:
		if req.AdminKey == "" {
			writeError(w, http.StatusBadRequest, "中安全性卡片需要 admin_key 才能导出")
			return
		}
		// 验证 AdminKey
		if _, err := local.DecryptTPMCertKey(card, req.AdminKey); err != nil {
			writeError(w, http.StatusUnauthorized, "AdminKey 验证失败")
			return
		}
	default: // low
		if req.Password == "" {
			writeError(w, http.StatusBadRequest, "需要卡片密码才能导出")
			return
		}
	}

	// 解锁主密钥
	slot := local.New(0, card, s.certRepo)
	loginPwd := req.Password
	if loginPwd == "" {
		loginPwd = req.AdminKey
	}
	if err := slot.Login(r.Context(), 1, loginPwd); err != nil {
		writeError(w, http.StatusUnauthorized, "密码/AdminKey 验证失败")
		return
	}
	defer slot.Logout(r.Context())

	masterKey := slot.MasterKey()
	if masterKey == nil {
		writeError(w, http.StatusInternalServerError, "获取主密钥失败")
		return
	}

	// 获取证书
	cert, err := s.certRepo.GetByUUID(r.Context(), certUUID)
	if err != nil || cert == nil {
		writeError(w, http.StatusNotFound, "证书不存在")
		return
	}

	// 解密私钥
	if len(cert.PrivateData) == 0 {
		writeError(w, http.StatusBadRequest, "该证书没有私钥")
		return
	}

	privDER, err := local.DecryptPrivateKey(masterKey, cert)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "解密私钥失败: "+err.Error())
		return
	}

	// 根据格式返回
	format := req.Format
	if format == "" {
		format = "pem"
	}

	result := map[string]string{
		"format": format,
	}

	switch format {
	case "pem":
		// 返回 PEM 格式的私钥和证书（base64 编码）
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
		result["private_key"] = base64.StdEncoding.EncodeToString(keyPEM)
		if len(cert.CertContent) > 0 {
			certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.DERContent()})
			result["certificate"] = base64.StdEncoding.EncodeToString(certPEM)
		}
	case "pfx":
		// PFX 格式：生成 PKCS12 文件，用 pfx_password 保护
		if req.PFXPassword == "" {
			writeError(w, http.StatusBadRequest, "PFX 格式导出需要设置 pfx_password")
			return
		}
		if len(cert.CertContent) == 0 {
			writeError(w, http.StatusBadRequest, "该证书没有证书内容，无法导出 PFX")
			return
		}
		// 将 DER 转为 PEM 以调用 ExportPKCS12
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.DERContent()})
		// 判断私钥类型并编码为 PEM
		var keyPEM []byte
		// 尝试解析为 PKCS8 以确定类型
		if _, err := x509.ParsePKCS8PrivateKey(privDER); err == nil {
			keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
		} else if _, err := x509.ParsePKCS1PrivateKey(privDER); err == nil {
			keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privDER})
		} else if _, err := x509.ParseECPrivateKey(privDER); err == nil {
			keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})
		} else {
			// 默认使用 PRIVATE KEY
			keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
		}
		pfxData, pfxErr := pki.ExportPKCS12(certPEM, keyPEM, req.PFXPassword)
		if pfxErr != nil {
			writeError(w, http.StatusInternalServerError, "生成 PFX 失败: "+pfxErr.Error())
			return
		}
		result["pfx_data"] = base64.StdEncoding.EncodeToString(pfxData)
	default:
		writeError(w, http.StatusBadRequest, "不支持的导出格式: "+format)
		return
	}

	writeOK(w, result)
}

// handleImportCertWithKey POST /api/cards/{card_uuid}/certs/import
// 向卡片导入证书+密钥（PEM 或 PFX 格式）。
// 请求体：{mode: "pem"|"pfx", cert_pem?, key_pem?, pfx_b64?, pfx_password?, card_password, remark?}
func (s *Server) handleImportCertWithKey(w http.ResponseWriter, r *http.Request) {
	cardUUID := r.PathValue("card_uuid")

	var req struct {
		Mode         string `json:"mode"`          // pem / pfx
		CertPEM      string `json:"cert_pem"`      // PEM 格式证书
		KeyPEM       string `json:"key_pem"`       // PEM 格式私钥
		PFXB64       string `json:"pfx_b64"`       // base64 编码的 PFX/PKCS12
		PFXPassword  string `json:"pfx_password"`  // PFX 密码
		CardPassword string `json:"card_password"` // 卡片密码（用于加密私钥）
		Remark       string `json:"remark"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	if req.CardPassword == "" {
		writeError(w, http.StatusBadRequest, "card_password 不能为空")
		return
	}
	if req.Mode == "" {
		req.Mode = "pem"
	}

	// 获取卡片并解锁主密钥
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

	var certDER, privDER []byte

	switch req.Mode {
	case "pem":
		if req.CertPEM == "" {
			writeError(w, http.StatusBadRequest, "PEM 模式下 cert_pem 不能为空")
			return
		}
		// 解析证书 PEM
		certDER, err = local.ParsePEMCert([]byte(req.CertPEM))
		if err != nil {
			writeError(w, http.StatusBadRequest, "解析证书 PEM 失败: "+err.Error())
			return
		}
		// 解析私钥 PEM（可选）
		if req.KeyPEM != "" {
			privDER, err = local.ParsePEMKey([]byte(req.KeyPEM))
			if err != nil {
				writeError(w, http.StatusBadRequest, "解析私钥 PEM 失败: "+err.Error())
				return
			}
		}
	case "pfx":
		if req.PFXB64 == "" {
			writeError(w, http.StatusBadRequest, "PFX 模式下 pfx_b64 不能为空")
			return
		}
		pfxData, decErr := base64.StdEncoding.DecodeString(req.PFXB64)
		if decErr != nil {
			writeError(w, http.StatusBadRequest, "pfx_b64 解码失败")
			return
		}
		certDER, privDER, err = local.ParsePFX(pfxData, req.PFXPassword)
		if err != nil {
			writeError(w, http.StatusBadRequest, "解析 PFX 失败: "+err.Error())
			return
		}
	default:
		writeError(w, http.StatusBadRequest, "mode 必须为 pem 或 pfx")
		return
	}

	// 导入证书（公钥部分）
	km := local.NewKeyManager(s.certRepo, s.cardRepo)

	if privDER != nil {
		// 有私钥：使用 ImportPrivateKey 加密存储
		pubDER := certDER // 证书 DER 作为公开部分
		result, impErr := km.ImportPrivateKey(r.Context(), local.KeyGenRequest{
			CardUUID: cardUUID,
			CertType: storage.CertTypeX509,
			KeyType:  "imported",
			Remark:   req.Remark,
		}, masterKey, privDER, pubDER)
		if impErr != nil {
			writeError(w, http.StatusInternalServerError, "导入证书+密钥失败: "+impErr.Error())
			return
		}
		// 修正 CertContent：将证书 DER 以 CERTIFICATE PEM 格式存储（而非 PUBLIC KEY）
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		certRecord, _ := s.certRepo.GetByUUID(r.Context(), result.CertUUID)
		if certRecord != nil {
			certRecord.CertContent = certPEM
			_ = s.certRepo.Update(r.Context(), certRecord)
		}
		// 导入成功后，自动传播到系统证书存储
		s.propagateCertAddDER(certDER, result.CertUUID, cardUUID, "imported", true)
		writeJSON(w, http.StatusCreated, Response{Code: 0, Message: "证书+密钥导入成功", Data: map[string]string{
			"cert_uuid": result.CertUUID,
		}})
	} else {
		// 仅证书（无私钥）
		cert, impErr := km.ImportCertificate(r.Context(), cardUUID, certDER, req.Remark)
		if impErr != nil {
			writeError(w, http.StatusInternalServerError, "导入证书失败: "+impErr.Error())
			return
		}
		// 导入成功后，自动传播到系统证书存储
		if cert != nil {
			s.propagateCertAddDER(certDER, cert.UUID, cardUUID, "imported", false)
		}
		writeJSON(w, http.StatusCreated, Response{Code: 0, Message: "证书导入成功", Data: cert})
	}
}

// handleCertDetail GET /api/cards/{card_uuid}/certs/{uuid}/detail
// 解析 X.509 证书返回详细信息。
func (s *Server) handleCertDetail(w http.ResponseWriter, r *http.Request) {
	certUUID := r.PathValue("uuid")

	cert, err := s.certRepo.GetByUUID(r.Context(), certUUID)
	if err != nil || cert == nil {
		writeError(w, http.StatusNotFound, "证书不存在")
		return
	}

	if cert.CertType != storage.CertTypeX509 || len(cert.CertContent) == 0 {
		writeError(w, http.StatusBadRequest, "仅支持 X.509 证书详情解析")
		return
	}

	// 直接传 CertContent（可能是 PEM 或 DER），ParseCertDetail 内部会自动判断格式
	detail, err := local.ParseCertDetail(cert.CertContent)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "解析证书失败: "+err.Error())
		return
	}

	writeOK(w, detail)
}

// ---- 密钥生成 Handler ----

// handleKeyGen POST /api/cards/{card_uuid}/keygen
// 在指定卡片中生成密钥对，需要提供卡片密码解锁主密钥
func (s *Server) handleKeyGen(w http.ResponseWriter, r *http.Request) {
	cardUUID := r.PathValue("card_uuid")

	var req struct {
		CardPassword string `json:"card_password"` // 用于解锁主密钥
		CertType     string `json:"cert_type"`     // x509/ssh/gpg
		KeyType      string `json:"key_type"`      // rsa2048/rsa4096/ec256/ec384/ec521
		Remark       string `json:"remark"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	if req.CardPassword == "" || req.KeyType == "" {
		writeError(w, http.StatusBadRequest, "card_password 和 key_type 不能为空")
		return
	}

	// 获取卡片
	card, err := s.cardRepo.GetByUUID(r.Context(), cardUUID)
	if err != nil || card == nil {
		writeError(w, http.StatusNotFound, "卡片不存在")
		return
	}

	// 创建临时 Slot 解锁主密钥
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

	certType := storage.CertType(req.CertType)
	if certType == "" {
		certType = storage.CertTypeX509
	}

	km := local.NewKeyManager(s.certRepo, s.cardRepo)
	result, err := km.GenerateKeyPair(r.Context(), local.KeyGenRequest{
		CardUUID: cardUUID,
		CertType: certType,
		KeyType:  req.KeyType,
		Remark:   req.Remark,
	}, masterKey, card)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "生成密钥对失败: "+err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, Response{
		Code:    0,
		Message: "ok",
		Data: map[string]string{
			"cert_uuid":      result.CertUUID,
			"public_key_b64": base64.StdEncoding.EncodeToString(result.PublicKeyDER),
		},
	})
}

// ---- 日志查询 Handler ----

// handleListLogs GET /api/logs?limit=20&offset=0
func (s *Server) handleListLogs(w http.ResponseWriter, r *http.Request) {
	limit := 20
	offset := 0

	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 100 {
			limit = n
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}

	logs, err := s.logRepo.List(r.Context(), limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "查询日志失败: "+err.Error())
		return
	}
	writeOK(w, logs)
}
