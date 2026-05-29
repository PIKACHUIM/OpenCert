package api

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"

	"github.com/globaltrusts/client-card/internal/card/local"
	"github.com/globaltrusts/client-card/internal/pki"
	"github.com/globaltrusts/client-card/internal/storage"
)

// ---- 自签名证书（保留原有功能）----

// handleSelfSignFromCSR POST /api/pki/certs/selfsign
// 通过已有 CSR（需含私钥）生成自签名证书并持久化到证书管理。
func (s *Server) handleSelfSignFromCSR(w http.ResponseWriter, r *http.Request) {
	var req pki.SelfSignFromCSRRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	if req.CSRUUID == "" {
		writeError(w, http.StatusBadRequest, "csr_uuid 不能为空")
		return
	}
	cert, err := pki.SelfSignFromCSR(r.Context(), s.csrRepo, s.pkiCertRepo, s.cardRepo, s.certRepo, &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "生成自签名证书失败: "+err.Error())
		return
	}
	// 自签名证书生成后，自动传播到系统证书存储
	if cert != nil && cert.CertPEM != "" {
		s.propagateCertAdd(cert.CertPEM, cert.UUID, cert.CardUUID, cert.CommonName, cert.KeyType, cert.HasPrivateKey)
	}
	writeJSON(w, http.StatusCreated, Response{Code: 0, Message: "ok", Data: cert})
}

// handleSelfSign POST /api/pki/selfsign
func (s *Server) handleSelfSign(w http.ResponseWriter, r *http.Request) {
	var req pki.SelfSignRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	if req.CommonName == "" {
		writeError(w, http.StatusBadRequest, "common_name 不能为空")
		return
	}
	if req.KeyType == "" {
		req.KeyType = "ec256"
	}
	result, err := pki.GenerateSelfSigned(&req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "生成自签名证书失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, Response{Code: 0, Message: "ok", Data: map[string]string{
		"cert_pem": string(result.CertPEM),
		"key_pem":  string(result.KeyPEM),
		"cert_der": base64.StdEncoding.EncodeToString(result.CertDER),
	}})
}

// ---- CSR 管理 ----

// handleListCSR GET /api/pki/csr
func (s *Server) handleListCSR(w http.ResponseWriter, r *http.Request) {
	page, pageSize := parsePageParams(r)
	list, total, err := s.csrRepo.List(r.Context(), page, pageSize)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "查询 CSR 列表失败: "+err.Error())
		return
	}
	if list == nil {
		list = []*storage.CSRRecord{}
	}
	writeOK(w, map[string]interface{}{"items": list, "total": total, "page": page, "page_size": pageSize})
}

// handleCreateCSR POST /api/pki/csr
func (s *Server) handleCreateCSR(w http.ResponseWriter, r *http.Request) {
	var req pki.CreateCSRRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	if req.CommonName == "" {
		writeError(w, http.StatusBadRequest, "common_name 不能为空")
		return
	}
	record, err := pki.CreateAndSaveCSR(r.Context(), s.csrRepo, s.certRepo, s.cardRepo, &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "生成 CSR 失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, Response{Code: 0, Message: "ok", Data: record})
}

// handleGetCSR GET /api/pki/csr/{uuid}
func (s *Server) handleGetCSR(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("uuid")
	record, err := s.csrRepo.GetByUUID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "查询 CSR 失败: "+err.Error())
		return
	}
	if record == nil {
		writeError(w, http.StatusNotFound, "CSR 不存在")
		return
	}
	writeOK(w, record)
}

// handleDeleteCSR DELETE /api/pki/csr/{uuid}
func (s *Server) handleDeleteCSR(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("uuid")
	if err := s.csrRepo.Delete(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, "删除 CSR 失败: "+err.Error())
		return
	}
	writeOK(w, nil)
}

// handleDownloadCSR GET /api/pki/csr/{uuid}/download
func (s *Server) handleDownloadCSR(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("uuid")
	record, err := s.csrRepo.GetByUUID(r.Context(), id)
	if err != nil || record == nil {
		writeError(w, http.StatusNotFound, "CSR 不存在")
		return
	}
	filename := fmt.Sprintf("%s.csr", record.CommonName)
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(record.CSRPEM)) //nolint:errcheck
}

// ---- CA 管理 ----

// handleListCA GET /api/pki/ca
func (s *Server) handleListCA(w http.ResponseWriter, r *http.Request) {
	page, pageSize := parsePageParams(r)
	list, total, err := s.caRepo.List(r.Context(), page, pageSize)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "查询 CA 列表失败: "+err.Error())
		return
	}
	if list == nil {
		list = []*storage.LocalCA{}
	}
	writeOK(w, map[string]interface{}{"items": list, "total": total, "page": page, "page_size": pageSize})
}

// handleCreateCA POST /api/pki/ca
func (s *Server) handleCreateCA(w http.ResponseWriter, r *http.Request) {
	var req pki.CreateCARequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	if req.CommonName == "" {
		writeError(w, http.StatusBadRequest, "common_name 不能为空")
		return
	}
	if req.Name == "" {
		req.Name = req.CommonName
	}
	ca, err := pki.CreateAndSaveCA(r.Context(), s.caRepo, &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "创建 CA 失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, Response{Code: 0, Message: "ok", Data: ca})
}

// handleImportCA POST /api/pki/ca/import
func (s *Server) handleImportCA(w http.ResponseWriter, r *http.Request) {
	var req pki.ImportCARequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	ca, err := pki.ImportAndSaveCA(r.Context(), s.caRepo, &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "导入 CA 失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, Response{Code: 0, Message: "ok", Data: ca})
}

// handleGetCA GET /api/pki/ca/{uuid}
func (s *Server) handleGetCA(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("uuid")
	ca, err := s.caRepo.GetByUUID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "查询 CA 失败: "+err.Error())
		return
	}
	if ca == nil {
		writeError(w, http.StatusNotFound, "CA 不存在")
		return
	}
	writeOK(w, ca)
}

// handleRevokeCA POST /api/pki/ca/{uuid}/revoke
func (s *Server) handleRevokeCA(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("uuid")
	if err := s.caRepo.Revoke(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, "吊销 CA 失败: "+err.Error())
		return
	}
	writeOK(w, nil)
}

// handleDeleteCA DELETE /api/pki/ca/{uuid}
func (s *Server) handleDeleteCA(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("uuid")
	if err := s.caRepo.Delete(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, "删除 CA 失败: "+err.Error())
		return
	}
	writeOK(w, nil)
}

// handleExportCA GET /api/pki/ca/{uuid}/export
func (s *Server) handleExportCA(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("uuid")
	format := r.URL.Query().Get("format") // pem / chain
	ca, err := s.caRepo.GetByUUID(r.Context(), id)
	if err != nil || ca == nil {
		writeError(w, http.StatusNotFound, "CA 不存在")
		return
	}

	var content string
	var filename string
	if format == "chain" && ca.ChainPEM != "" {
		content = ca.CertPEM + "\n" + ca.ChainPEM
		filename = ca.Name + "_chain.pem"
	} else {
		content = ca.CertPEM
		filename = ca.Name + ".pem"
	}

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(content)) //nolint:errcheck
}

// ---- 证书管理 ----

// handleListPKICerts GET /api/pki/certs
func (s *Server) handleListPKICerts(w http.ResponseWriter, r *http.Request) {
	page, pageSize := parsePageParams(r)
	list, total, err := s.pkiCertRepo.List(r.Context(), page, pageSize)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "查询证书列表失败: "+err.Error())
		return
	}
	if list == nil {
		list = []*storage.PKICert{}
	}
	writeOK(w, map[string]interface{}{"items": list, "total": total, "page": page, "page_size": pageSize})
}

// handleIssuePKICert POST /api/pki/certs/issue
func (s *Server) handleIssuePKICert(w http.ResponseWriter, r *http.Request) {
	var req pki.IssueCertFromCSRRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	if req.CSRUUID == "" || req.CAUUID == "" {
		writeError(w, http.StatusBadRequest, "csr_uuid 和 ca_uuid 不能为空")
		return
	}
	cert, err := pki.IssueCertFromCSR(r.Context(), s.csrRepo, s.caRepo, s.pkiCertRepo, s.certRepo, &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "签发证书失败: "+err.Error())
		return
	}
	// 签发成功后，自动传播到系统证书存储
	if cert != nil && cert.CertPEM != "" {
		s.propagateCertAdd(cert.CertPEM, cert.UUID, cert.CardUUID, cert.CommonName, cert.KeyType, cert.HasPrivateKey)
	}
	writeJSON(w, http.StatusCreated, Response{Code: 0, Message: "ok", Data: cert})
}

// handleImportPKICert POST /api/pki/certs/import
// 在 pki.ImportCert 完成数据库内匹配后，对 cert_only 模式额外扫描所有智能卡中的私钥，
// 若命中则返回 matched_source="card:<uuid>"（但不自动迁移卡上私钥，仅做关联提示）。
func (s *Server) handleImportPKICert(w http.ResponseWriter, r *http.Request) {
	var req pki.ImportCertRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	result, err := pki.ImportCert(r.Context(), s.pkiCertRepo, &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "导入证书失败: "+err.Error())
		return
	}

	// cert_only 且数据库内未匹配时，尝试在智能卡 certificates.cert_content 公钥中匹配
	if req.Mode == pki.ImportModeCertOnly && !result.KeyMatched && req.CertPEM != "" {
		if src, ok := s.findMatchingCardCert(r.Context(), req.CertPEM); ok {
			result.MatchedSource = src
			// 不迁移私钥，仅做提示。前端据此可引导用户"将该证书绑定到该卡片"
		}
	}

	// 导入成功后，自动传播到系统证书存储
	if result.Cert != nil && result.Cert.CertPEM != "" {
		s.propagateCertAdd(result.Cert.CertPEM, result.Cert.UUID, result.Cert.CardUUID,
			result.Cert.CommonName, result.Cert.KeyType, result.Cert.HasPrivateKey)
	}

	writeJSON(w, http.StatusCreated, Response{Code: 0, Message: "ok", Data: result})
}

// findMatchingCardCert 在所有本地/TPM2 卡片的 certificates 表中按公钥查找匹配项。
// 返回形如 "card:<card_uuid>/cert:<cert_uuid>" 的来源标识。
func (s *Server) findMatchingCardCert(ctx context.Context, certPEM string) (string, bool) {
	pubDER, err := parseCertPublicKeyPEM(certPEM)
	if err != nil || len(pubDER) == 0 {
		return "", false
	}

	cards, err := s.cardRepo.ListAll(ctx)
	if err != nil {
		return "", false
	}
	for _, c := range cards {
		if c.SlotType != storage.SlotTypeLocal && c.SlotType != storage.SlotTypeTPM2 {
			continue
		}
		certs, err := s.certRepo.ListByCard(ctx, c.UUID)
		if err != nil {
			continue
		}
		for _, cc := range certs {
			if len(cc.CertContent) == 0 {
				continue
			}
			// certificates.cert_content 可能是 PEM 证书或 PKIX 公钥；
			// 使用 DERContent() 提取 DER 后进行比较。
			if matchPubKeyAgainstCardCert(pubDER, cc.DERContent()) {
				return fmt.Sprintf("card:%s/cert:%s", c.UUID, cc.UUID), true
			}
		}
	}
	return "", false
}

// handleGetPKICert GET /api/pki/certs/{uuid}
func (s *Server) handleGetPKICert(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("uuid")
	cert, err := s.pkiCertRepo.GetByUUID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "查询证书失败: "+err.Error())
		return
	}
	if cert == nil {
		writeError(w, http.StatusNotFound, "证书不存在")
		return
	}
	writeOK(w, cert)
}

// handleDeletePKICert DELETE /api/pki/certs/{uuid}
func (s *Server) handleDeletePKICert(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("uuid")
	if err := s.pkiCertRepo.Delete(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, "删除证书失败: "+err.Error())
		return
	}
	// 删除后，从系统证书存储中移除
	s.propagateCertRemove(id)
	writeOK(w, nil)
}

// handleDeletePKICertKey DELETE /api/pki/certs/{uuid}/key
func (s *Server) handleDeletePKICertKey(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("uuid")
	if err := s.pkiCertRepo.DeletePrivateKey(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, "删除私钥失败: "+err.Error())
		return
	}
	writeOK(w, nil)
}

// handleExportPKICert POST /api/pki/certs/{uuid}/export
func (s *Server) handleExportPKICert(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("uuid")
	var req struct {
		Format   string `json:"format"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	cert, err := s.pkiCertRepo.GetByUUID(r.Context(), id)
	if err != nil || cert == nil {
		writeError(w, http.StatusNotFound, "证书不存在")
		return
	}

	data, contentType, err := pki.ExportCert(cert, pki.ExportCertFormat(req.Format), req.Password)
	if err != nil {
		writeError(w, http.StatusBadRequest, "导出证书失败: "+err.Error())
		return
	}

	ext := map[string]string{
		"pem":     ".pem",
		"der":     ".der",
		"pkcs12":  ".p12",
		"key_pem": ".key.pem",
	}[req.Format]
	filename := cert.CommonName + ext

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.WriteHeader(http.StatusOK)
	w.Write(data) //nolint:errcheck
}

// handleImportPKICertToCard POST /api/pki/certs/{uuid}/import-to-card
// 将 PKI 证书（含私钥时同时导入私钥）写入指定智能卡。
func (s *Server) handleImportPKICertToCard(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("uuid")
	var req struct {
		CardUUID     string `json:"card_uuid"`
		CardPassword string `json:"card_password"` // 卡片密码，用于解锁主密钥
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	if req.CardUUID == "" {
		writeError(w, http.StatusBadRequest, "card_uuid 不能为空")
		return
	}

	// 查询 PKI 证书
	cert, err := s.pkiCertRepo.GetByUUID(r.Context(), id)
	if err != nil || cert == nil {
		writeError(w, http.StatusNotFound, "证书不存在")
		return
	}
	if cert.CertPEM == "" {
		writeError(w, http.StatusBadRequest, "证书内容为空，无法导入")
		return
	}

	// 查询目标卡片
	targetCard, err := s.cardRepo.GetByUUID(r.Context(), req.CardUUID)
	if err != nil || targetCard == nil {
		writeError(w, http.StatusNotFound, "目标卡片不存在")
		return
	}
	if targetCard.SlotType == storage.SlotTypeCloud {
		writeError(w, http.StatusBadRequest, "不能导入到云端卡片，请选择本地或 TPM2 卡片")
		return
	}

	// 解锁卡片主密钥
	slot := local.New(0, targetCard, s.certRepo)
	if err := slot.Login(r.Context(), 1, req.CardPassword); err != nil {
		writeError(w, http.StatusForbidden, "卡片密码错误")
		return
	}
	defer slot.Logout(r.Context())

	masterKey := slot.MasterKey()
	if masterKey == nil {
		writeError(w, http.StatusInternalServerError, "获取卡片主密钥失败")
		return
	}

	km := local.NewKeyManagerWithTPM(s.certRepo, s.cardRepo, s.tpmProvider)

	// 将证书 PEM 转为 DER
	certDER, err := certPEMToDER(cert.CertPEM)
	if err != nil {
		writeError(w, http.StatusBadRequest, "解析证书 PEM 失败: "+err.Error())
		return
	}

	var resultMsg string

	// 如果有私钥，同时导入私钥
	if cert.HasPrivateKey && len(cert.PrivateKeyEnc) > 0 {
		keyDER, keyType, err := parsePrivateKeyPEM(string(cert.PrivateKeyEnc))
		if err != nil {
			writeError(w, http.StatusBadRequest, "解析私钥失败: "+err.Error())
			return
		}

		// 提取公钥 DER
		pubDER, err := parseCertPublicKeyPEM(cert.CertPEM)
		if err != nil {
			writeError(w, http.StatusBadRequest, "提取证书公钥失败: "+err.Error())
			return
		}

		result, err := km.ImportPrivateKey(r.Context(), local.KeyGenRequest{
			CardUUID: targetCard.UUID,
			CertType: storage.CertTypeX509,
			KeyType:  keyType,
			Remark:   fmt.Sprintf("从 PKI 导入: %s", cert.CommonName),
		}, masterKey, keyDER, pubDER)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "导入私钥到卡片失败: "+err.Error())
			return
		}

		// 修正 CertContent：将证书 DER 以 CERTIFICATE PEM 格式存储（而非 PUBLIC KEY）
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		certRecord, _ := s.certRepo.GetByUUID(r.Context(), result.CertUUID)
		if certRecord != nil {
			certRecord.CertContent = certPEM
			_ = s.certRepo.Update(r.Context(), certRecord)
		}

		resultMsg = "证书和私钥已导入到智能卡"
	} else {
		// 仅导入证书（无私钥）
		_, err = km.ImportCertificate(r.Context(), targetCard.UUID, certDER, fmt.Sprintf("从 PKI 导入: %s", cert.CommonName))
		if err != nil {
			writeError(w, http.StatusInternalServerError, "导入证书到卡片失败: "+err.Error())
			return
		}
		resultMsg = "证书已导入到智能卡（无私钥）"
	}

	// 广播 slot 变更事件
	s.notifySlotChanged("import")

	// 写审计日志
	s.auditRepo.Write(r.Context(), &storage.AuditLog{
		LogType:  "operation",
		LogLevel: "info",
		SlotType: string(targetCard.SlotType),
		CardUUID: targetCard.UUID,
		Title:    "PKI 证书导入到智能卡",
		Content:  fmt.Sprintf("cert=%s card=%s has_key=%v", cert.CommonName, targetCard.CardName, cert.HasPrivateKey),
	})

	writeOK(w, map[string]string{
		"message":   resultMsg,
		"card_uuid": targetCard.UUID,
		"card_name": targetCard.CardName,
	})
}

// handleRevokePKICert POST /api/pki/certs/{uuid}/revoke
func (s *Server) handleRevokePKICert(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("uuid")
	if err := s.pkiCertRepo.Revoke(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, "吊销证书失败: "+err.Error())
		return
	}
	writeOK(w, nil)
}

// ---- 格式转换（保留原有功能）----

// handleConvertCert POST /api/pki/convert
func (s *Server) handleConvertCert(w http.ResponseWriter, r *http.Request) {
	var req struct {
		InputFormat  string `json:"input_format"`
		OutputFormat string `json:"output_format"`
		Data         string `json:"data"`
		Password     string `json:"password"`
		ExportPass   string `json:"export_pass"`
		KeyPEM       string `json:"key_pem"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	inputData, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		inputData = []byte(req.Data)
	}

	var outputData []byte
	switch req.InputFormat + "->" + req.OutputFormat {
	case "pem->der":
		outputData, err = pki.ConvertPEMToDER(inputData)
	case "der->pem":
		outputData = pki.ConvertDERToPEM(inputData, "CERTIFICATE")
	case "pkcs12->pem":
		certPEM, keyPEM, e := pki.ImportPKCS12(inputData, req.Password)
		if e != nil {
			err = e
		} else {
			outputData = append(certPEM, keyPEM...)
		}
	case "pem->pkcs12":
		if len(req.ExportPass) < 8 {
			writeError(w, http.StatusBadRequest, "导出 PKCS#12 密码长度必须 >= 8 字符")
			return
		}
		outputData, err = pki.ExportPKCS12(inputData, []byte(req.KeyPEM), req.ExportPass)
	default:
		writeError(w, http.StatusBadRequest, "不支持的格式转换: "+req.InputFormat+" -> "+req.OutputFormat)
		return
	}

	if err != nil {
		writeError(w, http.StatusInternalServerError, "格式转换失败: "+err.Error())
		return
	}
	writeOK(w, map[string]string{
		"data":   base64.StdEncoding.EncodeToString(outputData),
		"format": req.OutputFormat,
	})
}

// handleParseCert POST /api/pki/parse
func (s *Server) handleParseCert(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Data string `json:"data"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	inputData, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		inputData = []byte(req.Data)
	}

	cert, err := pki.ParseCertificateAuto(inputData)
	if err != nil {
		writeError(w, http.StatusBadRequest, "解析证书失败: "+err.Error())
		return
	}
	if cert == nil {
		// 证书包含不兼容的策略扩展，无法完整解析但证书本身有效
		writeOK(w, map[string]interface{}{
			"error_hint": "证书包含不兼容的 Certificate Policies 扩展，部分信息无法解析",
		})
		return
	}

	writeOK(w, map[string]interface{}{
		"subject":              cert.Subject.String(),
		"issuer":               cert.Issuer.String(),
		"serial_number":        cert.SerialNumber.String(),
		"not_before":           cert.NotBefore,
		"not_after":            cert.NotAfter,
		"is_ca":                cert.IsCA,
		"key_usage":            cert.KeyUsage,
		"dns_names":            cert.DNSNames,
		"ip_addresses":         cert.IPAddresses,
		"emails":               cert.EmailAddresses,
		"signature_algorithm":  cert.SignatureAlgorithm.String(),
		"public_key_algorithm": cert.PublicKeyAlgorithm.String(),
	})
}

// ---- 工具函数 ----

// parsePageParams 从查询参数解析分页参数（page 从 1 开始）。
func parsePageParams(r *http.Request) (page, pageSize int) {
	page = 1
	pageSize = 20
	if v := r.URL.Query().Get("page"); v != "" {
		fmt.Sscanf(v, "%d", &page)
	}
	if v := r.URL.Query().Get("page_size"); v != "" {
		fmt.Sscanf(v, "%d", &pageSize)
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	return
}