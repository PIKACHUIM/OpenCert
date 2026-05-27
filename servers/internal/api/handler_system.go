package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/globaltrusts/server-card/internal/acme"
	"github.com/globaltrusts/server-card/internal/revocation"
)

// base64URLDecode 宽松解码 base64url 字符串（自动补 padding，兼容 RFC 8555 载荷）。
func base64URLDecode(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	// 先尝试无 padding
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	// 退回带 padding 版本
	return base64.URLEncoding.DecodeString(s)
}

// ---- ACME 处理器 ----

// handleACMEDirectory 返回 ACME 目录 JSON。
func (s *Server) handleACMEDirectory(w http.ResponseWriter, r *http.Request) {
	path := r.PathValue("path")
	if s.acmeSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "ACME 服务未启用")
		return
	}
	cfg, err := s.acmeSvc.GetConfigByPath(r.Context(), path)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	baseURL := fmt.Sprintf("%s://%s/acme/%s", scheme(r), r.Host, path)
	directory := map[string]interface{}{
		"newNonce":   baseURL + "/new-nonce",
		"newAccount": baseURL + "/new-account",
		"newOrder":   baseURL + "/new-order",
		"revokeCert": baseURL + "/revoke-cert",
		"keyChange":  baseURL + "/key-change",
		"meta": map[string]interface{}{
			"caaIdentities":  []string{r.Host},
			"termsOfService": baseURL + "/terms",
			"website":        fmt.Sprintf("%s://%s", scheme(r), r.Host),
		},
		"caUUID": cfg.CAUUID,
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	writeJSON(w, http.StatusOK, directory)
}

// handleACMENewNonce 返回 ACME Replay-Nonce。
func (s *Server) handleACMENewNonce(w http.ResponseWriter, r *http.Request) {
	if s.acmeSvc == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	nonce, err := s.acmeSvc.GenerateNonce()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}

// handleACMENewAccount 创建 ACME 账户（RFC 8555）。
func (s *Server) handleACMENewAccount(w http.ResponseWriter, r *http.Request) {
	if s.acmeSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "ACME 服务未启用")
		return
	}
	path := r.PathValue("path")
	cfg, err := s.acmeSvc.GetConfigByPath(r.Context(), path)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	var payload map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}

	// 简化实现：从 payload 中提取 contact 和 publicKey
	contact := "[]"
	if c, ok := payload["contact"]; ok {
		if contactJSON, err := json.Marshal(c); err == nil {
			contact = string(contactJSON)
		}
	}

	acct := &acme.Account{
		ConfigID:  cfg.UUID,
		KeyID:     fmt.Sprintf("key-%d", time.Now().UnixNano()),
		PublicKey: "{}",
		Contact:   contact,
	}
	if err := s.acmeSvc.CreateAccount(r.Context(), acct); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set("Location", fmt.Sprintf("%s://%s/acme/%s/acct/%s", scheme(r), r.Host, path, acct.UUID))
	writeJSON(w, http.StatusCreated, acct)
}

// handleACMENewOrder 创建 ACME 订单（RFC 8555）。
// 同时为每个 identifier 自动创建 Authorization，并为每个 Authorization 创建 http-01 和 dns-01 挑战。
func (s *Server) handleACMENewOrder(w http.ResponseWriter, r *http.Request) {
	if s.acmeSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "ACME 服务未启用")
		return
	}
	path := r.PathValue("path")

	var payload struct {
		Identifiers []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"identifiers"`
		NotBefore string `json:"notBefore"`
		NotAfter  string `json:"notAfter"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if len(payload.Identifiers) == 0 {
		writeError(w, http.StatusBadRequest, "identifiers 不能为空")
		return
	}

	idsJSON, _ := json.Marshal(payload.Identifiers)
	baseURL := fmt.Sprintf("%s://%s/acme/%s", scheme(r), r.Host, path)
	order := &acme.Order{
		AccountUUID: "unknown",
		Identifiers: string(idsJSON),
		FinalizeURL: "", // 等创建后拼接
	}
	if err := s.acmeSvc.CreateOrder(r.Context(), order); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// 回填 finalize URL（包含订单 UUID）并写回数据库
	order.FinalizeURL = fmt.Sprintf("%s/finalize/%s", baseURL, order.UUID)
	_, _ = s.db.ExecContext(r.Context(),
		`UPDATE acme_orders SET finalize_url = ? WHERE uuid = ?`,
		order.FinalizeURL, order.UUID,
	)

	// 为每个 identifier 创建 Authorization + 两种挑战
	authzURLs := make([]string, 0, len(payload.Identifiers))
	for _, id := range payload.Identifiers {
		idJSON, _ := json.Marshal(id)
		authz := &acme.Authorization{
			OrderUUID:  order.UUID,
			Identifier: string(idJSON),
		}
		if err := s.acmeSvc.CreateAuthorization(r.Context(), authz); err != nil {
			writeError(w, http.StatusInternalServerError, "创建授权失败: "+err.Error())
			return
		}
		for _, chType := range []string{"http-01", "dns-01"} {
			ch := &acme.Challenge{AuthzUUID: authz.UUID, Type: chType}
			if err := s.acmeSvc.CreateChallenge(r.Context(), ch); err != nil {
				writeError(w, http.StatusInternalServerError, "创建挑战失败: "+err.Error())
				return
			}
		}
		authzURLs = append(authzURLs, fmt.Sprintf("%s/authz/%s", baseURL, authz.UUID))
	}

	w.Header().Set("Location", fmt.Sprintf("%s/order/%s", baseURL, order.UUID))
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"uuid":           order.UUID,
		"status":         order.Status,
		"identifiers":    payload.Identifiers,
		"authorizations": authzURLs,
		"finalize":       order.FinalizeURL,
		"expires":        order.Expires,
	})
}

// handleACMEGetAccount 获取 ACME 账户信息。
func (s *Server) handleACMEGetAccount(w http.ResponseWriter, r *http.Request) {
	if s.acmeSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "ACME 服务未启用")
		return
	}
	id := r.PathValue("id")
	account, err := s.acmeSvc.GetAccountByUUID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, account)
}

// handleACMEGetOrder 获取 ACME 订单信息。
func (s *Server) handleACMEGetOrder(w http.ResponseWriter, r *http.Request) {
	if s.acmeSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "ACME 服务未启用")
		return
	}
	id := r.PathValue("id")
	order, err := s.acmeSvc.GetOrder(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, order)
}

// handleACMEGetAuthorization 获取 ACME 授权信息（含关联的挑战列表）。
func (s *Server) handleACMEGetAuthorization(w http.ResponseWriter, r *http.Request) {
	if s.acmeSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "ACME 服务未启用")
		return
	}
	path := r.PathValue("path")
	id := r.PathValue("id")

	// 读取授权
	var identifierJSON, status string
	var expires time.Time
	var createdAt time.Time
	err := s.db.QueryRowContext(r.Context(),
		`SELECT identifier, status, expires, created_at FROM acme_authorizations WHERE uuid = ?`, id,
	).Scan(&identifierJSON, &status, &expires, &createdAt)
	if err != nil {
		writeError(w, http.StatusNotFound, "授权不存在")
		return
	}
	var identifier interface{}
	_ = json.Unmarshal([]byte(identifierJSON), &identifier)

	// 读取关联挑战
	rows, err := s.db.QueryContext(r.Context(),
		`SELECT uuid, type, token, status FROM acme_challenges WHERE authz_uuid = ?`, id,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	baseURL := fmt.Sprintf("%s://%s/acme/%s", scheme(r), r.Host, path)
	var challenges []map[string]interface{}
	for rows.Next() {
		var chUUID, chType, chToken, chStatus string
		if err := rows.Scan(&chUUID, &chType, &chToken, &chStatus); err != nil {
			continue
		}
		challenges = append(challenges, map[string]interface{}{
			"uuid":   chUUID,
			"type":   chType,
			"token":  chToken,
			"status": chStatus,
			"url":    fmt.Sprintf("%s/chall/%s", baseURL, chUUID),
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"uuid":       id,
		"status":     status,
		"identifier": identifier,
		"expires":    expires,
		"challenges": challenges,
	})
}

// handleACMEChallenge 触发 ACME 挑战验证。
// 按 RFC 8555 §7.5.1，客户端 POST 空对象到挑战 URL 以触发服务器执行验证。
// 本实现同步执行 HTTP-01 / DNS-01 真实验证（带 15s 超时），并在成功后推进订单到 ready。
func (s *Server) handleACMEChallenge(w http.ResponseWriter, r *http.Request) {
	if s.acmeSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "ACME 服务未启用")
		return
	}
	id := r.PathValue("id")
	chall, err := s.acmeSvc.GetChallenge(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	// 从 Authorization 读取 identifier，提取域名
	var identifierJSON string
	if err := s.db.QueryRowContext(r.Context(),
		`SELECT identifier FROM acme_authorizations WHERE uuid = ?`, chall.AuthzUUID,
	).Scan(&identifierJSON); err != nil {
		writeError(w, http.StatusNotFound, "找不到挑战对应的授权")
		return
	}
	var ident struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	}
	if err := json.Unmarshal([]byte(identifierJSON), &ident); err != nil {
		writeError(w, http.StatusInternalServerError, "解析 identifier 失败")
		return
	}
	if ident.Type != "dns" {
		writeError(w, http.StatusBadRequest, "仅支持 dns 类型标识符")
		return
	}

	// 可选：从请求体取 keyAuthorization（客户端提供）；为空则放宽为 token 前缀匹配
	var payload struct {
		KeyAuthorization string `json:"keyAuthorization"`
	}
	_ = json.NewDecoder(r.Body).Decode(&payload)

	// 同步执行真实验证
	verr := s.acmeSvc.ValidateChallengeReal(r.Context(), id, ident.Value, payload.KeyAuthorization)
	// 重新读取以返回最新状态
	chall, _ = s.acmeSvc.GetChallenge(r.Context(), id)
	if verr != nil {
		writeJSON(w, http.StatusOK, chall) // RFC 建议即使失败也返回 200 + invalid 状态
		return
	}
	writeJSON(w, http.StatusOK, chall)
}

// handleACMEFinalize 完成 ACME 订单：解析 CSR 并调用 CA 签发。
// 请求体：{"csr":"<base64url(DER)>"}（RFC 8555 §7.4）。
func (s *Server) handleACMEFinalize(w http.ResponseWriter, r *http.Request) {
	if s.acmeSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "ACME 服务未启用")
		return
	}
	id := r.PathValue("id")

	var payload struct {
		CSR string `json:"csr"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if payload.CSR == "" {
		writeError(w, http.StatusBadRequest, "缺少 csr 字段")
		return
	}
	// base64url 解码 CSR
	csrDER, err := base64URLDecode(payload.CSR)
	if err != nil {
		writeError(w, http.StatusBadRequest, "CSR 解码失败: "+err.Error())
		return
	}

	// 同步签发（若成功，订单状态变为 valid，cert_url 指向签发的证书序列号）
	_, err = s.acmeSvc.FinalizeOrder(r.Context(), id, csrDER)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// 返回最新订单状态
	order, err := s.acmeSvc.GetOrder(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, order)
}

// handleACMEGetCertificate 下载 ACME 证书（返回 PEM 证书链）。
func (s *Server) handleACMEGetCertificate(w http.ResponseWriter, r *http.Request) {
	if s.acmeSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "ACME 服务未启用")
		return
	}
	id := r.PathValue("id")
	certPEM, err := s.acmeSvc.GetCertificateForOrder(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(certPEM))
}

// ---- CT 处理器 ----

// handleCTSubmit 接受证书 CT 提交请求。
// 认证方式：Header "Authorization: Bearer <CT_SUBMIT_TOKEN>"，Token 由 configs.CT.SubmitToken 配置。
// 若未配置 Token 则视为公开接口（仅开发环境使用）。
func (s *Server) handleCTSubmit(w http.ResponseWriter, r *http.Request) {
	if s.ctSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "CT 服务未启用")
		return
	}

	// 认证：如果配置了 SubmitToken，则要求 Bearer Token 匹配
	if s.cfg.CT.SubmitToken != "" {
		token := extractBearerToken(r)
		if token == "" || token != s.cfg.CT.SubmitToken {
			writeError(w, http.StatusUnauthorized, "CT 提交需要有效的 Bearer Token")
			return
		}
	}

	var req struct {
		CertUUID    string   `json:"cert_uuid"`
		CAUUID      string   `json:"ca_uuid"`
		CTServer    string   `json:"ct_server"`
		SubmittedBy string   `json:"submitted_by"`
		CertDER     []byte   `json:"cert_der"`  // base64 编码的 DER 数据
		ChainDER    [][]byte `json:"chain_der"` // 可选：签发 CA 链（base64 编码的 DER 数组）
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if req.CertUUID == "" || req.CTServer == "" {
		writeError(w, http.StatusBadRequest, "cert_uuid 和 ct_server 不能为空")
		return
	}
	entry, err := s.ctSvc.Submit(r.Context(), req.CertUUID, req.CAUUID, req.CTServer, req.SubmittedBy, req.CertDER, req.ChainDER)
	if err != nil {
		// 即便 CT 提交失败，entry 已被保存为 failed 状态，返回 502 但含 entry 数据供排查
		if entry != nil {
			writeJSON(w, http.StatusBadGateway, map[string]interface{}{
				"error": err.Error(),
				"entry": entry,
			})
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, entry)
}

// handleCTQuery 按证书哈希查询 CT 记录。
func (s *Server) handleCTQuery(w http.ResponseWriter, r *http.Request) {
	if s.ctSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "CT 服务未启用")
		return
	}
	certHash := r.URL.Query().Get("cert_hash")
	if certHash == "" {
		writeError(w, http.StatusBadRequest, "缺少 cert_hash 参数")
		return
	}
	entries, err := s.ctSvc.QueryByCertHash(r.Context(), certHash)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"entries": entries, "total": len(entries)})
}

// ---- 吊销服务管理处理器 ----

func (s *Server) handleListRevocationServices(w http.ResponseWriter, r *http.Request) {
	caUUID := r.URL.Query().Get("ca_uuid")
	configs, err := s.revocationSvc.ListServiceConfigs(r.Context(), caUUID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"services": configs, "total": len(configs)})
}

func (s *Server) handleCreateRevocationService(w http.ResponseWriter, r *http.Request) {
	var cfg revocation.ServiceConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if err := s.revocationSvc.CreateServiceConfig(r.Context(), &cfg); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, cfg)
}

func (s *Server) handleDeleteRevocationService(w http.ResponseWriter, r *http.Request) {
	cfgUUID := r.PathValue("uuid")
	if err := s.revocationSvc.DeleteServiceConfig(r.Context(), cfgUUID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "吊销服务配置已删除"})
}

// ---- ACME 配置管理处理器 ----

func (s *Server) handleListACMEConfigs(w http.ResponseWriter, r *http.Request) {
	configs, err := s.acmeSvc.ListConfigs(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"configs": configs, "total": len(configs)})
}

func (s *Server) handleCreateACMEConfig(w http.ResponseWriter, r *http.Request) {
	var cfg acme.Config
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if err := s.acmeSvc.CreateConfig(r.Context(), &cfg); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, cfg)
}

func (s *Server) handleDeleteACMEConfig(w http.ResponseWriter, r *http.Request) {
	cfgUUID := r.PathValue("uuid")
	if err := s.acmeSvc.DeleteConfig(r.Context(), cfgUUID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "ACME 配置已删除"})
}

// ---- CT 记录管理处理器 ----

func (s *Server) handleListCTEntries(w http.ResponseWriter, r *http.Request) {
	certUUID := r.URL.Query().Get("cert_uuid")
	page, pageSize := parsePagination(r)
	entries, total, err := s.ctSvc.List(r.Context(), certUUID, page, pageSize)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"entries": entries, "total": total})
}

func (s *Server) handleDeleteCTEntry(w http.ResponseWriter, r *http.Request) {
	entryUUID := r.PathValue("uuid")
	if err := s.ctSvc.Delete(r.Context(), entryUUID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "CT 记录已删除"})
}
