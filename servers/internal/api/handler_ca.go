package api

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/globaltrusts/server-card/internal/auth"
	"github.com/globaltrusts/server-card/internal/ca"
	"github.com/globaltrusts/server-card/internal/storage"
)

// ---- CA 管理处理器 ----

func (s *Server) handleListCAs(w http.ResponseWriter, r *http.Request) {
	cas, err := s.caSvc.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"cas": cas, "total": len(cas)})
}

// CreateCARequest 是创建 CA 请求体。
//
// 与「签发证书」共用同一套表单：选择 CA 类颁发模板约束算法/有效期范围，
// 可选上级 CA（为空则自签根 CA），可显式指定生效/失效时间与存储区域。
type CreateCARequest struct {
	Name             string `json:"name"`
	IssuanceTmplUUID string `json:"issuance_tmpl_uuid"` // CA 类颁发模板（可选，用于约束算法/路径长度）
	ParentUUID       string `json:"parent_uuid"`        // 上级 CA（为空表示自签根 CA）
	KeyType          string `json:"key_type"`           // rsa2048/rsa4096/ec256/ec384/ec521/sm2
	CommonName       string `json:"common_name"`
	Org              string `json:"organization"`
	Country          string `json:"country"`
	NotBefore        string `json:"not_before"` // RFC3339，为空取当前时间
	NotAfter         string `json:"not_after"`  // RFC3339，为空按 valid_days 计算
	ValidDays        int    `json:"valid_days"` // NotAfter 为空时使用，默认 3650
	PathLen          int    `json:"path_len"`
	PathLenZero      bool   `json:"path_len_zero"`
	StorageZoneUUID  string `json:"storage_zone_uuid"` // 私钥存储区域（为空使用本地加密存储）
}

func (s *Server) handleCreateCA(w http.ResponseWriter, r *http.Request) {
	var req CreateCARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if req.Name == "" || req.CommonName == "" {
		writeError(w, http.StatusBadRequest, "CA 名称和 CommonName 不能为空")
		return
	}
	if req.KeyType == "" {
		req.KeyType = "ec256"
	}

	notBefore, err := parseTimePtr(req.NotBefore)
	if err != nil {
		writeError(w, http.StatusBadRequest, "生效时间格式错误: "+err.Error())
		return
	}
	notAfter, err := parseTimePtr(req.NotAfter)
	if err != nil {
		writeError(w, http.StatusBadRequest, "失效时间格式错误: "+err.Error())
		return
	}

	params := &ca.CACreateParams{
		Name:             req.Name,
		Subject:          pkixName(req.CommonName, req.Org, req.Country),
		KeyType:          req.KeyType,
		NotBefore:        notBefore,
		NotAfter:         notAfter,
		ValidDays:        req.ValidDays,
		PathLen:          req.PathLen,
		PathLenZero:      req.PathLenZero,
		ParentUUID:       req.ParentUUID,
		IssuanceTmplUUID: req.IssuanceTmplUUID,
		StorageZoneUUID:  req.StorageZoneUUID,
	}

	// 指定了 CA 类颁发模板时，用统一策略校验算法、有效期、上级 CA 是否在模板允许范围内。
	if req.IssuanceTmplUUID != "" && s.issuanceSvc != nil {
		policy, err := s.issuanceSvc.ResolvePolicy(r.Context(), "", req.IssuanceTmplUUID, nil)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if !policy.IsCA {
			writeError(w, http.StatusBadRequest, "所选模板不是 CA 类颁发模板")
			return
		}
		days := req.ValidDays
		if notAfter != nil {
			from := time.Now()
			if notBefore != nil {
				from = *notBefore
			}
			days = int(notAfter.Sub(from).Hours() / 24)
		}
		if days == 0 {
			days = policy.DefaultValidDays
		}
		// 显式指定失效时间时有效期天数不是整数选项，只校验上限；按天数选择时需落在模板选项内。
		selDays := days
		if notAfter != nil {
			selDays = 0
		}
		// 创建 CA 时模板的"候选 CA"约束的是之后用该模板签发的 CA，与上级 CA 无关，
		// 所以这里只校验密钥算法与有效期。
		if err := policy.ValidateSelection("", req.KeyType, "", selDays); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if days > 3650 {
			writeError(w, http.StatusBadRequest, "CA 有效期不能超过 3650 天")
			return
		}
		if params.ValidDays == 0 && notAfter == nil {
			params.ValidDays = policy.DefaultValidDays
		}
		if params.PathLen == 0 && !params.PathLenZero {
			params.PathLen = policy.PathLen
			params.PathLenZero = policy.PathLen == 0
		}
	}

	newCA, err := s.caSvc.CreateCA(r.Context(), params)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	claims := claimsFromCtx(r.Context())
	s.logRepo.Create(r.Context(), &storage.Log{ //nolint:errcheck
		UserUUID: claims.UserUUID,
		Action:   "create_ca:" + req.Name,
		IPAddr:   r.RemoteAddr,
	})

	newCA.PrivateEnc = nil
	writeJSON(w, http.StatusCreated, newCA)
}

// parseTimePtr 解析 RFC3339 时间字符串；空字符串返回 nil。
func parseTimePtr(s string) (*time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// parseJSONStringArrayLocal / containsStringLocal：避免跨包导出内部小工具，
// 在 api 包内重复一份轻量实现（仅用于创建 CA 前的模板约束预检）。
func parseJSONStringArrayLocal(s string) []string {
	if s == "" || s == "[]" {
		return nil
	}
	var arr []string
	if err := json.Unmarshal([]byte(s), &arr); err != nil {
		return nil
	}
	return arr
}

func containsStringLocal(arr []string, v string) bool {
	for _, x := range arr {
		if x == v {
			return true
		}
	}
	return false
}

func (s *Server) handleGetCA(w http.ResponseWriter, r *http.Request) {
	caUUID := r.PathValue("uuid")
	result, err := s.caSvc.GetByUUID(r.Context(), caUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	// 不返回加密的私钥
	result.PrivateEnc = nil
	writeJSON(w, http.StatusOK, result)
}

// UpdateCARequest 是更新 CA 请求体。
type UpdateCARequest struct {
	Name     string `json:"name"`
	Status   string `json:"status"`
	IsPublic *bool  `json:"is_public"` // 为空表示不修改
}

func (s *Server) handleUpdateCA(w http.ResponseWriter, r *http.Request) {
	caUUID := r.PathValue("uuid")
	var req UpdateCARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if err := s.caSvc.Update(r.Context(), caUUID, req.Name, req.Status, req.IsPublic); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "CA 已更新"})
}

// handleDownloadCA 下载 CA 证书（GET /api/cas/{uuid}/download?format=pem|der|chain）。
// 只导出证书，不涉及私钥，已登录用户均可下载（CA 证书本身是公开信息）。
func (s *Server) handleDownloadCA(w http.ResponseWriter, r *http.Request) {
	caUUID := r.PathValue("uuid")
	obj, err := s.caSvc.GetByUUID(r.Context(), caUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	filename := sanitizeFilename(obj.Name)
	switch r.URL.Query().Get("format") {
	case "der":
		block, _ := pem.Decode([]byte(obj.CertPEM))
		if block == nil {
			writeError(w, http.StatusInternalServerError, "CA 证书内容损坏")
			return
		}
		w.Header().Set("Content-Type", "application/pkix-cert")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.cer"`, filename))
		w.Write(block.Bytes) //nolint:errcheck
	case "chain":
		chain, err := s.caSvc.GetChain(r.Context(), caUUID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-chain.pem"`, filename))
		fmt.Fprint(w, chain)
	default:
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.pem"`, filename))
		fmt.Fprint(w, obj.CertPEM)
	}
}

// sanitizeFilename 把 CA 名称转换为安全的下载文件名（去掉路径分隔符、引号与控制字符）。
func sanitizeFilename(name string) string {
	var sb strings.Builder
	for _, r := range strings.TrimSpace(name) {
		switch {
		case r < 0x20, r == '/', r == '\\', r == '"', r == ':', r == '*', r == '?', r == '<', r == '>', r == '|':
			sb.WriteRune('_')
		default:
			sb.WriteRune(r)
		}
	}
	if sb.Len() == 0 {
		return "ca"
	}
	return sb.String()
}

func (s *Server) handleDeleteCA(w http.ResponseWriter, r *http.Request) {
	caUUID := r.PathValue("uuid")
	if err := s.caSvc.Delete(r.Context(), caUUID); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "CA 已删除"})
}

// ImportCARequest 是导入外部 CA 请求体。
//
// 证书与私钥有两种提交方式：
//   - cert_pem + private_key_pem：PEM 文本（也可粘贴 DER/PKCS#7 的 base64，见 cert_base64）；
//   - pkcs12_base64 + pkcs12_password：PKCS#12 文件（含证书、链与私钥）。
type ImportCARequest struct {
	Name            string `json:"name"`              // CA 显示名称
	CertPEM         string `json:"cert_pem"`          // CA 证书 PEM（可含证书链）
	CertBase64      string `json:"cert_base64"`       // DER / PKCS#7 证书的 base64（二选一于 cert_pem）
	PrivateKeyPEM   string `json:"private_key_pem"`   // CA 私钥 PEM（可选）
	PKCS12Base64    string `json:"pkcs12_base64"`     // PKCS#12 文件的 base64
	PKCS12Password  string `json:"pkcs12_password"`   // PKCS#12 密码
	ParentUUID      string `json:"parent_uuid"`       // 可选：父 CA UUID
	CertOnly        bool   `json:"cert_only"`         // true 表示仅导入证书（外部 CA，不可签发，仅用于证书链）
	StorageZoneUUID string `json:"storage_zone_uuid"` // 私钥存储区域（为空使用本地加密存储）
}

// handleImportCA 导入外部 CA（POST /api/cas/import）。
// 需要管理员权限，已通过路由层控制。
func (s *Server) handleImportCA(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 8<<20)
	var req ImportCARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误或文件过大")
		return
	}

	var certData, p12Data []byte
	switch {
	case strings.TrimSpace(req.PKCS12Base64) != "":
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.PKCS12Base64))
		if err != nil {
			writeError(w, http.StatusBadRequest, "PKCS#12 文件内容不是有效的 base64")
			return
		}
		p12Data = raw
	case strings.TrimSpace(req.CertBase64) != "":
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.CertBase64))
		if err != nil {
			writeError(w, http.StatusBadRequest, "证书文件内容不是有效的 base64")
			return
		}
		certData = raw
	default:
		certData = []byte(req.CertPEM)
	}
	if len(certData) == 0 && len(p12Data) == 0 {
		writeError(w, http.StatusBadRequest, "请提供 CA 证书")
		return
	}

	bundle, err := ca.ParseImportBundle(certData, []byte(req.PrivateKeyPEM), p12Data, req.PKCS12Password)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// 选择了存储区域但没有私钥可导入（仅证书）时，忽略区域以免误导
	storageZone := req.StorageZoneUUID
	if req.CertOnly || bundle.Key == nil {
		storageZone = ""
	}

	newCA, err := s.caSvc.ImportCA(r.Context(), &ca.ImportCAParams{
		Name:            req.Name,
		Bundle:          bundle,
		ParentUUID:      req.ParentUUID,
		CertOnly:        req.CertOnly,
		StorageZoneUUID: storageZone,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	claims := claimsFromCtx(r.Context())
	s.auditLogRepo.Create(r.Context(), &storage.AuditLog{ //nolint:errcheck
		UserUUID:     claims.UserUUID,
		Action:       "import_ca",
		ResourceType: "ca",
		ResourceUUID: newCA.UUID,
		Detail:       fmt.Sprintf(`{"name":%q,"with_key":%t,"storage_zone":%q}`, req.Name, bundle.Key != nil && !req.CertOnly, storageZone),
		IPAddress:    r.RemoteAddr,
	})

	// 响应不返回私钥
	newCA.PrivateEnc = nil
	writeJSON(w, http.StatusCreated, newCA)
}

// handleGetCAChain 返回指定 CA 及其所有父 CA 的 PEM 证书链。
// 响应格式：application/x-pem-file 或 JSON（根据 Accept header）。
func (s *Server) handleGetCAChain(w http.ResponseWriter, r *http.Request) {
	caUUID := r.PathValue("uuid")
	chain, err := s.caSvc.GetChain(r.Context(), caUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	// 按 Accept 协商返回 PEM 或 JSON
	if accept := r.Header.Get("Accept"); accept == "application/x-pem-file" || accept == "text/plain" {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, chain)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"chain_pem": chain})
}

// handleGetCertChain 返回指定证书 + 其签发 CA 的完整证书链。
// 链顺序：叶子证书 → 签发 CA → 上级 CA → ... → 根 CA。
func (s *Server) handleGetCertChain(w http.ResponseWriter, r *http.Request) {
	certUUID := r.PathValue("uuid")
	certRepo := storage.NewCertRepo(s.db)
	cert, err := certRepo.GetByUUID(r.Context(), certUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, "证书不存在")
		return
	}

	// 非管理员只能查看自己的证书
	claims := claimsFromCtx(r.Context())
	if cert.UserUUID != claims.UserUUID && !auth.IsAdmin(claims.Role) {
		writeError(w, http.StatusForbidden, "无权查看此证书")
		return
	}

	chain := string(cert.CertContent)
	if cert.CAUUID != "" {
		if caChain, err := s.caSvc.GetChain(r.Context(), cert.CAUUID); err == nil {
			if chain != "" && chain[len(chain)-1] != '\n' {
				chain += "\n"
			}
			chain += caChain
		}
	}

	if accept := r.Header.Get("Accept"); accept == "application/x-pem-file" || accept == "text/plain" {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, chain)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"chain_pem": chain})
}

// ImportChainRequest 是导入证书链请求体。
type ImportChainRequest struct {
	ChainPEM string `json:"chain_pem"`
}

func (s *Server) handleImportCAChain(w http.ResponseWriter, r *http.Request) {
	caUUID := r.PathValue("uuid")
	var req ImportChainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if err := s.caSvc.ImportChain(r.Context(), caUUID, req.ChainPEM); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "证书链已导入"})
}

func (s *Server) handleListRevokedCerts(w http.ResponseWriter, r *http.Request) {
	caUUID := r.PathValue("uuid")
	certs, err := s.caSvc.ListRevokedCerts(r.Context(), caUUID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"revoked_certs": certs, "total": len(certs)})
}

// RevokeRequest 是吊销证书请求体。
type RevokeRequest struct {
	SerialNumber string `json:"serial_number"` // 十六进制序列号
	Reason       int    `json:"reason"`        // RFC 5280 吊销原因码
}

func (s *Server) handleRevokeCert(w http.ResponseWriter, r *http.Request) {
	caUUID := r.PathValue("uuid")
	var req RevokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if req.SerialNumber == "" {
		writeError(w, http.StatusBadRequest, "证书序列号不能为空")
		return
	}
	if err := s.caSvc.RevokeCert(r.Context(), caUUID, req.SerialNumber, req.Reason); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	claims := claimsFromCtx(r.Context())
	s.logRepo.Create(r.Context(), &storage.Log{ //nolint:errcheck
		UserUUID: claims.UserUUID,
		Action:   fmt.Sprintf("revoke_cert:%s:%s", caUUID, req.SerialNumber),
		IPAddr:   r.RemoteAddr,
	})

	writeJSON(w, http.StatusOK, map[string]string{"message": "证书已吊销"})
}

func (s *Server) handleGetCRL(w http.ResponseWriter, r *http.Request) {
	caUUID := r.PathValue("uuid")
	crlDER, err := s.caSvc.GenerateCRL(r.Context(), caUUID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.crl", caUUID))
	w.WriteHeader(http.StatusOK)
	w.Write(crlDER) //nolint:errcheck
}

// IssueCertRequest 是签发证书请求体。
type IssueCertRequest struct {
	KeyType          string   `json:"key_type"`
	ValidDays        int      `json:"valid_days"`
	NotBefore        string   `json:"not_before"` // RFC3339，可选：显式生效时间
	NotAfter         string   `json:"not_after"`  // RFC3339，可选：显式失效时间（优先于 valid_days）
	CommonName       string   `json:"common_name"`
	Org              string   `json:"organization"`
	Country          string   `json:"country"`
	IsCA             bool     `json:"is_ca"`
	PathLen          int      `json:"path_len"`
	DNSNames         []string `json:"dns_names"`
	IPAddresses      []string `json:"ip_addresses"`
	EmailAddrs       []string `json:"email_addresses"`
	URIs             []string `json:"uris"`                 // SAN URI 列表
	PolicyOIDs       []string `json:"certificate_policies"` // 证书策略 OID 列表
	CardUUID         string   `json:"card_uuid"`            // 签发后存入的卡片 UUID（可选）
	IssuanceTmplUUID string   `json:"issuance_tmpl_uuid"`   // 颁发模板 UUID（可选）
}

func (s *Server) handleIssueCert(w http.ResponseWriter, r *http.Request) {
	caUUID := r.PathValue("uuid")
	var req IssueCertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if req.CommonName == "" {
		writeError(w, http.StatusBadRequest, "CommonName 不能为空")
		return
	}
	if req.KeyType == "" {
		req.KeyType = "ec256"
	}
	if req.ValidDays <= 0 {
		req.ValidDays = 365
	}

	// 解析 IP 地址
	var ips []net.IP
	for _, ipStr := range req.IPAddresses {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("无效的 IP 地址: %s", ipStr))
			return
		}
		ips = append(ips, ip)
	}

	subject := pkixName(req.CommonName, req.Org, req.Country)

	// 默认 KU/EKU：仅当未指定颁发模板时使用（指定模板时由签发引擎按 KeyUsageTemplate 回填）。
	var defaultKeyUsage x509.KeyUsage
	var defaultExtKeyUsage []x509.ExtKeyUsage
	if req.IssuanceTmplUUID == "" {
		defaultKeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		if req.IsCA {
			defaultKeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		}
		defaultExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}

	issueReq := &ca.IssueRequest{
		CAUUID:           caUUID,
		Subject:          subject,
		KeyType:          req.KeyType,
		ValidDays:        req.ValidDays,
		IsCA:             req.IsCA,
		PathLen:          req.PathLen,
		KeyUsage:         defaultKeyUsage,
		ExtKeyUsage:      defaultExtKeyUsage,
		DNSNames:         req.DNSNames,
		IPAddresses:      ips,
		EmailAddrs:       req.EmailAddrs,
		URIs:             req.URIs,
		PolicyOIDs:       req.PolicyOIDs,
		IssuanceTmplUUID: req.IssuanceTmplUUID,
	}
	if t, err := parseTimePtr(req.NotBefore); err != nil {
		writeError(w, http.StatusBadRequest, "生效时间格式错误: "+err.Error())
		return
	} else {
		issueReq.NotBefore = t
	}
	if t, err := parseTimePtr(req.NotAfter); err != nil {
		writeError(w, http.StatusBadRequest, "失效时间格式错误: "+err.Error())
		return
	} else {
		issueReq.NotAfter = t
	}

	resp, err := s.caSvc.IssueCert(r.Context(), issueReq)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	claims := claimsFromCtx(r.Context())

	// 如果指定了卡片 UUID，将证书存入卡片
	var certUUID string
	if req.CardUUID != "" {
		certRepo := storage.NewCertRepo(s.db)
		cert := &storage.Certificate{
			CardUUID:            req.CardUUID,
			UserUUID:            claims.UserUUID,
			CertType:            "x509",
			KeyType:             req.KeyType,
			CertContent:         []byte(resp.CertPEM),
			PrivateData:         resp.PrivateEnc,
			CAUUID:              caUUID,
			SerialNumber:        resp.SerialNumber,
			SerialHex:           resp.SerialNumber,
			SubjectDN:           resp.SubjectDN,
			IssuerDN:            resp.IssuerDN,
			NotBefore:           &resp.NotBefore,
			NotAfter:            &resp.NotAfter,
			SANDNS:              jsonStrArray(req.DNSNames),
			SANIP:               jsonStrArray(req.IPAddresses),
			SANEmail:            jsonStrArray(req.EmailAddrs),
			SANURI:              jsonStrArray(req.URIs),
			CertificatePolicies: jsonStrArray(req.PolicyOIDs),
			IssuanceTmplUUID:    req.IssuanceTmplUUID,
			RevocationStatus:    "active",
		}
		if err := certRepo.Create(r.Context(), cert); err != nil {
			writeError(w, http.StatusInternalServerError, "保存证书失败: "+err.Error())
			return
		}
		certUUID = cert.UUID
	}

	// 写入审计日志
	s.auditLogRepo.Create(r.Context(), &storage.AuditLog{ //nolint:errcheck
		UserUUID:     claims.UserUUID,
		Action:       "issue_cert",
		ResourceType: "certificate",
		ResourceUUID: certUUID,
		Detail:       fmt.Sprintf(`{"ca_uuid":"%s","cn":"%s","serial":"%s"}`, caUUID, req.CommonName, resp.SerialNumber),
		IPAddress:    r.RemoteAddr,
	})

	s.logRepo.Create(r.Context(), &storage.Log{ //nolint:errcheck
		UserUUID: claims.UserUUID,
		Action:   fmt.Sprintf("issue_cert:%s:%s", caUUID, req.CommonName),
		IPAddr:   r.RemoteAddr,
	})

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"cert_pem":      resp.CertPEM,
		"serial_number": resp.SerialNumber,
		"subject_dn":    resp.SubjectDN,
		"issuer_dn":     resp.IssuerDN,
		"not_before":    resp.NotBefore,
		"not_after":     resp.NotAfter,
		"cert_uuid":     certUUID,
	})
}

// pkixName 构建 pkix.Name。
func pkixName(cn, org, country string) pkix.Name {
	name := pkix.Name{CommonName: cn}
	if org != "" {
		name.Organization = []string{org}
	}
	if country != "" {
		name.Country = []string{country}
	}
	return name
}

// ---- 公开服务处理器（无需认证）----

// handlePublicCRL 返回 CA 的 CRL 文件（DER 格式）。
func (s *Server) handlePublicCRL(w http.ResponseWriter, r *http.Request) {
	caUUID := r.PathValue("caUUID")
	if s.revocationSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "吊销服务未启用")
		return
	}
	crl, err := s.revocationSvc.GetCRL(r.Context(), caUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.crl\"", caUUID))
	w.WriteHeader(http.StatusOK)
	w.Write(crl) //nolint:errcheck
}

// handlePublicOCSP 处理 OCSP 查询请求。
// 支持 RFC 6960 三种调用方式：
//  1. POST application/ocsp-request + DER body → binary 响应
//  2. GET /ocsp/{caUUID}/{base64OcspReq} → binary 响应
//  3. GET /ocsp/{caUUID}?serial=xxx&format=json → JSON 调试响应（旧方式，保留）
func (s *Server) handlePublicOCSP(w http.ResponseWriter, r *http.Request) {
	caUUID := r.PathValue("caUUID")
	if s.revocationSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "吊销服务未启用")
		return
	}

	// 方式 3：JSON 调试（仅保留用于内部调试）
	if r.Method == http.MethodGet && r.URL.Query().Get("format") == "json" {
		serialNumber := r.URL.Query().Get("serial")
		if serialNumber == "" {
			writeError(w, http.StatusBadRequest, "缺少 serial 参数")
			return
		}
		status, err := s.revocationSvc.QueryOCSPStatus(r.Context(), caUUID, serialNumber)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, status)
		return
	}

	// 方式 1/2：RFC 6960 标准 binary
	reqDER, err := readOCSPRequestBytes(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	respDER, err := s.revocationSvc.CreateOCSPResponseDER(r.Context(), caUUID, reqDER)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/ocsp-response")
	w.WriteHeader(http.StatusOK)
	w.Write(respDER) //nolint:errcheck
}

// handlePublicCAIssuer 返回 CA 证书 PEM（用于 AIA CAIssuer）。
func (s *Server) handlePublicCAIssuer(w http.ResponseWriter, r *http.Request) {
	caUUID := r.PathValue("caUUID")
	if s.revocationSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "吊销服务未启用")
		return
	}
	certPEM, err := s.revocationSvc.GetCAIssuerCert(r.Context(), caUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, certPEM)
}

// ---- 自定义路径的吊销服务处理器 ----

// lookupCAByPath 通过自定义路径查找 CA UUID。
func (s *Server) lookupCAByPath(ctx context.Context, serviceType, path string) (string, error) {
	var caUUID string
	err := s.db.QueryRowContext(ctx,
		`SELECT ca_uuid FROM revocation_services WHERE service_type = ? AND path = ? AND enabled = 1`,
		serviceType, path,
	).Scan(&caUUID)
	if err != nil {
		return "", fmt.Errorf("未找到路径 %s 对应的 %s 服务配置", path, serviceType)
	}
	return caUUID, nil
}

// handlePublicCRLByPath 通过自定义路径返回 CRL。
func (s *Server) handlePublicCRLByPath(w http.ResponseWriter, r *http.Request) {
	path := r.PathValue("path")
	if s.revocationSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "吊销服务未启用")
		return
	}
	caUUID, err := s.lookupCAByPath(r.Context(), "crl", path)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	crl, err := s.revocationSvc.GetCRL(r.Context(), caUUID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.crl\"", path))
	w.WriteHeader(http.StatusOK)
	w.Write(crl) //nolint:errcheck
}

// handlePublicOCSPByPath 通过自定义路径处理 OCSP 请求（RFC 6960 binary）。
func (s *Server) handlePublicOCSPByPath(w http.ResponseWriter, r *http.Request) {
	path := r.PathValue("path")
	if s.revocationSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "吊销服务未启用")
		return
	}
	caUUID, err := s.lookupCAByPath(r.Context(), "ocsp", path)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	// 方式 3：JSON 调试
	if r.Method == http.MethodGet && r.URL.Query().Get("format") == "json" {
		serialNumber := r.URL.Query().Get("serial")
		if serialNumber == "" {
			writeError(w, http.StatusBadRequest, "缺少 serial 参数")
			return
		}
		status, err := s.revocationSvc.QueryOCSPStatus(r.Context(), caUUID, serialNumber)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, status)
		return
	}

	// 方式 1/2：RFC 6960 标准 binary
	reqDER, err := readOCSPRequestBytes(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	respDER, err := s.revocationSvc.CreateOCSPResponseDER(r.Context(), caUUID, reqDER)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/ocsp-response")
	w.WriteHeader(http.StatusOK)
	w.Write(respDER) //nolint:errcheck
}

// readOCSPRequestBytes 按 RFC 6960 从 HTTP 请求中提取 OCSP 请求 DER：
//   - POST：Content-Type 应为 application/ocsp-request，body 即为 DER
//   - GET：URL 路径末段或 ?req= 查询参数应为 base64(DER)
func readOCSPRequestBytes(r *http.Request) ([]byte, error) {
	if r.Method == http.MethodPost {
		der, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1MB 上限
		if err != nil {
			return nil, fmt.Errorf("读取请求体失败: %w", err)
		}
		if len(der) == 0 {
			return nil, fmt.Errorf("OCSP 请求体为空")
		}
		return der, nil
	}

	// GET：尝试从 ?req= 参数读取
	b64 := r.URL.Query().Get("req")
	if b64 == "" {
		// 尝试 URL 路径末段（部分 OCSP 客户端用 /ocsp/<base64> 形式）
		if p := r.URL.Path; p != "" {
			idx := strings.LastIndex(p, "/")
			if idx >= 0 && idx < len(p)-1 {
				b64 = p[idx+1:]
			}
		}
	}
	if b64 == "" {
		return nil, fmt.Errorf("GET 请求缺少 OCSP 请求数据（应通过 ?req= 或 URL 路径传递 base64 DER）")
	}
	// 某些客户端会 URL 编码 +/=，先尝试标准 base64 再尝试 URL-safe
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		if der, err = base64.URLEncoding.DecodeString(b64); err != nil {
			return nil, fmt.Errorf("OCSP 请求 base64 解码失败: %w", err)
		}
	}
	return der, nil
}

// handlePublicCAIssuerByPath 通过自定义路径返回 CA 证书。
func (s *Server) handlePublicCAIssuerByPath(w http.ResponseWriter, r *http.Request) {
	path := r.PathValue("path")
	if s.revocationSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "吊销服务未启用")
		return
	}
	caUUID, err := s.lookupCAByPath(r.Context(), "caissuer", path)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	certPEM, err := s.revocationSvc.GetCAIssuerCert(r.Context(), caUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, certPEM)
}

// jsonStrArray 将字符串切片编码为 JSON 数组字符串。
// 用于 Certificate 记录中的 san_dns/san_ip/san_email/san_uris/certificate_policies 列。
// nil 或空切片返回 "[]" 以兼容数据库 NOT NULL 约束。
func jsonStrArray(ss []string) string {
	if len(ss) == 0 {
		return "[]"
	}
	b, err := json.Marshal(ss)
	if err != nil {
		return "[]"
	}
	return string(b)
}
