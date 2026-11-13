package api

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/globaltrusts/server-card/internal/auth"
	"github.com/globaltrusts/server-card/internal/card"
	"github.com/globaltrusts/server-card/internal/storage"
)

// ---- 卡片处理器 ----

func writeCardServiceError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	if errors.Is(err, storage.ErrCardCertificateLimit) {
		status = http.StatusConflict
	} else if errors.Is(err, storage.ErrCardServiceUnavailable) {
		status = http.StatusForbidden
	}
	writeError(w, status, err.Error())
}

func (s *Server) handleListCards(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	cards, err := s.cardSvc.ListCards(r.Context(), claims.UserUUID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"cards": cards, "total": len(cards)})
}

// CreateCardRequest 是创建卡片请求体。
type CreateCardRequest struct {
	CardName        string `json:"card_name"`
	Remark          string `json:"remark"`
	StorageZoneUUID string `json:"storage_zone_uuid"` // 存储区域 UUID（可选）
	PIN             string `json:"pin"`               // 初始 PIN（可选）
	PUK             string `json:"puk"`               // 初始 PUK（可选）
	AdminKey        string `json:"admin_key"`         // Admin Key（可选）
	PINRetries      int    `json:"pin_retries"`       // PIN 错误最大次数，默认 3
	// OrderNo 销售模式下必填：已支付的云智能卡订单号
	OrderNo string `json:"order_no,omitempty"`

	// 高安全等级卡片所需字段
	SlotType         string            `json:"slot_type,omitempty"`         // software/tpmv2/apple_t2/apple_se
	SecurityLevel    string            `json:"security_level,omitempty"`    // low/medium/high
	Attestation      *card.Attestation `json:"attestation,omitempty"`       // 客户端 EK 认证
	AttestationNonce string            `json:"attestation_nonce,omitempty"` // 服务端下发的 nonce
}

func (s *Server) handleCreateCard(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	var req CreateCardRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if req.CardName == "" {
		writeError(w, http.StatusBadRequest, "卡片名称不能为空")
		return
	}
	// 生产环境要求 PIN 保护：无 PIN 的卡片任何人拿到账号 Token 即可远程签名
	if len(req.PIN) < 6 {
		writeError(w, http.StatusBadRequest, "请设置至少 6 位的 PIN")
		return
	}

	// 业务模式鉴权：管理员不受限；普通用户的销售权益从已支付订单快照读取。
	grant, err := s.authorizeCardCreation(r, claims, req.OrderNo)
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	orderNo := ""
	cardRequest := &card.CreateCardRequest{
		UserUUID:         claims.UserUUID,
		CardName:         req.CardName,
		Remark:           req.Remark,
		StorageZoneUUID:  req.StorageZoneUUID,
		PIN:              req.PIN,
		PUK:              req.PUK,
		AdminKey:         req.AdminKey,
		PINRetries:       req.PINRetries,
		SlotType:         card.SlotType(req.SlotType),
		SecurityLevel:    card.SecurityLevel(req.SecurityLevel),
		Attestation:      req.Attestation,
		AttestationNonce: req.AttestationNonce,
	}
	if grant != nil {
		orderNo = grant.OrderNo
	}
	if grant != nil && grant.Template != nil {
		if req.StorageZoneUUID != "" && req.StorageZoneUUID != grant.Template.StorageZoneUUID {
			writeError(w, http.StatusBadRequest, "当前云卡套餐不允许选择其他存储区域")
			return
		}
		if len(req.PIN) < grant.Template.PINMinLength {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("请设置至少 %d 位的 PIN", grant.Template.PINMinLength))
			return
		}
		expiresAt := time.Now().AddDate(0, grant.DurationMonths, 0)
		cardRequest.StorageZoneUUID = grant.Template.StorageZoneUUID
		cardRequest.CloudCardTmplUUID = grant.Template.UUID
		cardRequest.ServiceExpiresAt = &expiresAt
		cardRequest.CertificateLimit = grant.Template.CertificateLimit
		cardRequest.ReminderEnabled = grant.Template.ReminderEnabled
		cardRequest.ReminderDays = grant.Template.ReminderDays
	}

	c, err := s.cardSvc.CreateCard(r.Context(), cardRequest)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// 销售模式：原子绑定订单，防止同一订单被并发超额开卡
	if orderNo != "" {
		limit := s.cardOrderLimit(r, orderNo)
		ok, bindErr := storage.NewCardRepo(s.db).BindOrder(r.Context(), c.UUID, orderNo, limit)
		if bindErr != nil || !ok {
			s.cardSvc.DeleteCard(r.Context(), c.UUID, claims.UserUUID) //nolint:errcheck
			writeError(w, http.StatusForbidden, "该订单可开卡数量已用完")
			return
		}
		c.OrderNo = orderNo
		s.markCardOrderFulfilled(r, orderNo, limit)
	}

	s.logRepo.Create(r.Context(), &storage.Log{ //nolint:errcheck
		UserUUID: claims.UserUUID,
		Action:   fmt.Sprintf("create_card:%s:%s", c.UUID, orderNo),
		IPAddr:   r.RemoteAddr,
	})
	writeJSON(w, http.StatusCreated, c)
}

type renewCloudCardRequest struct {
	OrderNo string `json:"order_no"`
}

// handleRenewCloudCard 用新的已支付云卡订单延长同一张卡的服务期。
func (s *Server) handleRenewCloudCard(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	cardUUID := r.PathValue("uuid")
	var req renewCloudCardRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	cardRecord, err := s.cardSvc.GetCard(r.Context(), cardUUID, claims.UserUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, "云卡不存在")
		return
	}
	orderNo := strings.TrimSpace(req.OrderNo)
	order, err := s.workflowSvc.GetOrderByNo(r.Context(), orderNo)
	if err != nil || order.UserUUID != claims.UserUUID {
		writeError(w, http.StatusNotFound, "续费订单不存在")
		return
	}
	if order.Status != storage.CertOrderPaid {
		writeError(w, http.StatusConflict, "续费订单尚未支付或已履约")
		return
	}
	var spec struct {
		Kind               string `json:"kind"`
		Quantity           int    `json:"quantity"`
		DurationMonths     int    `json:"duration_months"`
		CloudCardTmplUUID  string `json:"cloud_card_tmpl_uuid"`
		CloudCardOperation string `json:"cloud_card_operation"`
	}
	if err := json.Unmarshal([]byte(order.SpecJSON), &spec); err != nil ||
		spec.Kind != storage.OrderKindCard || spec.Quantity <= 0 || spec.DurationMonths <= 0 ||
		spec.CloudCardOperation != "renewal" || spec.CloudCardTmplUUID == "" || spec.CloudCardTmplUUID != cardRecord.CloudCardTmplUUID {
		writeError(w, http.StatusBadRequest, "续费订单必须是 renewal 类型，并匹配该云卡的开通模板和服务期")
		return
	}
	tmpl, err := s.portalSvc.ResolveActiveCloudCardTemplate(r.Context(), spec.CloudCardTmplUUID)
	if err != nil {
		writeError(w, http.StatusConflict, "云卡开通模板或存储区域不可用，当前不能续费")
		return
	}
	expiresAt, renewed, err := storage.NewCardRepo(s.db).RenewCloudCardService(
		r.Context(), cardUUID, orderNo, tmpl.UUID, spec.DurationMonths, spec.Quantity)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if !renewed {
		writeError(w, http.StatusConflict, "该订单续费额度已用完")
		return
	}
	s.markCardOrderFulfilled(r, orderNo, spec.Quantity)
	s.logRepo.Create(r.Context(), &storage.Log{ //nolint:errcheck
		UserUUID: claims.UserUUID, CardUUID: cardUUID,
		Action: fmt.Sprintf("renew_cloud_card:%s", orderNo), IPAddr: r.RemoteAddr,
	})
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"card_uuid": cardUUID, "service_status": "active", "service_expires_at": expiresAt,
	})
}

func (s *Server) handleGetCard(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	cardUUID := r.PathValue("uuid")

	c, err := s.cardSvc.GetCard(r.Context(), cardUUID, claims.UserUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (s *Server) handleDeleteCard(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	cardUUID := r.PathValue("uuid")

	// 托管容器保存着用户已签发的下载型证书，禁止用户自行删除。
	c, err := s.cardSvc.GetCard(r.Context(), cardUUID, claims.UserUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	if c.IsHosting() {
		writeError(w, http.StatusForbidden, "证书托管容器由系统维护，不能删除")
		return
	}
	if err := s.cardSvc.DeleteCard(r.Context(), cardUUID, claims.UserUUID); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	if c.OrderNo != "" {
		writeJSON(w, http.StatusOK, map[string]string{"message": "云卡已终止服务，证书与订单历史已保留"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "卡片及关联证书已删除"})
}

// ---- 证书处理器 ----

func (s *Server) handleListCerts(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	cardUUID := r.PathValue("uuid")

	certs, err := s.cardSvc.ListCerts(r.Context(), cardUUID, claims.UserUUID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"certs": certs, "total": len(certs)})
}

// ImportCertRequest 是导入证书请求体。
type ImportCertRequest struct {
	CertType    string `json:"cert_type"`
	KeyType     string `json:"key_type"`
	CertContent []byte `json:"cert_content"` // Base64 编码的 DER
	Remark      string `json:"remark"`
}

func (s *Server) handleImportCert(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	cardUUID := r.PathValue("uuid")

	// PIN 会话校验
	if !s.checkPINSession(w, r, cardUUID) {
		return
	}

	var req ImportCertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}

	cert, err := s.cardSvc.ImportCert(r.Context(), cardUUID, claims.UserUUID, req.CertType, req.KeyType, req.Remark, req.CertContent)
	if err != nil {
		writeCardServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, cert)
}

func (s *Server) handleDeleteCert(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	cardUUID := r.PathValue("uuid")
	certUUID := r.PathValue("cert_uuid")

	// PIN 会话校验
	if !s.checkPINSession(w, r, cardUUID) {
		return
	}

	if err := s.cardSvc.DeleteCert(r.Context(), certUUID, cardUUID, claims.UserUUID); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "证书已删除"})
}

// KeyGenRequest 是密钥生成请求体。
type KeyGenRequest struct {
	KeyType string `json:"key_type"` // rsa2048/rsa4096/ec256/ec384/ec521
	Remark  string `json:"remark"`
}

func (s *Server) handleKeyGen(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	cardUUID := r.PathValue("uuid")

	// PIN 会话校验
	if !s.checkPINSession(w, r, cardUUID) {
		return
	}

	var req KeyGenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if req.KeyType == "" {
		req.KeyType = "ec256"
	}

	cert, err := s.cardSvc.GenerateKeyPair(r.Context(), cardUUID, claims.UserUUID, req.KeyType, req.Remark)
	if err != nil {
		writeCardServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, cert)
}

// SignRequest 是签名请求体。
type SignRequest struct {
	CertUUID  string `json:"cert_uuid"`
	Mechanism string `json:"mechanism"` // ECDSA_SHA256/SHA256_RSA_PKCS/...
	Data      []byte `json:"data"`      // 待签名数据（Base64）
}

func (s *Server) handleSign(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	cardUUID := r.PathValue("uuid")

	// PIN 会话校验（签名为高敏感操作，必须持有有效 PIN 会话）
	if !s.checkPINSession(w, r, cardUUID) {
		return
	}

	var req SignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}

	sig, err := s.cardSvc.Sign(r.Context(), req.CertUUID, cardUUID, claims.UserUUID, req.Mechanism, req.Data)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// 记录签名日志
	s.logRepo.Create(r.Context(), &storage.Log{ //nolint:errcheck
		UserUUID:  claims.UserUUID,
		CardUUID:  cardUUID,
		CertUUID:  req.CertUUID,
		Action:    fmt.Sprintf("sign:%s", req.Mechanism),
		IPAddr:    r.RemoteAddr,
		UserAgent: r.UserAgent(),
	})

	writeJSON(w, http.StatusOK, map[string][]byte{"signature": sig})
}

// DecryptRequest 是解密请求体。
type DecryptRequest struct {
	CertUUID   string `json:"cert_uuid"`
	Mechanism  string `json:"mechanism"`
	Ciphertext []byte `json:"ciphertext"`
}

func (s *Server) handleDecrypt(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	cardUUID := r.PathValue("uuid")

	// PIN 会话校验（解密为高敏感操作，必须持有有效 PIN 会话）
	if !s.checkPINSession(w, r, cardUUID) {
		return
	}

	var req DecryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}

	plaintext, err := s.cardSvc.Decrypt(r.Context(), req.CertUUID, cardUUID, claims.UserUUID, req.Mechanism, req.Ciphertext)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.logRepo.Create(r.Context(), &storage.Log{ //nolint:errcheck
		UserUUID:  claims.UserUUID,
		CardUUID:  cardUUID,
		CertUUID:  req.CertUUID,
		Action:    fmt.Sprintf("decrypt:%s", req.Mechanism),
		IPAddr:    r.RemoteAddr,
		UserAgent: r.UserAgent(),
	})

	writeJSON(w, http.StatusOK, map[string][]byte{"plaintext": plaintext})
}

// ---- 证书增强管理处理器 ----

func (s *Server) handleListCertsFiltered(w http.ResponseWriter, r *http.Request) {
	userUUID := r.URL.Query().Get("user_uuid")
	caUUID := r.URL.Query().Get("ca_uuid")
	tmplUUID := r.URL.Query().Get("template_uuid")
	certType := r.URL.Query().Get("cert_type")
	status := r.URL.Query().Get("status")
	page, pageSize := parsePagination(r)

	// 非管理员只能查看自己的证书
	claims := claimsFromCtx(r.Context())
	if !auth.IsAdmin(claims.Role) {
		userUUID = claims.UserUUID
	}

	certRepo := storage.NewCertRepo(s.db)
	certs, total, err := certRepo.ListFiltered(r.Context(), userUUID, caUUID, tmplUUID, "", certType, status, page, pageSize)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if certs == nil {
		certs = []*storage.Certificate{}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items":     certs,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

// RevokeCertRequest 是吊销证书请求体。
type RevokeCertRequest struct {
	Reason int `json:"reason"` // RFC 5280 吊销原因码
}

func (s *Server) handleRevokeCertByUUID(w http.ResponseWriter, r *http.Request) {
	certUUID := r.PathValue("uuid")
	var req RevokeCertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}

	certRepo := storage.NewCertRepo(s.db)

	// 获取证书信息
	cert, err := certRepo.GetByUUID(r.Context(), certUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	if cert.RevocationStatus == "revoked" {
		writeError(w, http.StatusBadRequest, "证书已被吊销")
		return
	}

	// 更新证书吊销状态
	if err := certRepo.Revoke(r.Context(), certUUID, req.Reason); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// 如果证书关联了 CA，将真实序列号加入 CA 的吊销列表
	if cert.CAUUID != "" && cert.SerialNumber != "" {
		if err := s.caSvc.RevokeCert(r.Context(), cert.CAUUID, cert.SerialNumber, req.Reason); err != nil {
			slog.Warn("加入 CA 吊销列表失败", "cert_uuid", certUUID, "ca_uuid", cert.CAUUID, "error", err)
		}
	}

	claims := claimsFromCtx(r.Context())
	s.logRepo.Create(r.Context(), &storage.Log{ //nolint:errcheck
		UserUUID: claims.UserUUID,
		CertUUID: certUUID,
		Action:   "revoke_cert",
		IPAddr:   r.RemoteAddr,
	})

	writeJSON(w, http.StatusOK, map[string]string{"message": "证书已吊销"})
}

// AssignCertRequest 是分配证书到智能卡请求体。
type AssignCertRequest struct {
	TargetCardUUID string `json:"target_card_uuid"`
}

func (s *Server) handleAssignCertToCard(w http.ResponseWriter, r *http.Request) {
	certUUID := r.PathValue("uuid")
	var req AssignCertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if req.TargetCardUUID == "" {
		writeError(w, http.StatusBadRequest, "目标智能卡 UUID 不能为空")
		return
	}

	certRepo := storage.NewCertRepo(s.db)

	// 验证证书存在
	if _, err := certRepo.GetByUUID(r.Context(), certUUID); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	// 验证目标卡片存在
	cardRepo := storage.NewCardRepo(s.db)
	if _, err := cardRepo.GetByUUID(r.Context(), req.TargetCardUUID); err != nil {
		writeError(w, http.StatusNotFound, "目标智能卡不存在")
		return
	}

	// 执行分配
	if err := certRepo.AssignToCard(r.Context(), certUUID, req.TargetCardUUID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	claims := claimsFromCtx(r.Context())
	s.logRepo.Create(r.Context(), &storage.Log{ //nolint:errcheck
		UserUUID: claims.UserUUID,
		CertUUID: certUUID,
		CardUUID: req.TargetCardUUID,
		Action:   "assign_cert_to_card",
		IPAddr:   r.RemoteAddr,
	})

	writeJSON(w, http.StatusOK, map[string]string{"message": "证书已分配到智能卡"})
}

// ---- 证书续期 ----

// RenewCertRequest 是证书续期请求体。
type RenewCertRequest struct {
	ValidDays int `json:"valid_days"` // 新的有效期天数
}

func (s *Server) handleRenewCert(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	certUUID := r.PathValue("uuid")

	var req RenewCertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if req.ValidDays <= 0 {
		req.ValidDays = 365
	}

	certRepo := storage.NewCertRepo(s.db)
	cert, err := certRepo.GetByUUID(r.Context(), certUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	// 权限检查：只有证书所有者或管理员可以续期
	cardRepo := storage.NewCardRepo(s.db)
	card, err := cardRepo.GetByUUID(r.Context(), cert.CardUUID)
	if err != nil || (card.UserUUID != claims.UserUUID && !auth.IsAdmin(claims.Role)) {
		writeError(w, http.StatusForbidden, "无权续期此证书")
		return
	}

	// 检查证书是否已被吊销
	if cert.RevocationStatus == "revoked" {
		writeError(w, http.StatusBadRequest, "已吊销的证书不能续期")
		return
	}

	// 调用 issuance 服务续期
	newCert, err := s.issuanceSvc.RenewCert(r.Context(), cert, req.ValidDays)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.logRepo.Create(r.Context(), &storage.Log{ //nolint:errcheck
		UserUUID: claims.UserUUID,
		CertUUID: certUUID,
		Action:   fmt.Sprintf("renew_cert:days=%d", req.ValidDays),
		IPAddr:   r.RemoteAddr,
	})

	writeJSON(w, http.StatusCreated, newCert)
}

// ---- 证书导出 ----

func (s *Server) handleExportCert(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	certUUID := r.PathValue("uuid")
	format := r.URL.Query().Get("format") // pem/der

	if format == "" {
		format = "pem"
	}

	certRepo := storage.NewCertRepo(s.db)
	cert, err := certRepo.GetByUUID(r.Context(), certUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	if !s.canAccessCert(r, cert, claims) {
		writeError(w, http.StatusForbidden, "无权导出此证书")
		return
	}

	switch format {
	case "pem":
		// 返回 PEM 格式证书（不含私钥）
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.CertContent,
		})
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.pem\"", certUUID))
		w.WriteHeader(http.StatusOK)
		w.Write(certPEM) //nolint:errcheck

	case "der":
		// 返回 DER 格式证书
		w.Header().Set("Content-Type", "application/pkix-cert")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.der\"", certUUID))
		w.WriteHeader(http.StatusOK)
		w.Write(cert.CertContent) //nolint:errcheck

	case "pkcs12":
		writeError(w, http.StatusBadRequest, "私钥材料必须通过 POST /api/certificates/{uuid}/download 受控下发；GET 导出不接受口令参数")

	default:
		writeError(w, http.StatusBadRequest, "不支持的导出格式，支持 pem/der")
	}
}

// ---- PIN/PUK/Admin Key 处理器 ----

// handleVerifyPIN 验证卡片 PIN 码。
// 验证成功后签发 PIN 会话令牌（X-PIN-Session），有效期 15 分钟。
// 后续签名/解密/密钥生成/证书增删等敏感操作需携带此令牌。
func (s *Server) handleVerifyPIN(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	cardUUID := r.PathValue("uuid")

	var req struct {
		PIN string `json:"pin"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}

	// 验证归属并拒绝已暂停、到期或终止的云卡。
	if _, ok := s.requireActiveCard(w, r, cardUUID); !ok {
		return
	}

	ok, remaining, err := s.cardSvc.VerifyPIN(r.Context(), cardUUID, req.PIN)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	resp := map[string]interface{}{
		"success":   ok,
		"remaining": remaining,
	}
	// PIN 验证成功时签发会话令牌
	if ok {
		session, sErr := s.pinSessions.Create(cardUUID, claims.UserUUID)
		if sErr != nil {
			writeError(w, http.StatusInternalServerError, sErr.Error())
			return
		}
		resp["pin_session_token"] = session.Token
		resp["expires_at"] = session.ExpiresAt
		resp["ttl_seconds"] = int(s.pinSessions.TTL().Seconds())
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleUnlockWithPUK 使用 PUK 解锁并重置 PIN。
func (s *Server) handleUnlockWithPUK(w http.ResponseWriter, r *http.Request) {
	cardUUID := r.PathValue("uuid")

	var req struct {
		PUK    string `json:"puk"`
		NewPIN string `json:"new_pin"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}

	if _, ok := s.requireActiveCard(w, r, cardUUID); !ok {
		return
	}

	if err := s.cardSvc.UnlockWithPUK(r.Context(), cardUUID, req.PUK, req.NewPIN); err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	// PIN 被重置，撤销该卡片的所有旧 PIN 会话
	s.pinSessions.RevokeByCard(cardUUID)
	writeJSON(w, http.StatusOK, map[string]string{"message": "PIN 已重置"})
}

// handleResetWithAdminKey 使用 Admin Key 重置 PIN 和 PUK。
func (s *Server) handleResetWithAdminKey(w http.ResponseWriter, r *http.Request) {
	cardUUID := r.PathValue("uuid")

	var req struct {
		AdminKey string `json:"admin_key"`
		NewPIN   string `json:"new_pin"`
		NewPUK   string `json:"new_puk"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}

	if _, ok := s.requireActiveCard(w, r, cardUUID); !ok {
		return
	}

	if err := s.cardSvc.ResetWithAdminKey(r.Context(), cardUUID, req.AdminKey, req.NewPIN, req.NewPUK); err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	// PIN/PUK 被重置，撤销该卡片的所有旧 PIN 会话
	s.pinSessions.RevokeByCard(cardUUID)
	writeJSON(w, http.StatusOK, map[string]string{"message": "PIN 和 PUK 已重置"})
}

// handleLogoutPINSession 主动撤销当前 PIN 会话令牌（从 X-PIN-Session Header 读取）。
// 用户主动登出或切换卡片时调用，立即失效令牌以降低令牌泄露风险。
func (s *Server) handleLogoutPINSession(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("X-PIN-Session")
	if token != "" {
		s.pinSessions.Revoke(token)
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "PIN 会话已注销"})
}
