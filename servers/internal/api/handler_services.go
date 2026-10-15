// Package api - handler_services.go：OCSP 响应服务、证书策略页面、优惠码/订阅/兑换码、用户自助吊销。
package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/globaltrusts/server-card/internal/cps"
	"github.com/globaltrusts/server-card/internal/promo"
	"github.com/globaltrusts/server-card/internal/revocation"
	"github.com/globaltrusts/server-card/internal/storage"
)

// ======================= OCSP 响应服务 =======================

func (s *Server) handleListOCSPResponders(w http.ResponseWriter, r *http.Request) {
	list, err := s.revocationSvc.ListResponders(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	base := fmt.Sprintf("%s://%s", scheme(r), r.Host)
	type view struct {
		*revocation.Responder
		URL string `json:"url"`
	}
	items := make([]view, 0, len(list))
	for _, x := range list {
		items = append(items, view{Responder: x, URL: base + "/ocsp/r/" + x.Path})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "total": len(items)})
}

func (s *Server) handleSaveOCSPResponder(w http.ResponseWriter, r *http.Request) {
	var req revocation.Responder
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	req.UUID = r.PathValue("uuid")
	if err := s.revocationSvc.SaveResponder(r.Context(), &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.auditAdmin(r, "save_ocsp_responder", "ocsp_responder", req.UUID, req.Name)
	writeJSON(w, http.StatusOK, req)
}

func (s *Server) handleDeleteOCSPResponder(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("uuid")
	if err := s.revocationSvc.DeleteResponder(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.auditAdmin(r, "delete_ocsp_responder", "ocsp_responder", id, "")
	writeJSON(w, http.StatusOK, map[string]string{"message": "已删除"})
}

// handleOCSPResponder 处理 /ocsp/r/{path}（POST DER 请求体，或 GET /ocsp/r/{path}/{base64}）。
func (s *Server) handleOCSPResponder(w http.ResponseWriter, r *http.Request) {
	resp, err := s.revocationSvc.GetResponderByPath(r.Context(), r.PathValue("path"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	var der []byte
	if r.Method == http.MethodPost {
		der, err = io.ReadAll(io.LimitReader(r.Body, 64<<10))
	} else {
		raw := r.PathValue("req")
		if raw == "" {
			raw = r.URL.Query().Get("req")
		}
		if u, e := url.PathUnescape(raw); e == nil {
			raw = u
		}
		der, err = base64.StdEncoding.DecodeString(raw)
		if err != nil {
			der, err = base64.URLEncoding.DecodeString(raw)
		}
	}
	if err != nil || len(der) == 0 {
		writeError(w, http.StatusBadRequest, "OCSP 请求格式错误")
		return
	}
	out, err := s.revocationSvc.Respond(r.Context(), resp, der)
	if err != nil {
		slog.Error("OCSP 响应签名失败", "responder", resp.Path, "error", err)
		writeError(w, http.StatusInternalServerError, "OCSP 响应签名失败")
		return
	}
	w.Header().Set("Content-Type", "application/ocsp-response")
	if r.Method == http.MethodGet {
		w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d, public", resp.NextUpdateMinutes*60/2))
	}
	w.Write(out) //nolint:errcheck
}

// ======================= 证书策略页面 =======================

func (s *Server) handleListCertPolicies(w http.ResponseWriter, r *http.Request) {
	list, err := s.cpsSvc.List(r.Context(), false, false)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": list, "total": len(list)})
}

func (s *Server) handleGetCertPolicy(w http.ResponseWriter, r *http.Request) {
	p, err := s.cpsSvc.Get(r.Context(), r.PathValue("uuid"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) handleSaveCertPolicy(w http.ResponseWriter, r *http.Request) {
	var p cps.Policy
	if err := json.NewDecoder(io.LimitReader(r.Body, 3<<20)).Decode(&p); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	p.UUID = r.PathValue("uuid")
	if err := s.cpsSvc.Save(r.Context(), &p); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.auditAdmin(r, "save_cert_policy", "cert_policy", p.UUID, p.Name)
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) handleDeleteCertPolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("uuid")
	if err := s.cpsSvc.Delete(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.auditAdmin(r, "delete_cert_policy", "cert_policy", id, "")
	writeJSON(w, http.StatusOK, map[string]string{"message": "已删除"})
}

// handlePublicPolicy GET /policy/{path}：按 Markdown 或 HTML 返回策略正文。
func (s *Server) handlePublicPolicy(w http.ResponseWriter, r *http.Request) {
	p, err := s.cpsSvc.GetByPath(r.Context(), r.PathValue("path"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Last-Modified", p.UpdatedAt.UTC().Format(http.TimeFormat))
	if p.ContentType == "html" {
		// 管理员编写的 HTML 在独立源下展示也禁止执行脚本
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src * data:")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	}
	io.WriteString(w, p.Content) //nolint:errcheck
}

// handlePortalPolicies GET /api/portal/policies：信任中心列出公开策略。
func (s *Server) handlePortalPolicies(w http.ResponseWriter, r *http.Request) {
	list, err := s.cpsSvc.List(r.Context(), true, false)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	base := fmt.Sprintf("%s://%s", scheme(r), r.Host)
	type view struct {
		Name        string    `json:"name"`
		Version     string    `json:"version"`
		ContentType string    `json:"content_type"`
		URL         string    `json:"url"`
		UpdatedAt   time.Time `json:"updated_at"`
	}
	items := make([]view, 0, len(list))
	for _, p := range list {
		items = append(items, view{p.Name, p.Version, p.ContentType, base + "/policy/" + p.Path, p.UpdatedAt})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items})
}

// ======================= 优惠码 =======================

func (s *Server) handleListCoupons(w http.ResponseWriter, r *http.Request) {
	list, err := s.promoSvc.ListCoupons(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": list, "total": len(list)})
}

func (s *Server) handleSaveCoupon(w http.ResponseWriter, r *http.Request) {
	var c promo.Coupon
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	c.UUID = r.PathValue("uuid")
	if err := s.promoSvc.SaveCoupon(r.Context(), &c); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.auditAdmin(r, "save_coupon", "coupon", c.UUID, c.Code)
	writeJSON(w, http.StatusOK, c)
}

func (s *Server) handleDeleteCoupon(w http.ResponseWriter, r *http.Request) {
	if err := s.promoSvc.DeleteCoupon(r.Context(), r.PathValue("uuid")); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "已删除"})
}

// handlePortalQuoteWithCoupon POST /api/portal/quotes/coupon {sku_code, quantity, coupon_code}
func (s *Server) handlePortalQuoteWithCoupon(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	var req struct {
		SKUCode    string `json:"sku_code"`
		Quantity   int    `json:"quantity"`
		CouponCode string `json:"coupon_code"`
		PlanCode   string `json:"plan_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if req.PlanCode != "" {
		p, err := s.promoSvc.GetPlan(r.Context(), req.PlanCode)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		out := map[string]interface{}{"total_cents": p.PriceCents, "discount_cents": 0, "payable_cents": p.PriceCents}
		if req.CouponCode != "" {
			if d, _, err := s.promoSvc.PreviewCoupon(r.Context(), req.CouponCode, claims.UserUUID, "plan:"+p.Code, p.PriceCents); err != nil {
				out["coupon_error"] = err.Error()
			} else {
				out["discount_cents"], out["payable_cents"] = d, p.PriceCents-d
			}
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	q, err := s.portalSvc.QuoteWithCoupon(r.Context(), req.SKUCode, req.Quantity, req.CouponCode, claims.UserUUID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, q)
}

// ======================= 订阅套餐 =======================

func (s *Server) handleListPlans(w http.ResponseWriter, r *http.Request) {
	list, err := s.promoSvc.ListPlans(r.Context(), false)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": list, "total": len(list)})
}

func (s *Server) handlePortalPlans(w http.ResponseWriter, r *http.Request) {
	list, err := s.promoSvc.ListPlans(r.Context(), true)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": list})
}

func (s *Server) handleSavePlan(w http.ResponseWriter, r *http.Request) {
	var p promo.Plan
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	p.UUID = r.PathValue("uuid")
	if err := s.promoSvc.SavePlan(r.Context(), &p); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.auditAdmin(r, "save_plan", "promo_plan", p.UUID, p.Code)
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) handleDeletePlan(w http.ResponseWriter, r *http.Request) {
	if err := s.promoSvc.DeletePlan(r.Context(), r.PathValue("uuid")); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "已删除"})
}

// handlePortalBuyPlan POST /api/portal/plans/{code}/orders：购买订阅套餐，返回待支付订单。
func (s *Server) handlePortalBuyPlan(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	var req struct {
		ApplicantEmail string `json:"applicant_email"`
		CouponCode     string `json:"coupon_code"`
	}
	json.NewDecoder(r.Body).Decode(&req) //nolint:errcheck
	if strings.TrimSpace(req.ApplicantEmail) == "" {
		req.ApplicantEmail = s.applicantEmailFromClaims(r)
	}
	order, err := s.portalSvc.CreatePlanOrder(r.Context(), claims.UserUUID, r.PathValue("code"), req.ApplicantEmail, req.CouponCode)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, order)
}

// ---- 订阅实例 ----

func (s *Server) handleMySubscriptions(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	s.promoSvc.ActivatePaidPlanOrders(r.Context(), claims.UserUUID)
	list, err := s.promoSvc.ListSubscriptions(r.Context(), claims.UserUUID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": list})
}

func (s *Server) handleAdminListSubscriptions(w http.ResponseWriter, r *http.Request) {
	list, err := s.promoSvc.ListSubscriptions(r.Context(), r.URL.Query().Get("user_uuid"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, sub := range list {
		if u, err := s.userRepo.GetByUUID(r.Context(), sub.UserUUID); err == nil {
			sub.Username = u.Username
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": list, "total": len(list)})
}

// handleAdminGrantSubscription POST /api/promo/subscriptions {username, plan_uuid}
func (s *Server) handleAdminGrantSubscription(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		PlanUUID string `json:"plan_uuid"`
		Remark   string `json:"remark"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	u, err := s.userRepo.GetByUsername(r.Context(), strings.TrimSpace(req.Username))
	if err != nil {
		writeError(w, http.StatusBadRequest, "用户不存在")
		return
	}
	ref := fmt.Sprintf("%d", time.Now().UnixNano())
	sub, err := s.promoSvc.Grant(r.Context(), u.UUID, req.PlanUUID, "admin", ref)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.auditAdmin(r, "grant_subscription", "subscription", sub.UUID, req.Username+" "+req.Remark)
	writeJSON(w, http.StatusCreated, sub)
}

func (s *Server) handleAdminCancelSubscription(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("uuid")
	if err := s.promoSvc.CancelSubscription(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.auditAdmin(r, "cancel_subscription", "subscription", id, "")
	writeJSON(w, http.StatusOK, map[string]string{"message": "订阅已终止"})
}

// ======================= 兑换码 =======================

func (s *Server) handleListRedeemCodes(w http.ResponseWriter, r *http.Request) {
	list, err := s.promoSvc.ListRedeemCodes(r.Context(), r.URL.Query().Get("batch"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": list, "total": len(list)})
}

func (s *Server) handleGenerateRedeemCodes(w http.ResponseWriter, r *http.Request) {
	var req struct {
		promo.RedeemCode
		Count int `json:"count"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	list, err := s.promoSvc.GenerateRedeemCodes(r.Context(), req.RedeemCode, req.Count)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.auditAdmin(r, "generate_redeem_codes", "redeem_code", req.BatchName, fmt.Sprintf("%d", len(list)))
	writeJSON(w, http.StatusCreated, map[string]interface{}{"items": list})
}

func (s *Server) handleSetRedeemEnabled(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	json.NewDecoder(r.Body).Decode(&req) //nolint:errcheck
	if err := s.promoSvc.SetRedeemEnabled(r.Context(), r.PathValue("uuid"), req.Enabled); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "已更新"})
}

// handleRedeem POST /api/portal/redeem {code}
func (s *Server) handleRedeem(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	var req struct {
		Code string `json:"code"`
	}
	json.NewDecoder(r.Body).Decode(&req) //nolint:errcheck
	res, err := s.promoSvc.Redeem(r.Context(), req.Code, claims.UserUUID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.logRepo.Create(r.Context(), &storage.Log{UserUUID: claims.UserUUID, Action: "redeem_code:" + res.GrantType, IPAddr: r.RemoteAddr}) //nolint:errcheck
	writeJSON(w, http.StatusOK, res)
}

// ======================= 用户自助吊销 =======================

// handleUserRevokeCert POST /api/my/certs/{uuid}/revoke {reason}
//
// 用户可吊销自己的证书；订阅套餐设置为不允许吊销时拒绝。
// 吊销后立即刷新 CRL 缓存，OCSP 实时查询吊销表。
func (s *Server) handleUserRevokeCert(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	var req RevokeCertRequest
	json.NewDecoder(r.Body).Decode(&req) //nolint:errcheck
	// 用户侧仅允许的吊销原因：未指定/密钥泄露/隶属变更/被替代/停止使用
	switch req.Reason {
	case 0, 1, 3, 4, 5:
	default:
		writeError(w, http.StatusBadRequest, "不支持的吊销原因")
		return
	}
	certRepo := storage.NewCertRepo(s.db)
	cert, err := certRepo.GetByUUID(r.Context(), r.PathValue("uuid"))
	if err != nil || cert.UserUUID != claims.UserUUID {
		writeError(w, http.StatusNotFound, "证书不存在")
		return
	}
	if cert.RevocationStatus == "revoked" {
		writeError(w, http.StatusBadRequest, "证书已被吊销")
		return
	}
	if cert.OrderNo != "" && s.promoSvc != nil {
		if order, err := s.workflowSvc.GetOrderByNo(r.Context(), cert.OrderNo); err == nil && order.SubscriptionUUID != "" {
			if p := s.promoSvc.PlanOfOrder(r.Context(), order.SubscriptionUUID); p != nil && !p.AllowRevoke {
				writeError(w, http.StatusForbidden, "该证书所属订阅套餐不允许自行吊销，请联系客服")
				return
			}
		}
	}
	if err := certRepo.Revoke(r.Context(), cert.UUID, req.Reason); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if cert.CAUUID != "" && cert.SerialNumber != "" {
		if err := s.caSvc.RevokeCert(r.Context(), cert.CAUUID, cert.SerialNumber, req.Reason); err != nil {
			slog.Warn("加入 CA 吊销列表失败", "cert_uuid", cert.UUID, "error", err)
		}
		if s.revocationSvc != nil {
			s.revocationSvc.RefreshCRL(r.Context(), cert.CAUUID) //nolint:errcheck
		}
	}
	s.logRepo.Create(r.Context(), &storage.Log{ //nolint:errcheck
		UserUUID: claims.UserUUID, CertUUID: cert.UUID, Action: "user_revoke_cert", IPAddr: r.RemoteAddr,
	})
	writeJSON(w, http.StatusOK, map[string]string{"message": "证书已吊销"})
}

// auditAdmin 记录管理操作审计日志。
func (s *Server) auditAdmin(r *http.Request, action, resType, resID, detail string) {
	claims := claimsFromCtx(r.Context())
	s.auditLogRepo.Create(r.Context(), &storage.AuditLog{ //nolint:errcheck
		UserUUID: claims.UserUUID, Action: action, ResourceType: resType, ResourceUUID: resID,
		Detail: fmt.Sprintf(`{"detail":%q}`, detail), IPAddress: r.RemoteAddr,
	})
}
