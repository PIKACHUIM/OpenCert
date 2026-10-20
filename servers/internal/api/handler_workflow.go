package api

import (
	"encoding/json"
	"net/http"

	"github.com/globaltrusts/server-card/internal/auth"
	"github.com/globaltrusts/server-card/internal/storage"
)

// ---- 证书订单与申请处理器 ----

// createCertOrderRequest 是控制台创建证书订单的请求体。
//
// 只接受"选择什么"的字段：金额、状态、订单号、商品快照一律由服务端生成或回填，
// 避免客户端构造已支付订单或篡改价格。
type createCertOrderRequest struct {
	CertApplyTmplUUID string `json:"cert_apply_tmpl_uuid"`
	TemplateUUID      string `json:"template_uuid"` // 兼容旧前端字段名
	ApplicantEmail    string `json:"applicant_email"`
}

func (s *Server) handleCreateCertOrder(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())

	var req createCertOrderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}

	applyTmpl := req.CertApplyTmplUUID
	if applyTmpl == "" {
		applyTmpl = req.TemplateUUID
	}

	// 颁发模板与密钥存储模板都由所选开通模板继承，不接受客户端指定
	// （否则可以通过构造请求绕过模板允许的算法、有效期与交付方式）。
	order := &storage.CertOrder{
		UserUUID:          claims.UserUUID,
		CertApplyTmplUUID: applyTmpl,
		ApplicantEmail:    req.ApplicantEmail,
	}
	if order.ApplicantEmail == "" {
		order.ApplicantEmail = s.applicantEmailFromClaims(r)
	}

	if err := s.workflowSvc.CreateOrder(r.Context(), order); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, order)
}

func (s *Server) handleListCertOrders(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	page, pageSize := parsePagination(r)
	orders, total, err := s.workflowSvc.ListOrders(r.Context(), claims.UserUUID, page, pageSize)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": orders, "orders": orders, "total": total, "page": page})
}

func (s *Server) handleGetCertOrder(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	orderUUID := r.PathValue("uuid")
	order, err := s.workflowSvc.GetOrder(r.Context(), orderUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	// 非管理员只能查看自己的订单
	if order.UserUUID != claims.UserUUID && !auth.IsAdmin(claims.Role) {
		writeError(w, http.StatusForbidden, "无权查看此订单")
		return
	}
	writeJSON(w, http.StatusOK, order)
}

// handlePayCertOrder 兼容旧接口：改为真实的余额扣款支付。
// 历史实现只改状态不扣款，任何登录用户都能"免费支付"，已修复。
func (s *Server) handlePayCertOrder(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	if err := s.payCertOrderWithBalance(r, claims.UserUUID, r.PathValue("uuid")); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "订单已使用余额支付"})
}

// handleCancelCertOrder 兼容旧接口：仅可取消待支付订单，并归还库存。
func (s *Server) handleCancelCertOrder(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	order, err := s.workflowSvc.GetOrder(r.Context(), r.PathValue("uuid"))
	if err != nil || order.UserUUID != claims.UserUUID {
		writeError(w, http.StatusNotFound, "订单不存在")
		return
	}
	if order.OrderNo != "" && s.portalSvc != nil {
		err = s.portalSvc.CancelOrder(r.Context(), order.OrderNo, claims.UserUUID)
	} else {
		err = s.workflowSvc.CancelOrder(r.Context(), order.UUID, claims.UserUUID)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "订单已取消"})
}

// handleCreateCertApplication 兼容旧接口：统一走申请向导的校验逻辑。
// 旧前端提交 subject_info_uuid / extension_info_uuids / order_uuid，这里一并映射。
func (s *Server) handleCreateCertApplication(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	var body struct {
		submitApplicationRequest
		OrderUUID string `json:"order_uuid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	req := body.submitApplicationRequest
	if req.OrderNo == "" && body.OrderUUID != "" {
		order, err := s.workflowSvc.GetOrder(r.Context(), body.OrderUUID)
		if err != nil || order.UserUUID != claims.UserUUID {
			writeError(w, http.StatusNotFound, "订单不存在")
			return
		}
		req.OrderNo = order.OrderNo
		if req.OrderNo == "" {
			writeError(w, http.StatusBadRequest, "历史订单缺少对外单号，请重新下单")
			return
		}
	}
	app, autoIssued, issueErr, status, err := s.submitApplication(r, claims, &req)
	if err != nil {
		writeError(w, status, err.Error())
		return
	}
	resp := map[string]interface{}{"application": app, "auto_issued": autoIssued}
	if issueErr != nil {
		resp["issue_error"] = issueErr.Error()
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) handleListCertApplications(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	userUUID := claims.UserUUID
	if auth.IsOperatorOrAbove(claims.Role) {
		userUUID = "" // 管理员/操作员查看所有申请
	}
	statusFilter := r.URL.Query().Get("status")
	page, pageSize := parsePagination(r)
	apps, total, err := s.workflowSvc.ListApplications(r.Context(), userUUID, statusFilter, page, pageSize)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": apps, "applications": apps, "total": total, "page": page})
}

func (s *Server) handleApproveCertApplication(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	appUUID := r.PathValue("uuid")
	if err := s.workflowSvc.ApproveApplication(r.Context(), appUUID, claims.UserUUID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "证书申请已审批通过"})
}

func (s *Server) handleRejectCertApplication(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	appUUID := r.PathValue("uuid")
	var req struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if err := s.workflowSvc.RejectApplication(r.Context(), appUUID, claims.UserUUID, req.Reason); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "证书申请已拒绝"})
}
