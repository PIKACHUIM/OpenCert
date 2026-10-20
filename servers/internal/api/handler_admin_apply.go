// Package api - handler_admin_apply.go：管理员代用户提交证书申请。
//
// 与用户自助申请共用同一套解析与校验（resolveApplySource / submitApplication），
// 差别只在第一步多了"选择用户"，并且可以由管理员直接录入资料、跳过审批。
package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/globaltrusts/server-card/internal/storage"
)

// adminApplyContext 是代办申请的上下文：目标用户可用的来源与资料。
type adminApplyContext struct {
	User struct {
		UUID     string `json:"uuid"`
		Username string `json:"username"`
		Email    string `json:"email"`
	} `json:"user"`
	Orders []map[string]interface{} `json:"orders"`
	// Templates 是可代办的证书类型（按可申请方式过滤）
	Templates []map[string]interface{} `json:"templates"`
	// Subscriptions 是该用户生效中的订阅
	Subscriptions []map[string]interface{} `json:"subscriptions"`
	// SubjectInfos / ExtensionInfos 是可直接复用的已通过资料
	SubjectInfos   []*storage.SubjectInfo   `json:"subject_infos"`
	ExtensionInfos []*storage.ExtensionInfo `json:"extension_infos"`
	Cards          []map[string]interface{} `json:"cards"`
}

// handleAdminApplyContext GET /api/admin/apply-context?user_uuid=
// 返回代办申请需要的信息：目标用户的订单、可用证书类型、订阅、已通过的主体与扩展信息。
func (s *Server) handleAdminApplyContext(w http.ResponseWriter, r *http.Request) {
	userUUID := strings.TrimSpace(r.URL.Query().Get("user_uuid"))
	if userUUID == "" {
		writeError(w, http.StatusBadRequest, "请选择要代办的客户")
		return
	}

	out := &adminApplyContext{}
	if err := s.db.QueryRowContext(r.Context(),
		`SELECT uuid, username, COALESCE(email, '') FROM users WHERE uuid = ?`, userUUID,
	).Scan(&out.User.UUID, &out.User.Username, &out.User.Email); err != nil {
		writeError(w, http.StatusNotFound, "客户不存在")
		return
	}

	// 该用户可用于提交申请的证书订单（已支付/申请中/审核中）
	out.Orders = []map[string]interface{}{}
	rows, err := s.db.QueryContext(r.Context(),
		`SELECT o.order_no, o.cert_apply_tmpl_uuid, COALESCE(t.name, ''), o.status, o.spec_json, o.created_at
		 FROM cert_orders o
		 LEFT JOIN cert_apply_templates t ON t.uuid = o.cert_apply_tmpl_uuid
		 WHERE o.user_uuid = ? AND o.status IN ('paid', 'applying', 'reviewing')
		 ORDER BY o.created_at DESC LIMIT 100`, userUUID)
	if err == nil {
		for rows.Next() {
			var orderNo, tmplUUID, tmplName, status, spec string
			var createdAt interface{}
			if rows.Scan(&orderNo, &tmplUUID, &tmplName, &status, &spec, &createdAt) != nil {
				continue
			}
			out.Orders = append(out.Orders, map[string]interface{}{
				"order_no": orderNo, "cert_apply_tmpl_uuid": tmplUUID,
				"template_name": tmplName, "status": status,
			})
		}
		rows.Close()
	}

	// 可代办的证书类型：启用且允许该申请方式（订单 / 自助 / 订阅）
	out.Templates = []map[string]interface{}{}
	trows, err := s.db.QueryContext(r.Context(),
		`SELECT uuid, name, COALESCE(description, ''), COALESCE(apply_modes, ''),
		        require_approval, issuance_tmpl_uuid
		 FROM cert_apply_templates WHERE enabled = 1 ORDER BY created_at DESC`)
	if err == nil {
		for trows.Next() {
			var uuid, name, desc, modes, issuanceUUID string
			var requireApproval int
			if trows.Scan(&uuid, &name, &desc, &modes, &requireApproval, &issuanceUUID) != nil {
				continue
			}
			modeList := parseJSONStringArrayLocal(modes)
			if len(modeList) == 0 {
				modeList = []string{"order", "self", "subscription"}
			}
			out.Templates = append(out.Templates, map[string]interface{}{
				"uuid": uuid, "name": name, "description": desc,
				"apply_modes": modeList, "require_approval": requireApproval == 1,
				"issuance_tmpl_uuid": issuanceUUID,
			})
		}
		trows.Close()
	}

	// 订阅额度
	now := time.Now()
	out.Subscriptions = []map[string]interface{}{}
	if s.promoSvc != nil {
		if subs, err := s.promoSvc.ListSubscriptions(r.Context(), userUUID); err == nil {
			for _, sub := range subs {
				out.Subscriptions = append(out.Subscriptions, map[string]interface{}{
					"uuid": sub.UUID, "plan_name": sub.Plan.Name,
					"active": sub.Active(now),
				})
			}
		}
	}

	// 已通过的资料与智能卡：管理员可直接选用，不必让用户重新提交
	if infos, err := s.verifySvc.ListSubjectInfos(r.Context(), userUUID); err == nil {
		for _, i := range infos {
			if i.SubjectUsable(now) {
				out.SubjectInfos = append(out.SubjectInfos, i)
			}
		}
	}
	if infos, err := s.verifySvc.ListExtensionInfos(r.Context(), userUUID); err == nil {
		for _, i := range infos {
			if i.Usable(now) {
				out.ExtensionInfos = append(out.ExtensionInfos, i)
			}
		}
	}
	out.Cards = []map[string]interface{}{}
	if s.cardSvc != nil {
		if cards, err := s.cardSvc.ListCards(r.Context(), userUUID); err == nil {
			for _, c := range cards {
				if c.IsHosting() {
					continue
				}
				out.Cards = append(out.Cards, map[string]interface{}{
					"uuid": c.UUID, "card_name": c.CardName, "card_kind": c.Kind,
				})
			}
		}
	}

	writeJSON(w, http.StatusOK, out)
}

// adminApplyRequest 是代办申请请求体。
//
// 来源三选一（与用户侧一致）：order_no / cert_apply_tmpl_uuid / subscription_uuid。
// 资料两种方式：引用该用户已有资料（*_uuid），或由管理员直接录入（subject / extensions）。
type adminApplyRequest struct {
	UserUUID           string             `json:"user_uuid"`
	OrderNo            string             `json:"order_no"`
	CertApplyTmplUUID  string             `json:"cert_apply_tmpl_uuid"`
	SubscriptionUUID   string             `json:"subscription_uuid"`
	SubjectInfoUUID    string             `json:"subject_info_uuid"`
	Subject            map[string]string  `json:"subject"`
	ExtensionInfoUUIDs []string           `json:"extension_info_uuids"`
	Extensions         []adminExtensionIn `json:"extensions"`
	KeyType            string             `json:"key_type"`
	CSRPEM             string             `json:"csr_pem"`
	CardUUID           string             `json:"card_uuid"`
	SkipApproval       bool               `json:"skip_approval"`
}

// adminExtensionIn 是管理员录入的一条扩展信息。
type adminExtensionIn struct {
	InfoType string `json:"info_type"` // domain / email / ip
	Value    string `json:"value"`
}

// handleAdminCreateApplication POST /api/admin/cert-applications
//
// 管理员代用户提交证书申请：可引用已有资料、可现场录入并直接核定、可跳过审批直接签发。
// 代办人与所属用户分别记录，便于审计追溯。
func (s *Server) handleAdminCreateApplication(w http.ResponseWriter, r *http.Request) {
	operator := claimsFromCtx(r.Context())
	if operator == nil || strings.TrimSpace(operator.UserUUID) == "" {
		// 路由已要求登录，这里防御性兜底：缺少身份时不能继续，避免解引用空指针 panic
		writeError(w, http.StatusUnauthorized, "请先登录")
		return
	}
	var req adminApplyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	userUUID := strings.TrimSpace(req.UserUUID)
	if userUUID == "" {
		writeError(w, http.StatusBadRequest, "请选择要代办的客户")
		return
	}
	var exists int
	if err := s.db.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM users WHERE uuid = ?`, userUUID).Scan(&exists); err != nil || exists == 0 {
		writeError(w, http.StatusNotFound, "客户不存在")
		return
	}

	// 以目标用户身份执行申请（资料归属、卡片归属、额度都按该用户校验），
	// 权限判断仍使用操作人身份，因此 operator 及以上即可代办。
	targetClaims := *operator
	targetClaims.UserUUID = userUUID

	src, st, err := s.resolveApplySource(r, &targetClaims, req.OrderNo, req.CertApplyTmplUUID, req.SubscriptionUUID)
	if err != nil {
		writeError(w, st, err.Error())
		return
	}

	// 管理员录入的主体信息：按该证书类型的主体模板创建并直接审核通过
	subjectInfoUUID := strings.TrimSpace(req.SubjectInfoUUID)
	if subjectInfoUUID == "" && len(req.Subject) > 0 {
		if src.SubjectUUID == "" {
			writeError(w, http.StatusBadRequest, "该证书类型未配置主体模板，无法录入主体信息")
			return
		}
		raw, _ := json.Marshal(req.Subject)
		info := &storage.SubjectInfo{
			UserUUID: userUUID, SubjectTmplUUID: src.SubjectUUID, FieldValues: string(raw),
		}
		if err := s.verifySvc.AdminCreateSubjectInfo(r.Context(), info, true, operator.UserUUID); err != nil {
			writeError(w, http.StatusBadRequest, "录入主体信息失败: "+err.Error())
			return
		}
		subjectInfoUUID = info.UUID
	}

	// 管理员录入的扩展信息：同样直接标记为已验证
	extUUIDs := append([]string(nil), req.ExtensionInfoUUIDs...)
	for _, e := range req.Extensions {
		if strings.TrimSpace(e.Value) == "" {
			continue
		}
		info := &storage.ExtensionInfo{
			UserUUID: userUUID, TmplUUID: src.ExtTmplUUID,
			InfoType: strings.ToLower(strings.TrimSpace(e.InfoType)), Value: strings.TrimSpace(e.Value),
		}
		if err := s.verifySvc.AdminCreateExtensionInfo(r.Context(), info, true); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("录入 %s 失败: %v", e.Value, err))
			return
		}
		extUUIDs = append(extUUIDs, info.UUID)
	}

	// 代办订单：来源是"直接按模板申请"时生成零金额订单，标记 admin-proxy
	if src.Kind == "self" {
		order, err := s.workflowSvc.CreateProxyOrder(r.Context(), userUUID, src.Template.UUID,
			s.adminUserEmail(r, userUUID))
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		src.Order = order
		src.OrderNo = order.OrderNo
	}

	sub := &submitApplicationRequest{
		ApplicantEmail:     s.adminUserEmail(r, userUUID),
		ViaAdmin:           true,
		OrderNo:            req.OrderNo,
		CertApplyTmplUUID:  req.CertApplyTmplUUID,
		SubscriptionUUID:   req.SubscriptionUUID,
		SubjectInfoUUID:    subjectInfoUUID,
		ExtensionInfoUUIDs: extUUIDs,
		KeyType:            req.KeyType,
		CSRPEM:             req.CSRPEM,
		CardUUID:           req.CardUUID,
	}
	// 自助来源已生成订单，改用订单号提交，避免重复生成
	if src.Kind == "self" && src.Order != nil {
		sub.OrderNo = src.Order.OrderNo
		sub.CertApplyTmplUUID = ""
	}

	app, autoIssued, issueErr, status, err := s.submitApplication(r, &targetClaims, sub)
	if err != nil {
		writeError(w, status, err.Error())
		return
	}

	// 记录代办人与代办标记：申请已经落库（甚至已签发），此处失败不能返回 500，
	// 否则操作人重试会产生重复申请。只记录告警，代办信息由审计日志兜底。
	if err := s.workflowSvc.MarkApplicationProxy(r.Context(), app.UUID, operator.UserUUID); err != nil {
		slog.Warn("记录代办信息失败", "application", app.UUID, "operator", operator.UserUUID, "error", err)
	}

	msg := "申请已提交，等待审核"
	if autoIssued {
		msg = "证书已签发"
	} else if req.SkipApproval {
		if err := s.workflowSvc.ApproveApplication(r.Context(), app.UUID, operator.UserUUID); err != nil {
			msg = "申请已提交，但跳过审批签发失败：" + err.Error()
		} else {
			msg = "审核已通过，证书已签发"
			autoIssued = true
		}
	}

	s.auditLogRepo.Create(r.Context(), &storage.AuditLog{ //nolint:errcheck
		UserUUID:     operator.UserUUID,
		Action:       "cert_application.proxy_submit",
		ResourceType: "cert_application",
		ResourceUUID: app.UUID,
		Detail: fmt.Sprintf(`{"target_user":%q,"order_no":%q,"skip_approval":%t}`,
			userUUID, app.OrderUUID, req.SkipApproval),
		IPAddress: r.RemoteAddr,
	})

	resp := map[string]interface{}{"application": app, "auto_issued": autoIssued, "message": msg}
	if issueErr != nil {
		resp["issue_error"] = issueErr.Error()
	}
	writeJSON(w, http.StatusCreated, resp)
}

// adminUserEmail 返回目标用户的邮箱（用于申请人联系邮箱；取不到时为空）。
func (s *Server) adminUserEmail(r *http.Request, userUUID string) string {
	var email string
	s.db.QueryRowContext(r.Context(), `SELECT COALESCE(email, '') FROM users WHERE uuid = ?`, userUUID).Scan(&email) //nolint:errcheck
	return strings.TrimSpace(email)
}
