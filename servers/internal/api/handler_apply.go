// Package api - handler_apply.go：证书申请向导（选择订单 → 主体信息 → 扩展信息 → 确认提交）。
//
// 申请来源三选一：
//   - 已支付订单（销售模式）；
//   - 自助申请（自助模式，按开通模板直接申请，系统生成零金额订单）；
//   - 订阅额度（按套餐内的开通模板与剩余额度申请）。
//
// 资料要求由「开通模板」决定：主体模板（字段、验证方式、派生规则）、扩展信息模板（各类型验证策略）；
// 数量与格式限制由「商品规格」决定（SAN 限制，自助/订阅使用站点配置 self_san_policy）。
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/globaltrusts/server-card/internal/auth"
	"github.com/globaltrusts/server-card/internal/identity"
	"github.com/globaltrusts/server-card/internal/storage"
	"github.com/globaltrusts/server-card/internal/workflow"
)

// applySource 是解析后的申请来源。
type applySource struct {
	Kind         string                     `json:"kind"` // order / self / subscription
	Order        *storage.CertOrder         `json:"-"`
	OrderNo      string                     `json:"order_no,omitempty"`
	ProductName  string                     `json:"product_name"`
	Remaining    int                        `json:"remaining"`
	Template     *storage.CertApplyTemplate `json:"template"`
	SubjectTmpl  *storage.SubjectTemplate   `json:"-"`
	SubjectUUID  string                     `json:"subject_tmpl_uuid"`
	ExtTmplUUID  string                     `json:"extension_tmpl_uuid"`
	SANPolicy    identity.SANPolicy         `json:"san_policy"`
	DeliveryMode string                     `json:"delivery_mode"`
	KeyTypes     []string                   `json:"key_types"`
	ValidDays    int                        `json:"valid_days"`
	SubUUID      string                     `json:"subscription_uuid,omitempty"`
}

// selfSANPolicy 读取自助/订阅申请使用的 SAN 限制。
func (s *Server) selfSANPolicy(r *http.Request) identity.SANPolicy {
	raw := ""
	if s.portalSvc != nil {
		if settings, err := s.portalSvc.GetSiteSettings(r.Context()); err == nil {
			raw = settings["self_san_policy"]
		}
	}
	return identity.ParseSANPolicy(raw, 5)
}

// resolveApplySource 解析订单 / 自助模板 / 订阅，并载入模板要求。
func (s *Server) resolveApplySource(r *http.Request, claims *auth.Claims, orderNo, tmplUUID, subUUID string) (*applySource, int, error) {
	ctx := r.Context()
	src := &applySource{}

	switch {
	case strings.TrimSpace(orderNo) != "":
		order, err := s.workflowSvc.GetOrderByNo(ctx, strings.TrimSpace(orderNo))
		if err != nil || order.UserUUID != claims.UserUUID {
			return nil, http.StatusNotFound, fmt.Errorf("订单不存在")
		}
		if workflow.SpecKind(order.SpecJSON) != storage.OrderKindCert {
			return nil, http.StatusBadRequest, fmt.Errorf("该订单不是证书订单")
		}
		switch order.Status {
		case storage.CertOrderPaid, storage.CertOrderApplying, storage.CertOrderReviewing:
		default:
			return nil, http.StatusBadRequest, fmt.Errorf("订单当前状态不能提交申请（%s）", order.Status)
		}
		var used int
		s.db.QueryRowContext(ctx, //nolint:errcheck
			`SELECT COUNT(*) FROM cert_applications WHERE order_uuid = ? AND status <> 'rejected'`, order.UUID).Scan(&used)
		src.Kind, src.Order, src.OrderNo = "order", order, order.OrderNo
		src.Remaining = workflow.SpecQuantity(order.SpecJSON) - used
		if src.Remaining <= 0 {
			return nil, http.StatusBadRequest, fmt.Errorf("该订单的申请份数已全部提交")
		}
		tmplUUID = order.CertApplyTmplUUID
		raw, fallback := workflow.SpecSANPolicy(order.SpecJSON)
		if order.SKUCode == "" || order.SKUCode == "self-service" || order.SKUCode == "subscription" {
			src.SANPolicy = s.selfSANPolicy(r)
		} else {
			src.SANPolicy = identity.ParseSANPolicy(raw, fallback)
		}
		src.DeliveryMode = workflow.SpecDeliveryMode(order.SpecJSON)
		var spec struct {
			ProductName string   `json:"product_name"`
			KeyTypes    []string `json:"key_types"`
		}
		json.Unmarshal([]byte(order.SpecJSON), &spec) //nolint:errcheck
		src.ProductName, src.KeyTypes = spec.ProductName, spec.KeyTypes
		src.ValidDays = workflow.SpecValidDays(order.SpecJSON)
		src.SubUUID = order.SubscriptionUUID

	case strings.TrimSpace(subUUID) != "":
		if s.promoSvc == nil {
			return nil, http.StatusServiceUnavailable, fmt.Errorf("订阅功能未启用")
		}
		sub, err := s.promoSvc.GetSubscription(ctx, subUUID)
		if err != nil || sub.UserUUID != claims.UserUUID {
			return nil, http.StatusNotFound, fmt.Errorf("订阅不存在")
		}
		if !sub.Active(time.Now()) {
			return nil, http.StatusBadRequest, fmt.Errorf("订阅已过期或已终止")
		}
		found := false
		for _, it := range sub.Plan.Items {
			if it.CertApplyTmplUUID == tmplUUID {
				found, src.ValidDays = true, it.ValidDays
			}
		}
		if !found {
			return nil, http.StatusBadRequest, fmt.Errorf("订阅不包含该证书类型")
		}
		for _, u := range s.promoSvc.ListSubscriptionUsage(ctx, sub) {
			if u.CertApplyTmplUUID == tmplUUID {
				src.Remaining = u.Remaining
			}
		}
		if src.Remaining <= 0 {
			return nil, http.StatusBadRequest, fmt.Errorf("该证书类型的订阅额度已用完")
		}
		src.Kind, src.SubUUID, src.ProductName = "subscription", sub.UUID, "订阅："+sub.Plan.Name
		src.SANPolicy = s.selfSANPolicy(r)
		src.DeliveryMode = string(storage.DeliveryDownload)

	default:
		if s.businessModes(r).CertApplyMode != storage.ModeSelfService && !auth.IsAdmin(claims.Role) {
			return nil, http.StatusForbidden, fmt.Errorf("请先购买证书并完成支付后再提交申请")
		}
		if tmplUUID == "" {
			return nil, http.StatusBadRequest, fmt.Errorf("请选择要申请的证书类型")
		}
		src.Kind, src.Remaining = "self", 1
		src.SANPolicy = s.selfSANPolicy(r)
		src.DeliveryMode = string(storage.DeliveryDownload)
	}

	tmpl, err := s.workflowSvc.LoadApplyTemplate(ctx, tmplUUID)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	if !tmpl.Enabled {
		return nil, http.StatusBadRequest, fmt.Errorf("该证书类型暂不开放申请")
	}
	src.Template = tmpl
	if src.ProductName == "" {
		src.ProductName = tmpl.Name
	}
	if len(src.KeyTypes) == 0 {
		json.Unmarshal([]byte(tmpl.AllowedKeyTypes), &src.KeyTypes) //nolint:errcheck
	}

	// 资料模板：开通模板优先，未配置时沿用颁发模板上的关联
	src.SubjectUUID, src.ExtTmplUUID = tmpl.SubjectTmplUUID, tmpl.ExtensionTmplUUID
	if (src.SubjectUUID == "" || src.ExtTmplUUID == "") && tmpl.IssuanceTmplUUID != "" && s.issuanceSvc != nil {
		if it, err := s.issuanceSvc.GetIssuanceTemplate(ctx, tmpl.IssuanceTmplUUID); err == nil {
			if src.SubjectUUID == "" {
				src.SubjectUUID = it.SubjectTmplUUID
			}
			if src.ExtTmplUUID == "" {
				src.ExtTmplUUID = it.ExtensionTmplUUID
			}
		}
	}
	if src.SubjectUUID != "" {
		st, err := s.issuanceSvc.GetSubjectTemplate(ctx, src.SubjectUUID)
		if err != nil {
			return nil, http.StatusInternalServerError, fmt.Errorf("开通模板关联的主体模板不存在，请联系管理员")
		}
		src.SubjectTmpl = st
	}
	return src, http.StatusOK, nil
}

// handleApplyContext GET /api/portal/apply-context?order_no=&tmpl=&subscription=
// 返回申请向导需要的全部信息：来源、模板要求、SAN 限制、用户可用的主体/扩展信息与卡片。
func (s *Server) handleApplyContext(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	q := r.URL.Query()
	if s.promoSvc != nil {
		s.promoSvc.ActivatePaidPlanOrders(r.Context(), claims.UserUUID)
	}
	src, status, err := s.resolveApplySource(r, claims, q.Get("order_no"), q.Get("tmpl"), q.Get("subscription"))
	if err != nil {
		writeError(w, status, err.Error())
		return
	}
	ctx := r.Context()

	fields := []identity.SubjectField{}
	validity, subjectName := "", ""
	if src.SubjectTmpl != nil {
		fields, _ = identity.ParseSubjectFields(src.SubjectTmpl.Fields)
		validity, subjectName = src.SubjectTmpl.VerifyValidity, src.SubjectTmpl.Name
	}
	subjectInfos := []*storage.SubjectInfo{}
	if all, err := s.verifySvc.ListSubjectInfos(ctx, claims.UserUUID); err == nil {
		for _, i := range all {
			if src.SubjectUUID == "" || i.SubjectTmplUUID == src.SubjectUUID {
				subjectInfos = append(subjectInfos, i)
			}
		}
	}

	now := time.Now()
	type extView struct {
		*storage.ExtensionInfo
		Usable       bool   `json:"usable"`
		NeedReverify bool   `json:"need_reverify"` // 已验证，但验证强度低于当前证书要求
		PolicyError  string `json:"policy_error,omitempty"`
	}
	policy := s.verifySvc.ExtensionPolicy(ctx, src.ExtTmplUUID)
	exts := []extView{}
	if all, err := s.verifySvc.ListExtensionInfos(ctx, claims.UserUUID); err == nil {
		for _, i := range all {
			v := extView{ExtensionInfo: i, Usable: i.Usable(now)}
			if e := s.checkExtensionForApply(r, i, policy, src.SANPolicy); e != nil {
				v.PolicyError = e.Error()
				v.NeedReverify = v.Usable && strings.Contains(e.Error(), "重新验证")
				v.Usable = false
			}
			exts = append(exts, v)
		}
	}

	cards := []*storage.Card{}
	if list, err := s.cardSvc.ListCards(ctx, claims.UserUUID); err == nil {
		for _, c := range list {
			if !c.IsHosting() {
				cards = append(cards, c)
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"source": src,
		"subject": map[string]interface{}{
			"template_uuid": src.SubjectUUID,
			"template_name": subjectName,
			"fields":        fields,
			"needs_info":    identity.NeedsSubjectInfo(fields) || src.SubjectUUID == "",
			"required":      identity.NeedsSubjectInfo(fields),
			"verify_mode":   identity.SubjectVerifyMode(fields),
			"validity":      validity,
		},
		"extension":       map[string]interface{}{"template_uuid": src.ExtTmplUUID, "policy": policy},
		"subject_infos":   subjectInfos,
		"extension_infos": exts,
		"cards":           cards,
	})
}

// checkExtensionForApply 校验扩展信息是否满足当前证书的类型开关、验证强度与 SAN 格式限制。
func (s *Server) checkExtensionForApply(r *http.Request, info *storage.ExtensionInfo, policy identity.ExtensionPolicy, san identity.SANPolicy) error {
	tp := policy.For(info.InfoType)
	if !tp.Enabled {
		return fmt.Errorf("该证书不支持%s", map[string]string{"domain": "域名", "email": "邮箱", "ip": "IP 地址"}[info.InfoType])
	}
	if err := san.CheckValue(info.InfoType, info.Value); err != nil {
		return err
	}
	// 当前证书要求验证，而该信息是在"免验证"策略下通过的 → 必须按当前要求重新验证
	if tp.Mode != identity.VerifyNone && info.VerifyStatus == "verified" {
		if s.verifySvc.ExtensionPolicy(r.Context(), info.TmplUUID).For(info.InfoType).Mode == identity.VerifyNone {
			return fmt.Errorf("该证书要求验证所有权，请按当前证书要求重新验证")
		}
	}
	return nil
}

// submitApplicationRequest 是证书申请向导的提交体。
//
// 主体与 SAN 只能引用本人已审核/已验证且未过期的信息，不接受任意填写，
// 以保证证书内容与经过核验的身份、域名/邮箱所有权一致。
type submitApplicationRequest struct {
	OrderNo            string   `json:"order_no"`             // 销售模式：已支付订单号
	CertApplyTmplUUID  string   `json:"cert_apply_tmpl_uuid"` // 自助/订阅：证书类型
	SubscriptionUUID   string   `json:"subscription_uuid"`    // 订阅：使用的订阅
	SubjectInfoUUID    string   `json:"subject_info_uuid"`
	ExtensionInfoUUIDs []string `json:"extension_info_uuids"`
	KeyType            string   `json:"key_type"`
	CSRPEM             string   `json:"csr_pem"`   // 自带 CSR（可选，私钥不进入服务端）
	CardUUID           string   `json:"card_uuid"` // 签发到的智能卡（可选）
}

// handlePortalSubmitApplication POST /api/portal/applications
func (s *Server) handlePortalSubmitApplication(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	var req submitApplicationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	app, autoIssued, issueErr, status, err := s.submitApplication(r, claims, &req)
	if err != nil {
		writeError(w, status, err.Error())
		return
	}
	msg := "申请已提交，证书审核中"
	switch {
	case autoIssued:
		msg = "证书已签发"
	case issueErr != nil:
		msg = "申请已提交，自动签发暂未完成，已转人工处理"
	}
	resp := map[string]interface{}{"application": app, "auto_issued": autoIssued, "message": msg}
	if issueErr != nil {
		resp["issue_error"] = issueErr.Error()
	}
	writeJSON(w, http.StatusCreated, resp)
}

// submitApplication 按来源与模板要求校验主体、SAN、目标卡，然后提交申请。
func (s *Server) submitApplication(r *http.Request, claims *auth.Claims, req *submitApplicationRequest) (
	app *storage.CertApplication, autoIssued bool, issueErr error, status int, err error,
) {
	ctx := r.Context()
	now := time.Now()
	email := s.applicantEmailFromClaims(r)
	bad := func(format string, a ...interface{}) (*storage.CertApplication, bool, error, int, error) {
		return nil, false, nil, http.StatusBadRequest, fmt.Errorf(format, a...)
	}

	src, st, err := s.resolveApplySource(r, claims, req.OrderNo, req.CertApplyTmplUUID, req.SubscriptionUUID)
	if err != nil {
		return nil, false, nil, st, err
	}

	// 1) 主体信息
	fields := []identity.SubjectField{}
	if src.SubjectTmpl != nil {
		if fields, err = identity.ParseSubjectFields(src.SubjectTmpl.Fields); err != nil {
			return nil, false, nil, http.StatusInternalServerError, err
		}
	}
	subject := map[string]string{}
	if req.SubjectInfoUUID != "" {
		info, e := s.verifySvc.GetSubjectInfo(ctx, req.SubjectInfoUUID)
		if e != nil || info.UserUUID != claims.UserUUID {
			return bad("主体信息不存在")
		}
		if src.SubjectUUID != "" && info.SubjectTmplUUID != src.SubjectUUID {
			return bad("所选主体信息不适用于该证书类型，请按要求重新填写")
		}
		if !info.SubjectUsable(now) {
			if info.Status == "approved" {
				return bad("所选主体信息的审核已过期，请重新提交验证")
			}
			return bad("所选主体信息尚未审核通过")
		}
		json.Unmarshal([]byte(info.FieldValues), &subject) //nolint:errcheck
	} else if identity.NeedsSubjectInfo(fields) {
		return bad("请选择或填写已审核通过的主体信息")
	}

	// 2) 扩展信息（SAN）
	policy := s.verifySvc.ExtensionPolicy(ctx, src.ExtTmplUUID)
	san := map[string][]string{}
	verified := map[string]bool{}
	seen := map[string]bool{}
	for _, id := range req.ExtensionInfoUUIDs {
		if seen[id] {
			continue
		}
		seen[id] = true
		info, e := s.verifySvc.GetExtensionInfo(ctx, id)
		if e != nil || info.UserUUID != claims.UserUUID {
			return bad("扩展信息不存在")
		}
		if !info.Usable(now) {
			return bad("%s 尚未通过验证或验证已过期", info.Value)
		}
		if e := s.checkExtensionForApply(r, info, policy, src.SANPolicy); e != nil {
			return bad("%s：%v", info.Value, e)
		}
		key := map[string]string{"domain": "dns", "email": "email", "ip": "ip"}[info.InfoType]
		san[key] = append(san[key], info.Value)
		verified[strings.ToLower(info.Value)] = true
	}
	if err := src.SANPolicy.Check(san); err != nil {
		return bad("%v", err)
	}

	// 3) 派生主体字段；无主体模板时以第一个已验证名称作为 CN（DV 场景）
	if err := identity.ApplyDerivedFields(fields, subject, san); err != nil {
		return bad("%v", err)
	}
	if subject["CN"] == "" && subject["commonName"] == "" {
		for _, k := range []string{"dns", "email", "ip"} {
			if len(san[k]) > 0 {
				subject["CN"] = san[k][0]
				break
			}
		}
	}
	if subject["CN"] == "" && subject["commonName"] == "" && strings.TrimSpace(req.CSRPEM) == "" {
		return bad("证书缺少通用名称（CN）：请填写主体信息或添加已验证的域名/邮箱")
	}

	// 4) 自带 CSR：CSR 中的名称必须全部在本次申请中通过验证
	if strings.TrimSpace(req.CSRPEM) != "" {
		names, e := csrNames(req.CSRPEM)
		if e != nil {
			return bad("%v", e)
		}
		for _, n := range names {
			if !verified[strings.ToLower(n)] && subject["CN"] != n {
				return bad("CSR 中的 %s 未在本次申请中通过所有权验证", n)
			}
		}
	}

	// 5) 密钥算法
	if req.KeyType != "" && len(src.KeyTypes) > 0 {
		ok := false
		for _, k := range src.KeyTypes {
			if k == req.KeyType {
				ok = true
			}
		}
		if !ok {
			return bad("该证书不支持密钥算法 %s", req.KeyType)
		}
	}

	// 6) 目标卡：云端使用型规格必须签入用户智能卡
	cardUUID := strings.TrimSpace(req.CardUUID)
	if storage.DeliveryMode(src.DeliveryMode) == storage.DeliveryCloudCard {
		if req.CSRPEM != "" {
			return bad("云端使用型证书由云端生成密钥，不能使用自带 CSR")
		}
		if cardUUID == "" {
			userCards := []*storage.Card{}
			if cards, e := s.cardSvc.ListCards(ctx, claims.UserUUID); e == nil {
				for _, c := range cards {
					if !c.IsHosting() {
						userCards = append(userCards, c)
					}
				}
			}
			switch len(userCards) {
			case 0:
				return bad("该证书需签发到云端智能卡，请先开通智能卡")
			case 1:
				cardUUID = userCards[0].UUID
			default:
				return bad("请选择证书要签发到的智能卡")
			}
		}
	}
	if cardUUID != "" {
		c, e := s.cardSvc.GetCard(ctx, cardUUID, claims.UserUUID)
		if e != nil {
			return bad("目标智能卡不存在")
		}
		if c.IsHosting() {
			cardUUID = ""
		}
	}

	// 7) 订单：校验全部通过后才为自助/订阅生成订单，避免产生无效订单
	order := src.Order
	switch src.Kind {
	case "self":
		if order, err = s.workflowSvc.CreateSelfServiceOrder(ctx, claims.UserUUID, src.Template.UUID, email); err != nil {
			return bad("%v", err)
		}
	case "subscription":
		item, unlock, e := s.promoSvc.ReserveQuota(ctx, src.SubUUID, claims.UserUUID, src.Template.UUID)
		if e != nil {
			return bad("%v", e)
		}
		defer unlock()
		policyJSON, _ := json.Marshal(src.SANPolicy)
		if order, err = s.workflowSvc.CreateSubscriptionOrder(ctx, claims.UserUUID, src.SubUUID, src.Template.UUID,
			email, item.ValidDays, string(policyJSON)); err != nil {
			return bad("%v", err)
		}
	}

	subjectJSON, _ := json.Marshal(subject)
	sanJSON, _ := json.Marshal(san)
	app = &storage.CertApplication{
		OrderUUID: order.UUID, UserUUID: claims.UserUUID, SubjectJSON: string(subjectJSON), SANJSON: string(sanJSON),
		KeyType: req.KeyType, CSRPEM: req.CSRPEM, ApplicantEmail: email, CardUUID: cardUUID,
	}
	autoIssued, issueErr, err = s.workflowSvc.SubmitApplication(ctx, app)
	if err != nil {
		if src.Kind != "order" {
			// 自助/订阅订单仅为本次申请生成，申请失败时一并作废
			s.db.ExecContext(ctx, `UPDATE cert_orders SET status = 'cancelled', updated_at = ? WHERE uuid = ?`, now, order.UUID) //nolint:errcheck
		}
		return bad("%v", err)
	}

	s.logRepo.Create(ctx, &storage.Log{ //nolint:errcheck
		UserUUID: claims.UserUUID,
		Action:   fmt.Sprintf("submit_cert_application:%s:%s", order.OrderNo, app.UUID),
		IPAddr:   r.RemoteAddr,
	})
	return app, autoIssued, issueErr, http.StatusCreated, nil
}
