// Package api - handler_business.go：业务模式（自助/销售）、统一申请入口与订单运营。
//
// 业务模式由站点配置决定：
//   - card_apply_mode = self  用户可直接开卡（受 card_self_limit 限制）
//   - card_apply_mode = sales 用户必须凭已支付的「云智能卡」订单开卡
//   - cert_apply_mode = self  用户可直接选择证书申请模板提交申请（系统生成零金额订单）
//   - cert_apply_mode = sales 用户必须凭已支付的证书订单提交申请
//
// 管理员（admin/super_admin）不受业务模式限制，便于运维代办。
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/globaltrusts/server-card/internal/auth"
	"github.com/globaltrusts/server-card/internal/payment"
	"github.com/globaltrusts/server-card/internal/portal"
	"github.com/globaltrusts/server-card/internal/storage"
	"github.com/globaltrusts/server-card/internal/workflow"
)

// businessModes 读取当前业务模式；门户服务未装配时按最严格的销售模式处理。
func (s *Server) businessModes(r *http.Request) portal.BusinessModes {
	if s.portalSvc == nil {
		return portal.BusinessModes{CertApplyMode: storage.ModeSales, CardApplyMode: storage.ModeSales}
	}
	return s.portalSvc.GetBusinessModes(r.Context())
}

// orderQuota 是一笔订单的可履约额度。
type orderQuota struct {
	OrderNo      string   `json:"order_no"`
	ProductName  string   `json:"product_name"`
	SKUName      string   `json:"sku_name"`
	Quantity     int      `json:"quantity"`
	Used         int      `json:"used"`
	Remaining    int      `json:"remaining"`
	DeliveryMode string   `json:"delivery_mode,omitempty"`
	KeyTypes     []string `json:"key_types,omitempty"`
	Status       string   `json:"status"`
}

// listOrderQuotas 列出用户可履约的订单额度（kind=card 开卡，kind=cert 申请证书）。
func (s *Server) listOrderQuotas(r *http.Request, userUUID, kind string) ([]orderQuota, error) {
	rows, err := s.db.QueryContext(r.Context(),
		`SELECT uuid, order_no, spec_json, status FROM cert_orders
		 WHERE user_uuid = ? AND status IN ('paid', 'applying', 'reviewing', 'issuing') AND order_no <> ''
		 ORDER BY created_at DESC`, userUUID)
	if err != nil {
		return nil, err
	}
	type row struct{ uuid, no, spec, status string }
	var list []row
	for rows.Next() {
		var x row
		if err := rows.Scan(&x.uuid, &x.no, &x.spec, &x.status); err != nil {
			rows.Close()
			return nil, err
		}
		list = append(list, x)
	}
	rows.Close()

	quotas := []orderQuota{}
	for _, x := range list {
		if workflow.SpecKind(x.spec) != kind {
			continue
		}
		var spec struct {
			ProductName  string   `json:"product_name"`
			SKUName      string   `json:"sku_name"`
			DeliveryMode string   `json:"delivery_mode"`
			KeyTypes     []string `json:"key_types"`
		}
		json.Unmarshal([]byte(x.spec), &spec) //nolint:errcheck

		qty := workflow.SpecQuantity(x.spec)
		var used int
		if kind == storage.OrderKindCard {
			s.db.QueryRowContext(r.Context(), //nolint:errcheck
				`SELECT COUNT(*) FROM cards WHERE order_no = ?`, x.no).Scan(&used)
		} else {
			s.db.QueryRowContext(r.Context(), //nolint:errcheck
				`SELECT COUNT(*) FROM cert_applications WHERE order_uuid = ? AND status <> 'rejected'`, x.uuid).Scan(&used)
		}
		if used >= qty {
			continue
		}
		quotas = append(quotas, orderQuota{
			OrderNo: x.no, ProductName: spec.ProductName, SKUName: spec.SKUName,
			Quantity: qty, Used: used, Remaining: qty - used,
			DeliveryMode: spec.DeliveryMode, KeyTypes: spec.KeyTypes, Status: x.status,
		})
	}
	return quotas, nil
}

// authorizeCardCreation 按业务模式校验开卡权限，返回需要绑定的订单号（自助模式为空）。
func (s *Server) authorizeCardCreation(r *http.Request, claims *auth.Claims, orderNo string) (string, error) {
	if auth.IsAdmin(claims.Role) {
		return "", nil
	}
	modes := s.businessModes(r)
	repo := storage.NewCardRepo(s.db)

	if modes.CardApplyMode == storage.ModeSelfService && strings.TrimSpace(orderNo) == "" {
		n, err := repo.CountUserCards(r.Context(), claims.UserUUID)
		if err != nil {
			return "", fmt.Errorf("查询卡片数量失败")
		}
		if n >= modes.CardSelfLimit {
			return "", fmt.Errorf("已达到可自助开通的智能卡数量上限（%d 张），如需更多请购买", modes.CardSelfLimit)
		}
		return "", nil
	}

	// 销售模式（或自助模式下主动使用订单）：必须是本人的、已支付的智能卡订单且仍有余量
	orderNo = strings.TrimSpace(orderNo)
	if orderNo == "" {
		return "", fmt.Errorf("当前需要购买云端智能卡后才能开通，请先在产品中心选购")
	}
	order, err := s.workflowSvc.GetOrderByNo(r.Context(), orderNo)
	if err != nil || order.UserUUID != claims.UserUUID {
		return "", fmt.Errorf("订单不存在")
	}
	if workflow.SpecKind(order.SpecJSON) != storage.OrderKindCard {
		return "", fmt.Errorf("该订单不是云端智能卡订单")
	}
	if order.Status != storage.CertOrderPaid {
		return "", fmt.Errorf("订单尚未支付或已完成（当前状态: %s）", order.Status)
	}
	used, _ := repo.CountByOrderNo(r.Context(), orderNo)
	if used >= workflow.SpecQuantity(order.SpecJSON) {
		return "", fmt.Errorf("该订单可开卡数量已用完")
	}
	return orderNo, nil
}

// cardOrderLimit 返回订单可开卡数量。
func (s *Server) cardOrderLimit(r *http.Request, orderNo string) int {
	order, err := s.workflowSvc.GetOrderByNo(r.Context(), orderNo)
	if err != nil {
		return 0
	}
	return workflow.SpecQuantity(order.SpecJSON)
}

// markCardOrderFulfilled 开卡数量用完后把订单置为已完成。
func (s *Server) markCardOrderFulfilled(r *http.Request, orderNo string, limit int) {
	used, err := storage.NewCardRepo(s.db).CountByOrderNo(r.Context(), orderNo)
	if err != nil || used < limit {
		return
	}
	s.db.ExecContext(r.Context(), //nolint:errcheck
		`UPDATE cert_orders SET status = ?, updated_at = ? WHERE order_no = ? AND status = ?`,
		storage.CertOrderCompleted, time.Now(), orderNo, storage.CertOrderPaid)
}

// ---- 能力查询 ----

// selfApplyTemplate 是自助模式下可直接申请的证书类型。
type selfApplyTemplate struct {
	UUID            string   `json:"uuid"`
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	AllowedKeyTypes []string `json:"allowed_key_types"`
	RequireApproval bool     `json:"require_approval"`
}

// handlePortalCapabilities GET /api/portal/capabilities
//
// 前端据此决定是否展示「创建智能卡」「申请证书」等入口，
// 但所有限制都在对应写接口上由服务端再次校验，前端隐藏仅用于体验。
func (s *Server) handlePortalCapabilities(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	modes := s.businessModes(r)
	isAdmin := auth.IsAdmin(claims.Role)

	cardCount, _ := storage.NewCardRepo(s.db).CountUserCards(r.Context(), claims.UserUUID)
	cardQuotas, err := s.listOrderQuotas(r, claims.UserUUID, storage.OrderKindCard)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	certQuotas, err := s.listOrderQuotas(r, claims.UserUUID, storage.OrderKindCert)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	canCreateCard, cardReason := false, ""
	switch {
	case isAdmin:
		canCreateCard = true
	case len(cardQuotas) > 0:
		canCreateCard = true
	case modes.CardApplyMode == storage.ModeSelfService && cardCount < modes.CardSelfLimit:
		canCreateCard = true
	case modes.CardApplyMode == storage.ModeSelfService:
		cardReason = fmt.Sprintf("已达到自助开通上限（%d 张）", modes.CardSelfLimit)
	default:
		cardReason = "需购买云端智能卡后开通"
	}

	templates := []selfApplyTemplate{}
	if modes.CertApplyMode == storage.ModeSelfService || isAdmin {
		rows, err := s.db.QueryContext(r.Context(),
			`SELECT uuid, name, description, allowed_key_types, require_approval
			 FROM cert_apply_templates WHERE enabled = 1 ORDER BY created_at DESC`)
		if err == nil {
			for rows.Next() {
				var t selfApplyTemplate
				var keyTypes string
				var requireApproval int
				if rows.Scan(&t.UUID, &t.Name, &t.Description, &keyTypes, &requireApproval) != nil {
					continue
				}
				json.Unmarshal([]byte(keyTypes), &t.AllowedKeyTypes) //nolint:errcheck
				t.RequireApproval = requireApproval == 1
				templates = append(templates, t)
			}
			rows.Close()
		}
	}

	// 订阅：已支付的套餐订单自动开通，并返回可用额度
	subscriptions := []interface{}{}
	if s.promoSvc != nil {
		s.promoSvc.ActivatePaidPlanOrders(r.Context(), claims.UserUUID)
		if subs, err := s.promoSvc.ListSubscriptions(r.Context(), claims.UserUUID); err == nil {
			for _, sub := range subs {
				if sub.Active(time.Now()) {
					subscriptions = append(subscriptions, sub)
				}
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"subscriptions":        subscriptions,
		"cert_apply_mode":      modes.CertApplyMode,
		"card_apply_mode":      modes.CardApplyMode,
		"card_self_limit":      modes.CardSelfLimit,
		"user_card_count":      cardCount,
		"is_admin":             isAdmin,
		"can_create_card":      canCreateCard,
		"card_create_reason":   cardReason,
		"card_entitlements":    cardQuotas,
		"cert_order_quotas":    certQuotas,
		"can_self_apply_cert":  modes.CertApplyMode == storage.ModeSelfService || isAdmin,
		"self_apply_templates": templates,
	})
}

// ---- 订单：用户侧 ----

// handlePortalCancelOrder POST /api/portal/orders/{orderNo}/cancel
func (s *Server) handlePortalCancelOrder(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	orderNo := r.PathValue("orderNo")
	if err := s.portalSvc.CancelOrder(r.Context(), orderNo, claims.UserUUID); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "订单已取消"})
}

// ---- 订单：运营侧 ----

// handleAdminListOrders GET /api/portal/admin/orders?status=&keyword=&page=&page_size=
func (s *Server) handleAdminListOrders(w http.ResponseWriter, r *http.Request) {
	page, pageSize := parsePagination(r)
	orders, total, err := s.workflowSvc.ListAllOrders(r.Context(),
		r.URL.Query().Get("status"), r.URL.Query().Get("keyword"), page, pageSize)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// 附带下单用户名，便于运营识别
	names := map[string]string{}
	type orderView struct {
		*storage.CertOrder
		Username string `json:"username"`
	}
	items := make([]orderView, 0, len(orders))
	for _, o := range orders {
		if _, ok := names[o.UserUUID]; !ok {
			if u, err := s.userRepo.GetByUUID(r.Context(), o.UserUUID); err == nil {
				names[o.UserUUID] = u.Username
			} else {
				names[o.UserUUID] = ""
			}
		}
		items = append(items, orderView{CertOrder: o, Username: names[o.UserUUID]})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "total": total, "page": page})
}

// handleAdminConfirmOfflinePayment POST /api/portal/admin/orders/{orderNo}/confirm-payment
//
// 未接入在线支付插件时，由财务确认线下到账（对公转账等）后放行履约。
func (s *Server) handleAdminConfirmOfflinePayment(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	orderNo := r.PathValue("orderNo")
	var req struct {
		Reference string `json:"reference"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if s.paymentSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "支付服务未启用")
		return
	}
	if err := s.paymentSvc.ConfirmOfflinePayment(r.Context(), orderNo, req.Reference); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.auditLogRepo.Create(r.Context(), &storage.AuditLog{ //nolint:errcheck
		UserUUID:     claims.UserUUID,
		Action:       "confirm_offline_payment",
		ResourceType: "cert_order",
		ResourceUUID: orderNo,
		Detail:       fmt.Sprintf(`{"reference":%q}`, req.Reference),
		IPAddress:    r.RemoteAddr,
	})
	writeJSON(w, http.StatusOK, map[string]string{"message": "已确认到账"})
}

// handleAdminCancelOrder POST /api/portal/admin/orders/{orderNo}/cancel
func (s *Server) handleAdminCancelOrder(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	orderNo := r.PathValue("orderNo")
	if err := s.portalSvc.CancelOrder(r.Context(), orderNo, ""); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.auditLogRepo.Create(r.Context(), &storage.AuditLog{ //nolint:errcheck
		UserUUID: claims.UserUUID, Action: "admin_cancel_order",
		ResourceType: "cert_order", ResourceUUID: orderNo, IPAddress: r.RemoteAddr,
	})
	writeJSON(w, http.StatusOK, map[string]string{"message": "订单已取消"})
}

// ---- 智能卡：运营侧 ----

// handleAdminListCards GET /api/admin/cards?user_uuid=
func (s *Server) handleAdminListCards(w http.ResponseWriter, r *http.Request) {
	page, pageSize := parsePagination(r)
	cards, total, err := storage.NewCardRepo(s.db).ListAll(r.Context(), r.URL.Query().Get("user_uuid"), page, pageSize)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	type cardView struct {
		*storage.Card
		Username  string `json:"username"`
		CertCount int    `json:"cert_count"`
	}
	names := map[string]string{}
	items := make([]cardView, 0, len(cards))
	for _, c := range cards {
		if _, ok := names[c.UserUUID]; !ok {
			if u, err := s.userRepo.GetByUUID(r.Context(), c.UserUUID); err == nil {
				names[c.UserUUID] = u.Username
			}
		}
		var n int
		s.db.QueryRowContext(r.Context(), //nolint:errcheck
			`SELECT COUNT(*) FROM certificates WHERE card_uuid = ?`, c.UUID).Scan(&n)
		items = append(items, cardView{Card: c, Username: names[c.UserUUID], CertCount: n})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "total": total, "page": page})
}

// handleAdminUnlockCard POST /api/admin/cards/{uuid}/unlock
// 管理员重置 PIN 错误计数并解除锁定（用户仍需使用原 PIN）。
func (s *Server) handleAdminUnlockCard(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	cardUUID := r.PathValue("uuid")
	if err := storage.NewCardRepo(s.db).UpdatePINStatus(r.Context(), cardUUID, 0, false); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.auditLogRepo.Create(r.Context(), &storage.AuditLog{ //nolint:errcheck
		UserUUID: claims.UserUUID, Action: "admin_unlock_card",
		ResourceType: "card", ResourceUUID: cardUUID, IPAddress: r.RemoteAddr,
	})
	writeJSON(w, http.StatusOK, map[string]string{"message": "已解除锁定"})
}

// handleAdminDeleteCard DELETE /api/admin/cards/{uuid}
// 删除卡片会连带删除其中证书，仅管理员可执行并记录审计。
func (s *Server) handleAdminDeleteCard(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	cardUUID := r.PathValue("uuid")
	repo := storage.NewCardRepo(s.db)
	c, err := repo.GetByUUID(r.Context(), cardUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, "卡片不存在")
		return
	}
	if err := repo.Delete(r.Context(), cardUUID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.auditLogRepo.Create(r.Context(), &storage.AuditLog{ //nolint:errcheck
		UserUUID: claims.UserUUID, Action: "admin_delete_card",
		ResourceType: "card", ResourceUUID: cardUUID,
		Detail: fmt.Sprintf(`{"owner":%q,"name":%q}`, c.UserUUID, c.CardName), IPAddress: r.RemoteAddr,
	})
	writeJSON(w, http.StatusOK, map[string]string{"message": "卡片已删除"})
}

// ---- 兼容旧接口 ----

// payCertOrderWithBalance 让旧的 /api/cert-orders/{uuid}/pay 走真实余额扣款，
// 不再出现"未扣款即置为已支付"的问题。
func (s *Server) payCertOrderWithBalance(r *http.Request, userUUID, orderUUID string) error {
	order, err := s.workflowSvc.GetOrder(r.Context(), orderUUID)
	if err != nil || order.UserUUID != userUUID {
		return fmt.Errorf("订单不存在")
	}
	if order.OrderNo == "" {
		return fmt.Errorf("历史订单缺少对外单号，请重新下单")
	}
	if s.paymentSvc == nil {
		return fmt.Errorf("支付服务未启用")
	}
	_, err = s.paymentSvc.CreateCertOrderPayment(r.Context(), payment.CheckoutInput{
		UserUUID: userUUID, OrderNo: order.OrderNo, Channel: storage.ChannelBalance,
	})
	return err
}

// csrNames 解析 CSR 中的 CN 与 SAN 名称，用于所有权校验。
func csrNames(csrPEM string) ([]string, error) {
	csr, err := workflow.ParseCSR(csrPEM)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	names := []string{}
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v != "" && !seen[strings.ToLower(v)] {
			seen[strings.ToLower(v)] = true
			names = append(names, v)
		}
	}
	add(csr.Subject.CommonName)
	for _, d := range csr.DNSNames {
		add(d)
	}
	for _, e := range csr.EmailAddresses {
		add(e)
	}
	for _, ip := range csr.IPAddresses {
		add(ip.String())
	}
	return names, nil
}
