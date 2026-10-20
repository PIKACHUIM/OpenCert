// Package api - handler_portal.go：门户（官网/商城）商品目录、报价与下单接口。
//
// 分层约定：
//   - /api/portal/*        面向门户前台，其中商品目录与报价公开，下单与订单查询需登录
//   - /api/portal/admin/*  面向运营后台，需要管理员权限
//   - /api/site-settings   站点配置，读取需登录、写入需管理员
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/globaltrusts/server-card/internal/auth"
	"github.com/globaltrusts/server-card/internal/issuance"
	"github.com/globaltrusts/server-card/internal/payment"
	"github.com/globaltrusts/server-card/internal/portal"
	"github.com/globaltrusts/server-card/internal/storage"
)

// ---- 分类 ----

// portalCategory 是门户商品分类定义。
type portalCategory struct {
	Code        string `json:"code"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Count       int    `json:"count"`
}

// portalCategories 是内置分类清单（顺序即前台展示顺序）。
var portalCategories = []portalCategory{
	{Code: string(storage.ProductCategorySSL), Name: "SSL/TLS 证书", Description: "为网站与 API 提供加密传输与身份证明"},
	{Code: string(storage.ProductCategoryCodeSign), Name: "代码签名证书", Description: "为软件与脚本提供发布者签名"},
	{Code: string(storage.ProductCategoryEmail), Name: "邮件证书", Description: "邮件签名与加密（S/MIME）"},
	{Code: string(storage.ProductCategoryDocSign), Name: "文档签名证书", Description: "为 PDF 与办公文档提供签名"},
	{Code: string(storage.ProductCategoryCloudCard), Name: "云端智能卡", Description: "私钥保留在云端，通过客户端远程安全使用"},
}

// handlePortalListCategories GET /api/portal/categories
// 返回分类清单及各分类下的可售商品数量。
func (s *Server) handlePortalListCategories(w http.ResponseWriter, r *http.Request) {
	counts := map[string]int{}
	if s.portalSvc != nil {
		views, err := s.portalSvc.ListProducts(r.Context(), true, "")
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		for _, v := range views {
			counts[string(v.Product.Category)]++
		}
	}

	result := make([]portalCategory, 0, len(portalCategories))
	for _, c := range portalCategories {
		c.Count = counts[c.Code]
		result = append(result, c)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": result})
}

// ---- 站点配置 ----

// handlePortalGetSiteSettings GET /api/portal/site
// 公开读取站点展示配置（不含任何敏感信息）。
func (s *Server) handlePortalGetSiteSettings(w http.ResponseWriter, r *http.Request) {
	if s.portalSvc == nil {
		writeJSON(w, http.StatusOK, portal.DefaultSiteSettings())
		return
	}
	settings, err := s.portalSvc.GetSiteSettings(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, settings)
}

// handleGetSiteSettings GET /api/site-settings（管理员）
func (s *Server) handleGetSiteSettings(w http.ResponseWriter, r *http.Request) {
	s.handlePortalGetSiteSettings(w, r)
}

// handleUpdateSiteSettings PUT /api/site-settings（管理员）
func (s *Server) handleUpdateSiteSettings(w http.ResponseWriter, r *http.Request) {
	if s.portalSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "门户服务未启用")
		return
	}
	var req map[string]string
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if err := s.portalSvc.UpdateSiteSettings(r.Context(), req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	settings, err := s.portalSvc.GetSiteSettings(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, settings)
}

// ---- 商品目录（公开） ----

// handlePortalListProducts GET /api/portal/products?category=
// 仅返回已发布（visible + enabled）的商品。
func (s *Server) handlePortalListProducts(w http.ResponseWriter, r *http.Request) {
	if s.portalSvc == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"items": []interface{}{}})
		return
	}
	category := strings.TrimSpace(r.URL.Query().Get("category"))
	views, err := s.portalSvc.ListProducts(r.Context(), true, category)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": views, "total": len(views)})
}

// handlePortalGetProduct GET /api/portal/products/{code}
func (s *Server) handlePortalGetProduct(w http.ResponseWriter, r *http.Request) {
	if s.portalSvc == nil {
		writeError(w, http.StatusNotFound, "商品不存在")
		return
	}
	code := r.PathValue("code")
	view, err := s.portalSvc.GetProductDetail(r.Context(), code, true)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// ---- 报价（公开） ----

// portalQuoteRequest 是报价请求体。
type portalQuoteRequest struct {
	SKUCode  string `json:"sku_code"`
	Quantity int    `json:"quantity"`
}

// handlePortalQuote POST /api/portal/quotes
// 服务端权威报价；不创建订单、不占用库存。
func (s *Server) handlePortalQuote(w http.ResponseWriter, r *http.Request) {
	if s.portalSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "门户服务未启用")
		return
	}
	var req portalQuoteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	quote, err := s.portalSvc.Quote(r.Context(), req.SKUCode, req.Quantity)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, quote)
}

// ---- 订单（需登录） ----

// handlePortalCreateOrder POST /api/portal/orders
// 必须登录后下单。金额、模板关联与状态均由服务端决定。
func (s *Server) handlePortalCreateOrder(w http.ResponseWriter, r *http.Request) {
	if s.portalSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "门户服务未启用")
		return
	}
	claims := claimsFromCtx(r.Context())

	var req portal.CreateOrderInput
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if strings.TrimSpace(req.ApplicantEmail) == "" {
		req.ApplicantEmail = s.applicantEmailFromClaims(r)
	}

	order, err := s.portalSvc.CreateOrder(r.Context(), claims.UserUUID, req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, order)
}

// handlePortalListMyOrders GET /api/portal/orders
func (s *Server) handlePortalListMyOrders(w http.ResponseWriter, r *http.Request) {
	if s.workflowSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "工作流服务未启用")
		return
	}
	claims := claimsFromCtx(r.Context())
	page, pageSize := parsePagination(r)
	orders, total, err := s.workflowSvc.ListOrders(r.Context(), claims.UserUUID, page, pageSize)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": orders, "orders": orders, "total": total})
}

// handlePortalGetMyOrder GET /api/portal/orders/{orderNo}
// 仅允许订单归属人查询，避免通过单号枚举他人订单。
func (s *Server) handlePortalGetMyOrder(w http.ResponseWriter, r *http.Request) {
	if s.workflowSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "工作流服务未启用")
		return
	}
	claims := claimsFromCtx(r.Context())
	orderNo := r.PathValue("orderNo")

	order, err := s.workflowSvc.GetOrderByNo(r.Context(), orderNo)
	if err != nil {
		writeError(w, http.StatusNotFound, "订单不存在")
		return
	}
	if order.UserUUID != claims.UserUUID && !auth.IsAdmin(claims.Role) {
		// 与"不存在"保持一致的响应，避免泄露订单是否存在
		writeError(w, http.StatusNotFound, "订单不存在")
		return
	}
	writeJSON(w, http.StatusOK, order)
}

// ---- 收银台与退款（需登录） ----

// handlePortalPaymentChannels GET /api/portal/payment-channels
// 返回可用的支付渠道（余额 + 已启用的第三方渠道，脱敏）。
func (s *Server) handlePortalPaymentChannels(w http.ResponseWriter, r *http.Request) {
	if s.paymentSvc == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"items": []interface{}{}})
		return
	}
	channels := s.paymentSvc.ListChannels(r.Context())
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": channels})
}

// portalPayRequest 是发起支付的请求体。
type portalPayRequest struct {
	Channel string `json:"channel"`
}

// handlePortalPayOrder POST /api/portal/orders/{orderNo}/pay
//
// 金额与渠道校验均由服务端完成：余额支付当场结算，第三方渠道返回支付链接/二维码。
func (s *Server) handlePortalPayOrder(w http.ResponseWriter, r *http.Request) {
	if s.paymentSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "支付服务未启用")
		return
	}
	claims := claimsFromCtx(r.Context())
	orderNo := r.PathValue("orderNo")

	var req portalPayRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}

	notifyURL := ""
	if req.Channel != "" {
		notifyURL = fmt.Sprintf("%s/api/payment/callback/%s", s.cfg.API.BaseURL, req.Channel)
	}

	result, err := s.paymentSvc.CreateCertOrderPayment(r.Context(), payment.CheckoutInput{
		UserUUID:  claims.UserUUID,
		OrderNo:   orderNo,
		Channel:   req.Channel,
		NotifyURL: notifyURL,
		Subject:   "OpenCert 订单 " + orderNo,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.logRepo.Create(r.Context(), &storage.Log{ //nolint:errcheck
		UserUUID: claims.UserUUID,
		Action:   fmt.Sprintf("pay_order:%s:%s", orderNo, result.Channel),
		IPAddr:   r.RemoteAddr,
	})
	writeJSON(w, http.StatusOK, result)
}

// handlePortalOrderPaymentState GET /api/portal/orders/{orderNo}/payment
// 供收银台轮询支付结果；仅返回本人订单的支付尝试。
func (s *Server) handlePortalOrderPaymentState(w http.ResponseWriter, r *http.Request) {
	if s.paymentSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "支付服务未启用")
		return
	}
	claims := claimsFromCtx(r.Context())
	orderNo := r.PathValue("orderNo")

	// 先确认订单归属，避免通过支付接口探测他人订单
	if s.workflowSvc != nil {
		order, err := s.workflowSvc.GetOrderByNo(r.Context(), orderNo)
		if err != nil {
			writeError(w, http.StatusNotFound, "订单不存在")
			return
		}
		if order.UserUUID != claims.UserUUID && !auth.IsAdmin(claims.Role) {
			writeError(w, http.StatusNotFound, "订单不存在")
			return
		}
	}

	attempt, err := s.paymentSvc.GetOrderPaymentState(r.Context(), orderNo)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, attempt)
}

// handlePortalRequestRefund POST /api/portal/orders/{orderNo}/refund
func (s *Server) handlePortalRequestRefund(w http.ResponseWriter, r *http.Request) {
	if s.paymentSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "支付服务未启用")
		return
	}
	claims := claimsFromCtx(r.Context())
	orderNo := r.PathValue("orderNo")

	var req struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req) //nolint:errcheck

	refund, err := s.paymentSvc.RequestCertOrderRefund(r.Context(), claims.UserUUID, orderNo, req.Reason)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.logRepo.Create(r.Context(), &storage.Log{ //nolint:errcheck
		UserUUID: claims.UserUUID,
		Action:   fmt.Sprintf("refund_request:%s", orderNo),
		IPAddr:   r.RemoteAddr,
	})
	writeJSON(w, http.StatusCreated, refund)
}

// handlePortalListMyRefunds GET /api/portal/refunds
func (s *Server) handlePortalListMyRefunds(w http.ResponseWriter, r *http.Request) {
	if s.paymentSvc == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"items": []interface{}{}, "total": 0})
		return
	}
	claims := claimsFromCtx(r.Context())
	page, pageSize := parsePagination(r)
	refunds, total, err := s.paymentSvc.ListUserRefunds(r.Context(), claims.UserUUID, page, pageSize)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": refunds, "total": total})
}

// ---- 运营后台：商品管理 ----

// handleAdminListProducts GET /api/portal/admin/products
func (s *Server) handleAdminListProducts(w http.ResponseWriter, r *http.Request) {
	if s.portalSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "门户服务未启用")
		return
	}
	category := strings.TrimSpace(r.URL.Query().Get("category"))
	views, err := s.portalSvc.ListAllProducts(r.Context(), category)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": views, "total": len(views)})
}

// handleAdminCreateProduct POST /api/portal/admin/products
func (s *Server) handleAdminCreateProduct(w http.ResponseWriter, r *http.Request) {
	if s.portalSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "门户服务未启用")
		return
	}
	var p storage.PortalProduct
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if err := s.portalSvc.CreateProduct(r.Context(), &p); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

// handleAdminUpdateProduct PUT /api/portal/admin/products/{uuid}
func (s *Server) handleAdminUpdateProduct(w http.ResponseWriter, r *http.Request) {
	if s.portalSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "门户服务未启用")
		return
	}
	var p storage.PortalProduct
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	p.UUID = r.PathValue("uuid")
	if err := s.portalSvc.UpdateProduct(r.Context(), &p); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// handleAdminDeleteProduct DELETE /api/portal/admin/products/{uuid}
func (s *Server) handleAdminDeleteProduct(w http.ResponseWriter, r *http.Request) {
	if s.portalSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "门户服务未启用")
		return
	}
	if err := s.portalSvc.DeleteProduct(r.Context(), r.PathValue("uuid")); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "商品已删除"})
}

// handleAdminListSKUs GET /api/portal/admin/products/{uuid}/skus
func (s *Server) handleAdminListSKUs(w http.ResponseWriter, r *http.Request) {
	if s.portalSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "门户服务未启用")
		return
	}
	skus, err := s.portalSvc.ListSKUs(r.Context(), r.PathValue("uuid"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": skus, "total": len(skus)})
}

// validateSKUNarrowing 校验规格的有效期、算法、交付方式没有超出所关联证书类型
// （开通模板 → 颁发模板）允许的范围。规格只能收窄，不能放宽。
func (s *Server) validateSKUNarrowing(r *http.Request, sku *storage.PortalProductSKU) error {
	if sku.CertApplyTmplUUID == "" || s.issuanceSvc == nil {
		return nil
	}
	var keyTypes []string
	if sku.KeyTypes != "" {
		if err := json.Unmarshal([]byte(sku.KeyTypes), &keyTypes); err != nil {
			return fmt.Errorf("可选密钥算法格式错误")
		}
	}
	policy, err := s.issuanceSvc.ResolvePolicy(r.Context(), sku.CertApplyTmplUUID, "", nil)
	if err != nil {
		return err
	}
	return policy.ValidateNarrowing(&issuance.Narrowing{
		ValidDays:    sku.ValidDays,
		KeyTypes:     keyTypes,
		DeliveryMode: string(sku.DeliveryMode),
	})
}

// handleAdminCreateSKU POST /api/portal/admin/skus
func (s *Server) handleAdminCreateSKU(w http.ResponseWriter, r *http.Request) {
	if s.portalSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "门户服务未启用")
		return
	}
	var sku storage.PortalProductSKU
	if err := json.NewDecoder(r.Body).Decode(&sku); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if err := s.validateSKUNarrowing(r, &sku); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.portalSvc.CreateSKU(r.Context(), &sku); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, sku)
}

// handleAdminUpdateSKU PUT /api/portal/admin/skus/{uuid}
func (s *Server) handleAdminUpdateSKU(w http.ResponseWriter, r *http.Request) {
	if s.portalSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "门户服务未启用")
		return
	}
	var sku storage.PortalProductSKU
	if err := json.NewDecoder(r.Body).Decode(&sku); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	sku.UUID = r.PathValue("uuid")
	if err := s.validateSKUNarrowing(r, &sku); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.portalSvc.UpdateSKU(r.Context(), &sku); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, sku)
}

// handleAdminDeleteSKU DELETE /api/portal/admin/skus/{uuid}
func (s *Server) handleAdminDeleteSKU(w http.ResponseWriter, r *http.Request) {
	if s.portalSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "门户服务未启用")
		return
	}
	if err := s.portalSvc.DeleteSKU(r.Context(), r.PathValue("uuid")); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "规格已删除"})
}

// applicantEmailFromClaims 尽力确定下单联系邮箱：优先 JWT 中的用户，其次查询用户资料。
// JWT 载荷不包含邮箱，因此通过用户仓储回查；查询失败时返回空串，由上层提示用户填写。
func (s *Server) applicantEmailFromClaims(r *http.Request) string {
	claims := claimsFromCtx(r.Context())
	if claims == nil || s.userRepo == nil {
		return ""
	}
	user, err := s.userRepo.GetByUUID(r.Context(), claims.UserUUID)
	if err != nil {
		return ""
	}
	return user.Email
}
