package api

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/globaltrusts/server-card/internal/payment"
	"github.com/globaltrusts/server-card/internal/storage"
	"github.com/google/uuid"
)

// ---- 支付系统处理器 ----

// RechargeRequest 是充值请求体。
type RechargeRequest struct {
	AmountCents int64  `json:"amount_cents"` // 金额（分）
	Channel     string `json:"channel"`      // 支付渠道
}

func (s *Server) handleCreateRecharge(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	var req RechargeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if req.AmountCents <= 0 {
		writeError(w, http.StatusBadRequest, "充值金额必须大于0")
		return
	}
	if req.Channel == "" {
		writeError(w, http.StatusBadRequest, "支付渠道不能为空")
		return
	}

	notifyURL := fmt.Sprintf("%s/api/payment/callback/%s", s.cfg.API.BaseURL, req.Channel)
	order, payResp, err := s.paymentSvc.CreateRechargeOrder(r.Context(), claims.UserUUID, req.AmountCents, req.Channel, notifyURL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"order":   order,
		"pay_url": payResp.PayURL,
		"qr_code": payResp.QRCode,
	})
}

func (s *Server) handleListOrders(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	page, pageSize := parsePagination(r)

	orders, total, err := s.paymentSvc.ListOrders(r.Context(), claims.UserUUID, page, pageSize)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"orders": orders,
		"total":  total,
		"page":   page,
	})
}

func (s *Server) handleGetBalance(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	balance, err := s.paymentSvc.GetBalance(r.Context(), claims.UserUUID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, balance)
}

// RefundRequestBody 是退款请求体。
type RefundRequestBody struct {
	OrderNo string `json:"order_no"`
	Reason  string `json:"reason"`
}

func (s *Server) handleCreateRefund(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	var req RefundRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if req.OrderNo == "" {
		writeError(w, http.StatusBadRequest, "订单号不能为空")
		return
	}

	refund, err := s.paymentSvc.CreateRefund(r.Context(), claims.UserUUID, req.OrderNo, req.Reason)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// 记录退款申请日志
	s.logRepo.Create(r.Context(), &storage.Log{ //nolint:errcheck
		UserUUID: claims.UserUUID,
		Action:   fmt.Sprintf("refund_request:%s", req.OrderNo),
		IPAddr:   r.RemoteAddr,
	})

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"message": "退款申请已提交，等待管理员审批",
		"refund":  refund,
	})
}

func (s *Server) handlePaymentCallback(w http.ResponseWriter, r *http.Request) {
	channel := r.PathValue("channel")
	body, err := io.ReadAll(io.LimitReader(r.Body, 1024*1024)) // 限制 1MB
	if err != nil {
		writeError(w, http.StatusBadRequest, "读取请求体失败")
		return
	}

	headers := make(map[string]string)
	for k, v := range r.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	if err := s.paymentSvc.HandleCallback(r.Context(), channel, body, headers); err != nil {
		slog.Error("支付回调处理失败", "channel", channel, "error", err)
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// 大多数支付平台期望返回 "success" 字符串
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("success")) //nolint:errcheck
}

// ---- 支付插件管理处理器（管理员）----

func (s *Server) handleListPaymentPlugins(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.QueryContext(r.Context(),
		`SELECT uuid, name, plugin_type, enabled, sort_weight, created_at, updated_at
		 FROM payment_plugins ORDER BY sort_weight DESC, created_at DESC`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	var plugins []map[string]interface{}
	for rows.Next() {
		var p storage.PaymentPlugin
		var enabled int
		if err := rows.Scan(&p.UUID, &p.Name, &p.PluginType, &enabled, &p.SortWeight, &p.CreatedAt, &p.UpdatedAt); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		p.Enabled = enabled == 1
		// 不返回敏感配置
		plugins = append(plugins, map[string]interface{}{
			"uuid":        p.UUID,
			"name":        p.Name,
			"plugin_type": p.PluginType,
			"enabled":     p.Enabled,
			"sort_weight": p.SortWeight,
			"created_at":  p.CreatedAt,
			"updated_at":  p.UpdatedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"plugins": plugins, "total": len(plugins)})
}

// CreatePaymentPluginRequest 是创建支付插件请求体。
type CreatePaymentPluginRequest struct {
	Name       string                 `json:"name"`
	PluginType string                 `json:"plugin_type"` // alipay/wechat/stripe/paypal
	Config     map[string]interface{} `json:"config"`      // API Key/Secret 等（将加密存储）
	Enabled    bool                   `json:"enabled"`
	SortWeight int                    `json:"sort_weight"`
}

func (s *Server) handleCreatePaymentPlugin(w http.ResponseWriter, r *http.Request) {
	var req CreatePaymentPluginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if req.Name == "" || req.PluginType == "" {
		writeError(w, http.StatusBadRequest, "插件名称和类型不能为空")
		return
	}

	// 加密存储配置
	var configEnc []byte
	if req.Config != nil {
		configJSON, err := json.Marshal(req.Config)
		if err != nil {
			writeError(w, http.StatusBadRequest, "配置格式错误")
			return
		}
		// 启用状态下立即校验配置可用；停用状态允许先保存草稿配置
		if req.Enabled {
			if err := payment.ValidateProviderConfig(req.PluginType, configJSON); err != nil {
				writeError(w, http.StatusBadRequest, "插件配置无效: "+err.Error())
				return
			}
		}
		// 使用 card service 的加密功能
		configEnc, err = s.cardSvc.EncryptData(configJSON)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "加密配置失败")
			return
		}
	}

	pluginUUID := uuid.New().String()
	now := time.Now()
	_, err := s.db.ExecContext(r.Context(),
		`INSERT INTO payment_plugins (uuid, name, plugin_type, config_enc, enabled, sort_weight, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		pluginUUID, req.Name, req.PluginType, configEnc, boolToIntLocal(req.Enabled), req.SortWeight, now, now)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.reloadPaymentPlugins(r)
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"uuid":        pluginUUID,
		"name":        req.Name,
		"plugin_type": req.PluginType,
		"enabled":     req.Enabled,
		"sort_weight": req.SortWeight,
		"created_at":  now,
	})
}

// reloadPaymentPlugins 在插件增删改后热加载，使启停立即生效（无需重启服务）。
func (s *Server) reloadPaymentPlugins(r *http.Request) {
	if s.paymentLoader == nil {
		return
	}
	if loaded, err := s.paymentLoader.Reload(r.Context()); err != nil {
		slog.Warn("支付插件热加载失败", "error", err)
	} else {
		slog.Info("支付插件已热加载", "types", loaded)
	}
}

// UpdatePaymentPluginRequest 是更新支付插件请求体。
type UpdatePaymentPluginRequest struct {
	Name       string `json:"name"`
	Enabled    bool   `json:"enabled"`
	SortWeight int    `json:"sort_weight"`
}

func (s *Server) handleUpdatePaymentPlugin(w http.ResponseWriter, r *http.Request) {
	pluginUUID := r.PathValue("uuid")
	var req UpdatePaymentPluginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}

	_, err := s.db.ExecContext(r.Context(),
		`UPDATE payment_plugins SET name = ?, enabled = ?, sort_weight = ?, updated_at = ? WHERE uuid = ?`,
		req.Name, boolToIntLocal(req.Enabled), req.SortWeight, time.Now(), pluginUUID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.reloadPaymentPlugins(r)
	writeJSON(w, http.StatusOK, map[string]string{"message": "支付插件已更新"})
}

func (s *Server) handleDeletePaymentPlugin(w http.ResponseWriter, r *http.Request) {
	pluginUUID := r.PathValue("uuid")
	_, err := s.db.ExecContext(r.Context(), `DELETE FROM payment_plugins WHERE uuid = ?`, pluginUUID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.reloadPaymentPlugins(r)
	writeJSON(w, http.StatusOK, map[string]string{"message": "支付插件已删除"})
}

// ---- 退款审批处理器（管理员）----

// handleListRefunds 查询全部退款工单（管理员）。
func (s *Server) handleListRefunds(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	page, pageSize := parsePagination(r)

	refunds, total, err := s.paymentSvc.ListAllRefunds(r.Context(), status, page, pageSize)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"refunds": refunds, "items": refunds, "total": total, "page": page,
	})
}

// handleApproveRefund 审批退款：余额支付退回余额，第三方渠道调用原路退款。
//
// 渠道退款失败时返回错误并保留 failed 状态与失败原因，不会谎报退款成功。
func (s *Server) handleApproveRefund(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	refundUUID := r.PathValue("uuid")

	if err := s.paymentSvc.ApproveRefund(r.Context(), refundUUID, claims.UserUUID); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.logRepo.Create(r.Context(), &storage.Log{ //nolint:errcheck
		UserUUID: claims.UserUUID,
		Action:   fmt.Sprintf("approve_refund:%s", refundUUID),
		IPAddr:   r.RemoteAddr,
	})

	writeJSON(w, http.StatusOK, map[string]string{"message": "退款已处理"})
}

// handleRejectRefund 驳回退款申请。
func (s *Server) handleRejectRefund(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	refundUUID := r.PathValue("uuid")

	var req struct {
		Reason string `json:"reason"`
	}
	// 请求体可选；解析失败时使用默认原因
	_ = json.NewDecoder(r.Body).Decode(&req) //nolint:errcheck
	if req.Reason == "" {
		req.Reason = "管理员驳回"
	}

	if err := s.paymentSvc.RejectRefund(r.Context(), refundUUID, claims.UserUUID, req.Reason); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.logRepo.Create(r.Context(), &storage.Log{ //nolint:errcheck
		UserUUID: claims.UserUUID,
		Action:   fmt.Sprintf("reject_refund:%s", refundUUID),
		IPAddr:   r.RemoteAddr,
	})

	writeJSON(w, http.StatusOK, map[string]string{"message": "退款申请已拒绝"})
}

// boolToIntLocal 是本地 bool 转 int 工具函数。
func boolToIntLocal(b bool) int {
	if b {
		return 1
	}
	return 0
}
