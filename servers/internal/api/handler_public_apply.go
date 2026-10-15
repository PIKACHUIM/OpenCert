// Package api - handler_public_apply.go：已下线的匿名证书申请接口。
//
// 平台规则为「注册后才能申请/下单」：匿名申请无法归属用户、无法走支付与所有权验证，
// 且会以任意填写的组织名称生成申请，存在身份冒用风险，因此统一返回 410。
// 保留路由是为了给旧客户端明确的迁移提示，而不是 404。
package api

import "net/http"

const publicApplyGoneMessage = "匿名证书申请已下线：请注册并登录后，在控制台「申请证书」中提交申请"

// handlePublicCreateCertApplication POST /api/public/cert-applications（已下线）
func (s *Server) handlePublicCreateCertApplication(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusGone, publicApplyGoneMessage)
}

// handlePublicGetCertApplicationStatus GET /api/public/cert-applications/{uuid}（已下线）
func (s *Server) handlePublicGetCertApplicationStatus(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusGone, publicApplyGoneMessage)
}
