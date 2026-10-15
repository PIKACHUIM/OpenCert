// Package api - handler_help.go：帮助中心文档接口。
package api

import (
	"net/http"

	"github.com/globaltrusts/server-card/internal/help"
)

// handleHelpPublicDocs GET /api/help/docs —— 用户文档，公开访问。
func (s *Server) handleHelpPublicDocs(w http.ResponseWriter, r *http.Request) {
	docs, err := help.List(help.AudienceUser)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "读取帮助文档失败")
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": docs, "total": len(docs)})
}

// handleHelpAdminDocs GET /api/help/admin-docs —— 管理员文档，路由层已限定 adminOnly。
// 文档含部署与运维细节，不对普通用户与匿名访客开放。
func (s *Server) handleHelpAdminDocs(w http.ResponseWriter, r *http.Request) {
	docs, err := help.List(help.AudienceAdmin)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "读取帮助文档失败")
		return
	}
	w.Header().Set("Cache-Control", "private, no-store")
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": docs, "total": len(docs)})
}
