// Package api 提供 REST API 服务，供前端管理界面调用。
// 使用 Go 1.22 标准库 net/http ServeMux。
package api

import (
	"encoding/json"
	"net/http"
)

// ---- 通用响应结构 ----

// Response 是 API 统一响应格式。
type Response struct {
	Code    int         `json:"code"` // 0=成功，非0=错误
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// PageResponse 是分页响应格式。
type PageResponse struct {
	Total int         `json:"total"`
	Items interface{} `json:"items"`
}

// writeJSON 写入 JSON 响应。
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// writeOK 写入成功响应。
func writeOK(w http.ResponseWriter, data interface{}) {
	writeJSON(w, http.StatusOK, Response{Code: 0, Message: "ok", Data: data})
}

// writeError 写入错误响应。
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, Response{Code: status, Message: msg})
}

// decodeJSON 解析请求体 JSON。
func decodeJSON(r *http.Request, v interface{}) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}
