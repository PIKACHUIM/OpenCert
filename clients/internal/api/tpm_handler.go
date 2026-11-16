package api

import (
	"net/http"

	"github.com/globaltrusts/client-card/internal/card/tpmsc"
)

// handleTPMStatus GET /api/tpm/status
// 返回本机 TPM 与 VSC 支持状态，用于前端诊断展示。
func (s *Server) handleTPMStatus(w http.ResponseWriter, r *http.Request) {
	status, err := tpmsc.GetTPMStatus()
	resp := map[string]any{
		"available": status.Available,
		"version":   status.Version,
		"admin":     status.Admin,
		// VSC 需要 TPM 就绪，否则创建一定失败，不能只按 tpmvscmgr 是否存在判断。
		"vsc_available": tpmsc.IsAvailable() && status.Available,
	}
	if err != nil {
		resp["message"] = err.Error()
	}
	writeOK(w, resp)
}
