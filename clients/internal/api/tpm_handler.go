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
		"available":     status.Available,
		"version":       status.Version,
		"admin":         status.Admin,
		"vsc_available": tpmsc.IsAvailable(),
	}
	if err != nil {
		resp["message"] = err.Error()
	}
	writeOK(w, resp)
}
