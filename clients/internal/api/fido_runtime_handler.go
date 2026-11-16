package api

import (
	"net/http"

	"github.com/globaltrusts/client-card/internal/fido"
)

// handleFIDORuntimeStatus GET /api/fido/runtime
func (s *Server) handleFIDORuntimeStatus(w http.ResponseWriter, r *http.Request) {
	writeOK(w, fido.Inspect())
}
