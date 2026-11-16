package api

import (
	"context"
	"net/http"
	"sync"

	"github.com/globaltrusts/client-card/internal/sshagent"
	"github.com/globaltrusts/client-card/internal/storage"
)

var (
	sshAgentMu     sync.Mutex
	sshAgentCancel context.CancelFunc
	sshAgentErr    string
)

// handleSSHAgentStatus GET /api/ssh/agent
func (s *Server) handleSSHAgentStatus(w http.ResponseWriter, r *http.Request) {
	sshAgentMu.Lock()
	running := sshAgentCancel != nil
	lastErr := sshAgentErr
	sshAgentMu.Unlock()
	writeOK(w, map[string]any{
		"running":    running,
		"pipe":       `\\.\pipe\openssh-ssh-agent`,
		"last_error": lastErr,
	})
}

// handleSSHAgentToggle POST /api/ssh/agent {enabled}
func (s *Server) handleSSHAgentToggle(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	sshAgentMu.Lock()
	if !req.Enabled {
		if sshAgentCancel != nil {
			sshAgentCancel()
			sshAgentCancel = nil
		}
		sshAgentErr = ""
		sshAgentMu.Unlock()
		writeOK(w, map[string]any{"running": false})
		return
	}
	if sshAgentCancel != nil {
		sshAgentMu.Unlock()
		writeOK(w, map[string]any{"running": true})
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	sshAgentCancel = cancel
	sshAgentMu.Unlock()

	backend := &sshagent.KSPBackend{Readers: func() ([]string, error) {
		cards, err := s.cardRepo.ListAll(context.Background())
		if err != nil {
			return nil, err
		}
		var readers []string
		seen := map[string]bool{}
		for _, card := range cards {
			if card.SlotType != storage.SlotTypeTPMSC || card.TPMSCState != storage.TPMSCStateReady {
				continue
			}
			if card.TPMSCReaderName == "" || seen[card.TPMSCReaderName] {
				continue
			}
			seen[card.TPMSCReaderName] = true
			readers = append(readers, card.TPMSCReaderName)
		}
		return readers, nil
	}}
	go func() {
		err := sshagent.Listen(ctx, backend)
		sshAgentMu.Lock()
		defer sshAgentMu.Unlock()
		if ctx.Err() != nil {
			return
		}
		sshAgentCancel = nil
		if err != nil {
			sshAgentErr = err.Error()
		}
	}()
	writeOK(w, map[string]any{"running": true})
}
