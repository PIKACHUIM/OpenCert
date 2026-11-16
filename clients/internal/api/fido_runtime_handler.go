package api

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"

	"github.com/globaltrusts/client-card/internal/fido"
)

var (
	fidoMu     sync.Mutex
	fidoCancel context.CancelFunc
	fidoProc   *fido.Process
	fidoErr    string
)

// handleFIDORuntimeStatus GET /api/fido/runtime
func (s *Server) handleFIDORuntimeStatus(w http.ResponseWriter, r *http.Request) {
	status := fido.Inspect()
	fidoMu.Lock()
	running := fidoCancel != nil
	lastErr := fidoErr
	fidoMu.Unlock()
	writeOK(w, map[string]any{
		"driver_installed": status.DriverInstalled,
		"exe_path":         status.ExePath,
		"version":          status.Version,
		"message":          status.Message,
		"running":          running,
		"last_error":       lastErr,
	})
}

// handleFIDOStart POST /api/fido/start
// 环境不完整时直接 409，不做假启动。
func (s *Server) handleFIDOStart(w http.ResponseWriter, r *http.Request) {
	status := fido.Inspect()
	if !status.DriverInstalled || status.ExePath == "" {
		writeError(w, http.StatusConflict, status.Message)
		return
	}
	fidoMu.Lock()
	if fidoCancel != nil {
		fidoMu.Unlock()
		writeOK(w, map[string]any{"running": true})
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	fidoCancel = cancel
	fidoErr = ""
	fidoMu.Unlock()

	store := fido.NewKeyStore("")
	pinSvc, err := fido.NewPINService(fido.NewPersistentPINState(""))
	if err != nil {
		fidoMu.Lock()
		fidoCancel = nil
		fidoErr = err.Error()
		fidoMu.Unlock()
		cancel()
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	handler := func(cmd uint32, payload []byte) (any, error) {
		switch cmd {
		case fido.CmdGetInfo:
			return fido.GetInfoResponse(), nil
		case fido.CmdCancel:
			return map[string]any{"rv": 0}, nil
		case fido.CmdClientPIN:
			var body map[string]any
			if len(payload) > 0 {
				_ = json.Unmarshal(payload, &body)
			}
			return pinSvc.Handle(body), nil
		case fido.CmdMakeCredential, fido.CmdGetAssertion:
			var body map[string]any
			if len(payload) > 0 {
				if err := json.Unmarshal(payload, &body); err != nil {
					return map[string]any{"rv": 1}, nil
				}
			}
			return fido.HandleCTAP(store, pinSvc, cmd, body)
		default:
			return map[string]any{"rv": 1}, nil
		}
	}
	go func() {
		err := fido.Listen(ctx, handler)
		fidoMu.Lock()
		defer fidoMu.Unlock()
		if ctx.Err() != nil {
			return
		}
		// 监听失败（如管道被占用）必须把状态复位，否则界面会一直显示“运行中”。
		fidoCancel = nil
		if proc := fidoProc; proc != nil {
			proc.Stop()
			fidoProc = nil
		}
		if err != nil {
			fidoErr = err.Error()
		}
	}()
	proc, err := fido.StartProcess(ctx, status.ExePath)
	if err != nil {
		cancel()
		fidoMu.Lock()
		fidoCancel = nil
		fidoErr = err.Error()
		fidoMu.Unlock()
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	fidoMu.Lock()
	fidoProc = proc
	fidoMu.Unlock()
	writeOK(w, map[string]any{"running": true})
}

// handleFIDOStop POST /api/fido/stop
func (s *Server) handleFIDOStop(w http.ResponseWriter, r *http.Request) {
	fidoMu.Lock()
	cancel := fidoCancel
	proc := fidoProc
	fidoCancel = nil
	fidoProc = nil
	fidoMu.Unlock()
	if cancel != nil {
		cancel()
	}
	if proc != nil {
		proc.Stop()
	}
	writeOK(w, map[string]any{"running": false})
}
