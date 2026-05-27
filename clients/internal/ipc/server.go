package ipc

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"runtime"
	"sync"
	"time"
)

// Handler 是 IPC 命令处理函数类型。
type Handler func(ctx context.Context, req *Frame) (interface{}, uint32)

// cmdNames 命令码到名称的映射，用于结构化日志。
var cmdNames = map[CmdCode]string{
	CmdPing:             "Ping",
	CmdHandshake:        "Handshake",
	CmdGetInfo:          "GetInfo",
	CmdGetSlotList:      "GetSlotList",
	CmdGetSlotInfo:      "GetSlotInfo",
	CmdGetTokenInfo:     "GetTokenInfo",
	CmdGetMechanismList: "GetMechanismList",
	CmdGetMechanismInfo: "GetMechanismInfo",
	CmdOpenSession:      "OpenSession",
	CmdCloseSession:     "CloseSession",
	CmdCloseAllSessions: "CloseAllSessions",
	CmdGetSessionInfo:   "GetSessionInfo",
	CmdLogin:            "Login",
	CmdLogout:           "Logout",
	CmdInitPIN:          "InitPIN",
	CmdSetPIN:           "SetPIN",
	CmdFindObjectsInit:  "FindObjectsInit",
	CmdFindObjects:      "FindObjects",
	CmdFindObjectsFinal: "FindObjectsFinal",
	CmdGetAttributeValue: "GetAttributeValue",
	CmdSetAttributeValue: "SetAttributeValue",
	CmdCreateObject:     "CreateObject",
	CmdDestroyObject:    "DestroyObject",
	CmdGetObjectSize:    "GetObjectSize",
	CmdSignInit:         "SignInit",
	CmdSign:             "Sign",
	CmdSignUpdate:       "SignUpdate",
	CmdSignFinal:        "SignFinal",
	CmdVerifyInit:       "VerifyInit",
	CmdVerify:           "Verify",
	CmdDecryptInit:      "DecryptInit",
	CmdDecrypt:          "Decrypt",
	CmdEncryptInit:      "EncryptInit",
	CmdEncrypt:          "Encrypt",
	CmdGenerateKeyPair:  "GenerateKeyPair",
	CmdGenerateRandom:   "GenerateRandom",
	CmdDigestInit:       "DigestInit",
	CmdDigest:           "Digest",
	CmdDigestUpdate:     "DigestUpdate",
	CmdDigestKey:        "DigestKey",
	CmdDigestFinal:      "DigestFinal",
	CmdVerifyUpdate:     "VerifyUpdate",
	CmdVerifyFinal:      "VerifyFinal",
	CmdSeedRandom:       "SeedRandom",
}

// cmdName 返回命令码的可读名称。
func cmdName(cmd CmdCode) string {
	if name, ok := cmdNames[cmd]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(0x%04X)", uint32(cmd))
}

// Server 是 IPC 服务端，监听 Named Pipe 或 Unix Socket。
type Server struct {
	pipePath string
	handlers map[CmdCode]Handler
	mu       sync.RWMutex
	listener net.Listener
	done     chan struct{}
	wg       sync.WaitGroup // 跟踪活跃连接数
	conns    map[net.Conn]struct{}
	connsMu  sync.Mutex
}

// NewServer 创建 IPC 服务端。
func NewServer(pipePath string) *Server {
	return &Server{
		pipePath: pipePath,
		handlers: make(map[CmdCode]Handler),
		done:     make(chan struct{}),
		conns:    make(map[net.Conn]struct{}),
	}
}

// Register 注册命令处理函数。
func (s *Server) Register(cmd CmdCode, h Handler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers[cmd] = h
}

// Start 启动 IPC 服务端监听。
func (s *Server) Start() error {
	ln, err := listenPipe(s.pipePath)
	if err != nil {
		return fmt.Errorf("启动 IPC 监听失败 [%s]: %w", s.pipePath, err)
	}
	s.listener = ln
	slog.Info("IPC 服务已启动", "path", s.pipePath, "platform", runtime.GOOS)

	go s.acceptLoop()
	return nil
}

// Stop 停止 IPC 服务端。
func (s *Server) Stop() {
	close(s.done)
	if s.listener != nil {
		s.listener.Close()
	}
}

// GracefulStop 优雅关闭 IPC 服务端。
// 停止接受新连接，等待当前操作完成（最长 maxWait），然后强制关闭所有连接。
func (s *Server) GracefulStop(maxWait time.Duration) {
	slog.Info("IPC 服务开始优雅关闭", "max_wait", maxWait)

	// 1. 停止接受新连接
	close(s.done)
	if s.listener != nil {
		s.listener.Close()
	}

	// 2. 等待当前操作完成（最长 maxWait）
	waitDone := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(waitDone)
	}()

	select {
	case <-waitDone:
		slog.Info("IPC 所有连接已正常关闭")
	case <-time.After(maxWait):
		slog.Warn("IPC 优雅关闭超时，强制关闭所有连接", "timeout", maxWait)
		// 3. 超时后强制关闭所有活跃连接
		s.forceCloseAllConns()
	}
}

// trackConn 注册一个活跃连接。
func (s *Server) trackConn(conn net.Conn) {
	s.connsMu.Lock()
	s.conns[conn] = struct{}{}
	s.connsMu.Unlock()
	s.wg.Add(1)
}

// untrackConn 注销一个活跃连接。
func (s *Server) untrackConn(conn net.Conn) {
	s.connsMu.Lock()
	delete(s.conns, conn)
	s.connsMu.Unlock()
	s.wg.Done()
}

// forceCloseAllConns 强制关闭所有活跃连接。
func (s *Server) forceCloseAllConns() {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()

	for conn := range s.conns {
		conn.Close()
	}
	slog.Info("已强制关闭所有 IPC 连接", "count", len(s.conns))
}

// acceptLoop 接受新连接。
func (s *Server) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				slog.Error("IPC 接受连接失败", "error", err)
				continue
			}
		}
		s.trackConn(conn)
		go s.handleConn(conn)
	}
}

// BroadcastSlotChanged 向所有当前活跃的 IPC 连接推送一个 CmdSlotChanged 事件。
// 该方法不会阻塞调用方：每条连接的推送都在独立 goroutine 中异步发送，
// 并带 2 秒写入超时，避免慢客户端拖累整体广播。
//
// reason 可选 "create" / "delete" / "update" / "sync"，仅用于诊断。
// 失败（连接已断开、对端未 accept 等）仅记录 warn 日志，不向上返回错误。
func (s *Server) BroadcastSlotChanged(reason string) {
	payload, err := json.Marshal(SlotChangedEvent{
		Reason:    reason,
		Timestamp: time.Now().Unix(),
	})
	if err != nil {
		slog.Warn("序列化 SlotChanged 事件失败", "error", err)
		return
	}

	s.connsMu.Lock()
	conns := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.connsMu.Unlock()

	if len(conns) == 0 {
		slog.Debug("BroadcastSlotChanged: 无活跃连接")
		return
	}

	for _, c := range conns {
		conn := c
		go func() {
			_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			if err := WriteFrame(conn, CmdSlotChanged, payload); err != nil {
				slog.Warn("推送 SlotChanged 事件失败", "error", err)
			}
		}()
	}
	slog.Debug("已广播 SlotChanged 事件", "conn_count", len(conns), "reason", reason)
}

// handleConn 处理单个连接的请求循环。
func (s *Server) handleConn(conn net.Conn) {
	defer func() {
		conn.Close()
		s.untrackConn(conn)
	}()
	slog.Debug("IPC 新连接", "remote", conn.RemoteAddr())

	for {
		// 设置读取超时
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))

		frame, err := ReadFrame(conn)
		if err != nil {
			// 连接关闭或超时，正常退出
			return
		}

		// 检查是否正在关闭
		select {
		case <-s.done:
			// 服务正在关闭，不再处理新请求
			return
		default:
		}

		// 重置写入超时
		conn.SetWriteDeadline(time.Now().Add(30 * time.Second))

		s.mu.RLock()
		h, ok := s.handlers[frame.Cmd]
		s.mu.RUnlock()

		if !ok {
			slog.Warn("未知 IPC 命令", "cmd", frame.Cmd)
			// 返回 CKR_FUNCTION_NOT_SUPPORTED = 0x54
			if err := WriteResponse(conn, frame.Cmd, 0x54, nil); err != nil {
				slog.Error("写入响应失败", "error", err)
				return
			}
			continue
		}

		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		data, rv := h(ctx, frame)
		cancel()
		duration := time.Since(start)

		// 结构化日志：记录每个 IPC 命令的执行情况
		logLevel := slog.LevelDebug
		if rv != 0 {
			logLevel = slog.LevelWarn
		}
		if duration > 5*time.Second {
			logLevel = slog.LevelWarn
		}
		slog.Log(context.Background(), logLevel, "IPC 命令执行",
			"cmd", cmdName(frame.Cmd),
			"cmd_code", fmt.Sprintf("0x%04X", uint32(frame.Cmd)),
			"rv", rv,
			"duration_ms", duration.Milliseconds(),
			"payload_len", len(frame.Payload),
			"module", "ipc",
		)

		if err := WriteResponse(conn, frame.Cmd, rv, data); err != nil {
			slog.Error("写入响应失败", "cmd", cmdName(frame.Cmd), "error", err)
			return
		}
	}
}