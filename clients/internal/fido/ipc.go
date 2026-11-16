package fido

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

// 与 fido-go.exe 的 IPC 契约（来自参考项目 Module/FidoIpc.py）。
const (
	IPCMagic = 0x504B3131 // "PK11"

	CmdGetInfo        = 0x0300
	CmdMakeCredential = 0x0301
	CmdGetAssertion   = 0x0302
	CmdCancel         = 0x0303
	CmdLogin          = 0x0304
	CmdClientPIN      = 0x0305

	maxFrameSize = 8 << 20
)

// Handler 处理一条 IPC 命令，返回将被 JSON 编码的响应体。
type Handler func(cmd uint32, payload []byte) (any, error)

// Serve 在连接上循环读取帧并响应，直到连接关闭。
func Serve(conn io.ReadWriteCloser, handler Handler) error {
	defer conn.Close()
	for {
		cmd, payload, err := readFrame(conn)
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return nil
			}
			return err
		}
		resp, err := handler(cmd, payload)
		if err != nil {
			resp = map[string]any{"error": err.Error()}
		}
		body, err := json.Marshal(resp)
		if err != nil {
			return fmt.Errorf("编码响应失败: %w", err)
		}
		if err := writeFrame(conn, cmd, body); err != nil {
			return err
		}
	}
}

func readFrame(r io.Reader) (uint32, []byte, error) {
	var header [12]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, err
	}
	magic := binary.BigEndian.Uint32(header[0:4])
	if magic != IPCMagic {
		return 0, nil, fmt.Errorf("IPC magic 不匹配: 0x%08X", magic)
	}
	cmd := binary.BigEndian.Uint32(header[4:8])
	length := binary.BigEndian.Uint32(header[8:12])
	if length > maxFrameSize {
		return 0, nil, fmt.Errorf("IPC 帧过大: %d", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return cmd, payload, nil
}

func writeFrame(w io.Writer, cmd uint32, body []byte) error {
	var header [12]byte
	binary.BigEndian.PutUint32(header[0:4], IPCMagic)
	binary.BigEndian.PutUint32(header[4:8], cmd)
	binary.BigEndian.PutUint32(header[8:12], uint32(len(body)))
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}
