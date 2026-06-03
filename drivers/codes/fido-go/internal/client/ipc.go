// Package client 实现 OpenCert FIDO2 IPC 客户端。
// 通过 Named Pipe 与 client-card Go 后端通信，使用标准 IPC 帧协议：
//
//	请求帧：Magic(4B,BE) + Cmd(4B,BE) + Len(4B,BE) + JSON Payload
//	响应帧：Magic(4B,BE) + Cmd(4B,BE) + Len(4B,BE) + {"rv":N,"data":{...}}
//
// 协议与 clients/internal/ipc/protocol.go 完全一致。
package client

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/Microsoft/go-winio"
)

const (
	pipeName = `\\.\pipe\pkcs11-client-card`

	// 协议魔数 "PK11"
	ipcMagic uint32 = 0x504B3131

	// 帧头大小：Magic(4) + Cmd(4) + Len(4) = 12 字节
	ipcHeaderSize = 12

	// FIDO 命令码（与 clients/internal/ipc/protocol.go 一致）
	cmdFIDOGetInfo        uint32 = 0x0300
	cmdFIDOMakeCredential uint32 = 0x0301
	cmdFIDOGetAssertion   uint32 = 0x0302
	cmdFIDOCancel         uint32 = 0x0303
	cmdFIDOLogin          uint32 = 0x0304
)

// ipcCall 发送一次 IPC 请求并返回响应 JSON。
// 使用标准帧协议：Magic(4B,BE) + Cmd(4B,BE) + Len(4B,BE) + JSON
func ipcCall(cmd uint32, reqJSON []byte) ([]byte, error) {
	// 连接 Named Pipe（最多等待 5 秒）
	timeout := 5 * time.Second
	conn, err := winio.DialPipe(pipeName, &timeout)
	if err != nil {
		return nil, fmt.Errorf("连接 Named Pipe 失败: %w", err)
	}
	defer conn.Close()

	// 构造请求帧：Magic(4B,BE) + Cmd(4B,BE) + Len(4B,BE) + JSON
	header := make([]byte, ipcHeaderSize)
	binary.BigEndian.PutUint32(header[0:4], ipcMagic)
	binary.BigEndian.PutUint32(header[4:8], cmd)
	binary.BigEndian.PutUint32(header[8:12], uint32(len(reqJSON)))

	if _, err := conn.Write(header); err != nil {
		return nil, fmt.Errorf("发送帧头失败: %w", err)
	}
	if len(reqJSON) > 0 {
		if _, err := conn.Write(reqJSON); err != nil {
			return nil, fmt.Errorf("发送 payload 失败: %w", err)
		}
	}

	// 读取响应帧头（12 字节）
	respHeader := make([]byte, ipcHeaderSize)
	if _, err := io.ReadFull(conn, respHeader); err != nil {
		return nil, fmt.Errorf("读取响应帧头失败: %w", err)
	}

	respMagic := binary.BigEndian.Uint32(respHeader[0:4])
	if respMagic != ipcMagic {
		return nil, fmt.Errorf("响应魔数不匹配: 0x%08X", respMagic)
	}

	respLen := binary.BigEndian.Uint32(respHeader[8:12])
	if respLen == 0 {
		return nil, nil
	}

	respJSON := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respJSON); err != nil {
		return nil, fmt.Errorf("读取响应 payload 失败: %w", err)
	}

	slog.Debug("IPC 响应", "cmd", fmt.Sprintf("0x%04X", cmd), "len", respLen)
	return respJSON, nil
}

// ipcResponse 是 IPC 响应的通用结构。
type ipcResponse struct {
	RV   uint32          `json:"rv"`
	Data json.RawMessage `json:"data"`
}

// callAndParse 发送 IPC 请求并解析响应。
func callAndParse(cmd uint32, req interface{}, resp interface{}) error {
	reqJSON, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("序列化请求失败: %w", err)
	}

	respJSON, err := ipcCall(cmd, reqJSON)
	if err != nil {
		return err
	}

	if resp == nil || len(respJSON) == 0 {
		return nil
	}

	var wrapper ipcResponse
	if err := json.Unmarshal(respJSON, &wrapper); err != nil {
		return fmt.Errorf("解析 IPC 响应失败: %w", err)
	}

	if wrapper.RV != 0 {
		return fmt.Errorf("IPC 返回错误码: %d", wrapper.RV)
	}

	if resp != nil && len(wrapper.Data) > 0 {
		if err := json.Unmarshal(wrapper.Data, resp); err != nil {
			return fmt.Errorf("解析响应数据失败: %w", err)
		}
	}

	return nil
}