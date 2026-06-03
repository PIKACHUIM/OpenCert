// Package client 实现 OpenCert FIDO2 IPC 代理。
// 实现 virtual-fido 的 CTAPHIDClient 接口，将 CTAP2 CBOR 数据
// 直接透传给 client-card Go 后端，无需在本地处理任何 CTAP2 逻辑。
//
// 数据流：
//
//	virtual-fido USB/IP 层
//	  → CTAPHIDServer（virtual-fido 内置）
//	  → IPCCTAPProxy.HandleMessage(cbor)  ← 本文件
//	  → IPC Named Pipe → client-card
//	  ← CBOR 响应
package client

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
)

// IPCCTAPProxy 实现 virtual-fido 的 CTAPHIDClient 接口。
// 将 CTAP2 CBOR 消息透传给 client-card IPC 后端。
type IPCCTAPProxy struct{}

// NewIPCCTAPProxy 创建 IPC CTAP 代理。
func NewIPCCTAPProxy() *IPCCTAPProxy {
	return &IPCCTAPProxy{}
}

// HandleMessage 接收 CTAP2 CBOR 消息，透传给 IPC 后端，返回 CBOR 响应。
// 消息格式：[1字节命令码][CBOR 数据]
func (p *IPCCTAPProxy) HandleMessage(data []byte) []byte {
	if len(data) == 0 {
		return []byte{0x01} // CTAP1_ERR_INVALID_COMMAND
	}

	cmd := data[0]
	cbor := data[1:]

	slog.Debug("CTAP2 消息", "cmd", fmt.Sprintf("0x%02X", cmd), "len", len(cbor))

	var ipcCmd uint32
	switch cmd {
	case 0x04: // authenticatorGetInfo
		return p.handleGetInfo()
	case 0x01: // authenticatorMakeCredential
		ipcCmd = cmdFIDOMakeCredential
	case 0x02: // authenticatorGetAssertion
		ipcCmd = cmdFIDOGetAssertion
	case 0x11: // authenticatorCancel
		ipcCmd = cmdFIDOCancel
		cbor = nil
	default:
		slog.Warn("未知 CTAP2 命令", "cmd", fmt.Sprintf("0x%02X", cmd))
		return []byte{0x01} // CTAP1_ERR_INVALID_COMMAND
	}

	// 构造 IPC 请求：{"cbor_req": "<base64>"}
	req := map[string]string{
		"cbor_req": base64.StdEncoding.EncodeToString(cbor),
	}
	reqJSON, _ := json.Marshal(req)

	respJSON, err := ipcCall(ipcCmd, reqJSON)
	if err != nil {
		slog.Error("IPC 调用失败", "cmd", fmt.Sprintf("0x%02X", cmd), "error", err)
		return []byte{0x7F} // CTAP1_ERR_OTHER
	}

	// 解析响应：{"rv": 0, "data": {"cbor_resp": "<base64>"}}
	var wrapper struct {
		RV   uint32 `json:"rv"`
		Data struct {
			CBORResp []byte `json:"cbor_resp"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respJSON, &wrapper); err != nil {
		slog.Error("解析 IPC 响应失败", "error", err)
		return []byte{0x7F}
	}

	if wrapper.RV != 0 {
		// 将 PKCS#11 错误码转换为 CTAP2 错误码
		return []byte{ctap2ErrFromRV(wrapper.RV)}
	}

	// 返回 [0x00 成功][CBOR 响应]
	return append([]byte{0x00}, wrapper.Data.CBORResp...)
}

// handleGetInfo 处理 authenticatorGetInfo，直接调用 IPC。
func (p *IPCCTAPProxy) handleGetInfo() []byte {
	req := map[string]interface{}{}
	reqJSON, _ := json.Marshal(req)

	respJSON, err := ipcCall(cmdFIDOGetInfo, reqJSON)
	if err != nil {
		slog.Error("GetInfo IPC 调用失败", "error", err)
		return []byte{0x7F}
	}

	var wrapper struct {
		RV   uint32 `json:"rv"`
		Data struct {
			CBORInfo []byte `json:"cbor_info"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respJSON, &wrapper); err != nil {
		slog.Error("解析 GetInfo 响应失败", "error", err)
		return []byte{0x7F}
	}

	if wrapper.RV != 0 {
		return []byte{ctap2ErrFromRV(wrapper.RV)}
	}

	return append([]byte{0x00}, wrapper.Data.CBORInfo...)
}

// ctap2ErrFromRV 将 PKCS#11 返回值转换为 CTAP2 错误码。
func ctap2ErrFromRV(rv uint32) byte {
	// CKR_USER_NOT_LOGGED_IN → CTAP2_ERR_PIN_REQUIRED
	if rv == 0x00000101 {
		return 0x36
	}
	// CKR_FUNCTION_FAILED → CTAP1_ERR_OTHER
	return 0x7F
}