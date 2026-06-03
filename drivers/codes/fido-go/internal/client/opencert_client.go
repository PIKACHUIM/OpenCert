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
type IPCCTAPProxy struct {
	// OnPINSuccess 在 PIN 登录成功后被调用。
	// 用于触发 USB/IP 设备重启（detach + re-attach），
	// 让 Windows 重新发现设备并发起新请求（此时卡片已登录）。
	OnPINSuccess func()
}

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
		RV   uint32          `json:"rv"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(respJSON, &wrapper); err != nil {
		slog.Error("解析 IPC 响应失败", "error", err)
		return []byte{0x7F}
	}

	slog.Info("IPC 响应", "cmd", fmt.Sprintf("0x%02X", cmd), "rv", wrapper.RV, "dataLen", len(wrapper.Data))

	// 如果返回 CTAP2_ERR_PIN_REQUIRED (0x36)，弹出 PIN 对话框并重试
	if wrapper.RV == 0x36 && (cmd == 0x01 || cmd == 0x02) {
		slog.Info("收到 PIN_REQUIRED，准备弹出 PIN 对话框")
		result := p.handlePINRequired(wrapper.Data, ipcCmd, reqJSON)
		if result != nil {
			return result
		}
		// PIN 对话框失败/取消，返回原始错误
		slog.Warn("PIN 对话框返回 nil，返回 CTAP2_ERR_PIN_REQUIRED")
		return []byte{0x36}
	}

	if wrapper.RV != 0 {
		return []byte{ctap2ErrFromRV(wrapper.RV)}
	}

	// 解析 cbor_resp
	var dataResp struct {
		CBORResp []byte `json:"cbor_resp"`
	}
	if err := json.Unmarshal(wrapper.Data, &dataResp); err != nil {
		slog.Error("解析 cbor_resp 失败", "error", err)
		return []byte{0x7F}
	}

	// 返回 [0x00 成功][CBOR 响应]
	return append([]byte{0x00}, dataResp.CBORResp...)
}

// handlePINRequired 处理 PIN_REQUIRED 错误：弹出对话框让用户选择卡片并输入 PIN。
func (p *IPCCTAPProxy) handlePINRequired(data json.RawMessage, ipcCmd uint32, reqJSON []byte) []byte {
	slog.Info("handlePINRequired: 开始处理", "dataRaw", string(data))

	// 解析卡片列表
	var cardList struct {
		Cards []CardInfo `json:"cards"`
	}
	if err := json.Unmarshal(data, &cardList); err != nil || len(cardList.Cards) == 0 {
		slog.Error("解析卡片列表失败", "error", err, "data", string(data))
		return nil
	}

	slog.Info("FIDO2 需要 PIN 认证", "cards", len(cardList.Cards))

	// 弹出 PIN 对话框（卡片选择 + PIN 输入）
	result, err := PromptPIN(cardList.Cards)
	if err != nil {
		slog.Warn("用户取消了 PIN 输入", "error", err)
		return nil
	}

	// 调用 CmdFIDOLogin 登录
	loginReq := map[string]string{
		"card_uuid": result.CardUUID,
		"pin":       result.PIN,
	}
	loginJSON, _ := json.Marshal(loginReq)

	loginResp, err := ipcCall(cmdFIDOLogin, loginJSON)
	if err != nil {
		slog.Error("FIDO Login IPC 调用失败", "error", err)
		return nil
	}

	var loginWrapper struct {
		RV uint32 `json:"rv"`
	}
	if err := json.Unmarshal(loginResp, &loginWrapper); err != nil || loginWrapper.RV != 0 {
		slog.Warn("FIDO Login 失败", "rv", loginWrapper.RV)
		return nil
	}

	slog.Info("FIDO Login 成功")

	// PIN 登录成功后，触发 USB/IP 重启回调。
	// 不再重试原始请求（因为 Windows 可能已超时），
	// 而是通过 detach + re-attach 让 Windows 重新发现设备并发起新请求。
	if p.OnPINSuccess != nil {
		go p.OnPINSuccess()
	}

	// 返回 CTAP2_ERR_OPERATION_DENIED (0x27)，让当前请求优雅失败。
	// Windows 会在设备重新 attach 后自动重试。
	return []byte{0x27}
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