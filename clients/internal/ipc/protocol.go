// Package ipc 实现与 pkcs11-mock C 库的 IPC 通信协议。
// 通信方式：Windows 使用 Named Pipe，macOS/Linux 使用 Unix Domain Socket。
// 协议格式：Magic(4B) + Cmd(4B) + Len(4B) + Payload(JSON)
package ipc

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

// 协议魔数，用于帧同步校验。
const Magic uint32 = 0x504B3131 // "PK11"

// 帧头大小：Magic(4) + Cmd(4) + Len(4) = 12 字节。
const HeaderSize = 12

// 最大 Payload 大小：4MB。
const MaxPayloadSize = 4 * 1024 * 1024

// CmdCode 是 PKCS#11 命令码。
type CmdCode uint32

// PKCS#11 命令码定义，对应 C 层的函数调用。
const (
	CmdPing             CmdCode = 0x0000 // 心跳命令
	CmdGetInfo          CmdCode = 0x0001
	CmdGetSlotList      CmdCode = 0x0002
	CmdGetSlotInfo      CmdCode = 0x0003
	CmdGetTokenInfo     CmdCode = 0x0004
	CmdGetMechanismList CmdCode = 0x0005
	CmdGetMechanismInfo CmdCode = 0x0006
	CmdOpenSession      CmdCode = 0x0007
	CmdCloseSession     CmdCode = 0x0008
	CmdCloseAllSessions CmdCode = 0x0009
	CmdLogin            CmdCode = 0x000A
	CmdLogout           CmdCode = 0x000B
	CmdFindObjectsInit  CmdCode = 0x000C
	CmdFindObjects      CmdCode = 0x000D
	CmdFindObjectsFinal CmdCode = 0x000E
	CmdGetAttributeValue CmdCode = 0x000F
	CmdSetAttributeValue CmdCode = 0x0010
	CmdCreateObject     CmdCode = 0x0011
	CmdDestroyObject    CmdCode = 0x0012
	CmdGetObjectSize    CmdCode = 0x0013
	CmdSignInit         CmdCode = 0x0014
	CmdSign             CmdCode = 0x0015
	CmdSignUpdate       CmdCode = 0x0016
	CmdSignFinal        CmdCode = 0x0017
	CmdVerifyInit       CmdCode = 0x0018
	CmdVerify           CmdCode = 0x0019
	CmdDecryptInit      CmdCode = 0x001A
	CmdDecrypt          CmdCode = 0x001B
	CmdEncryptInit      CmdCode = 0x001C
	CmdEncrypt          CmdCode = 0x001D
	CmdGenerateKeyPair  CmdCode = 0x001E
	CmdGenerateRandom   CmdCode = 0x001F
	CmdDigestInit       CmdCode = 0x0020
	CmdDigest           CmdCode = 0x0021
	CmdGetSessionInfo   CmdCode = 0x0022
	CmdInitPIN          CmdCode = 0x0023
	CmdSetPIN           CmdCode = 0x0024
	// 流式 Digest / Verify 与 SeedRandom（v1.1 扩展）
	CmdDigestUpdate     CmdCode = 0x0025
	CmdDigestKey        CmdCode = 0x0026
	CmdDigestFinal      CmdCode = 0x0027
	CmdVerifyUpdate     CmdCode = 0x0028
	CmdVerifyFinal      CmdCode = 0x0029
	CmdSeedRandom       CmdCode = 0x002A
	CmdHandshake        CmdCode = 0x00FF // 版本协商命令

	// CmdSlotChanged 是服务端主动推送事件：卡片（Slot）列表发生变化，
	// 客户端收到后应重置内部 slot 缓存并重新调用 CmdGetSlotList。
	// 该事件不需要请求/响应配对，服务端可随时向所有已建立的长连接广播。
	CmdSlotChanged CmdCode = 0x0100

	// ---- KSP 专用命令（0x0200 系列）----
	// 这些命令供 Windows KSP DLL 使用，不需要 PKCS#11 Session 模型，
	// 直接按容器名（container_name）定位密钥并执行操作。

	// CmdKSPEnumKeys 枚举所有可用的密钥容器。
	// 请求: {} (无参数)
	// 响应: {"keys":[{"container":"OpenCert_xxx_yyy","algorithm":"RSA","bits":2048,"has_cert":true},...]}
	CmdKSPEnumKeys CmdCode = 0x0200

	// CmdKSPGetKeyInfo 获取指定容器的密钥属性。
	// 请求: {"container":"OpenCert_xxx_yyy"}
	// 响应: {"algorithm":"RSA","bits":2048,"public_key":"base64..."}
	CmdKSPGetKeyInfo CmdCode = 0x0201

	// CmdKSPSign 按容器名直接签名（无需 Session/Login）。
	// 请求: {"container":"OpenCert_xxx_yyy","algorithm":"RSA","hash_alg":"SHA256","data":"base64...","flags":0}
	// 响应: {"signature":"base64..."}
	CmdKSPSign CmdCode = 0x0202

	// CmdKSPDecrypt 按容器名直接解密。
	// 请求: {"container":"OpenCert_xxx_yyy","algorithm":"RSA","data":"base64...","flags":0}
	// 响应: {"plaintext":"base64..."}
	CmdKSPDecrypt CmdCode = 0x0203

	// CmdKSPLogin 为指定卡片执行 PIN 登录（KSP 场景下由 DLL 弹窗获取 PIN）。
	// 请求: {"card_uuid":"xxx","pin":"1234"}
	// 响应: {} (成功时 rv=0，失败时 rv=CKR_PIN_INCORRECT 等)
	CmdKSPLogin CmdCode = 0x0204

	// ---- FIDO2 CCID 专用命令（0x0300 系列）----
	// 这些命令供 Windows FIDO2 CCID 虚拟智能卡 DLL 使用。
	// DLL 将浏览器的 CTAP2 CBOR 请求透传给 Go 后端处理，
	// 私钥存储在 OpenCert 智能卡（本地/TPM/云端）。

	// CmdFIDOGetInfo 获取认证器信息（authenticatorGetInfo）。
	// 请求: {} (无参数)
	// 响应: {"cbor_info":"base64..."} CBOR 编码的 GetInfo 响应
	CmdFIDOGetInfo CmdCode = 0x0300

	// CmdFIDOMakeCredential 创建 FIDO2 凭据（authenticatorMakeCredential）。
	// 请求: {"cbor_req":"base64..."} CBOR 编码的 MakeCredential 请求
	// 响应: {"cbor_resp":"base64..."} CBOR 编码的 attestationObject
	CmdFIDOMakeCredential CmdCode = 0x0301

	// CmdFIDOGetAssertion 获取断言（authenticatorGetAssertion）。
	// 请求: {"cbor_req":"base64..."} CBOR 编码的 GetAssertion 请求
	// 响应: {"cbor_resp":"base64..."} CBOR 编码的 assertionObject
	CmdFIDOGetAssertion CmdCode = 0x0302

	// CmdFIDOCancel 取消当前 FIDO2 操作。
	// 请求: {} (无参数)
	// 响应: {} (rv=0 表示成功取消)
	CmdFIDOCancel CmdCode = 0x0303

	// CmdFIDOLogin 为 FIDO2 操作执行 PIN 登录。
	// 请求: {"card_uuid":"xxx","pin":"1234"}
	// 响应: {} (成功时 rv=0)
	CmdFIDOLogin CmdCode = 0x0304
)

// 协议版本号。
const ProtocolVersion uint32 = 1

// HandshakeReq 是版本协商请求。
type HandshakeReq struct {
	Version uint32 `json:"version"`
}

// HandshakeResp 是版本协商响应。
type HandshakeResp struct {
	Version    uint32 `json:"version"`
	Compatible bool   `json:"compatible"`
}

// SlotChangedEvent 是 CmdSlotChanged 事件的 payload。
// Reason 标识变化来源（create/delete/sync 等），便于客户端做差异化处理。
type SlotChangedEvent struct {
	Reason    string `json:"reason"`     // create / delete / update / sync
	Timestamp int64  `json:"timestamp"`  // Unix 秒
}

// Frame 是 IPC 通信帧。
type Frame struct {
	Cmd     CmdCode
	Payload []byte
}

// Request 是 IPC 请求的通用结构（JSON Payload）。
type Request struct {
	SessionID uint32          `json:"session_id,omitempty"`
	SlotID    uint32          `json:"slot_id,omitempty"`
	Data      json.RawMessage `json:"data,omitempty"`
}

// Response 是 IPC 响应的通用结构（JSON Payload）。
type Response struct {
	RV   uint32          `json:"rv"`            // CK_RV 返回码
	Data json.RawMessage `json:"data,omitempty"` // 各命令特定数据
}

// WriteFrame 向 writer 写入一个 IPC 帧。
func WriteFrame(w io.Writer, cmd CmdCode, payload []byte) error {
	if len(payload) > MaxPayloadSize {
		return fmt.Errorf("payload 超过最大限制 %d 字节", MaxPayloadSize)
	}

	header := make([]byte, HeaderSize)
	binary.BigEndian.PutUint32(header[0:4], Magic)
	binary.BigEndian.PutUint32(header[4:8], uint32(cmd))
	binary.BigEndian.PutUint32(header[8:12], uint32(len(payload)))

	if _, err := w.Write(header); err != nil {
		return fmt.Errorf("写入帧头失败: %w", err)
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return fmt.Errorf("写入 payload 失败: %w", err)
		}
	}
	return nil
}

// ReadFrame 从 reader 读取一个 IPC 帧。
func ReadFrame(r io.Reader) (*Frame, error) {
	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("读取帧头失败: %w", err)
	}

	magic := binary.BigEndian.Uint32(header[0:4])
	if magic != Magic {
		return nil, fmt.Errorf("魔数不匹配: 期望 0x%08X，实际 0x%08X", Magic, magic)
	}

	cmd := CmdCode(binary.BigEndian.Uint32(header[4:8]))
	payloadLen := binary.BigEndian.Uint32(header[8:12])

	if payloadLen > MaxPayloadSize {
		return nil, fmt.Errorf("payload 长度 %d 超过最大限制", payloadLen)
	}

	payload := make([]byte, payloadLen)
	if payloadLen > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, fmt.Errorf("读取 payload 失败: %w", err)
		}
	}

	return &Frame{Cmd: cmd, Payload: payload}, nil
}

// WriteResponse 向 writer 写入一个响应帧。
func WriteResponse(w io.Writer, cmd CmdCode, rv uint32, data interface{}) error {
	resp := Response{RV: rv}
	if data != nil {
		b, err := json.Marshal(data)
		if err != nil {
			return fmt.Errorf("序列化响应数据失败: %w", err)
		}
		resp.Data = b
	}

	payload, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("序列化响应失败: %w", err)
	}

	return WriteFrame(w, cmd, payload)
}

// ParseRequest 解析请求帧的 Payload。
func ParseRequest(payload []byte, out interface{}) error {
	if err := json.Unmarshal(payload, out); err != nil {
		return fmt.Errorf("解析请求失败: %w", err)
	}
	return nil
}

// ParseResponse 解析响应帧的 Payload，返回 Response 结构。
func ParseResponse(payload []byte) (*Response, error) {
	var resp Response
	if err := json.Unmarshal(payload, &resp); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}
	return &resp, nil
}