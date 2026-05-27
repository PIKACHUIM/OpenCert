// Package ipc - KSP 专用命令处理器。
//
// Windows KSP DLL 通过这些命令直接按容器名执行签名/解密操作，
// 无需走 PKCS#11 的 Session 模型（OpenSession → Login → SignInit → Sign）。
//
// 容器名格式：OpenCert_<card_uuid>_<cert_uuid>
package ipc

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"strings"

	"github.com/globaltrusts/client-card/internal/card"
	"github.com/globaltrusts/client-card/pkg/pkcs11types"
)

// containerPrefix 是 KSP 容器名前缀。
const containerPrefix = "OpenCert_"

// RegisterKSPHandlers 注册 KSP 专用命令到 IPC Server。
func (h *PKCSHandler) RegisterKSPHandlers(s *Server) {
	s.Register(CmdKSPEnumKeys, h.handleKSPEnumKeys)
	s.Register(CmdKSPGetKeyInfo, h.handleKSPGetKeyInfo)
	s.Register(CmdKSPSign, h.handleKSPSign)
	s.Register(CmdKSPDecrypt, h.handleKSPDecrypt)
}

// ---- 请求/响应结构 ----

type kspEnumKeysResp struct {
	Keys []kspKeyEntry `json:"keys"`
}

type kspKeyEntry struct {
	Container string `json:"container"`
	Algorithm string `json:"algorithm"`
	Bits      int    `json:"bits"`
	HasCert   bool   `json:"has_cert"`
}

type kspGetKeyInfoReq struct {
	Container string `json:"container"`
}

type kspGetKeyInfoResp struct {
	Algorithm string `json:"algorithm"`
	Bits      int    `json:"bits"`
	PublicKey []byte `json:"public_key,omitempty"` // DER 编码的公钥
}

type kspSignReq struct {
	Container string `json:"container"`
	Algorithm string `json:"algorithm"` // "RSA" 或 "ECDSA"
	HashAlg   string `json:"hash_alg"`  // "SHA256", "SHA384", "SHA512"
	Data      []byte `json:"data"`      // 待签名的哈希值
	Flags     uint32 `json:"flags"`     // BCRYPT_PAD_PKCS1 = 2, BCRYPT_PAD_PSS = 8
}

type kspSignResp struct {
	Signature []byte `json:"signature"`
}

type kspDecryptReq struct {
	Container string `json:"container"`
	Algorithm string `json:"algorithm"`
	Data      []byte `json:"data"`  // 密文
	Flags     uint32 `json:"flags"` // BCRYPT_PAD_PKCS1 = 2, BCRYPT_PAD_OAEP = 4
}

type kspDecryptResp struct {
	Plaintext []byte `json:"plaintext"`
}

// ---- Handler 实现 ----

// handleKSPEnumKeys 枚举所有可用的密钥容器。
func (h *PKCSHandler) handleKSPEnumKeys(ctx context.Context, req *Frame) (interface{}, uint32) {
	resp := &kspEnumKeysResp{Keys: make([]kspKeyEntry, 0)}

	// 遍历所有 Slot，查找私钥对象
	slotIDs := h.manager.GetSlotList(true)
	for _, slotID := range slotIDs {
		slot := h.manager.GetSlot(slotID)
		if slot == nil {
			continue
		}

		// 构建查找私钥的模板
		classBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(classBytes, uint32(pkcs11types.CKO_PRIVATE_KEY))

		handles, err := slot.FindObjects(ctx, []pkcs11types.Attribute{
			{Type: pkcs11types.CKA_CLASS, Value: classBytes},
		})
		if err != nil || len(handles) == 0 {
			continue
		}

		info := slot.TokenInfo()
		for _, handle := range handles {
			attrs, err := slot.GetAttributes(ctx, handle, []pkcs11types.AttributeType{
				pkcs11types.CKA_ID,
				pkcs11types.CKA_KEY_TYPE,
				pkcs11types.CKA_MODULUS_BITS,
			})
			if err != nil {
				continue
			}

			entry := kspKeyEntry{HasCert: true}
			var certUUID string

			for _, attr := range attrs {
				switch attr.Type {
				case pkcs11types.CKA_ID:
					certUUID = string(attr.Value)
				case pkcs11types.CKA_KEY_TYPE:
					if len(attr.Value) >= 4 {
						kt := binary.LittleEndian.Uint32(attr.Value)
						switch kt {
						case 0x00: // CKK_RSA
							entry.Algorithm = "RSA"
						case 0x03: // CKK_EC
							entry.Algorithm = "ECDSA"
						default:
							entry.Algorithm = "UNKNOWN"
						}
					}
				case pkcs11types.CKA_MODULUS_BITS:
					if len(attr.Value) >= 4 {
						entry.Bits = int(binary.LittleEndian.Uint32(attr.Value))
					}
				}
			}

			if certUUID != "" {
				cardUUID := info.SerialNumber
				entry.Container = containerPrefix + cardUUID + "_" + certUUID
				resp.Keys = append(resp.Keys, entry)
			}
		}
	}

	return resp, uint32(pkcs11types.CKR_OK)
}

// handleKSPGetKeyInfo 获取指定容器的密钥属性。
func (h *PKCSHandler) handleKSPGetKeyInfo(ctx context.Context, req *Frame) (interface{}, uint32) {
	var r kspGetKeyInfoReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}

	slot, handle, err := h.resolveContainer(ctx, r.Container)
	if err != nil {
		slog.Warn("KSP GetKeyInfo: 容器解析失败", "container", r.Container, "error", err)
		return nil, uint32(pkcs11types.CKR_KEY_HANDLE_INVALID)
	}

	attrs, err := slot.GetAttributes(ctx, handle, []pkcs11types.AttributeType{
		pkcs11types.CKA_KEY_TYPE,
		pkcs11types.CKA_MODULUS_BITS,
		pkcs11types.CKA_PUBLIC_KEY_INFO,
	})
	if err != nil {
		return nil, uint32(pkcs11types.CKR_FUNCTION_FAILED)
	}

	resp := &kspGetKeyInfoResp{}
	for _, attr := range attrs {
		switch attr.Type {
		case pkcs11types.CKA_KEY_TYPE:
			if len(attr.Value) >= 4 {
				kt := binary.LittleEndian.Uint32(attr.Value)
				switch kt {
				case 0x00:
					resp.Algorithm = "RSA"
				case 0x03:
					resp.Algorithm = "ECDSA"
				}
			}
		case pkcs11types.CKA_MODULUS_BITS:
			if len(attr.Value) >= 4 {
				resp.Bits = int(binary.LittleEndian.Uint32(attr.Value))
			}
		case pkcs11types.CKA_PUBLIC_KEY_INFO:
			resp.PublicKey = attr.Value
		}
	}

	return resp, uint32(pkcs11types.CKR_OK)
}

// handleKSPSign 按容器名直接签名。
func (h *PKCSHandler) handleKSPSign(ctx context.Context, req *Frame) (interface{}, uint32) {
	var r kspSignReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}

	if len(r.Data) == 0 {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}

	slot, handle, err := h.resolveContainer(ctx, r.Container)
	if err != nil {
		slog.Warn("KSP Sign: 容器解析失败", "container", r.Container, "error", err)
		return nil, uint32(pkcs11types.CKR_KEY_HANDLE_INVALID)
	}

	// 将 KSP 的算法/哈希参数映射到 PKCS#11 Mechanism
	mechanism := kspToMechanism(r.Algorithm, r.HashAlg, r.Flags)

	sig, err := slot.Sign(ctx, handle, mechanism, r.Data)
	if err != nil {
		slog.Error("KSP Sign 失败", "container", r.Container, "error", err)
		return nil, uint32(pkcs11types.CKR_FUNCTION_FAILED)
	}

	return &kspSignResp{Signature: sig}, uint32(pkcs11types.CKR_OK)
}

// handleKSPDecrypt 按容器名直接解密。
func (h *PKCSHandler) handleKSPDecrypt(ctx context.Context, req *Frame) (interface{}, uint32) {
	var r kspDecryptReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}

	if len(r.Data) == 0 {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}

	slot, handle, err := h.resolveContainer(ctx, r.Container)
	if err != nil {
		slog.Warn("KSP Decrypt: 容器解析失败", "container", r.Container, "error", err)
		return nil, uint32(pkcs11types.CKR_KEY_HANDLE_INVALID)
	}

	mechanism := kspDecryptToMechanism(r.Algorithm, r.Flags)

	plain, err := slot.Decrypt(ctx, handle, mechanism, r.Data)
	if err != nil {
		slog.Error("KSP Decrypt 失败", "container", r.Container, "error", err)
		return nil, uint32(pkcs11types.CKR_FUNCTION_FAILED)
	}

	return &kspDecryptResp{Plaintext: plain}, uint32(pkcs11types.CKR_OK)
}

// ---- 辅助方法 ----

// resolveContainer 根据容器名解析出对应的 Slot 和密钥句柄。
// 容器名格式：OpenCert_<card_uuid>_<cert_uuid>
func (h *PKCSHandler) resolveContainer(ctx context.Context, container string) (card.SlotProvider, pkcs11types.ObjectHandle, error) {
	if !strings.HasPrefix(container, containerPrefix) {
		return nil, 0, fmt.Errorf("无效的容器名前缀: %s", container)
	}

	// 解析容器名：OpenCert_<card_uuid>_<cert_uuid>
	parts := strings.TrimPrefix(container, containerPrefix)
	lastUnderscore := strings.LastIndex(parts, "_")
	if lastUnderscore < 0 {
		return nil, 0, fmt.Errorf("容器名格式错误: %s", container)
	}

	cardUUID := parts[:lastUnderscore]
	certUUID := parts[lastUnderscore+1:]

	if cardUUID == "" || certUUID == "" {
		return nil, 0, fmt.Errorf("容器名中 card_uuid 或 cert_uuid 为空: %s", container)
	}

	// 在所有 Slot 中查找匹配的卡片
	slotIDs := h.manager.GetSlotList(true)
	for _, slotID := range slotIDs {
		slot := h.manager.GetSlot(slotID)
		if slot == nil {
			continue
		}

		info := slot.TokenInfo()
		// TokenInfo.SerialNumber 存储的是 card UUID（可能截断到 16 字符）
		serialMatch := info.SerialNumber == cardUUID
		if !serialMatch && len(cardUUID) > len(info.SerialNumber) {
			serialMatch = strings.HasPrefix(cardUUID, info.SerialNumber)
		}
		if !serialMatch && len(info.SerialNumber) > len(cardUUID) {
			serialMatch = strings.HasPrefix(info.SerialNumber, cardUUID)
		}
		if !serialMatch {
			continue
		}

		// 在此 Slot 中查找 CKA_ID == certUUID 的私钥
		classBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(classBytes, uint32(pkcs11types.CKO_PRIVATE_KEY))

		handles, err := slot.FindObjects(ctx, []pkcs11types.Attribute{
			{Type: pkcs11types.CKA_CLASS, Value: classBytes},
			{Type: pkcs11types.CKA_ID, Value: []byte(certUUID)},
		})
		if err != nil || len(handles) == 0 {
			continue
		}

		return slot, handles[0], nil
	}

	return nil, 0, fmt.Errorf("未找到容器 %s 对应的密钥", container)
}

// kspToMechanism 将 KSP 的算法参数映射到 PKCS#11 Mechanism。
func kspToMechanism(algorithm, hashAlg string, flags uint32) pkcs11types.Mechanism {
	const (
		bcryptPadPKCS1 = 0x00000002
		bcryptPadPSS   = 0x00000008
	)

	switch strings.ToUpper(algorithm) {
	case "RSA":
		if flags&bcryptPadPSS != 0 {
			switch strings.ToUpper(hashAlg) {
			case "SHA384":
				return pkcs11types.Mechanism{Type: pkcs11types.CKM_SHA384_RSA_PKCS_PSS}
			case "SHA512":
				return pkcs11types.Mechanism{Type: pkcs11types.CKM_SHA512_RSA_PKCS_PSS}
			default:
				return pkcs11types.Mechanism{Type: pkcs11types.CKM_SHA256_RSA_PKCS_PSS}
			}
		}
		switch strings.ToUpper(hashAlg) {
		case "SHA384":
			return pkcs11types.Mechanism{Type: pkcs11types.CKM_SHA384_RSA_PKCS}
		case "SHA512":
			return pkcs11types.Mechanism{Type: pkcs11types.CKM_SHA512_RSA_PKCS}
		case "SHA256":
			return pkcs11types.Mechanism{Type: pkcs11types.CKM_SHA256_RSA_PKCS}
		default:
			return pkcs11types.Mechanism{Type: pkcs11types.CKM_RSA_PKCS}
		}
	case "ECDSA", "EC":
		switch strings.ToUpper(hashAlg) {
		case "SHA384":
			return pkcs11types.Mechanism{Type: pkcs11types.CKM_ECDSA_SHA384}
		case "SHA512":
			return pkcs11types.Mechanism{Type: pkcs11types.CKM_ECDSA_SHA512}
		case "SHA256":
			return pkcs11types.Mechanism{Type: pkcs11types.CKM_ECDSA_SHA256}
		default:
			return pkcs11types.Mechanism{Type: pkcs11types.CKM_ECDSA}
		}
	default:
		return pkcs11types.Mechanism{Type: pkcs11types.CKM_RSA_PKCS}
	}
}

// kspDecryptToMechanism 将 KSP 解密参数映射到 PKCS#11 Mechanism。
func kspDecryptToMechanism(algorithm string, flags uint32) pkcs11types.Mechanism {
	const (
		bcryptPadPKCS1 = 0x00000002
		bcryptPadOAEP  = 0x00000004
	)

	if strings.ToUpper(algorithm) == "RSA" && flags&bcryptPadOAEP != 0 {
		return pkcs11types.Mechanism{Type: pkcs11types.CKM_RSA_PKCS_OAEP}
	}
	return pkcs11types.Mechanism{Type: pkcs11types.CKM_RSA_PKCS}
}