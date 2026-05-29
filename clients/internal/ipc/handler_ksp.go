// Package ipc - KSP 专用命令处理器。
//
// Windows KSP DLL 通过这些命令直接按容器名执行签名/解密操作，
// 无需走 PKCS#11 的 Session 模型（OpenSession → Login → SignInit → Sign）。
//
// 容器名格式：OpenCert_<card_uuid>_<cert_uuid>
//
// PIN 登录流程：
//  1. KSP DLL 调用 CmdKSPGetKeyInfo/CmdKSPSign 等命令
//  2. 后端发现 Slot 未登录，返回 CKR_USER_NOT_LOGGED_IN (0x100)
//  3. KSP DLL 弹出 PIN 输入对话框
//  4. 用户输入 PIN 后，KSP DLL 调用 CmdKSPLogin 发送 PIN
//  5. 后端执行 Login，加载对象，启动自动 Logout 定时器
//  6. KSP DLL 重试原始操作
package ipc

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/globaltrusts/client-card/internal/card"
	"github.com/globaltrusts/client-card/pkg/pkcs11types"
)

// containerPrefix 是 KSP 容器名前缀。
const containerPrefix = "OpenCert_"

// defaultPINCacheTTL 是 PIN 缓存的默认有效期（15 分钟）。
const defaultPINCacheTTL = 15 * time.Minute

// pinCacheManager 管理 Slot 的 PIN 缓存和自动 Logout 定时器。
type pinCacheManager struct {
	mu     sync.Mutex
	timers map[pkcs11types.SlotID]*time.Timer
	ttl    time.Duration
}

// newPINCacheManager 创建 PIN 缓存管理器。
func newPINCacheManager() *pinCacheManager {
	return &pinCacheManager{
		timers: make(map[pkcs11types.SlotID]*time.Timer),
		ttl:    defaultPINCacheTTL,
	}
}

// refreshTimer 刷新指定 Slot 的自动 Logout 定时器。
// 每次成功使用密钥后调用，延长 PIN 缓存有效期。
func (m *pinCacheManager) refreshTimer(slotID pkcs11types.SlotID, slot card.SlotProvider) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 取消旧定时器
	if t, ok := m.timers[slotID]; ok {
		t.Stop()
	}

	// 创建新定时器
	m.timers[slotID] = time.AfterFunc(m.ttl, func() {
		slog.Info("PIN 缓存过期，自动 Logout", "slotID", slotID)
		_ = slot.Logout(context.Background())
		m.mu.Lock()
		delete(m.timers, slotID)
		m.mu.Unlock()
	})
}

// cancelTimer 取消指定 Slot 的定时器（手动 Logout 时调用）。
func (m *pinCacheManager) cancelTimer(slotID pkcs11types.SlotID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t, ok := m.timers[slotID]; ok {
		t.Stop()
		delete(m.timers, slotID)
	}
}

// pinCache 是全局 PIN 缓存管理器实例。
var pinCache = newPINCacheManager()

// RegisterKSPHandlers 注册 KSP 专用命令到 IPC Server。
func (h *PKCSHandler) RegisterKSPHandlers(s *Server) {
	s.Register(CmdKSPEnumKeys, h.handleKSPEnumKeys)
	s.Register(CmdKSPGetKeyInfo, h.handleKSPGetKeyInfo)
	s.Register(CmdKSPSign, h.handleKSPSign)
	s.Register(CmdKSPDecrypt, h.handleKSPDecrypt)
	s.Register(CmdKSPLogin, h.handleKSPLogin)
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

type kspLoginReq struct {
	CardUUID string `json:"card_uuid"` // 卡片 UUID（完整或前缀）
	PIN      string `json:"pin"`       // 用户输入的 PIN
}

// ---- Handler 实现 ----

// handleKSPLogin 处理 KSP PIN 登录请求。
// KSP DLL 在收到 CKR_USER_NOT_LOGGED_IN 后弹出 PIN 输入框，
// 用户输入 PIN 后通过此命令发送给后端。
func (h *PKCSHandler) handleKSPLogin(ctx context.Context, req *Frame) (interface{}, uint32) {
	var r kspLoginReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}

	if r.PIN == "" {
		return nil, uint32(pkcs11types.CKR_PIN_INVALID)
	}

	// 查找匹配的 Slot
	slot, slotID := h.findSlotByCardUUID(r.CardUUID)
	if slot == nil {
		slog.Warn("KSP Login: 找不到匹配的卡片", "cardUUID", r.CardUUID)
		return nil, uint32(pkcs11types.CKR_SLOT_ID_INVALID)
	}

	// 如果已经登录，直接刷新定时器
	if slot.IsLoggedIn() {
		pinCache.refreshTimer(slotID, slot)
		slog.Info("KSP Login: 已登录，刷新 PIN 缓存", "slotID", slotID)
		return nil, uint32(pkcs11types.CKR_OK)
	}

	// 执行 Login
	if err := slot.Login(ctx, pkcs11types.CKU_USER, r.PIN); err != nil {
		slog.Warn("KSP Login: PIN 验证失败", "slotID", slotID, "error", err)
		// 根据错误类型返回对应的 PKCS#11 错误码
		if strings.Contains(err.Error(), "PIN_LOCKED") || strings.Contains(err.Error(), "已锁定") {
			return nil, uint32(pkcs11types.CKR_PIN_LOCKED)
		}
		return nil, uint32(pkcs11types.CKR_PIN_INCORRECT)
	}

	// 登录成功，启动自动 Logout 定时器
	pinCache.refreshTimer(slotID, slot)
	slog.Info("KSP Login: 登录成功", "slotID", slotID, "ttl", pinCache.ttl)

	return nil, uint32(pkcs11types.CKR_OK)
}

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

		// 如果 Slot 未登录，跳过（需要先 Login 才能枚举）
		if !slot.IsLoggedIn() {
			continue
		}

		// 构建查找私钥的模板
		classBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(classBytes, uint32(pkcs11types.CKO_PRIVATE_KEY))

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
						kt := binary.BigEndian.Uint32(attr.Value)
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
						entry.Bits = int(binary.BigEndian.Uint32(attr.Value))
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

	slot, handle, rv := h.resolveContainer(ctx, r.Container)
	if rv == uint32(pkcs11types.CKR_USER_NOT_LOGGED_IN) {
		// 返回卡片信息，供 KSP DLL 在 PIN 弹窗中显示
		cardInfo := h.getCardInfoForContainer(r.Container)
		return cardInfo, rv
	}
	if rv != uint32(pkcs11types.CKR_OK) {
		return nil, rv
	}

	attrs, err := slot.GetAttributes(ctx, handle, []pkcs11types.AttributeType{
		pkcs11types.CKA_KEY_TYPE,
		pkcs11types.CKA_MODULUS_BITS,
		pkcs11types.CKA_PUBLIC_KEY_INFO,
	})
	if err != nil {
		slog.Warn("KSP GetKeyInfo: GetAttributes 失败", "error", err)
		return nil, uint32(pkcs11types.CKR_FUNCTION_FAILED)
	}

	// 刷新 PIN 缓存定时器
	pinCache.refreshTimer(slot.SlotID(), slot)

	resp := &kspGetKeyInfoResp{}
	for _, attr := range attrs {
		slog.Debug("KSP GetKeyInfo: 属性",
			"type", fmt.Sprintf("0x%04X", attr.Type),
			"valueLen", len(attr.Value),
			"valueHex", fmt.Sprintf("%x", attr.Value))
		switch attr.Type {
		case pkcs11types.CKA_KEY_TYPE:
			if len(attr.Value) >= 4 {
				kt := binary.BigEndian.Uint32(attr.Value)
				slog.Debug("KSP GetKeyInfo: CKA_KEY_TYPE 解析", "raw", kt)
				switch kt {
				case 0x00:
					resp.Algorithm = "RSA"
				case 0x03:
					resp.Algorithm = "ECDSA"
				}
			} else {
				slog.Warn("KSP GetKeyInfo: CKA_KEY_TYPE 值长度不足", "len", len(attr.Value))
			}
		case pkcs11types.CKA_MODULUS_BITS:
			if len(attr.Value) >= 4 {
				resp.Bits = int(binary.BigEndian.Uint32(attr.Value))
				slog.Debug("KSP GetKeyInfo: CKA_MODULUS_BITS 解析", "bits", resp.Bits)
			} else {
				slog.Warn("KSP GetKeyInfo: CKA_MODULUS_BITS 值长度不足", "len", len(attr.Value))
			}
		case pkcs11types.CKA_PUBLIC_KEY_INFO:
			resp.PublicKey = attr.Value
		}
	}
	slog.Info("KSP GetKeyInfo: 最终结果", "algorithm", resp.Algorithm, "bits", resp.Bits, "pubKeyLen", len(resp.PublicKey))

	return resp, uint32(pkcs11types.CKR_OK)
}

// handleKSPSign 按容器名直接签名。
//
// 重要：Windows KSP 调用 NCryptSignHash 时，pbHashValue 是已经计算好的哈希值。
// 因此不能使用 CKM_SHA256_RSA_PKCS 等机制（会双重哈希），而应：
//   - RSA PKCS1: 构造 DigestInfo + 哈希值，使用 CKM_RSA_PKCS
//   - RSA PSS: 使用 CKM_RSA_PKCS_PSS（接收预哈希数据）
//   - ECDSA: 使用 CKM_ECDSA（接收预哈希数据）
func (h *PKCSHandler) handleKSPSign(ctx context.Context, req *Frame) (interface{}, uint32) {
	var r kspSignReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}

	if len(r.Data) == 0 {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}

	slot, handle, rv := h.resolveContainer(ctx, r.Container)
	if rv != uint32(pkcs11types.CKR_OK) {
		return nil, rv
	}

	// KSP 传入的数据是预哈希值，需要使用不再次哈希的机制
	var mechanism pkcs11types.Mechanism
	var signData []byte = r.Data

	switch strings.ToUpper(r.Algorithm) {
	case "RSA":
		const (
			bcryptPadPKCS1 = 0x00000002
			bcryptPadPSS   = 0x00000008
		)
		if r.Flags&bcryptPadPSS != 0 {
			// PSS: 使用 CKM_RSA_PKCS_PSS（接收预哈希数据，不再次哈希）
			mechanism = pkcs11types.Mechanism{Type: pkcs11types.CKM_RSA_PKCS_PSS}
		} else {
			// PKCS1 v1.5: 构造 DigestInfo + 哈希值，使用 CKM_RSA_PKCS
			prefix, err := digestInfoPrefix(r.HashAlg)
			if err != nil {
				slog.Error("KSP Sign: 无法构造 DigestInfo", "hashAlg", r.HashAlg, "error", err)
				return nil, uint32(pkcs11types.CKR_MECHANISM_INVALID)
			}
			signData = make([]byte, len(prefix)+len(r.Data))
			copy(signData, prefix)
			copy(signData[len(prefix):], r.Data)
			mechanism = pkcs11types.Mechanism{Type: pkcs11types.CKM_RSA_PKCS}
		}
	case "ECDSA", "EC":
		// ECDSA: 使用 CKM_ECDSA（接收预哈希数据，不再次哈希）
		mechanism = pkcs11types.Mechanism{Type: pkcs11types.CKM_ECDSA}
	default:
		mechanism = kspToMechanism(r.Algorithm, r.HashAlg, r.Flags)
	}

	sig, err := slot.Sign(ctx, handle, mechanism, signData)
	if err != nil {
		slog.Error("KSP Sign 失败", "container", r.Container, "error", err)
		return nil, uint32(pkcs11types.CKR_FUNCTION_FAILED)
	}

	// 签名成功，刷新 PIN 缓存定时器
	pinCache.refreshTimer(slot.SlotID(), slot)

	return &kspSignResp{Signature: sig}, uint32(pkcs11types.CKR_OK)
}

// digestInfoPrefix 返回指定哈希算法的 ASN.1 DigestInfo 前缀字节。
// 调用方需将实际哈希值追加到前缀之后，构成完整的 DigestInfo。
//
// DigestInfo ::= SEQUENCE {
//   digestAlgorithm AlgorithmIdentifier,
//   digest OCTET STRING
// }
func digestInfoPrefix(hashAlg string) ([]byte, error) {
	switch strings.ToUpper(hashAlg) {
	case "SHA1":
		// 30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14
		return []byte{
			0x30, 0x21, 0x30, 0x09, 0x06, 0x05,
			0x2b, 0x0e, 0x03, 0x02, 0x1a,
			0x05, 0x00, 0x04, 0x14,
		}, nil
	case "SHA256":
		// 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
		return []byte{
			0x30, 0x31, 0x30, 0x0d, 0x06, 0x09,
			0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
			0x05, 0x00, 0x04, 0x20,
		}, nil
	case "SHA384":
		// 30 41 30 0d 06 09 60 86 48 01 65 03 04 02 02 05 00 04 30
		return []byte{
			0x30, 0x41, 0x30, 0x0d, 0x06, 0x09,
			0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
			0x05, 0x00, 0x04, 0x30,
		}, nil
	case "SHA512":
		// 30 51 30 0d 06 09 60 86 48 01 65 03 04 02 03 05 00 04 40
		return []byte{
			0x30, 0x51, 0x30, 0x0d, 0x06, 0x09,
			0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
			0x05, 0x00, 0x04, 0x40,
		}, nil
	default:
		return nil, fmt.Errorf("不支持的哈希算法: %s", hashAlg)
	}
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

	slot, handle, rv := h.resolveContainer(ctx, r.Container)
	if rv != uint32(pkcs11types.CKR_OK) {
		return nil, rv
	}

	mechanism := kspDecryptToMechanism(r.Algorithm, r.Flags)

	plain, err := slot.Decrypt(ctx, handle, mechanism, r.Data)
	if err != nil {
		slog.Error("KSP Decrypt 失败", "container", r.Container, "error", err)
		return nil, uint32(pkcs11types.CKR_FUNCTION_FAILED)
	}

	// 解密成功，刷新 PIN 缓存定时器
	pinCache.refreshTimer(slot.SlotID(), slot)

	return &kspDecryptResp{Plaintext: plain}, uint32(pkcs11types.CKR_OK)
}

// ---- 辅助方法 ----

// resolveContainer 根据容器名解析出对应的 Slot 和密钥句柄。
// 容器名格式：OpenCert_<card_uuid>_<cert_uuid>
//
// 返回值：
//   - slot, handle, CKR_OK: 成功找到密钥
//   - nil, 0, CKR_USER_NOT_LOGGED_IN: Slot 未登录，需要 PIN
//   - nil, 0, CKR_KEY_HANDLE_INVALID: 其他错误
func (h *PKCSHandler) resolveContainer(ctx context.Context, container string) (card.SlotProvider, pkcs11types.ObjectHandle, uint32) {
	if !strings.HasPrefix(container, containerPrefix) {
		return nil, 0, uint32(pkcs11types.CKR_KEY_HANDLE_INVALID)
	}

	// 解析容器名：OpenCert_<card_uuid>_<cert_uuid>
	parts := strings.TrimPrefix(container, containerPrefix)
	lastUnderscore := strings.LastIndex(parts, "_")
	if lastUnderscore < 0 {
		return nil, 0, uint32(pkcs11types.CKR_KEY_HANDLE_INVALID)
	}

	cardUUID := parts[:lastUnderscore]
	certUUID := parts[lastUnderscore+1:]

	if cardUUID == "" || certUUID == "" {
		return nil, 0, uint32(pkcs11types.CKR_KEY_HANDLE_INVALID)
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
		if !matchCardUUID(info.SerialNumber, cardUUID) {
			continue
		}

		// 找到匹配的 Slot，检查是否已登录
		if !slot.IsLoggedIn() {
			slog.Info("resolveContainer: Slot 未登录，需要 PIN",
				"slotID", slotID, "cardUUID", cardUUID)
			return nil, 0, uint32(pkcs11types.CKR_USER_NOT_LOGGED_IN)
		}

		// 在此 Slot 中查找 CKA_ID == certUUID 的私钥
		classBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(classBytes, uint32(pkcs11types.CKO_PRIVATE_KEY))

		findAttrs := []pkcs11types.Attribute{
			{Type: pkcs11types.CKA_CLASS, Value: classBytes},
			{Type: pkcs11types.CKA_ID, Value: []byte(certUUID)},
		}

		handles, err := slot.FindObjects(ctx, findAttrs)
		if err != nil || len(handles) == 0 {
			// 可能是证书导入后缓存未刷新，尝试 reload 一次
			if reloader, ok := slot.(interface{ ReloadObjects(context.Context) error }); ok {
				if rerr := reloader.ReloadObjects(ctx); rerr == nil {
					handles, err = slot.FindObjects(ctx, findAttrs)
				}
			}
		}
		if err != nil || len(handles) == 0 {
			slog.Warn("resolveContainer: 找不到私钥",
				"container", container, "certUUID", certUUID)
			return nil, 0, uint32(pkcs11types.CKR_KEY_HANDLE_INVALID)
		}

		return slot, handles[0], uint32(pkcs11types.CKR_OK)
	}

	// 没有找到匹配的 Slot
	slog.Warn("resolveContainer: 找不到匹配的卡片", "container", container)
	return nil, 0, uint32(pkcs11types.CKR_KEY_HANDLE_INVALID)
}

// kspCardInfoResp 在返回 CKR_USER_NOT_LOGGED_IN 时附带卡片信息，
// 供 KSP DLL 在 PIN 弹窗中显示卡片名称和 UUID。
type kspCardInfoResp struct {
	CardName string `json:"card_name"` // 卡片名称（如 "OpenCert SmartCard"）
	CardUUID string `json:"card_uuid"` // 卡片完整 UUID
}

// getCardInfoForContainer 从容器名中提取卡片信息。
// 用于在返回 CKR_USER_NOT_LOGGED_IN 时附带卡片名称供 PIN 弹窗显示。
func (h *PKCSHandler) getCardInfoForContainer(container string) *kspCardInfoResp {
	parts := strings.TrimPrefix(container, containerPrefix)
	lastUnderscore := strings.LastIndex(parts, "_")
	if lastUnderscore < 0 {
		return &kspCardInfoResp{CardName: "SmartCard", CardUUID: ""}
	}
	cardUUID := parts[:lastUnderscore]

	// 查找 Slot 获取卡片名称
	slotIDs := h.manager.GetSlotList(true)
	for _, slotID := range slotIDs {
		slot := h.manager.GetSlot(slotID)
		if slot == nil {
			continue
		}
		info := slot.TokenInfo()
		if matchCardUUID(info.SerialNumber, cardUUID) {
			return &kspCardInfoResp{
				CardName: info.Label,
				CardUUID: cardUUID,
			}
		}
	}

	return &kspCardInfoResp{CardName: "SmartCard", CardUUID: cardUUID}
}

// findSlotByCardUUID 根据卡片 UUID 查找 Slot。
func (h *PKCSHandler) findSlotByCardUUID(cardUUID string) (card.SlotProvider, pkcs11types.SlotID) {
	slotIDs := h.manager.GetSlotList(true)
	for _, slotID := range slotIDs {
		slot := h.manager.GetSlot(slotID)
		if slot == nil {
			continue
		}
		info := slot.TokenInfo()
		if matchCardUUID(info.SerialNumber, cardUUID) {
			return slot, slotID
		}
	}
	return nil, 0
}

// matchCardUUID 比较 SerialNumber 和 cardUUID（支持截断匹配）。
func matchCardUUID(serialNumber, cardUUID string) bool {
	if serialNumber == cardUUID {
		return true
	}
	if len(cardUUID) > len(serialNumber) {
		return strings.HasPrefix(cardUUID, serialNumber)
	}
	if len(serialNumber) > len(cardUUID) {
		return strings.HasPrefix(serialNumber, cardUUID)
	}
	return false
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
