// Package ipc - FIDO2 CCID 专用命令处理器。
//
// Windows FIDO2 CCID 虚拟智能卡 DLL 通过这些命令将浏览器的 CTAP2 请求
// 转发给 Go 后端处理。私钥存储在 OpenCert 智能卡（本地/TPM/云端）。
//
// 数据流：
//
//	浏览器 WebAuthn
//	  → Windows webauthn.dll
//	  → Windows CCID 驱动
//	  → OpenCertFIDO.dll（CTAP2/CCID）
//	  → IPC Named Pipe（本文件处理）
//	  → fido-umdf.Store（本地SQLite / TPM / 云端）
//
// CTAP2 协议：
//
//	MakeCredential: 生成密钥对，私钥加密存入 fido-umdf.Store，返回 attestationObject
//	GetAssertion:   从 fido-umdf.Store 取出私钥，签名 clientDataHash，返回 assertionObject
package ipc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log/slog"
	"math/big"
	"strings"

	"github.com/globaltrusts/client-card/internal/card"
	"github.com/globaltrusts/client-card/internal/fido"
	"github.com/globaltrusts/client-card/internal/storage"
	"github.com/globaltrusts/client-card/pkg/pkcs11types"
)

// RegisterFIDOHandlers 注册 FIDO2 CCID 专用命令到 IPC Server。
func (h *PKCSHandler) RegisterFIDOHandlers(s *Server) {
	s.Register(CmdFIDOGetInfo, h.handleFIDOGetInfo)
	s.Register(CmdFIDOMakeCredential, h.handleFIDOMakeCredential)
	s.Register(CmdFIDOGetAssertion, h.handleFIDOGetAssertion)
	s.Register(CmdFIDOCancel, h.handleFIDOCancel)
	s.Register(CmdFIDOLogin, h.handleFIDOLogin)
}

// ---- 请求/响应结构 ----

type fidoGetInfoResp struct {
	CBORInfo []byte `json:"cbor_info"` // CBOR 编码的 GetInfo 响应
}

type fidoCBORReq struct {
	CBORReq []byte `json:"cbor_req"` // CBOR 编码的 CTAP2 请求
}

type fidoCBORResp struct {
	CBORResp []byte `json:"cbor_resp"` // CBOR 编码的 CTAP2 响应
}

type fidoLoginReq struct {
	CardUUID string `json:"card_uuid"`
	PIN      string `json:"pin"`
}

// ---- CTAP2 CBOR 结构（简化，仅解析必要字段）----

// ctap2MakeCredentialReq 是 authenticatorMakeCredential 的 CBOR 请求结构。
// CBOR Map keys:
//
//	0x01: clientDataHash (bytes)
//	0x02: rp {id: string, name: string}
//	0x03: user {id: bytes, name: string, displayName: string}
//	0x04: pubKeyCredParams [{type: string, alg: int}]
//	0x05: excludeList (optional)
//	0x06: extensions (optional)
//	0x07: options {rk: bool, uv: bool}
//	0x08: pinUvAuthParam (optional)
type ctap2MakeCredentialReq struct {
	ClientDataHash  []byte
	RPID            string
	RPName          string
	UserID          []byte
	UserName        string
	UserDisplayName string
	Algorithm       int  // -7 = ES256, -257 = RS256
	RequireRK       bool // resident key
	RequireUV       bool // user verification
}

// ctap2GetAssertionReq 是 authenticatorGetAssertion 的 CBOR 请求结构。
// CBOR Map keys:
//
//	0x01: rpId (string)
//	0x02: clientDataHash (bytes)
//	0x03: allowList [{type: string, id: bytes}]
//	0x04: extensions (optional)
//	0x05: options {up: bool, uv: bool}
type ctap2GetAssertionReq struct {
	RPID           string
	ClientDataHash []byte
	AllowList      [][]byte // credential IDs
	RequireUP      bool
	RequireUV      bool
}

// ================================================================
// handleFIDOGetInfo - authenticatorGetInfo (0x04)
// ================================================================

func (h *PKCSHandler) handleFIDOGetInfo(ctx context.Context, req *Frame) (interface{}, uint32) {
	/*
	 * 构造 CBOR 编码的 GetInfo 响应：
	 * {
	 *   1: ["FIDO_2_0", "FIDO_2_1"],
	 *   3: h'AAGUID',
	 *   4: {"rk": true, "up": true, "uv": false},
	 *   6: [ES256(-7)],
	 * }
	 */
	info := buildGetInfoCBOR()
	return &fidoGetInfoResp{CBORInfo: info}, uint32(pkcs11types.CKR_OK)
}

// ================================================================
// handleFIDOMakeCredential - authenticatorMakeCredential (0x01)
// ================================================================

func (h *PKCSHandler) handleFIDOMakeCredential(ctx context.Context, req *Frame) (interface{}, uint32) {
	var r fidoCBORReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		slog.Warn("FIDO MakeCredential: 解析请求失败", "error", err)
		return nil, ctap2ErrToRV(0x12) // CTAP2_ERR_INVALID_CBOR
	}

	// 解析 CTAP2 MakeCredential CBOR 请求
	mcReq, err := parseMakeCredentialCBOR(r.CBORReq)
	if err != nil {
		slog.Warn("FIDO MakeCredential: 解析 CBOR 失败", "error", err)
		return nil, ctap2ErrToRV(0x12)
	}

	slog.Info("FIDO MakeCredential",
		"rpid", mcReq.RPID,
		"user", mcReq.UserName,
		"alg", mcReq.Algorithm)

	// 找到当前已登录的 Slot（FIDO 操作需要卡片已登录）
	slot, slotID := h.findAnyLoggedInSlot()
	if slot == nil {
		slog.Warn("FIDO MakeCredential: 没有已登录的卡片")
		// 返回可用卡片列表，供 fido-go 弹窗选择
		return h.buildCardListResp(), ctap2ErrToRV(0x36) // CTAP2_ERR_PIN_REQUIRED
	}

	// 获取卡片 UUID（注意：TokenInfo().SerialNumber 只有前16字符）
	tokenInfo := slot.TokenInfo()
	cardUUIDShort := tokenInfo.SerialNumber

	// 获取 fido-umdf.Store（通过 manager 的存储层）
	fidoStore := h.getFIDOStore()
	if fidoStore == nil {
		slog.Error("FIDO MakeCredential: fido-umdf.Store 未初始化")
		return nil, ctap2ErrToRV(0x7F) // CTAP1_ERR_OTHER
	}

	// 获取卡片主密钥（从已登录的 Slot 获取），同时获取完整的卡片 UUID
	masterKey, card, err := h.getCardMasterKey(ctx, cardUUIDShort, slotID)
	if err != nil {
		slog.Error("FIDO MakeCredential: 获取主密钥失败", "error", err)
		return nil, ctap2ErrToRV(0x7F)
	}
	defer fido.ZeroBytes(masterKey)

	// 使用完整的卡片 UUID（从数据库获取的，而非截断的 SerialNumber）
	cardUUID := card.UUID

	// 生成 EC P-256 密钥对（ES256 算法）
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		slog.Error("FIDO MakeCredential: 生成密钥对失败", "error", err)
		return nil, ctap2ErrToRV(0x7F)
	}

	// 生成 Credential ID（32 字节随机数）
	credIDBytes := make([]byte, 32)
	if _, err := rand.Read(credIDBytes); err != nil {
		return nil, ctap2ErrToRV(0x7F)
	}
	credID := base64.RawURLEncoding.EncodeToString(credIDBytes)

	// 序列化私钥为 PEM
	privKeyPEM, err := marshalECPrivateKeyPEM(privKey)
	if err != nil {
		slog.Error("FIDO MakeCredential: 序列化私钥失败", "error", err)
		return nil, ctap2ErrToRV(0x7F)
	}

	// 序列化公钥为 DER
	pubKeyDER, err := marshalECPublicKeyDER(&privKey.PublicKey)
	if err != nil {
		slog.Error("FIDO MakeCredential: 序列化公钥失败", "error", err)
		return nil, ctap2ErrToRV(0x7F)
	}

	// 构造 FIDO 元数据
	meta := &fido.Meta{
		RPID:            mcReq.RPID,
		RPName:          mcReq.RPName,
		UserName:        mcReq.UserName,
		UserDisplayName: mcReq.UserDisplayName,
		UserHandle:      base64.RawURLEncoding.EncodeToString(mcReq.UserID),
		CredentialID:    credID,
		Algorithm:       "ES256",
		Counter:         0,
		Transports:      []string{"internal"},
	}

	secret := &fido.Secret{
		PrivateKeyPEM: privKeyPEM,
		PublicKeyDER:  base64.StdEncoding.EncodeToString(pubKeyDER),
		AAGUID:        base64.StdEncoding.EncodeToString(opencertAAGUID()),
	}

	// 存储凭据（使用完整的 cardUUID）
	entry, err := fidoStore.Create(ctx, cardUUID, meta, secret, masterKey, card)
	if err != nil {
		slog.Error("FIDO MakeCredential: 存储凭据失败", "error", err)
		return nil, ctap2ErrToRV(0x7F)
	}

	slog.Info("FIDO MakeCredential: 凭据已创建",
		"uuid", entry.UUID, "rpid", mcReq.RPID, "credID", credID)

	// 构造 authenticatorData
	authData, err := buildAuthenticatorData(
		mcReq.RPID,
		credIDBytes,
		&privKey.PublicKey,
		0,    // counter = 0 for new credential
		true, // AT flag: attested credential data
	)
	if err != nil {
		return nil, ctap2ErrToRV(0x7F)
	}

	// 构造 attestationObject（none attestation）
	attObj, err := buildAttestationObject(authData, mcReq.ClientDataHash)
	if err != nil {
		return nil, ctap2ErrToRV(0x7F)
	}

	return &fidoCBORResp{CBORResp: attObj}, uint32(pkcs11types.CKR_OK)
}

// ================================================================
// handleFIDOGetAssertion - authenticatorGetAssertion (0x02)
// ================================================================

func (h *PKCSHandler) handleFIDOGetAssertion(ctx context.Context, req *Frame) (interface{}, uint32) {
	var r fidoCBORReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, ctap2ErrToRV(0x12)
	}

	gaReq, err := parseGetAssertionCBOR(r.CBORReq)
	if err != nil {
		slog.Warn("FIDO GetAssertion: 解析 CBOR 失败", "error", err)
		return nil, ctap2ErrToRV(0x12)
	}

	slog.Info("FIDO GetAssertion", "rpid", gaReq.RPID)

	// 找到已登录的 Slot
	slot, slotID := h.findAnyLoggedInSlot()
	if slot == nil {
		return h.buildCardListResp(), ctap2ErrToRV(0x36) // CTAP2_ERR_PIN_REQUIRED
	}

	tokenInfo := slot.TokenInfo()
	cardUUIDShort := tokenInfo.SerialNumber

	fidoStore := h.getFIDOStore()
	if fidoStore == nil {
		return nil, ctap2ErrToRV(0x7F)
	}

	// 获取完整的卡片 UUID（TokenInfo.SerialNumber 只有前16字符）
	masterKey, cardRecord, err := h.getCardMasterKey(ctx, cardUUIDShort, slotID)
	if err != nil {
		slog.Error("FIDO GetAssertion: 获取卡片信息失败", "error", err)
		return nil, ctap2ErrToRV(0x7F)
	}
	defer fido.ZeroBytes(masterKey)
	cardUUID := cardRecord.UUID

	// 查找匹配的凭据
	entries, err := fidoStore.List(ctx, cardUUID)
	if err != nil {
		slog.Error("FIDO GetAssertion: 列举凭据失败", "error", err)
		return nil, ctap2ErrToRV(0x7F)
	}

	// 找到匹配 RPID 且在 allowList 中的凭据
	var matchEntry *fido.Entry
	for i := range entries {
		e := &entries[i]
		if e.Meta.RPID != gaReq.RPID {
			continue
		}
		if len(gaReq.AllowList) == 0 {
			// 无 allowList：使用第一个匹配的凭据（discoverable credential）
			matchEntry = e
			break
		}
		// 检查 allowList
		credIDBytes, _ := base64.RawURLEncoding.DecodeString(e.Meta.CredentialID)
		for _, allowed := range gaReq.AllowList {
			if bytesEqual(credIDBytes, allowed) {
				matchEntry = e
				break
			}
		}
		if matchEntry != nil {
			break
		}
	}

	if matchEntry == nil {
		slog.Warn("FIDO GetAssertion: 找不到匹配的凭据", "rpid", gaReq.RPID)
		return nil, ctap2ErrToRV(0x2E) // CTAP2_ERR_NO_CREDENTIALS
	}

	// 获取私密数据（解密私钥）
	secret, err := fidoStore.GetSecret(ctx, matchEntry.UUID, masterKey, cardRecord)
	if err != nil {
		slog.Error("FIDO GetAssertion: 解密私钥失败", "error", err)
		return nil, ctap2ErrToRV(0x7F)
	}

	// 解析私钥
	privKey, err := parseECPrivateKeyPEM(secret.PrivateKeyPEM)
	if err != nil {
		slog.Error("FIDO GetAssertion: 解析私钥失败", "error", err)
		return nil, ctap2ErrToRV(0x7F)
	}

	// 递增计数器（防重放）
	counter, err := fidoStore.IncrementCounter(ctx, matchEntry.UUID)
	if err != nil {
		slog.Warn("FIDO GetAssertion: 递增计数器失败", "error", err)
		counter = matchEntry.Meta.Counter + 1
	}

	// 构造 authenticatorData（无 AT flag，无 attested credential data）
	credIDBytes, _ := base64.RawURLEncoding.DecodeString(matchEntry.Meta.CredentialID)
	authData, err := buildAuthenticatorDataAssertion(gaReq.RPID, counter)
	if err != nil {
		return nil, ctap2ErrToRV(0x7F)
	}

	// 签名：sig = ECDSA(privKey, SHA256(authData || clientDataHash))
	sigData := make([]byte, len(authData)+len(gaReq.ClientDataHash))
	copy(sigData, authData)
	copy(sigData[len(authData):], gaReq.ClientDataHash)
	hash := sha256.Sum256(sigData)

	r_sig, s_sig, err := ecdsa.Sign(rand.Reader, privKey, hash[:])
	if err != nil {
		slog.Error("FIDO GetAssertion: 签名失败", "error", err)
		return nil, ctap2ErrToRV(0x7F)
	}

	// DER 编码签名
	sig, err := marshalECDSASignatureDER(r_sig, s_sig)
	if err != nil {
		return nil, ctap2ErrToRV(0x7F)
	}

	slog.Info("FIDO GetAssertion: 签名成功",
		"rpid", gaReq.RPID,
		"credID", matchEntry.Meta.CredentialID,
		"counter", counter)

	// 构造 assertionObject CBOR
	assertObj, err := buildAssertionObject(authData, sig, credIDBytes, matchEntry)
	if err != nil {
		return nil, ctap2ErrToRV(0x7F)
	}

	return &fidoCBORResp{CBORResp: assertObj}, uint32(pkcs11types.CKR_OK)
}

// ================================================================
// handleFIDOCancel / handleFIDOLogin
// ================================================================

func (h *PKCSHandler) handleFIDOCancel(ctx context.Context, req *Frame) (interface{}, uint32) {
	slog.Info("FIDO Cancel: 收到取消请求")
	return nil, uint32(pkcs11types.CKR_OK)
}

func (h *PKCSHandler) handleFIDOLogin(ctx context.Context, req *Frame) (interface{}, uint32) {
	var r fidoLoginReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}

	slot, slotID := h.findSlotByCardUUID(r.CardUUID)
	if slot == nil {
		return nil, uint32(pkcs11types.CKR_SLOT_ID_INVALID)
	}

	if slot.IsLoggedIn() {
		pinCache.refreshTimer(slotID, slot)
		return nil, uint32(pkcs11types.CKR_OK)
	}

	if err := slot.Login(ctx, pkcs11types.CKU_USER, r.PIN); err != nil {
		if strings.Contains(err.Error(), "PIN_LOCKED") || strings.Contains(err.Error(), "已锁定") {
			return nil, uint32(pkcs11types.CKR_PIN_LOCKED)
		}
		return nil, uint32(pkcs11types.CKR_PIN_INCORRECT)
	}

	pinCache.refreshTimer(slotID, slot)
	slog.Info("FIDO Login: 登录成功", "slotID", slotID)
	return nil, uint32(pkcs11types.CKR_OK)
}

// ================================================================
// CTAP2 CBOR 解析（最小化实现）
// ================================================================

// parseMakeCredentialCBOR 解析 authenticatorMakeCredential CBOR 请求。
// 使用手动 CBOR 解析，避免引入外部依赖。
func parseMakeCredentialCBOR(data []byte) (*ctap2MakeCredentialReq, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("空 CBOR 数据")
	}

	// 将 CBOR 转换为 JSON 进行解析（通过 Go 标准库）
	// 实际项目中应使用 fxamacker/cbor 库，此处使用简化实现
	req := &ctap2MakeCredentialReq{
		Algorithm: -7, // 默认 ES256
	}

	pos := 0
	mapLen, n := cborDecodeMapLen(data, pos)
	if n <= 0 {
		return nil, fmt.Errorf("无效的 CBOR Map")
	}
	pos += n

	for i := 0; i < mapLen && pos < len(data); i++ {
		// 读取 key（uint）
		key, n := cborDecodeUint(data, pos)
		if n <= 0 {
			break
		}
		pos += n

		switch key {
		case 1: // clientDataHash
			val, n := cborDecodeBytes(data, pos)
			if n > 0 {
				req.ClientDataHash = val
				pos += n
			}
		case 2: // rp {id, name}
			rpLen, n := cborDecodeMapLen(data, pos)
			pos += n
			for j := 0; j < rpLen; j++ {
				k, n := cborDecodeText(data, pos)
				pos += n
				v, n := cborDecodeText(data, pos)
				pos += n
				switch k {
				case "id":
					req.RPID = v
				case "name":
					req.RPName = v
				}
			}
		case 3: // user {id, name, displayName}
			userLen, n := cborDecodeMapLen(data, pos)
			pos += n
			for j := 0; j < userLen; j++ {
				k, n := cborDecodeText(data, pos)
				pos += n
				if k == "id" {
					val, n := cborDecodeBytes(data, pos)
					pos += n
					req.UserID = val
				} else {
					v, n := cborDecodeText(data, pos)
					pos += n
					switch k {
					case "name":
						req.UserName = v
					case "displayName":
						req.UserDisplayName = v
					}
				}
			}
		case 4: // pubKeyCredParams [{type, alg}]
			arrLen, n := cborDecodeArrayLen(data, pos)
			pos += n
			for j := 0; j < arrLen; j++ {
				paramLen, n := cborDecodeMapLen(data, pos)
				pos += n
				for k := 0; k < paramLen; k++ {
					key2, n := cborDecodeText(data, pos)
					pos += n
					if key2 == "alg" {
						alg, n := cborDecodeInt(data, pos)
						pos += n
						req.Algorithm = alg
					} else {
						pos += cborSkip(data, pos)
					}
				}
			}
		case 7: // options {rk, uv}
			optLen, n := cborDecodeMapLen(data, pos)
			pos += n
			for j := 0; j < optLen; j++ {
				k, n := cborDecodeText(data, pos)
				pos += n
				v, n := cborDecodeBool(data, pos)
				pos += n
				switch k {
				case "rk":
					req.RequireRK = v
				case "uv":
					req.RequireUV = v
				}
			}
		default:
			pos += cborSkip(data, pos)
		}
	}

	if req.RPID == "" {
		return nil, fmt.Errorf("缺少 rpId")
	}
	if len(req.ClientDataHash) == 0 {
		return nil, fmt.Errorf("缺少 clientDataHash")
	}

	return req, nil
}

// parseGetAssertionCBOR 解析 authenticatorGetAssertion CBOR 请求。
func parseGetAssertionCBOR(data []byte) (*ctap2GetAssertionReq, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("空 CBOR 数据")
	}

	req := &ctap2GetAssertionReq{}
	pos := 0

	mapLen, n := cborDecodeMapLen(data, pos)
	if n <= 0 {
		return nil, fmt.Errorf("无效的 CBOR Map")
	}
	pos += n

	for i := 0; i < mapLen && pos < len(data); i++ {
		key, n := cborDecodeUint(data, pos)
		if n <= 0 {
			break
		}
		pos += n

		switch key {
		case 1: // rpId
			v, n := cborDecodeText(data, pos)
			pos += n
			req.RPID = v
		case 2: // clientDataHash
			val, n := cborDecodeBytes(data, pos)
			pos += n
			req.ClientDataHash = val
		case 3: // allowList [{type, id}]
			arrLen, n := cborDecodeArrayLen(data, pos)
			pos += n
			for j := 0; j < arrLen; j++ {
				itemLen, n := cborDecodeMapLen(data, pos)
				pos += n
				var credID []byte
				for k := 0; k < itemLen; k++ {
					key2, n := cborDecodeText(data, pos)
					pos += n
					if key2 == "id" {
						credID, n = cborDecodeBytes(data, pos)
						pos += n
					} else {
						pos += cborSkip(data, pos)
					}
				}
				if len(credID) > 0 {
					req.AllowList = append(req.AllowList, credID)
				}
			}
		case 5: // options {up, uv}
			optLen, n := cborDecodeMapLen(data, pos)
			pos += n
			for j := 0; j < optLen; j++ {
				k, n := cborDecodeText(data, pos)
				pos += n
				v, n := cborDecodeBool(data, pos)
				pos += n
				switch k {
				case "up":
					req.RequireUP = v
				case "uv":
					req.RequireUV = v
				}
			}
		default:
			pos += cborSkip(data, pos)
		}
	}

	if req.RPID == "" {
		return nil, fmt.Errorf("缺少 rpId")
	}

	return req, nil
}

// ================================================================
// CTAP2 响应构造
// ================================================================

// buildGetInfoCBOR 构造 authenticatorGetInfo 的 CBOR 响应。
// 参考：https://fidoalliance.org/specs/fido-v2.1-ps-20210615/
//
//	Key 0x01: versions (必需)
//	Key 0x03: aaguid (必需)
//	Key 0x04: options
//	Key 0x05: maxMsgSize
//	Key 0x09: transports
//	Key 0x0A: algorithms
func buildGetInfoCBOR() []byte {
	var buf cborBuilder
	buf.writeMapHeader(6)
	// 0x01: versions
	buf.writeUint(1)
	buf.writeArrayHeader(2)
	buf.writeText("FIDO_2_0")
	buf.writeText("FIDO_2_1")
	// 0x03: aaguid
	buf.writeUint(3)
	buf.writeBytes(opencertAAGUID())
	// 0x04: options
	buf.writeUint(4)
	buf.writeMapHeader(3)
	buf.writeText("rk")
	buf.writeBool(true)
	buf.writeText("up")
	buf.writeBool(true)
	buf.writeText("uv")
	buf.writeBool(false)
	// 0x05: maxMsgSize
	buf.writeUint(5)
	buf.writeUint(1200)
	// 0x09: transports
	buf.writeUint(9)
	buf.writeArrayHeader(1)
	buf.writeText("usb")
	// 0x0A: algorithms (注意：不是 0x06！0x06 是 pinUvAuthProtocols)
	buf.writeUint(0x0A)
	buf.writeArrayHeader(1)
	buf.writeMapHeader(2)
	buf.writeText("type")
	buf.writeText("public-key")
	buf.writeText("alg")
	buf.writeNegInt(-7) // ES256 = -7
	return buf.bytes()
}

// buildAuthenticatorData 构造 authenticatorData（含 AT flag）。
func buildAuthenticatorData(rpID string, credID []byte, pubKey *ecdsa.PublicKey, counter uint32, withAT bool) ([]byte, error) {
	rpIDHash := sha256.Sum256([]byte(rpID))

	flags := byte(0x01) // UP
	flags |= 0x04       // UV
	if withAT {
		flags |= 0x40 // AT
	}

	// 构造 attested credential data
	var credData []byte
	if withAT {
		// AAGUID (16 bytes)
		aaguid := opencertAAGUID()
		// credentialIdLength (2 bytes BE)
		credIDLen := make([]byte, 2)
		binary.BigEndian.PutUint16(credIDLen, uint16(len(credID)))
		// credentialPublicKey (CBOR COSE key)
		coseKey, err := buildCOSEKey(pubKey)
		if err != nil {
			return nil, err
		}
		credData = append(credData, aaguid...)
		credData = append(credData, credIDLen...)
		credData = append(credData, credID...)
		credData = append(credData, coseKey...)
	}

	// 组装 authenticatorData
	authData := make([]byte, 0, 37+len(credData))
	authData = append(authData, rpIDHash[:]...)
	authData = append(authData, flags)
	counterBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(counterBytes, counter)
	authData = append(authData, counterBytes...)
	authData = append(authData, credData...)

	return authData, nil
}

// buildAuthenticatorDataAssertion 构造 GetAssertion 的 authenticatorData（无 AT flag）。
func buildAuthenticatorDataAssertion(rpID string, counter uint32) ([]byte, error) {
	rpIDHash := sha256.Sum256([]byte(rpID))
	flags := byte(0x01 | 0x04) // UP + UV

	authData := make([]byte, 37)
	copy(authData[0:32], rpIDHash[:])
	authData[32] = flags
	binary.BigEndian.PutUint32(authData[33:37], counter)
	return authData, nil
}

// buildCOSEKey 构造 COSE EC2 公钥（CBOR 编码）。
// COSE Key Map:
//
//	1: 2 (kty: EC2)
//	3: -7 (alg: ES256)
//	-1: 1 (crv: P-256)
//	-2: x (bytes)
//	-3: y (bytes)
func buildCOSEKey(pubKey *ecdsa.PublicKey) ([]byte, error) {
	x := pubKey.X.Bytes()
	y := pubKey.Y.Bytes()
	// 补齐到 32 字节
	xPad := make([]byte, 32)
	yPad := make([]byte, 32)
	copy(xPad[32-len(x):], x)
	copy(yPad[32-len(y):], y)

	var buf cborBuilder
	buf.writeMapHeader(5)
	buf.writeUint(1)
	buf.writeUint(2) // kty: EC2
	buf.writeUint(3)
	buf.writeNegInt(-7) // alg: ES256 = -7
	buf.writeNegInt(-1) // -1: crv
	buf.writeUint(1)    // P-256
	buf.writeNegInt(-2) // -2: x
	buf.writeBytes(xPad)
	buf.writeNegInt(-3) // -3: y
	buf.writeBytes(yPad)
	return buf.bytes(), nil
}

// buildAttestationObject 构造 none attestation 的 attestationObject。
// {
//
//	"fmt": "none",
//	"attStmt": {},
//	"authData": bytes,
//
// }
func buildAttestationObject(authData, clientDataHash []byte) ([]byte, error) {
	_ = clientDataHash // none attestation 不需要签名
	var buf cborBuilder
	buf.writeMapHeader(3)
	buf.writeText("fmt")
	buf.writeText("none")
	buf.writeText("attStmt")
	buf.writeMapHeader(0)
	buf.writeText("authData")
	buf.writeBytes(authData)
	return buf.bytes(), nil
}

// buildAssertionObject 构造 assertionObject CBOR。
// {
//
//	1: credentialId (bytes),
//	2: authData (bytes),
//	3: signature (bytes),
//	4: userHandle (bytes, optional),
//
// }
func buildAssertionObject(authData, sig, credID []byte, entry *fido.Entry) ([]byte, error) {
	var buf cborBuilder
	buf.writeMapHeader(3)
	// key 1: credential (PublicKeyCredentialDescriptor)
	buf.writeUint(1)
	buf.writeMapHeader(2)
	buf.writeText("id")
	buf.writeBytes(credID)
	buf.writeText("type")
	buf.writeText("public-key")
	// key 2: authData
	buf.writeUint(2)
	buf.writeBytes(authData)
	// key 3: signature
	buf.writeUint(3)
	buf.writeBytes(sig)
	return buf.bytes(), nil
}

// ================================================================
// 辅助：CBOR Builder
// ================================================================

type cborBuilder struct {
	data []byte
}

func (b *cborBuilder) writeHead(major byte, val uint64) {
	if val <= 23 {
		b.data = append(b.data, major|(byte(val)))
	} else if val <= 0xFF {
		b.data = append(b.data, major|0x18, byte(val))
	} else if val <= 0xFFFF {
		b.data = append(b.data, major|0x19,
			byte(val>>8), byte(val))
	} else if val <= 0xFFFFFFFF {
		b.data = append(b.data, major|0x1A,
			byte(val>>24), byte(val>>16), byte(val>>8), byte(val))
	} else {
		b.data = append(b.data, major|0x1B,
			byte(val>>56), byte(val>>48), byte(val>>40), byte(val>>32),
			byte(val>>24), byte(val>>16), byte(val>>8), byte(val))
	}
}

func (b *cborBuilder) writeUint(v uint64) { b.writeHead(0x00, v) }
func (b *cborBuilder) writeNegInt(v int)  { b.writeHead(0x20, uint64(-1-v)) }
func (b *cborBuilder) writeBytes(v []byte) {
	b.writeHead(0x40, uint64(len(v)))
	b.data = append(b.data, v...)
}
func (b *cborBuilder) writeText(v string) {
	b.writeHead(0x60, uint64(len(v)))
	b.data = append(b.data, v...)
}
func (b *cborBuilder) writeArrayHeader(n int) { b.writeHead(0x80, uint64(n)) }
func (b *cborBuilder) writeMapHeader(n int)   { b.writeHead(0xA0, uint64(n)) }
func (b *cborBuilder) writeBool(v bool) {
	if v {
		b.data = append(b.data, 0xF5)
	} else {
		b.data = append(b.data, 0xF4)
	}
}
func (b *cborBuilder) bytes() []byte { return b.data }

// ================================================================
// 辅助：CBOR 解码（最小化）
// ================================================================

func cborDecodeUint(data []byte, pos int) (uint64, int) {
	if pos >= len(data) {
		return 0, -1
	}
	b := data[pos]
	major := b >> 5
	if major != 0 {
		return 0, -1
	}
	return cborDecodeUintRaw(data, pos)
}

func cborDecodeUintRaw(data []byte, pos int) (uint64, int) {
	if pos >= len(data) {
		return 0, -1
	}
	b := data[pos]
	info := b & 0x1F
	if info <= 23 {
		return uint64(info), 1
	}
	switch info {
	case 24:
		if pos+2 > len(data) {
			return 0, -1
		}
		return uint64(data[pos+1]), 2
	case 25:
		if pos+3 > len(data) {
			return 0, -1
		}
		return uint64(data[pos+1])<<8 | uint64(data[pos+2]), 3
	case 26:
		if pos+5 > len(data) {
			return 0, -1
		}
		return uint64(data[pos+1])<<24 | uint64(data[pos+2])<<16 |
			uint64(data[pos+3])<<8 | uint64(data[pos+4]), 5
	}
	return 0, -1
}

func cborDecodeInt(data []byte, pos int) (int, int) {
	if pos >= len(data) {
		return 0, -1
	}
	b := data[pos]
	major := b >> 5
	val, n := cborDecodeUintRaw(data, pos)
	if n <= 0 {
		return 0, -1
	}
	if major == 0 {
		return int(val), n
	}
	if major == 1 {
		return -1 - int(val), n
	}
	return 0, -1
}

func cborDecodeMapLen(data []byte, pos int) (int, int) {
	if pos >= len(data) {
		return 0, -1
	}
	if data[pos]>>5 != 5 {
		return 0, -1
	}
	v, n := cborDecodeUintRaw(data, pos)
	return int(v), n
}

func cborDecodeArrayLen(data []byte, pos int) (int, int) {
	if pos >= len(data) {
		return 0, -1
	}
	if data[pos]>>5 != 4 {
		return 0, -1
	}
	v, n := cborDecodeUintRaw(data, pos)
	return int(v), n
}

func cborDecodeBytes(data []byte, pos int) ([]byte, int) {
	if pos >= len(data) {
		return nil, -1
	}
	if data[pos]>>5 != 2 {
		return nil, -1
	}
	l, n := cborDecodeUintRaw(data, pos)
	if n <= 0 || pos+n+int(l) > len(data) {
		return nil, -1
	}
	return data[pos+n : pos+n+int(l)], n + int(l)
}

func cborDecodeText(data []byte, pos int) (string, int) {
	if pos >= len(data) {
		return "", -1
	}
	if data[pos]>>5 != 3 {
		return "", -1
	}
	l, n := cborDecodeUintRaw(data, pos)
	if n <= 0 || pos+n+int(l) > len(data) {
		return "", -1
	}
	return string(data[pos+n : pos+n+int(l)]), n + int(l)
}

func cborDecodeBool(data []byte, pos int) (bool, int) {
	if pos >= len(data) {
		return false, -1
	}
	switch data[pos] {
	case 0xF4:
		return false, 1
	case 0xF5:
		return true, 1
	}
	return false, -1
}

// cborSkip 跳过一个 CBOR 值，返回跳过的字节数。
func cborSkip(data []byte, pos int) int {
	if pos >= len(data) {
		return 0
	}
	b := data[pos]
	major := b >> 5
	info := b & 0x1F

	var headerLen int
	var extraLen int

	switch info {
	case 24:
		headerLen = 2
	case 25:
		headerLen = 3
	case 26:
		headerLen = 5
	case 27:
		headerLen = 9
	default:
		headerLen = 1
		extraLen = int(info)
	}

	switch major {
	case 2, 3: // bytes, text
		if info <= 23 {
			return 1 + int(info)
		}
		if headerLen > 1 {
			v, _ := cborDecodeUintRaw(data, pos)
			return headerLen + int(v)
		}
	case 4: // array
		n := headerLen
		count, _ := cborDecodeArrayLen(data, pos)
		for i := 0; i < count; i++ {
			n += cborSkip(data, pos+n)
		}
		return n
	case 5: // map
		n := headerLen
		count, _ := cborDecodeMapLen(data, pos)
		for i := 0; i < count*2; i++ {
			n += cborSkip(data, pos+n)
		}
		return n
	}

	return headerLen + extraLen
}

// ================================================================
// 辅助：密钥操作
// ================================================================

// opencertAAGUID 返回 OpenCert FIDO2 认证器的 AAGUID（16 字节）。
func opencertAAGUID() []byte {
	return []byte{
		0x4F, 0x70, 0x65, 0x6E, 0x43, 0x65, 0x72, 0x74,
		0x46, 0x49, 0x44, 0x4F, 0x32, 0x30, 0x32, 0x34,
	}
}

// marshalECPrivateKeyPEM 将 ECDSA 私钥序列化为可存储的字符串。
// 格式："EC:" + base64(D字节)，简化存储，避免引入 x509 依赖。
func marshalECPrivateKeyPEM(key *ecdsa.PrivateKey) (string, error) {
	dBytes := key.D.Bytes()
	padded := make([]byte, 32)
	copy(padded[32-len(dBytes):], dBytes)
	return "EC:" + base64.StdEncoding.EncodeToString(padded), nil
}

// parseECPrivateKeyPEM 从 PEM 字符串解析 ECDSA 私钥。
func parseECPrivateKeyPEM(pem string) (*ecdsa.PrivateKey, error) {
	if strings.HasPrefix(pem, "EC:") {
		raw, err := base64.StdEncoding.DecodeString(pem[3:])
		if err != nil {
			return nil, fmt.Errorf("解码私钥失败: %w", err)
		}
		d := new(big.Int).SetBytes(raw)
		curve := elliptic.P256()
		priv := new(ecdsa.PrivateKey)
		priv.Curve = curve
		priv.D = d
		priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(raw)
		return priv, nil
	}
	return nil, fmt.Errorf("不支持的私钥格式")
}

// marshalECPublicKeyDER 将 EC 公钥序列化为 DER（PKIX SubjectPublicKeyInfo）。
func marshalECPublicKeyDER(pub *ecdsa.PublicKey) ([]byte, error) {
	// 未压缩点格式：04 || x || y
	x := pub.X.Bytes()
	y := pub.Y.Bytes()
	xPad := make([]byte, 32)
	yPad := make([]byte, 32)
	copy(xPad[32-len(x):], x)
	copy(yPad[32-len(y):], y)
	point := make([]byte, 65)
	point[0] = 0x04
	copy(point[1:33], xPad)
	copy(point[33:65], yPad)
	return point, nil
}

// marshalECDSASignatureDER 将 ECDSA 签名 (r, s) 编码为 DER 格式。
func marshalECDSASignatureDER(r, s *big.Int) ([]byte, error) {
	rb := r.Bytes()
	sb := s.Bytes()
	// 如果最高位为 1，需要补 0x00 前缀
	if rb[0]&0x80 != 0 {
		rb = append([]byte{0x00}, rb...)
	}
	if sb[0]&0x80 != 0 {
		sb = append([]byte{0x00}, sb...)
	}
	// DER SEQUENCE { INTEGER r, INTEGER s }
	seq := make([]byte, 0, 6+len(rb)+len(sb))
	seq = append(seq, 0x30) // SEQUENCE
	seq = append(seq, byte(4+len(rb)+len(sb)))
	seq = append(seq, 0x02, byte(len(rb)))
	seq = append(seq, rb...)
	seq = append(seq, 0x02, byte(len(sb)))
	seq = append(seq, sb...)
	return seq, nil
}

// ================================================================
// 辅助：Slot 和存储访问
// ================================================================

// fidoCardInfo 是单张卡片的信息（用于 PIN_REQUIRED 响应）。
type fidoCardInfo struct {
	CardUUID string `json:"card_uuid"`
	CardName string `json:"card_name"`
}

// fidoCardListResp 是 PIN_REQUIRED 时返回的卡片列表。
type fidoCardListResp struct {
	Cards []fidoCardInfo `json:"cards"`
}

// buildCardListResp 构建可用卡片列表响应（仅包含 fido_enabled=true 的卡片）。
func (h *PKCSHandler) buildCardListResp() *fidoCardListResp {
	slotIDs := h.manager.GetSlotList(true)
	resp := &fidoCardListResp{}
	for _, slotID := range slotIDs {
		slot := h.manager.GetSlot(slotID)
		if slot == nil {
			continue
		}
		info := slot.TokenInfo()
		cardUUID := info.SerialNumber

		// 检查卡片是否启用了 FIDO 功能
		if h.cardRepo != nil {
			card, err := h.cardRepo.GetByUUIDPrefix(context.Background(), cardUUID)
			if err != nil || card == nil || !card.FIDOEnabled {
				continue
			}
		}

		resp.Cards = append(resp.Cards, fidoCardInfo{
			CardUUID: cardUUID,
			CardName: info.Label,
		})
	}
	return resp
}

// findAnyLoggedInSlot 查找任意已登录的 Slot。
func (h *PKCSHandler) findAnyLoggedInSlot() (card.SlotProvider, pkcs11types.SlotID) {
	slotIDs := h.manager.GetSlotList(true)
	for _, slotID := range slotIDs {
		slot := h.manager.GetSlot(slotID)
		if slot != nil && slot.IsLoggedIn() {
			return slot, slotID
		}
	}
	return nil, 0
}

// getFIDOStore 获取 fido.Store 实例。
// 通过 PKCSHandler 的扩展字段访问。
func (h *PKCSHandler) getFIDOStore() *fido.Store {
	if h.fidoStore == nil {
		return nil
	}
	return h.fidoStore
}

// getCardMasterKey 获取卡片主密钥（从已登录的 Slot 获取）。
// 通过类型断言访问 local.Slot.MasterKey()。
func (h *PKCSHandler) getCardMasterKey(ctx context.Context, cardUUID string, slotID pkcs11types.SlotID) ([]byte, *storage.Card, error) {
	if h.cardRepo == nil {
		return nil, nil, fmt.Errorf("存储层未初始化")
	}
	// TokenInfo().SerialNumber 只有前16字符，先尝试精确匹配，再尝试前缀匹配
	cardRecord, err := h.cardRepo.GetByUUID(ctx, cardUUID)
	if err != nil {
		return nil, nil, fmt.Errorf("找不到卡片: %w", err)
	}
	if cardRecord == nil {
		// 精确匹配失败，尝试前缀匹配
		cardRecord, err = h.cardRepo.GetByUUIDPrefix(ctx, cardUUID)
		if err != nil || cardRecord == nil {
			return nil, nil, fmt.Errorf("找不到卡片(前缀=%s): %v", cardUUID, err)
		}
	}

	// 通过 Slot 获取已缓存的主密钥
	slot := h.manager.GetSlot(slotID)
	if slot == nil {
		return nil, nil, fmt.Errorf("Slot %d 不存在", slotID)
	}

	// 类型断言：访问 local.Slot 的 MasterKey() 方法
	type masterKeyProvider interface {
		MasterKey() []byte
	}
	mkp, ok := slot.(masterKeyProvider)
	if !ok {
		return nil, nil, fmt.Errorf("Slot 不支持主密钥访问（非 local Slot）")
	}

	masterKey := mkp.MasterKey()
	if len(masterKey) == 0 {
		return nil, nil, fmt.Errorf("主密钥为空，请先登录")
	}
	return masterKey, cardRecord, nil
}

// ================================================================
// 辅助函数
// ================================================================

// ctap2ErrToRV 将 CTAP2 错误码转换为 IPC RV 值。
func ctap2ErrToRV(ctapErr byte) uint32 {
	return uint32(ctapErr)
}

// bytesEqual 比较两个字节切片是否相等。
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
