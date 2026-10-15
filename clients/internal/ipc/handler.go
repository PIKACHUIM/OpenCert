package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/globaltrusts/client-card/internal/card"
	"github.com/globaltrusts/client-card/internal/fido"
	"github.com/globaltrusts/client-card/internal/storage"
	"github.com/globaltrusts/client-card/pkg/pkcs11types"
)

// PKCSHandler 处理所有 PKCS#11 和扩展 IPC 命令。
type PKCSHandler struct {
	manager *card.Manager
	// FIDO2 CCID 扩展字段
	fidoStore *fido.Store
	cardRepo  *storage.CardRepo
	certRepo  *storage.CertRepo
}

// PKCSHandlerOptions 是 PKCSHandler 的可选配置。
type PKCSHandlerOptions struct {
	FIDOStore *fido.Store
	CardRepo  *storage.CardRepo
	CertRepo  *storage.CertRepo
}

// NewPKCSHandler 创建 PKCS#11 命令处理器。
func NewPKCSHandler(manager *card.Manager) *PKCSHandler {
	return &PKCSHandler{manager: manager}
}

// NewPKCSHandlerWithOptions 创建带扩展选项的 PKCS#11 命令处理器。
func NewPKCSHandlerWithOptions(manager *card.Manager, opts PKCSHandlerOptions) *PKCSHandler {
	return &PKCSHandler{
		manager:   manager,
		fidoStore: opts.FIDOStore,
		cardRepo:  opts.CardRepo,
		certRepo:  opts.CertRepo,
	}
}

// Register 将所有命令处理函数注册到 server。
func (h *PKCSHandler) Register(s *Server) {
	s.Register(CmdPing, h.handlePing)
	s.Register(CmdHandshake, h.handleHandshake)
	s.Register(CmdGetInfo, h.handleGetInfo)
	s.Register(CmdGetSlotList, h.handleGetSlotList)
	s.Register(CmdGetSlotInfo, h.handleGetSlotInfo)
	s.Register(CmdGetTokenInfo, h.handleGetTokenInfo)
	s.Register(CmdGetMechanismList, h.handleGetMechanismList)
	s.Register(CmdGetMechanismInfo, h.handleGetMechanismInfo)
	s.Register(CmdOpenSession, h.handleOpenSession)
	s.Register(CmdCloseSession, h.handleCloseSession)
	s.Register(CmdCloseAllSessions, h.handleCloseAllSessions)
	s.Register(CmdGetSessionInfo, h.handleGetSessionInfo)
	s.Register(CmdLogin, h.handleLogin)
	s.Register(CmdLogout, h.handleLogout)
	s.Register(CmdInitPIN, h.handleInitPIN)
	s.Register(CmdSetPIN, h.handleSetPIN)
	s.Register(CmdFindObjectsInit, h.handleFindObjectsInit)
	s.Register(CmdFindObjects, h.handleFindObjects)
	s.Register(CmdFindObjectsFinal, h.handleFindObjectsFinal)
	s.Register(CmdGetAttributeValue, h.handleGetAttributeValue)
	s.Register(CmdCreateObject, h.handleCreateObject)
	s.Register(CmdDestroyObject, h.handleDestroyObject)
	s.Register(CmdSetAttributeValue, h.handleSetAttributeValue)
	s.Register(CmdGetObjectSize, h.handleGetObjectSize)
	s.Register(CmdSignInit, h.handleSignInit)
	s.Register(CmdSign, h.handleSign)
	s.Register(CmdDecryptInit, h.handleDecryptInit)
	s.Register(CmdDecrypt, h.handleDecrypt)
	s.Register(CmdEncryptInit, h.handleEncryptInit)
	s.Register(CmdEncrypt, h.handleEncrypt)
	s.Register(CmdGenerateKeyPair, h.handleGenerateKeyPair)

	// 流式 Digest / Verify 与 Random 一族
	h.RegisterDigestVerifyRandom(s)
	// KSP 专用命令
	h.RegisterKSPHandlers(s)
	// FIDO2 CCID 专用命令
	h.RegisterFIDOHandlers(s)
}

// ---- GetSlotList ----

type getSlotListReq struct {
	TokenPresent bool `json:"token_present"`
}

type getSlotListResp struct {
	SlotIDs []uint32 `json:"slot_ids"`
	Count   uint32   `json:"count"` // C 驱动依据 count 决定读取多少个 slot_id
}

func (h *PKCSHandler) handleGetSlotList(ctx context.Context, req *Frame) (interface{}, uint32) {
	var r getSlotListReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		slog.Warn("GetSlotList 解析请求失败", "error", err)
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}

	ids := h.manager.GetSlotList(r.TokenPresent)
	result := make([]uint32, len(ids))
	for i, id := range ids {
		result[i] = uint32(id)
	}
	return &getSlotListResp{SlotIDs: result, Count: uint32(len(result))}, uint32(pkcs11types.CKR_OK)
}

// ---- GetSlotInfo ----

type slotIDReq struct {
	SlotID uint32 `json:"slot_id"`
}

// slotInfoResp 的键名与 C 驱动解析逻辑严格一致：
// slot_description / manufacturer_id / flags / hw_major / hw_minor / fw_major / fw_minor。
type slotInfoResp struct {
	SlotDescription string `json:"slot_description"`
	ManufacturerID  string `json:"manufacturer_id"`
	Flags           uint32 `json:"flags"`
	HWVersionMajor  uint8  `json:"hw_major"`
	HWVersionMinor  uint8  `json:"hw_minor"`
	FWVersionMajor  uint8  `json:"fw_major"`
	FWVersionMinor  uint8  `json:"fw_minor"`
}

func (h *PKCSHandler) handleGetSlotInfo(ctx context.Context, req *Frame) (interface{}, uint32) {
	var r slotIDReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}

	info, err := h.manager.GetSlotInfo(pkcs11types.SlotID(r.SlotID))
	if err != nil {
		return nil, uint32(pkcs11types.CKR_SLOT_ID_INVALID)
	}
	return &slotInfoResp{
		SlotDescription: info.Description,
		ManufacturerID:  info.Manufacturer,
		Flags:           info.Flags,
		HWVersionMajor:  1,
		HWVersionMinor:  0,
		FWVersionMajor:  1,
		FWVersionMinor:  0,
	}, uint32(pkcs11types.CKR_OK)
}

// ---- GetTokenInfo ----

// tokenInfoResp 的键名与 C 驱动解析逻辑一致（厂商字段名为 manufacturer_id）。
type tokenInfoResp struct {
	Label          string `json:"label"`
	ManufacturerID string `json:"manufacturer_id"`
	Model          string `json:"model"`
	SerialNumber   string `json:"serial_number"`
	Flags          uint32 `json:"flags"`
}

func (h *PKCSHandler) handleGetTokenInfo(ctx context.Context, req *Frame) (interface{}, uint32) {
	var r slotIDReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}

	info, err := h.manager.GetTokenInfo(pkcs11types.SlotID(r.SlotID))
	if err != nil {
		return nil, uint32(pkcs11types.CKR_SLOT_ID_INVALID)
	}
	return &tokenInfoResp{
		Label:          info.Label,
		ManufacturerID: info.Manufacturer,
		Model:          info.Model,
		SerialNumber:   info.SerialNumber,
		Flags:          info.Flags,
	}, uint32(pkcs11types.CKR_OK)
}

// ---- GetMechanismList ----

type getMechListResp struct {
	Mechanisms []uint32 `json:"mechanisms"`
	Count      uint32   `json:"count"` // C 驱动依据 count 决定读取多少个 mechanism
}

func (h *PKCSHandler) handleGetMechanismList(ctx context.Context, req *Frame) (interface{}, uint32) {
	var r slotIDReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}

	mechs, err := h.manager.GetMechanisms(pkcs11types.SlotID(r.SlotID))
	if err != nil {
		return nil, uint32(pkcs11types.CKR_SLOT_ID_INVALID)
	}
	result := make([]uint32, len(mechs))
	for i, m := range mechs {
		result[i] = uint32(m)
	}
	return &getMechListResp{Mechanisms: result, Count: uint32(len(result))}, uint32(pkcs11types.CKR_OK)
}

// ---- OpenSession ----

type openSessionReq struct {
	SlotID uint32 `json:"slot_id"`
	Flags  uint32 `json:"flags"`
}

type openSessionResp struct {
	SessionHandle uint32 `json:"session_id"`
}

func (h *PKCSHandler) handleOpenSession(ctx context.Context, req *Frame) (interface{}, uint32) {
	var r openSessionReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}

	handle, err := h.manager.OpenSession(pkcs11types.SlotID(r.SlotID), r.Flags)
	if err != nil {
		return nil, uint32(pkcs11types.CKR_SLOT_ID_INVALID)
	}
	return &openSessionResp{SessionHandle: uint32(handle)}, uint32(pkcs11types.CKR_OK)
}

// ---- CloseSession ----

type sessionReq struct {
	SessionHandle uint32 `json:"session_id"`
}

func (h *PKCSHandler) handleCloseSession(ctx context.Context, req *Frame) (interface{}, uint32) {
	var r sessionReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}

	if err := h.manager.CloseSession(pkcs11types.SessionHandle(r.SessionHandle)); err != nil {
		return nil, uint32(pkcs11types.CKR_SESSION_HANDLE_INVALID)
	}
	return nil, uint32(pkcs11types.CKR_OK)
}

// ---- CloseAllSessions ----

func (h *PKCSHandler) handleCloseAllSessions(ctx context.Context, req *Frame) (interface{}, uint32) {
	var r slotIDReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}
	h.manager.CloseAllSessions(pkcs11types.SlotID(r.SlotID))
	return nil, uint32(pkcs11types.CKR_OK)
}

// ---- Login ----

type loginReq struct {
	SessionHandle uint32 `json:"session_id"`
	UserType      uint32 `json:"user_type"`
	PIN           string `json:"pin"`
}

func (h *PKCSHandler) handleLogin(ctx context.Context, req *Frame) (interface{}, uint32) {
	var r loginReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}

	err := h.manager.Login(ctx, pkcs11types.SessionHandle(r.SessionHandle),
		pkcs11types.UserType(r.UserType), r.PIN)
	if err != nil {
		slog.Warn("Login 失败", "session", r.SessionHandle, "error", err)
		// 直接返回具体 CKR：错误可能被 fmt.Errorf("%w") 包装，必须用 errors.As 解包，
		// 否则 PIN 锁定/已登录等语义都会退化成 PIN_INCORRECT。
		return nil, ckrFromError(err, uint32(pkcs11types.CKR_PIN_INCORRECT))
	}
	return nil, uint32(pkcs11types.CKR_OK)
}

// ---- Logout ----

func (h *PKCSHandler) handleLogout(ctx context.Context, req *Frame) (interface{}, uint32) {
	var r sessionReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}

	if err := h.manager.Logout(ctx, pkcs11types.SessionHandle(r.SessionHandle)); err != nil {
		return nil, ckrFromError(err, uint32(pkcs11types.CKR_SESSION_HANDLE_INVALID))
	}
	return nil, uint32(pkcs11types.CKR_OK)
}

// ---- FindObjectsInit ----

type findObjectsInitReq struct {
	SessionHandle uint32 `json:"session_id"`
	Template      []struct {
		Type  uint32 `json:"type"`
		Value []byte `json:"value"`
	} `json:"template"`
}

func (h *PKCSHandler) handleFindObjectsInit(ctx context.Context, req *Frame) (interface{}, uint32) {
	var r findObjectsInitReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}

	s, err := h.manager.GetSession(pkcs11types.SessionHandle(r.SessionHandle))
	if err != nil {
		return nil, uint32(pkcs11types.CKR_SESSION_HANDLE_INVALID)
	}

	s.Lock()
	defer s.Unlock()

	// 检查是否已有查找操作进行中
	if s.FindActive {
		return nil, uint32(pkcs11types.CKR_OPERATION_ACTIVE)
	}

	template := make([]pkcs11types.Attribute, len(r.Template))
	for i, t := range r.Template {
		template[i] = pkcs11types.Attribute{
			Type:  pkcs11types.AttributeType(t.Type),
			Value: t.Value,
		}
	}

	handles, err := s.Provider.FindObjects(ctx, template)
	if err != nil {
		slog.Error("FindObjects 失败", "error", err)
		return nil, uint32(pkcs11types.CKR_FUNCTION_FAILED)
	}

	s.FindTemplate = template
	s.FindResults = handles
	s.FindPos = 0
	s.FindActive = true

	// C 驱动期望 {"count":N,"handles":[h1,h2,...]}，否则会解析出 0 个对象
	result := make([]uint32, len(handles))
	for i, h := range handles {
		result[i] = uint32(h)
	}
	return &findObjectsInitResp{Count: uint32(len(result)), Handles: result}, uint32(pkcs11types.CKR_OK)
}

// ---- FindObjects ----

type findObjectsReq struct {
	SessionHandle uint32 `json:"session_id"`
	MaxCount      uint32 `json:"max_count"`
}

// findObjectsInitResp 对应 FindObjectsInit：C 驱动读取 count 与 "handles":[...] 数组。
type findObjectsInitResp struct {
	Count   uint32   `json:"count"`
	Handles []uint32 `json:"handles"`
}

func (h *PKCSHandler) handleFindObjects(ctx context.Context, req *Frame) (interface{}, uint32) {
	var r findObjectsReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}

	s, err := h.manager.GetSession(pkcs11types.SessionHandle(r.SessionHandle))
	if err != nil {
		return nil, uint32(pkcs11types.CKR_SESSION_HANDLE_INVALID)
	}

	s.Lock()
	defer s.Unlock()

	if !s.FindActive {
		return nil, uint32(pkcs11types.CKR_OPERATION_NOT_INITIALIZED)
	}

	remaining := s.FindResults[s.FindPos:]
	count := int(r.MaxCount)
	if count > len(remaining) {
		count = len(remaining)
	}

	// C 驱动按 count + "handles[i]" 索引键逐个读取句柄，
	// 因此这里返回 {"count":N,"handles[0]":h0,"handles[1]":h1,...}
	body := make(map[string]interface{}, count+1)
	body["count"] = uint32(count)
	for i := 0; i < count; i++ {
		body[fmt.Sprintf("handles[%d]", i)] = uint32(remaining[i])
	}
	s.FindPos += count

	return body, uint32(pkcs11types.CKR_OK)
}

// ---- FindObjectsFinal ----

func (h *PKCSHandler) handleFindObjectsFinal(ctx context.Context, req *Frame) (interface{}, uint32) {
	var r sessionReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}

	s, err := h.manager.GetSession(pkcs11types.SessionHandle(r.SessionHandle))
	if err != nil {
		return nil, uint32(pkcs11types.CKR_SESSION_HANDLE_INVALID)
	}

	s.Lock()
	defer s.Unlock()

	if !s.FindActive {
		return nil, uint32(pkcs11types.CKR_OPERATION_NOT_INITIALIZED)
	}

	s.FindResults = nil
	s.FindPos = 0
	s.FindActive = false
	return nil, uint32(pkcs11types.CKR_OK)
}

// ---- GetAttributeValue ----

// getAttrReq 对应 C 驱动 C_GetAttributeValue 的请求：
// {"session_id":N,"object_handle":M,"types":[t1,t2,...]}
type getAttrReq struct {
	SessionHandle uint32   `json:"session_id"`
	ObjectHandle  uint32   `json:"object_handle"`
	AttrTypes     []uint32 `json:"types"`
}

// getAttrResp 的 JSON 键名必须为 attrs：C 驱动通过 strstr(resp, "\"attrs\":[")
// 定位属性数组，随后逐个匹配 "type":N 并读取 value。
type getAttrResp struct {
	Attributes []struct {
		Type  uint32 `json:"type"`
		Value []byte `json:"value"`
	} `json:"attrs"`
}

func (h *PKCSHandler) handleGetAttributeValue(ctx context.Context, req *Frame) (interface{}, uint32) {
	var r getAttrReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}

	s, err := h.manager.GetSession(pkcs11types.SessionHandle(r.SessionHandle))
	if err != nil {
		return nil, uint32(pkcs11types.CKR_SESSION_HANDLE_INVALID)
	}

	attrTypes := make([]pkcs11types.AttributeType, len(r.AttrTypes))
	for i, t := range r.AttrTypes {
		attrTypes[i] = pkcs11types.AttributeType(t)
	}

	attrs, err := s.Provider.GetAttributes(ctx, pkcs11types.ObjectHandle(r.ObjectHandle), attrTypes)
	if err != nil {
		return nil, uint32(pkcs11types.CKR_OBJECT_HANDLE_INVALID)
	}

	resp := &getAttrResp{}
	for _, a := range attrs {
		resp.Attributes = append(resp.Attributes, struct {
			Type  uint32 `json:"type"`
			Value []byte `json:"value"`
		}{Type: uint32(a.Type), Value: a.Value})
	}
	return resp, uint32(pkcs11types.CKR_OK)
}

// ---- SignInit ----

type signInitReq struct {
	SessionHandle uint32 `json:"session_id"`
	MechanismType uint32 `json:"mechanism"`
	MechParam     []byte `json:"mech_param,omitempty"`
	KeyHandle     uint32 `json:"key_handle"`
}

func (h *PKCSHandler) handleSignInit(ctx context.Context, req *Frame) (interface{}, uint32) {
	var r signInitReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}

	s, err := h.manager.GetSession(pkcs11types.SessionHandle(r.SessionHandle))
	if err != nil {
		return nil, uint32(pkcs11types.CKR_SESSION_HANDLE_INVALID)
	}

	s.Lock()
	defer s.Unlock()

	// 检查是否已有签名操作进行中
	if s.SignActive {
		return nil, uint32(pkcs11types.CKR_OPERATION_ACTIVE)
	}

	s.SignHandle = pkcs11types.ObjectHandle(r.KeyHandle)
	s.SignMechanism = pkcs11types.Mechanism{
		Type:      pkcs11types.MechanismType(r.MechanismType),
		Parameter: r.MechParam,
	}
	s.SignActive = true
	return nil, uint32(pkcs11types.CKR_OK)
}

// ---- Sign ----

type signReq struct {
	SessionHandle uint32 `json:"session_id"`
	Data          []byte `json:"data"`
}

type signResp struct {
	Signature []byte `json:"signature"`
}

func (h *PKCSHandler) handleSign(ctx context.Context, req *Frame) (interface{}, uint32) {
	var r signReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}

	s, err := h.manager.GetSession(pkcs11types.SessionHandle(r.SessionHandle))
	if err != nil {
		return nil, uint32(pkcs11types.CKR_SESSION_HANDLE_INVALID)
	}

	s.Lock()
	if !s.SignActive {
		s.Unlock()
		return nil, uint32(pkcs11types.CKR_OPERATION_NOT_INITIALIZED)
	}
	if !s.Provider.IsLoggedIn() {
		s.Unlock()
		return nil, uint32(pkcs11types.CKR_USER_NOT_LOGGED_IN)
	}
	// 复制签名参数后释放锁，避免长时间持有
	signHandle := s.SignHandle
	signMech := s.SignMechanism
	s.SignActive = false // 签名操作完成后重置
	s.Unlock()

	sig, err := s.Provider.Sign(ctx, signHandle, signMech, r.Data)
	if err != nil {
		slog.Error("Sign 失败", "error", err)
		return nil, uint32(pkcs11types.CKR_FUNCTION_FAILED)
	}
	return &signResp{Signature: sig}, uint32(pkcs11types.CKR_OK)
}

// ---- DecryptInit ----

type cryptInitReq struct {
	SessionHandle uint32 `json:"session_id"`
	MechanismType uint32 `json:"mechanism"`
	MechParam     []byte `json:"mech_param,omitempty"`
	KeyHandle     uint32 `json:"key_handle"`
}

func (h *PKCSHandler) handleDecryptInit(ctx context.Context, req *Frame) (interface{}, uint32) {
	var r cryptInitReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}

	s, err := h.manager.GetSession(pkcs11types.SessionHandle(r.SessionHandle))
	if err != nil {
		return nil, uint32(pkcs11types.CKR_SESSION_HANDLE_INVALID)
	}

	s.Lock()
	defer s.Unlock()

	if s.DecryptActive {
		return nil, uint32(pkcs11types.CKR_OPERATION_ACTIVE)
	}

	s.DecryptHandle = pkcs11types.ObjectHandle(r.KeyHandle)
	s.DecryptMech = pkcs11types.Mechanism{
		Type:      pkcs11types.MechanismType(r.MechanismType),
		Parameter: r.MechParam,
	}
	s.DecryptActive = true
	return nil, uint32(pkcs11types.CKR_OK)
}

// ---- Decrypt ----

// decryptReq 对应 C 驱动 C_Decrypt：{"session_id","key_handle","mechanism","data":<b64>}
type decryptReq struct {
	SessionHandle uint32 `json:"session_id"`
	Data          []byte `json:"data"`
}

type decryptResp struct {
	Plaintext []byte `json:"plaintext"`
}

func (h *PKCSHandler) handleDecrypt(ctx context.Context, req *Frame) (interface{}, uint32) {
	var r decryptReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}

	s, err := h.manager.GetSession(pkcs11types.SessionHandle(r.SessionHandle))
	if err != nil {
		return nil, uint32(pkcs11types.CKR_SESSION_HANDLE_INVALID)
	}

	s.Lock()
	if !s.DecryptActive {
		s.Unlock()
		return nil, uint32(pkcs11types.CKR_OPERATION_NOT_INITIALIZED)
	}
	if !s.Provider.IsLoggedIn() {
		s.Unlock()
		return nil, uint32(pkcs11types.CKR_USER_NOT_LOGGED_IN)
	}
	decryptHandle := s.DecryptHandle
	decryptMech := s.DecryptMech
	s.DecryptActive = false
	s.Unlock()

	plain, err := s.Provider.Decrypt(ctx, decryptHandle, decryptMech, r.Data)
	if err != nil {
		slog.Error("Decrypt 失败", "error", err)
		return nil, uint32(pkcs11types.CKR_FUNCTION_FAILED)
	}
	return &decryptResp{Plaintext: plain}, uint32(pkcs11types.CKR_OK)
}

// ---- EncryptInit ----

func (h *PKCSHandler) handleEncryptInit(ctx context.Context, req *Frame) (interface{}, uint32) {
	var r cryptInitReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}

	s, err := h.manager.GetSession(pkcs11types.SessionHandle(r.SessionHandle))
	if err != nil {
		return nil, uint32(pkcs11types.CKR_SESSION_HANDLE_INVALID)
	}

	s.Lock()
	defer s.Unlock()

	if s.EncryptActive {
		return nil, uint32(pkcs11types.CKR_OPERATION_ACTIVE)
	}

	s.EncryptHandle = pkcs11types.ObjectHandle(r.KeyHandle)
	s.EncryptMech = pkcs11types.Mechanism{
		Type:      pkcs11types.MechanismType(r.MechanismType),
		Parameter: r.MechParam,
	}
	s.EncryptActive = true
	return nil, uint32(pkcs11types.CKR_OK)
}

// ---- Encrypt ----

// encryptReq 对应 C 驱动 C_Encrypt：{"session_id","key_handle","mechanism","data":<b64>}
type encryptReq struct {
	SessionHandle uint32 `json:"session_id"`
	Data          []byte `json:"data"`
}

type encryptResp struct {
	Ciphertext []byte `json:"ciphertext"`
}

func (h *PKCSHandler) handleEncrypt(ctx context.Context, req *Frame) (interface{}, uint32) {
	var r encryptReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}

	s, err := h.manager.GetSession(pkcs11types.SessionHandle(r.SessionHandle))
	if err != nil {
		return nil, uint32(pkcs11types.CKR_SESSION_HANDLE_INVALID)
	}

	s.Lock()
	if !s.EncryptActive {
		s.Unlock()
		return nil, uint32(pkcs11types.CKR_OPERATION_NOT_INITIALIZED)
	}
	encryptHandle := s.EncryptHandle
	encryptMech := s.EncryptMech
	s.EncryptActive = false
	s.Unlock()

	cipher, err := s.Provider.Encrypt(ctx, encryptHandle, encryptMech, r.Data)
	if err != nil {
		slog.Error("Encrypt 失败", "error", err)
		return nil, uint32(pkcs11types.CKR_FUNCTION_FAILED)
	}
	return &encryptResp{Ciphertext: cipher}, uint32(pkcs11types.CKR_OK)
}

// 确保 json 包被使用（用于 RawMessage）
var _ = json.Marshal

// ---- Ping（心跳） ----

func (h *PKCSHandler) handlePing(_ context.Context, _ *Frame) (interface{}, uint32) {
	return nil, uint32(pkcs11types.CKR_OK)
}

// ---- Handshake（版本协商） ----

func (h *PKCSHandler) handleHandshake(_ context.Context, req *Frame) (interface{}, uint32) {
	var r HandshakeReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}

	compatible := r.Version == ProtocolVersion
	resp := &HandshakeResp{
		Version:    ProtocolVersion,
		Compatible: compatible,
	}
	if !compatible {
		slog.Warn("IPC 协议版本不兼容", "client_version", r.Version, "server_version", ProtocolVersion)
		return resp, uint32(pkcs11types.CKR_CANT_LOCK)
	}
	return resp, uint32(pkcs11types.CKR_OK)
}

// ---- GetInfo ----

// getInfoResp 的键名与 C 驱动解析逻辑一致：
// manufacturer_id / library_description / library_version_major / library_version_minor。
type getInfoResp struct {
	ManufacturerID       string `json:"manufacturer_id"`
	Flags                uint32 `json:"flags"`
	LibraryDescription   string `json:"library_description"`
	LibraryVersionMajor  uint8  `json:"library_version_major"`
	LibraryVersionMinor  uint8  `json:"library_version_minor"`
	CryptokiVersionMajor uint8  `json:"cryptoki_version_major"`
	CryptokiVersionMinor uint8  `json:"cryptoki_version_minor"`
}

func (h *PKCSHandler) handleGetInfo(_ context.Context, _ *Frame) (interface{}, uint32) {
	return &getInfoResp{
		ManufacturerID:       "OpenCert Project",
		LibraryDescription:   "OpenCert PKCS#11 Driver",
		LibraryVersionMajor:  1,
		LibraryVersionMinor:  0,
		CryptokiVersionMajor: 2,
		CryptokiVersionMinor: 40,
	}, uint32(pkcs11types.CKR_OK)
}

// ---- GetSessionInfo ----

type getSessionInfoResp struct {
	SlotID      uint32 `json:"slot_id"`
	State       uint32 `json:"state"`
	Flags       uint32 `json:"flags"`
	DeviceError uint32 `json:"device_error"`
}

func (h *PKCSHandler) handleGetSessionInfo(_ context.Context, req *Frame) (interface{}, uint32) {
	var r sessionReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}

	s, err := h.manager.GetSession(pkcs11types.SessionHandle(r.SessionHandle))
	if err != nil {
		return nil, uint32(pkcs11types.CKR_SESSION_HANDLE_INVALID)
	}

	s.Lock()
	defer s.Unlock()

	resp := &getSessionInfoResp{
		SlotID: uint32(s.SlotID),
		State:  uint32(s.State),
		Flags:  s.Flags,
	}
	return resp, uint32(pkcs11types.CKR_OK)
}

// ---- GetMechanismInfo ----

type getMechInfoReq struct {
	SlotID        uint32 `json:"slot_id"`
	MechanismType uint32 `json:"mechanism"`
}

type getMechInfoResp struct {
	MinKeySize uint32 `json:"min_key_size"`
	MaxKeySize uint32 `json:"max_key_size"`
	Flags      uint32 `json:"flags"`
}

// 机制信息标志位。
const (
	CKF_ENCRYPT           uint32 = 0x00000100
	CKF_DECRYPT           uint32 = 0x00000200
	CKF_SIGN              uint32 = 0x00000800
	CKF_VERIFY            uint32 = 0x00002000
	CKF_GENERATE_KEY_PAIR uint32 = 0x00010000
)

func (h *PKCSHandler) handleGetMechanismInfo(_ context.Context, req *Frame) (interface{}, uint32) {
	var r getMechInfoReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}

	// 根据机制类型返回对应的密钥长度范围和操作标志
	mechType := pkcs11types.MechanismType(r.MechanismType)
	info, ok := mechanismInfoMap[mechType]
	if !ok {
		return nil, uint32(pkcs11types.CKR_MECHANISM_INVALID)
	}
	return &info, uint32(pkcs11types.CKR_OK)
}

// mechanismInfoMap 存储各机制的信息。
var mechanismInfoMap = map[pkcs11types.MechanismType]getMechInfoResp{
	// RSA
	pkcs11types.CKM_RSA_PKCS_KEY_PAIR_GEN: {MinKeySize: 1024, MaxKeySize: 8192, Flags: CKF_GENERATE_KEY_PAIR},
	pkcs11types.CKM_RSA_PKCS:              {MinKeySize: 1024, MaxKeySize: 8192, Flags: CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY},
	pkcs11types.CKM_RSA_PKCS_OAEP:         {MinKeySize: 1024, MaxKeySize: 8192, Flags: CKF_ENCRYPT | CKF_DECRYPT},
	pkcs11types.CKM_RSA_PKCS_PSS:          {MinKeySize: 1024, MaxKeySize: 8192, Flags: CKF_SIGN | CKF_VERIFY},
	pkcs11types.CKM_SHA1_RSA_PKCS:         {MinKeySize: 1024, MaxKeySize: 8192, Flags: CKF_SIGN | CKF_VERIFY},
	pkcs11types.CKM_SHA256_RSA_PKCS:       {MinKeySize: 1024, MaxKeySize: 8192, Flags: CKF_SIGN | CKF_VERIFY},
	pkcs11types.CKM_SHA384_RSA_PKCS:       {MinKeySize: 1024, MaxKeySize: 8192, Flags: CKF_SIGN | CKF_VERIFY},
	pkcs11types.CKM_SHA512_RSA_PKCS:       {MinKeySize: 1024, MaxKeySize: 8192, Flags: CKF_SIGN | CKF_VERIFY},
	pkcs11types.CKM_SHA1_RSA_PKCS_PSS:     {MinKeySize: 1024, MaxKeySize: 8192, Flags: CKF_SIGN | CKF_VERIFY},
	pkcs11types.CKM_SHA256_RSA_PKCS_PSS:   {MinKeySize: 1024, MaxKeySize: 8192, Flags: CKF_SIGN | CKF_VERIFY},
	pkcs11types.CKM_SHA384_RSA_PKCS_PSS:   {MinKeySize: 1024, MaxKeySize: 8192, Flags: CKF_SIGN | CKF_VERIFY},
	pkcs11types.CKM_SHA512_RSA_PKCS_PSS:   {MinKeySize: 1024, MaxKeySize: 8192, Flags: CKF_SIGN | CKF_VERIFY},
	// EC
	pkcs11types.CKM_EC_KEY_PAIR_GEN: {MinKeySize: 256, MaxKeySize: 521, Flags: CKF_GENERATE_KEY_PAIR},
	pkcs11types.CKM_ECDSA:           {MinKeySize: 256, MaxKeySize: 521, Flags: CKF_SIGN | CKF_VERIFY},
	pkcs11types.CKM_ECDSA_SHA256:    {MinKeySize: 256, MaxKeySize: 521, Flags: CKF_SIGN | CKF_VERIFY},
	pkcs11types.CKM_ECDSA_SHA384:    {MinKeySize: 256, MaxKeySize: 521, Flags: CKF_SIGN | CKF_VERIFY},
	pkcs11types.CKM_ECDSA_SHA512:    {MinKeySize: 256, MaxKeySize: 521, Flags: CKF_SIGN | CKF_VERIFY},
	// EdDSA (Ed25519)
	pkcs11types.CKM_EDDSA: {MinKeySize: 256, MaxKeySize: 256, Flags: CKF_SIGN | CKF_VERIFY},
	// AES
	pkcs11types.CKM_AES_CBC: {MinKeySize: 128, MaxKeySize: 256, Flags: CKF_ENCRYPT | CKF_DECRYPT},
	pkcs11types.CKM_AES_GCM: {MinKeySize: 128, MaxKeySize: 256, Flags: CKF_ENCRYPT | CKF_DECRYPT},
	// ChaCha20
	pkcs11types.CKM_CHACHA20_POLY1305: {MinKeySize: 256, MaxKeySize: 256, Flags: CKF_ENCRYPT | CKF_DECRYPT},
	// 摘要算法
	pkcs11types.CKM_SHA_1:    {MinKeySize: 0, MaxKeySize: 0, Flags: 0},
	pkcs11types.CKM_SHA256:   {MinKeySize: 0, MaxKeySize: 0, Flags: 0},
	pkcs11types.CKM_SHA384:   {MinKeySize: 0, MaxKeySize: 0, Flags: 0},
	pkcs11types.CKM_SHA512:   {MinKeySize: 0, MaxKeySize: 0, Flags: 0},
	pkcs11types.CKM_SHA3_256: {MinKeySize: 0, MaxKeySize: 0, Flags: 0},
	pkcs11types.CKM_SHA3_384: {MinKeySize: 0, MaxKeySize: 0, Flags: 0},
	pkcs11types.CKM_SHA3_512: {MinKeySize: 0, MaxKeySize: 0, Flags: 0},
	pkcs11types.CKM_MD5:      {MinKeySize: 0, MaxKeySize: 0, Flags: 0},
	// 国密
	pkcs11types.CKM_SM2_KEY_PAIR_GEN: {MinKeySize: 256, MaxKeySize: 256, Flags: CKF_GENERATE_KEY_PAIR},
	pkcs11types.CKM_SM2:              {MinKeySize: 256, MaxKeySize: 256, Flags: CKF_SIGN | CKF_VERIFY | CKF_ENCRYPT | CKF_DECRYPT},
	pkcs11types.CKM_SM3:              {MinKeySize: 0, MaxKeySize: 0, Flags: 0},
	pkcs11types.CKM_SM4_CBC:          {MinKeySize: 128, MaxKeySize: 128, Flags: CKF_ENCRYPT | CKF_DECRYPT},
	pkcs11types.CKM_SM4_GCM:          {MinKeySize: 128, MaxKeySize: 128, Flags: CKF_ENCRYPT | CKF_DECRYPT},
}

// ---- InitPIN ----

type initPINReq struct {
	SessionHandle uint32 `json:"session_id"`
	PIN           string `json:"pin"`
}

func (h *PKCSHandler) handleInitPIN(ctx context.Context, req *Frame) (interface{}, uint32) {
	var r initPINReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}

	s, err := h.manager.GetSession(pkcs11types.SessionHandle(r.SessionHandle))
	if err != nil {
		return nil, uint32(pkcs11types.CKR_SESSION_HANDLE_INVALID)
	}

	s.Lock()
	// InitPIN 只能在 RW_SO 状态下调用
	isSO := s.State == pkcs11types.CKS_RW_SO_FUNCTIONS
	provider := s.Provider
	s.Unlock()
	if !isSO {
		return nil, uint32(pkcs11types.CKR_USER_NOT_LOGGED_IN)
	}

	pinMgr, ok := provider.(card.PINManager)
	if !ok {
		return nil, uint32(pkcs11types.CKR_FUNCTION_NOT_SUPPORTED)
	}
	if err := pinMgr.SetUserPIN(ctx, r.PIN); err != nil {
		slog.Warn("InitPIN 失败", "session", r.SessionHandle, "error", err)
		return nil, ckrFromError(err, uint32(pkcs11types.CKR_FUNCTION_FAILED))
	}
	return nil, uint32(pkcs11types.CKR_OK)
}

// ---- SetPIN ----

type setPINReq struct {
	SessionHandle uint32 `json:"session_id"`
	OldPIN        string `json:"old_pin"`
	NewPIN        string `json:"new_pin"`
}

func (h *PKCSHandler) handleSetPIN(ctx context.Context, req *Frame) (interface{}, uint32) {
	var r setPINReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}

	s, err := h.manager.GetSession(pkcs11types.SessionHandle(r.SessionHandle))
	if err != nil {
		return nil, uint32(pkcs11types.CKR_SESSION_HANDLE_INVALID)
	}

	s.Lock()
	// SetPIN 需要在 RW_USER 或 RW_SO 状态下调用
	rw := s.State == pkcs11types.CKS_RW_USER_FUNCTIONS || s.State == pkcs11types.CKS_RW_SO_FUNCTIONS
	provider := s.Provider
	s.Unlock()
	if !rw {
		return nil, uint32(pkcs11types.CKR_SESSION_READ_ONLY)
	}

	pinMgr, ok := provider.(card.PINManager)
	if !ok {
		return nil, uint32(pkcs11types.CKR_FUNCTION_NOT_SUPPORTED)
	}
	if err := pinMgr.SetPIN(ctx, r.OldPIN, r.NewPIN); err != nil {
		slog.Warn("SetPIN 失败", "session", r.SessionHandle, "error", err)
		return nil, ckrFromError(err, uint32(pkcs11types.CKR_FUNCTION_FAILED))
	}
	return nil, uint32(pkcs11types.CKR_OK)
}

// ---- CreateObject ----

// createObjectReq 对应 C 驱动 C_CreateObject：
// {"session_id":N,"attr_count":M,"template":[{"type":T,"value":"<base64>"},...]}
type createObjectReq struct {
	SessionHandle uint32 `json:"session_id"`
	Template      []struct {
		Type  uint32 `json:"type"`
		Value []byte `json:"value"`
	} `json:"template"`
}

// createObjectResp 的键名 handle 与 C 驱动 json_get_int(resp, "handle", ...) 一致。
type createObjectResp struct {
	ObjectHandle uint32 `json:"handle"`
}

func (h *PKCSHandler) handleCreateObject(ctx context.Context, req *Frame) (interface{}, uint32) {
	var r createObjectReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}

	s, err := h.manager.GetSession(pkcs11types.SessionHandle(r.SessionHandle))
	if err != nil {
		return nil, uint32(pkcs11types.CKR_SESSION_HANDLE_INVALID)
	}

	s.Lock()
	rw := s.IsRW()
	provider := s.Provider
	s.Unlock()
	if !rw {
		return nil, uint32(pkcs11types.CKR_SESSION_READ_ONLY)
	}

	objMgr, ok := provider.(card.ObjectManager)
	if !ok {
		return nil, uint32(pkcs11types.CKR_FUNCTION_NOT_SUPPORTED)
	}
	if len(r.Template) == 0 {
		// C 驱动旧版本只发送 attr_count、不发送模板内容
		return nil, uint32(pkcs11types.CKR_TEMPLATE_INCOMPLETE)
	}

	template := make([]pkcs11types.Attribute, len(r.Template))
	for i, t := range r.Template {
		template[i] = pkcs11types.Attribute{
			Type:  pkcs11types.AttributeType(t.Type),
			Value: t.Value,
		}
	}

	handle, err := objMgr.CreateObject(ctx, template)
	if err != nil {
		slog.Warn("CreateObject 失败", "session", r.SessionHandle, "error", err)
		return nil, ckrFromError(err, uint32(pkcs11types.CKR_FUNCTION_FAILED))
	}
	return &createObjectResp{ObjectHandle: uint32(handle)}, uint32(pkcs11types.CKR_OK)
}

// ---- DestroyObject ----

// destroyObjectReq 对应 C 驱动 C_DestroyObject：{"session_id":N,"handle":H}
type destroyObjectReq struct {
	SessionHandle uint32 `json:"session_id"`
	ObjectHandle  uint32 `json:"handle"`
}

func (h *PKCSHandler) handleDestroyObject(ctx context.Context, req *Frame) (interface{}, uint32) {
	var r destroyObjectReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}

	s, err := h.manager.GetSession(pkcs11types.SessionHandle(r.SessionHandle))
	if err != nil {
		return nil, uint32(pkcs11types.CKR_SESSION_HANDLE_INVALID)
	}

	s.Lock()
	rw := s.IsRW()
	provider := s.Provider
	s.Unlock()
	if !rw {
		return nil, uint32(pkcs11types.CKR_SESSION_READ_ONLY)
	}

	objMgr, ok := provider.(card.ObjectManager)
	if !ok {
		return nil, uint32(pkcs11types.CKR_FUNCTION_NOT_SUPPORTED)
	}
	if err := objMgr.DestroyObject(ctx, pkcs11types.ObjectHandle(r.ObjectHandle)); err != nil {
		slog.Warn("DestroyObject 失败", "session", r.SessionHandle, "error", err)
		return nil, ckrFromError(err, uint32(pkcs11types.CKR_FUNCTION_FAILED))
	}
	return nil, uint32(pkcs11types.CKR_OK)
}

// ---- SetAttributeValue ----

// setAttributeValueReq 对应 C 驱动 C_SetAttributeValue：
// {"session_id":N,"object_handle":H,"attrs":[{"type":T,"value":"<base64>"},...]}
type setAttributeValueReq struct {
	SessionHandle uint32 `json:"session_id"`
	ObjectHandle  uint32 `json:"object_handle"`
	Attrs         []struct {
		Type  uint32 `json:"type"`
		Value []byte `json:"value"`
	} `json:"attrs"`
}

func (h *PKCSHandler) handleSetAttributeValue(ctx context.Context, req *Frame) (interface{}, uint32) {
	var r setAttributeValueReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}

	s, err := h.manager.GetSession(pkcs11types.SessionHandle(r.SessionHandle))
	if err != nil {
		return nil, uint32(pkcs11types.CKR_SESSION_HANDLE_INVALID)
	}

	s.Lock()
	rw := s.IsRW()
	provider := s.Provider
	s.Unlock()
	if !rw {
		return nil, uint32(pkcs11types.CKR_SESSION_READ_ONLY)
	}

	objMgr, ok := provider.(card.ObjectManager)
	if !ok {
		return nil, uint32(pkcs11types.CKR_FUNCTION_NOT_SUPPORTED)
	}

	attrs := make([]pkcs11types.Attribute, len(r.Attrs))
	for i, a := range r.Attrs {
		attrs[i] = pkcs11types.Attribute{
			Type:  pkcs11types.AttributeType(a.Type),
			Value: a.Value,
		}
	}
	if err := objMgr.SetAttributes(ctx, pkcs11types.ObjectHandle(r.ObjectHandle), attrs); err != nil {
		slog.Warn("SetAttributeValue 失败", "session", r.SessionHandle, "error", err)
		return nil, ckrFromError(err, uint32(pkcs11types.CKR_FUNCTION_FAILED))
	}
	return nil, uint32(pkcs11types.CKR_OK)
}

// ---- GetObjectSize ----

// getObjectSizeReq 对应 C 驱动 C_GetObjectSize：{"session_id":N,"object_handle":H}
type getObjectSizeReq struct {
	SessionHandle uint32 `json:"session_id"`
	ObjectHandle  uint32 `json:"object_handle"`
}

type getObjectSizeResp struct {
	Size uint32 `json:"size"`
}

func (h *PKCSHandler) handleGetObjectSize(ctx context.Context, req *Frame) (interface{}, uint32) {
	var r getObjectSizeReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}

	s, err := h.manager.GetSession(pkcs11types.SessionHandle(r.SessionHandle))
	if err != nil {
		return nil, uint32(pkcs11types.CKR_SESSION_HANDLE_INVALID)
	}

	objMgr, ok := s.Provider.(card.ObjectManager)
	if !ok {
		return nil, uint32(pkcs11types.CKR_FUNCTION_NOT_SUPPORTED)
	}
	size, err := objMgr.ObjectSize(ctx, pkcs11types.ObjectHandle(r.ObjectHandle))
	if err != nil {
		return nil, ckrFromError(err, uint32(pkcs11types.CKR_FUNCTION_FAILED))
	}
	return &getObjectSizeResp{Size: size}, uint32(pkcs11types.CKR_OK)
}

// ---- GenerateKeyPair ----

// generateKeyPairReq 对应 C 驱动 C_GenerateKeyPair：{"session_id":N,"mechanism":M}。
// C 驱动不传递密钥模板，因此密钥规格由机制决定（RSA→2048、EC→P-256）。
type generateKeyPairReq struct {
	SessionHandle uint32 `json:"session_id"`
	MechanismType uint32 `json:"mechanism"`
	MechParam     []byte `json:"mech_param,omitempty"`
	PubTemplate   []struct {
		Type  uint32 `json:"type"`
		Value []byte `json:"value"`
	} `json:"pub_template"`
	PrivTemplate []struct {
		Type  uint32 `json:"type"`
		Value []byte `json:"value"`
	} `json:"priv_template"`
}

// generateKeyPairResp 的键名与 C 驱动 json_get_int(resp, "pub_handle"/"priv_handle") 一致。
type generateKeyPairResp struct {
	PubKeyHandle  uint32 `json:"pub_handle"`
	PrivKeyHandle uint32 `json:"priv_handle"`
}

func (h *PKCSHandler) handleGenerateKeyPair(ctx context.Context, req *Frame) (interface{}, uint32) {
	var r generateKeyPairReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}

	s, err := h.manager.GetSession(pkcs11types.SessionHandle(r.SessionHandle))
	if err != nil {
		return nil, uint32(pkcs11types.CKR_SESSION_HANDLE_INVALID)
	}

	s.Lock()
	rw := s.IsRW()
	loggedIn := s.Provider.IsLoggedIn()
	provider := s.Provider
	s.Unlock()
	if !rw {
		return nil, uint32(pkcs11types.CKR_SESSION_READ_ONLY)
	}
	if !loggedIn {
		return nil, uint32(pkcs11types.CKR_USER_NOT_LOGGED_IN)
	}

	gen, ok := provider.(card.KeyPairGenerator)
	if !ok {
		return nil, uint32(pkcs11types.CKR_FUNCTION_NOT_SUPPORTED)
	}
	pub, priv, err := gen.GenerateKeyPair(ctx, pkcs11types.MechanismType(r.MechanismType))
	if err != nil {
		slog.Warn("GenerateKeyPair 失败", "session", r.SessionHandle, "error", err)
		return nil, ckrFromError(err, uint32(pkcs11types.CKR_FUNCTION_FAILED))
	}
	return &generateKeyPairResp{
		PubKeyHandle:  uint32(pub),
		PrivKeyHandle: uint32(priv),
	}, uint32(pkcs11types.CKR_OK)
}

// ckrFromError 把 Provider 返回的错误还原为 PKCS#11 错误码。
// 各 Slot 实现以 pkcs11types.CKRv 作为错误值包装（fmt.Errorf("%w: ...")），
// 因此可用 errors.As 精确提取；无法识别时返回 fallback。
func ckrFromError(err error, fallback uint32) uint32 {
	var ckr pkcs11types.CKRv
	if errors.As(err, &ckr) {
		return uint32(ckr)
	}
	return fallback
}
