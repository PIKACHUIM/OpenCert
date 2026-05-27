package ipc

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/globaltrusts/client-card/internal/card"
	"github.com/globaltrusts/client-card/pkg/pkcs11types"
)

// Handler 注册所有 PKCS#11 命令处理函数到 IPC Server。
type PKCSHandler struct {
	manager *card.Manager
}

// NewPKCSHandler 创建 PKCS#11 命令处理器。
func NewPKCSHandler(manager *card.Manager) *PKCSHandler {
	return &PKCSHandler{manager: manager}
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
	s.Register(CmdSignInit, h.handleSignInit)
	s.Register(CmdSign, h.handleSign)
	s.Register(CmdDecryptInit, h.handleDecryptInit)
	s.Register(CmdDecrypt, h.handleDecrypt)
	s.Register(CmdEncryptInit, h.handleEncryptInit)
	s.Register(CmdEncrypt, h.handleEncrypt)
	s.Register(CmdGenerateKeyPair, h.handleGenerateKeyPair)

	// 流式 Digest / Verify 与 Random 一族
	h.RegisterDigestVerifyRandom(s)
}

// ---- GetSlotList ----

type getSlotListReq struct {
	TokenPresent bool `json:"token_present"`
}

type getSlotListResp struct {
	SlotIDs []uint32 `json:"slot_ids"`
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
	return &getSlotListResp{SlotIDs: result}, uint32(pkcs11types.CKR_OK)
}

// ---- GetSlotInfo ----

type slotIDReq struct {
	SlotID uint32 `json:"slot_id"`
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
	return &info, uint32(pkcs11types.CKR_OK)
}

// ---- GetTokenInfo ----

func (h *PKCSHandler) handleGetTokenInfo(ctx context.Context, req *Frame) (interface{}, uint32) {
	var r slotIDReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}

	info, err := h.manager.GetTokenInfo(pkcs11types.SlotID(r.SlotID))
	if err != nil {
		return nil, uint32(pkcs11types.CKR_SLOT_ID_INVALID)
	}
	return &info, uint32(pkcs11types.CKR_OK)
}

// ---- GetMechanismList ----

type getMechListResp struct {
	Mechanisms []uint32 `json:"mechanisms"`
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
	return &getMechListResp{Mechanisms: result}, uint32(pkcs11types.CKR_OK)
}

// ---- OpenSession ----

type openSessionReq struct {
	SlotID uint32 `json:"slot_id"`
	Flags  uint32 `json:"flags"`
}

type openSessionResp struct {
	SessionHandle uint32 `json:"session_handle"`
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
	SessionHandle uint32 `json:"session_handle"`
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
	SessionHandle uint32 `json:"session_handle"`
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
		// 将特定的 CKR 错误码直接返回
		if ckr, ok := err.(pkcs11types.CKRv); ok {
			return nil, uint32(ckr)
		}
		return nil, uint32(pkcs11types.CKR_PIN_INCORRECT)
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
		if ckr, ok := err.(pkcs11types.CKRv); ok {
			return nil, uint32(ckr)
		}
		return nil, uint32(pkcs11types.CKR_SESSION_HANDLE_INVALID)
	}
	return nil, uint32(pkcs11types.CKR_OK)
}

// ---- FindObjectsInit ----

type findObjectsInitReq struct {
	SessionHandle uint32 `json:"session_handle"`
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
	return nil, uint32(pkcs11types.CKR_OK)
}

// ---- FindObjects ----

type findObjectsReq struct {
	SessionHandle uint32 `json:"session_handle"`
	MaxCount      uint32 `json:"max_count"`
}

type findObjectsResp struct {
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

	result := make([]uint32, count)
	for i := 0; i < count; i++ {
		result[i] = uint32(remaining[i])
	}
	s.FindPos += count

	return &findObjectsResp{Handles: result}, uint32(pkcs11types.CKR_OK)
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

type getAttrReq struct {
	SessionHandle uint32   `json:"session_handle"`
	ObjectHandle  uint32   `json:"object_handle"`
	AttrTypes     []uint32 `json:"attr_types"`
}

type getAttrResp struct {
	Attributes []struct {
		Type  uint32 `json:"type"`
		Value []byte `json:"value"`
	} `json:"attributes"`
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
	SessionHandle uint32 `json:"session_handle"`
	MechanismType uint32 `json:"mechanism_type"`
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
	SessionHandle uint32 `json:"session_handle"`
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
	SessionHandle uint32 `json:"session_handle"`
	MechanismType uint32 `json:"mechanism_type"`
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

type decryptReq struct {
	SessionHandle uint32 `json:"session_handle"`
	Ciphertext    []byte `json:"ciphertext"`
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

	plain, err := s.Provider.Decrypt(ctx, decryptHandle, decryptMech, r.Ciphertext)
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

type encryptReq struct {
	SessionHandle uint32 `json:"session_handle"`
	Plaintext     []byte `json:"plaintext"`
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

	cipher, err := s.Provider.Encrypt(ctx, encryptHandle, encryptMech, r.Plaintext)
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

type getInfoResp struct {
	CryptokiVersion struct {
		Major uint8 `json:"major"`
		Minor uint8 `json:"minor"`
	} `json:"cryptoki_version"`
	ManufacturerID  string `json:"manufacturer_id"`
	Flags           uint32 `json:"flags"`
	LibraryDesc     string `json:"library_desc"`
	LibraryVersion  struct {
		Major uint8 `json:"major"`
		Minor uint8 `json:"minor"`
	} `json:"library_version"`
}

func (h *PKCSHandler) handleGetInfo(_ context.Context, _ *Frame) (interface{}, uint32) {
	resp := &getInfoResp{
		ManufacturerID: "OpenCert Project",
		LibraryDesc:    "OpenCert PKCS#11 Driver",
	}
	resp.CryptokiVersion.Major = 2
	resp.CryptokiVersion.Minor = 40
	resp.LibraryVersion.Major = 1
	resp.LibraryVersion.Minor = 0
	return resp, uint32(pkcs11types.CKR_OK)
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
	MechanismType uint32 `json:"mechanism_type"`
}

type getMechInfoResp struct {
	MinKeySize uint32 `json:"min_key_size"`
	MaxKeySize uint32 `json:"max_key_size"`
	Flags      uint32 `json:"flags"`
}

// 机制信息标志位。
const (
	CKF_ENCRYPT  uint32 = 0x00000100
	CKF_DECRYPT  uint32 = 0x00000200
	CKF_SIGN     uint32 = 0x00000800
	CKF_VERIFY   uint32 = 0x00002000
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
	pkcs11types.CKM_EC_KEY_PAIR_GEN:       {MinKeySize: 256, MaxKeySize: 521, Flags: CKF_GENERATE_KEY_PAIR},
	pkcs11types.CKM_ECDSA:                 {MinKeySize: 256, MaxKeySize: 521, Flags: CKF_SIGN | CKF_VERIFY},
	pkcs11types.CKM_ECDSA_SHA256:          {MinKeySize: 256, MaxKeySize: 521, Flags: CKF_SIGN | CKF_VERIFY},
	pkcs11types.CKM_ECDSA_SHA384:          {MinKeySize: 256, MaxKeySize: 521, Flags: CKF_SIGN | CKF_VERIFY},
	pkcs11types.CKM_ECDSA_SHA512:          {MinKeySize: 256, MaxKeySize: 521, Flags: CKF_SIGN | CKF_VERIFY},
	// EdDSA (Ed25519)
	pkcs11types.CKM_EDDSA:                 {MinKeySize: 256, MaxKeySize: 256, Flags: CKF_SIGN | CKF_VERIFY},
	// AES
	pkcs11types.CKM_AES_CBC:               {MinKeySize: 128, MaxKeySize: 256, Flags: CKF_ENCRYPT | CKF_DECRYPT},
	pkcs11types.CKM_AES_GCM:               {MinKeySize: 128, MaxKeySize: 256, Flags: CKF_ENCRYPT | CKF_DECRYPT},
	// ChaCha20
	pkcs11types.CKM_CHACHA20_POLY1305:     {MinKeySize: 256, MaxKeySize: 256, Flags: CKF_ENCRYPT | CKF_DECRYPT},
	// 摘要算法
	pkcs11types.CKM_SHA_1:                 {MinKeySize: 0, MaxKeySize: 0, Flags: 0},
	pkcs11types.CKM_SHA256:                {MinKeySize: 0, MaxKeySize: 0, Flags: 0},
	pkcs11types.CKM_SHA384:                {MinKeySize: 0, MaxKeySize: 0, Flags: 0},
	pkcs11types.CKM_SHA512:                {MinKeySize: 0, MaxKeySize: 0, Flags: 0},
	pkcs11types.CKM_SHA3_256:              {MinKeySize: 0, MaxKeySize: 0, Flags: 0},
	pkcs11types.CKM_SHA3_384:              {MinKeySize: 0, MaxKeySize: 0, Flags: 0},
	pkcs11types.CKM_SHA3_512:              {MinKeySize: 0, MaxKeySize: 0, Flags: 0},
	pkcs11types.CKM_MD5:                   {MinKeySize: 0, MaxKeySize: 0, Flags: 0},
	// 国密
	pkcs11types.CKM_SM2_KEY_PAIR_GEN:      {MinKeySize: 256, MaxKeySize: 256, Flags: CKF_GENERATE_KEY_PAIR},
	pkcs11types.CKM_SM2:                   {MinKeySize: 256, MaxKeySize: 256, Flags: CKF_SIGN | CKF_VERIFY | CKF_ENCRYPT | CKF_DECRYPT},
	pkcs11types.CKM_SM3:                   {MinKeySize: 0, MaxKeySize: 0, Flags: 0},
	pkcs11types.CKM_SM4_CBC:               {MinKeySize: 128, MaxKeySize: 128, Flags: CKF_ENCRYPT | CKF_DECRYPT},
	pkcs11types.CKM_SM4_GCM:               {MinKeySize: 128, MaxKeySize: 128, Flags: CKF_ENCRYPT | CKF_DECRYPT},
}

// ---- InitPIN ----

type initPINReq struct {
	SessionHandle uint32 `json:"session_handle"`
	PIN           string `json:"pin"`
}

func (h *PKCSHandler) handleInitPIN(_ context.Context, req *Frame) (interface{}, uint32) {
	var r initPINReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}

	s, err := h.manager.GetSession(pkcs11types.SessionHandle(r.SessionHandle))
	if err != nil {
		return nil, uint32(pkcs11types.CKR_SESSION_HANDLE_INVALID)
	}

	s.Lock()
	defer s.Unlock()

	// InitPIN 只能在 RW_SO 状态下调用
	if s.State != pkcs11types.CKS_RW_SO_FUNCTIONS {
		return nil, uint32(pkcs11types.CKR_USER_NOT_LOGGED_IN)
	}

	// TODO: 实际的 PIN 初始化逻辑（设置 Token 的 User PIN）
	slog.Info("InitPIN 调用", "session", r.SessionHandle)
	return nil, uint32(pkcs11types.CKR_OK)
}

// ---- SetPIN ----

type setPINReq struct {
	SessionHandle uint32 `json:"session_handle"`
	OldPIN        string `json:"old_pin"`
	NewPIN        string `json:"new_pin"`
}

func (h *PKCSHandler) handleSetPIN(_ context.Context, req *Frame) (interface{}, uint32) {
	var r setPINReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}

	s, err := h.manager.GetSession(pkcs11types.SessionHandle(r.SessionHandle))
	if err != nil {
		return nil, uint32(pkcs11types.CKR_SESSION_HANDLE_INVALID)
	}

	s.Lock()
	defer s.Unlock()

	// SetPIN 需要在 RW_USER 或 RW_SO 状态下调用
	if s.State != pkcs11types.CKS_RW_USER_FUNCTIONS && s.State != pkcs11types.CKS_RW_SO_FUNCTIONS {
		return nil, uint32(pkcs11types.CKR_SESSION_READ_ONLY)
	}

	// TODO: 实际的 PIN 修改逻辑
	slog.Info("SetPIN 调用", "session", r.SessionHandle)
	return nil, uint32(pkcs11types.CKR_OK)
}

// ---- CreateObject ----

type createObjectReq struct {
	SessionHandle uint32 `json:"session_handle"`
	Template      []struct {
		Type  uint32 `json:"type"`
		Value []byte `json:"value"`
	} `json:"template"`
}

type createObjectResp struct {
	ObjectHandle uint32 `json:"object_handle"`
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
	// 创建对象需要 RW 会话
	if !s.IsRW() {
		s.Unlock()
		return nil, uint32(pkcs11types.CKR_SESSION_READ_ONLY)
	}
	s.Unlock()

	// 转换模板
	template := make([]pkcs11types.Attribute, len(r.Template))
	for i, t := range r.Template {
		template[i] = pkcs11types.Attribute{
			Type:  pkcs11types.AttributeType(t.Type),
			Value: t.Value,
		}
	}

	// TODO: 实际的对象创建逻辑（通过 Provider 接口）
	slog.Info("CreateObject 调用", "session", r.SessionHandle, "attrs", len(template))
	return &createObjectResp{ObjectHandle: 0}, uint32(pkcs11types.CKR_OK)
}

// ---- DestroyObject ----

type destroyObjectReq struct {
	SessionHandle uint32 `json:"session_handle"`
	ObjectHandle  uint32 `json:"object_handle"`
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
	if !s.IsRW() {
		s.Unlock()
		return nil, uint32(pkcs11types.CKR_SESSION_READ_ONLY)
	}
	s.Unlock()

	// TODO: 实际的对象删除逻辑（通过 Provider 接口）
	slog.Info("DestroyObject 调用", "session", r.SessionHandle, "object", r.ObjectHandle)
	return nil, uint32(pkcs11types.CKR_OK)
}

// ---- GenerateKeyPair ----

type generateKeyPairReq struct {
	SessionHandle uint32 `json:"session_handle"`
	MechanismType uint32 `json:"mechanism_type"`
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

type generateKeyPairResp struct {
	PubKeyHandle  uint32 `json:"pub_key_handle"`
	PrivKeyHandle uint32 `json:"priv_key_handle"`
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
	if !s.IsRW() {
		s.Unlock()
		return nil, uint32(pkcs11types.CKR_SESSION_READ_ONLY)
	}
	if !s.Provider.IsLoggedIn() {
		s.Unlock()
		return nil, uint32(pkcs11types.CKR_USER_NOT_LOGGED_IN)
	}
	s.Unlock()

	// TODO: 实际的密钥对生成逻辑（复用现有 keygen 逻辑）
	slog.Info("GenerateKeyPair 调用", "session", r.SessionHandle, "mechanism", r.MechanismType)
	return &generateKeyPairResp{PubKeyHandle: 0, PrivKeyHandle: 0}, uint32(pkcs11types.CKR_OK)
}
