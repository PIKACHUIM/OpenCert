package pkcs11

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

// CK_FUNCTION_LIST 的头部长度（CK_VERSION 之后第一个函数指针的字节偏移）。
//
// 这里存在两种实现约定，且都是真实存在的：
//   - 自然对齐（默认，GCC/MSVC 默认行为）：offset = 8（64 位）；
//   - 1 字节打包（头文件外围加了 #pragma pack(push, 1)）：offset = 2。
//
// 因此加载时会用「函数表项 vs 模块导出符号」交叉比对来自动判定，
// 无法判定时回退到自然对齐（业界主流做法）。
const functionListHeaderSize = 8

// packedListHeaderSize 是 1 字节打包情况下的头部偏移。
const packedListHeaderSize = 2

// CK_FUNCTION_LIST 中各函数的序号（1 起，顺序与 pkcs11f.h 完全一致）。
const (
	ordInitialize       = 1
	ordFinalize         = 2
	ordGetInfo          = 3
	ordGetSlotList      = 5
	ordGetSlotInfo      = 6
	ordGetTokenInfo     = 7
	ordGetMechanismList = 8
	ordGetMechanismInfo = 9
	ordOpenSession      = 13
	ordCloseSession     = 14
	ordLogin            = 19
	ordLogout           = 20
	ordCreateObject     = 21
	ordDestroyObject    = 23
	ordGetAttributeVal  = 25
	ordFindObjectsInit  = 27
	ordFindObjects      = 28
	ordFindObjectsFinal = 29
	ordDecryptInit      = 34
	ordDecrypt          = 35
	ordSignInit         = 43
	ordSign             = 44
	ordGenerateKeyPair  = 60
)

// functions 保存从 CK_FUNCTION_LIST 解析出的函数指针。
// 所有结构体指针参数一律以 unsafe.Pointer 传递，由布局层负责编组。
type functions struct {
	initialize       func(pInitArgs unsafe.Pointer) ckULong
	finalize         func(pReserved unsafe.Pointer) ckULong
	getInfo          func(pInfo unsafe.Pointer) ckULong
	getSlotList      func(tokenPresent byte, pSlotList *ckULong, pulCount *ckULong) ckULong
	getSlotInfo      func(slotID ckULong, pInfo unsafe.Pointer) ckULong
	getTokenInfo     func(slotID ckULong, pInfo unsafe.Pointer) ckULong
	getMechanismList func(slotID ckULong, pList *ckULong, pulCount *ckULong) ckULong
	getMechanismInfo func(slotID ckULong, mech ckULong, pInfo unsafe.Pointer) ckULong
	openSession      func(slotID ckULong, flags ckFlags, pApp unsafe.Pointer, notify unsafe.Pointer, phSession *ckULong) ckULong
	closeSession     func(hSession ckULong) ckULong
	login            func(hSession ckULong, userType ckULong, pPin *byte, ulPinLen ckULong) ckULong
	logout           func(hSession ckULong) ckULong
	createObject     func(hSession ckULong, pTemplate unsafe.Pointer, ulCount ckULong, phObject *ckULong) ckULong
	destroyObject    func(hSession ckULong, hObject ckULong) ckULong
	getAttributeVal  func(hSession ckULong, hObject ckULong, pTemplate unsafe.Pointer, ulCount ckULong) ckULong
	findObjectsInit  func(hSession ckULong, pTemplate unsafe.Pointer, ulCount ckULong) ckULong
	findObjects      func(hSession ckULong, phObject *ckULong, ulMax ckULong, pulCount *ckULong) ckULong
	findObjectsFinal func(hSession ckULong) ckULong
	decryptInit      func(hSession ckULong, pMechanism unsafe.Pointer, hKey ckULong) ckULong
	decrypt          func(hSession ckULong, pEnc *byte, ulEncLen ckULong, pData *byte, pulDataLen *ckULong) ckULong
	signInit         func(hSession ckULong, pMechanism unsafe.Pointer, hKey ckULong) ckULong
	sign             func(hSession ckULong, pData *byte, ulDataLen ckULong, pSig *byte, pulSigLen *ckULong) ckULong
	generateKeyPair  func(hSession ckULong, pMechanism unsafe.Pointer,
		pPubTmpl unsafe.Pointer, ulPubCount ckULong,
		pPrivTmpl unsafe.Pointer, ulPrivCount ckULong,
		phPub *ckULong, phPriv *ckULong) ckULong
}

// Module 是一个已加载的 PKCS#11 模块。
type Module struct {
	path   string
	handle uintptr
	fns    *functions
	// table 是模块返回的 CK_FUNCTION_LIST 指针（仅用于诊断/测试）。
	table unsafe.Pointer
	// layout 是模块的结构体布局（自然对齐 / 1 字节打包）。
	layout layout
	// offsetDetected 表示布局是通过导出符号交叉比对得到的。
	offsetDetected bool

	mu       sync.Mutex
	inited   bool
	initRefs int
}

// Layout 返回函数表头部偏移与是否已自动识别。
func (m *Module) Layout() (offset int, detected bool) {
	return m.headerOffsetValue(), m.offsetDetected
}

// headerOffset 记录函数表头部偏移。
func (m *Module) headerOffsetValue() int {
	if m.layout.packed {
		return packedListHeaderSize
	}
	return functionListHeaderSize
}

// LayoutNote 返回人类可读的函数表布局说明。
func (m *Module) LayoutNote() string {
	if !m.offsetDetected {
		return "未识别（按自然对齐解析）"
	}
	if m.layout.packed {
		return "1 字节打包布局"
	}
	return "标准自然对齐布局"
}

// StructLayoutPacked 报告模块是否使用 1 字节打包的结构体布局。
func (m *Module) StructLayoutPacked() bool { return m.layout.packed }

// LibraryInfo 是模块自报信息。
type LibraryInfo struct {
	Manufacturer  string
	Description   string
	CryptokiMajor byte
	CryptokiMinor byte
	LibraryMajor  byte
	LibraryMinor  byte
}

var (
	moduleMu sync.Mutex
	modules  = map[string]*Module{}
)

// LoadModule 加载（或复用）一个 PKCS#11 动态库，并完成 C_Initialize。
func LoadModule(path string) (*Module, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("PKCS#11 模块路径为空")
	}

	moduleMu.Lock()
	defer moduleMu.Unlock()

	if m, ok := modules[path]; ok {
		if err := m.init(); err != nil {
			return nil, err
		}
		m.initRefs++
		return m, nil
	}

	m, err := openModule(path)
	if err != nil {
		return nil, err
	}
	if err := m.init(); err != nil {
		_ = m.unload()
		return nil, err
	}
	m.initRefs = 1
	modules[path] = m
	return m, nil
}

// ReleaseModule 释放一次模块引用；引用归零时执行 C_Finalize 并卸载动态库。
func ReleaseModule(path string) {
	moduleMu.Lock()
	defer moduleMu.Unlock()
	m, ok := modules[path]
	if !ok {
		return
	}
	m.initRefs--
	if m.initRefs > 0 {
		return
	}
	delete(modules, path)
	_ = m.unload()
}

// openModule 打开动态库并解析 CK_FUNCTION_LIST。
func openModule(path string) (*Module, error) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		return nil, fmt.Errorf("当前平台不是 64 位，暂不支持加载 PKCS#11 模块")
	}

	handle, err := loadLibrary(path)
	if err != nil {
		return nil, fmt.Errorf("加载 PKCS#11 模块失败（%s）: %w；"+
			"请确认路径正确、位数与进程一致（64 位服务需 64 位模块）", path, err)
	}

	getFuncListAddr, err := lookupSymbol(handle, "C_GetFunctionList")
	if err != nil {
		releaseLibrary(handle)
		return nil, fmt.Errorf("%s 不是合法的 PKCS#11 模块：缺少 C_GetFunctionList 导出", path)
	}

	var getFuncList func(ppFunctionList *unsafe.Pointer) ckULong
	purego.RegisterFunc(&getFuncList, getFuncListAddr)

	var list unsafe.Pointer
	if rv := getFuncList(&list); rv != ckrOK {
		releaseLibrary(handle)
		return nil, fmt.Errorf("C_GetFunctionList 失败: 0x%08X（%s）", uint64(rv), ckRVText(rv))
	}
	if list == nil {
		releaseLibrary(handle)
		return nil, fmt.Errorf("C_GetFunctionList 返回空函数表")
	}

	packed, detected := detectStructLayout(list, handle)
	m := &Module{
		path:           path,
		handle:         handle,
		table:          list,
		layout:         newLayout(packed),
		offsetDetected: detected,
		fns:            &functions{},
	}
	if !detected {
		slog.Warn("[PKCS#11] 无法通过导出符号判定结构体布局，按自然对齐解析；"+
			"若调用失败请在存储区域配置中改用其它模块或反馈排障", "module", path)
	} else {
		slog.Debug("[PKCS#11] 布局判定完成", "module", path, "packed", packed)
	}
	m.bind(list)
	if err := m.checkBinding(); err != nil {
		releaseLibrary(handle)
		return nil, err
	}
	return m, nil
}

// detectStructLayout 通过「函数表项 vs 模块导出符号」交叉比对，判断模块的结构体布局：
//   - 函数指针位于头部偏移 2 → 1 字节打包；
//   - 位于头部偏移 8 → 标准自然对齐。
func detectStructLayout(list unsafe.Pointer, handle uintptr) (packed bool, detected bool) {
	probes := []struct {
		ord  int
		name string
	}{
		{ordGetInfo, "C_GetInfo"},
		{ordGetSlotList, "C_GetSlotList"},
		{ordFinalize, "C_Finalize"},
		{ordGetSlotInfo, "C_GetSlotInfo"},
		{ordGetTokenInfo, "C_GetTokenInfo"},
	}
	candidates := []struct {
		offset int
		packed bool
	}{
		{functionListHeaderSize, false},
		{packedListHeaderSize, true},
	}
	for _, candidate := range candidates {
		matched, checked := 0, 0
		for _, p := range probes {
			sym, err := lookupSymbol(handle, p.name)
			if err != nil || sym == 0 {
				continue
			}
			checked++
			addr := *(*uintptr)(unsafe.Add(list, uintptr(candidate.offset)+uintptr(p.ord-1)*unsafe.Sizeof(uintptr(0))))
			if addr == sym {
				matched++
			}
		}
		// 至少比对成功两个函数才认为判定有效，避免巧合
		if checked >= 2 && matched == checked {
			return candidate.packed, true
		}
	}
	return false, false
}

// bind 按序号把函数表项注册为 Go 函数。
//
// CK_FUNCTION_LIST 是一张函数指针表：第 0 项是 CK_VERSION，其后按 pkcs11f.h 的顺序排列 C_*。
func (m *Module) bind(list unsafe.Pointer) {
	f := m.fns
	offset := m.headerOffsetValue()
	reg := func(ord int, target any) {
		addr := *(*uintptr)(unsafe.Add(list, uintptr(offset)+uintptr(ord-1)*unsafe.Sizeof(uintptr(0))))
		if addr == 0 {
			return
		}
		purego.RegisterFunc(target, addr)
	}

	reg(ordInitialize, &f.initialize)
	reg(ordFinalize, &f.finalize)
	reg(ordGetInfo, &f.getInfo)
	reg(ordGetSlotList, &f.getSlotList)
	reg(ordGetSlotInfo, &f.getSlotInfo)
	reg(ordGetTokenInfo, &f.getTokenInfo)
	reg(ordGetMechanismList, &f.getMechanismList)
	reg(ordGetMechanismInfo, &f.getMechanismInfo)
	reg(ordOpenSession, &f.openSession)
	reg(ordCloseSession, &f.closeSession)
	reg(ordLogin, &f.login)
	reg(ordLogout, &f.logout)
	reg(ordCreateObject, &f.createObject)
	reg(ordDestroyObject, &f.destroyObject)
	reg(ordGetAttributeVal, &f.getAttributeVal)
	reg(ordFindObjectsInit, &f.findObjectsInit)
	reg(ordFindObjects, &f.findObjects)
	reg(ordFindObjectsFinal, &f.findObjectsFinal)
	reg(ordDecryptInit, &f.decryptInit)
	reg(ordDecrypt, &f.decrypt)
	reg(ordSignInit, &f.signInit)
	reg(ordSign, &f.sign)
	reg(ordGenerateKeyPair, &f.generateKeyPair)
}

// checkBinding 检查必需函数是否都已解析。
func (m *Module) checkBinding() error {
	f := m.fns
	missing := ""
	switch {
	case f.initialize == nil:
		missing = "C_Initialize"
	case f.getInfo == nil:
		missing = "C_GetInfo"
	case f.getSlotList == nil:
		missing = "C_GetSlotList"
	case f.getTokenInfo == nil:
		missing = "C_GetTokenInfo"
	case f.openSession == nil:
		missing = "C_OpenSession"
	case f.login == nil:
		missing = "C_Login"
	case f.findObjectsInit == nil:
		missing = "C_FindObjectsInit"
	case f.signInit == nil:
		missing = "C_SignInit"
	case f.generateKeyPair == nil:
		missing = "C_GenerateKeyPair"
	}
	if missing != "" {
		return fmt.Errorf("PKCS#11 模块缺少必需函数 %s（函数表可能不是标准 v2.x，或布局判定错误）", missing)
	}
	return nil
}

// init 执行 C_Initialize（已被初始化过视为成功）。
func (m *Module) init() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.inited {
		return nil
	}
	if m.fns.initialize == nil {
		return fmt.Errorf("PKCS#11 模块缺少 C_Initialize 函数")
	}
	if r := m.fns.initialize(nil); r != ckrOK && r != ckrCryptokiAlreadyInit {
		return fmt.Errorf("C_Initialize 失败: 0x%08X（%s）", uint64(r), ckRVText(r))
	}
	m.inited = true
	return nil
}

// unload 执行 C_Finalize 并卸载动态库。
func (m *Module) unload() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.inited && m.fns.finalize != nil {
		if rv := m.fns.finalize(nil); rv != ckrOK && rv != ckrCryptokiNotInitialized {
			slog.Warn("[PKCS#11] C_Finalize 返回错误", "module", m.path, "rv", fmt.Sprintf("0x%08X", uint64(rv)))
		}
		m.inited = false
	}
	if m.handle != 0 {
		releaseLibrary(m.handle)
		m.handle = 0
	}
	return nil
}

// Path 返回模块路径。
func (m *Module) Path() string { return m.path }

// LibraryInfo 返回模块自身信息（按布局解析，避免打包/对齐差异导致错位）。
func (m *Module) LibraryInfo() (LibraryInfo, error) {
	var out LibraryInfo
	if m.fns.getInfo == nil {
		return out, fmt.Errorf("模块不支持 C_GetInfo")
	}
	l := m.layout
	buf := make([]byte, l.infoTotal+64)
	if rv := m.fns.getInfo(unsafe.Pointer(&buf[0])); rv != ckrOK {
		return out, ckError("C_GetInfo", rv)
	}
	out.CryptokiMajor = buf[0]
	out.CryptokiMinor = buf[1]
	out.Manufacturer = ckString(buf[2:34])
	out.Description = ckString(buf[l.infoDescOff : l.infoDescOff+32])
	out.LibraryMajor = buf[l.infoDescOff+32]
	out.LibraryMinor = buf[l.infoDescOff+33]
	return out, nil
}

// ---- 槽位与令牌 ----

// Slot 描述一个已发现的槽位/令牌。
type Slot struct {
	ID           ckULong
	Index        int
	Description  string
	Manufacturer string
	TokenPresent bool
	Token        TokenInfo
}

// TokenInfo 是令牌摘要。
type TokenInfo struct {
	Label           string
	Manufacturer    string
	Model           string
	Serial          string
	Flags           ckFlags
	LoginRequired   bool
	UserPinInit     bool
	UserPinLocked   bool
	UserPinFinalTry bool
	SessionCount    uint64
	MaxSessionCount uint64
}

// ListSlots 枚举槽位与令牌信息。
func (m *Module) ListSlots() ([]Slot, error) {
	var count ckULong
	if rv := m.fns.getSlotList(0, nil, &count); rv != ckrOK {
		return nil, ckError("C_GetSlotList", rv)
	}
	if count == 0 {
		return nil, nil
	}
	ids := make([]ckULong, count)
	got := count
	if rv := m.fns.getSlotList(0, &ids[0], &got); rv != ckrOK {
		return nil, ckError("C_GetSlotList", rv)
	}
	ids = ids[:got]

	l := m.layout
	out := make([]Slot, 0, len(ids))
	for i, id := range ids {
		s := Slot{ID: id, Index: i}

		if m.fns.getSlotInfo != nil {
			raw := make([]byte, l.slotInfoTotal+64)
			if rv := m.fns.getSlotInfo(id, unsafe.Pointer(&raw[0])); rv == ckrOK {
				s.Description = ckString(raw[0:64])
				s.Manufacturer = ckString(raw[64:96])
			}
		}
		if m.fns.getTokenInfo != nil {
			raw := make([]byte, l.tokenInfoTotal+64)
			if rv := m.fns.getTokenInfo(id, unsafe.Pointer(&raw[0])); rv == ckrOK {
				s.TokenPresent = true
				flags := l.readULong(raw[96:])
				s.Token = TokenInfo{
					Label:           ckString(raw[0:32]),
					Manufacturer:    ckString(raw[32:64]),
					Model:           ckString(raw[64:80]),
					Serial:          ckString(raw[80:96]),
					Flags:           ckFlags(flags),
					LoginRequired:   flags&ckFlags(ckfLoginRequired) != 0,
					UserPinInit:     flags&ckFlags(ckfUserPinInitialized) != 0,
					UserPinLocked:   flags&ckFlags(ckfUserPinLocked) != 0,
					UserPinFinalTry: flags&ckFlags(ckfUserPinFinalTry) != 0,
					SessionCount:    uint64(l.readULong(raw[l.tokenULongOffset(1):])),
					MaxSessionCount: uint64(l.readULong(raw[l.tokenULongOffset(0):])),
				}
			}
		}
		out = append(out, s)
	}
	return out, nil
}

// ---- 会话 ----

// Session 是一次打开的 PKCS#11 会话。
type Session struct {
	m      *Module
	handle ckULong
	logged bool
	closed bool
}

// OpenSession 打开一个读写会话；login 为真时使用 pin 登录。
func (m *Module) OpenSession(slotID ckULong, pin string, login bool) (*Session, error) {
	if m.fns.openSession == nil {
		return nil, fmt.Errorf("模块不支持 C_OpenSession")
	}
	var hSession ckULong
	flags := ckfSerialSession | ckfRW
	if rv := m.fns.openSession(slotID, flags, nil, nil, &hSession); rv != ckrOK {
		return nil, ckError("C_OpenSession", rv)
	}
	s := &Session{m: m, handle: hSession}

	if login {
		if err := s.Login(pin); err != nil {
			_ = s.Close()
			return nil, err
		}
	}
	return s, nil
}

// Login 以 CKU_USER 身份登录。
func (s *Session) Login(pin string) error {
	if s.logged {
		return nil
	}
	pinBytes := []byte(pin)
	var pPin *byte
	if len(pinBytes) > 0 {
		pPin = &pinBytes[0]
	}
	rv := s.m.fns.login(s.handle, ckuUser, pPin, ckULong(len(pinBytes)))
	switch rv {
	case ckrOK, ckrUserAlreadyLoggedIn, ckrUserTypeInvalid, ckrUserAnotherAlreadyLogged:
		s.logged = true
		return nil
	default:
		return fmt.Errorf("登录令牌失败: 0x%08X（%s）", uint64(rv), ckRVText(rv))
	}
}

// Close 关闭会话。
func (s *Session) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	if s.logged && s.m.fns.logout != nil {
		_ = s.m.fns.logout(s.handle)
		s.logged = false
	}
	if s.m.fns.closeSession != nil {
		if rv := s.m.fns.closeSession(s.handle); rv != ckrOK {
			return ckError("C_CloseSession", rv)
		}
	}
	return nil
}

// LoggedIn 返回是否已登录。
func (s *Session) LoggedIn() bool { return s.logged }

// ---- 辅助 ----

func ckString(b []byte) string {
	return strings.TrimRight(string(b), " \x00")
}

// ckError 构造带返回码与中文说明的错误。
func ckError(op string, rv ckULong) error {
	return fmt.Errorf("%s 失败: 0x%08X（%s）", op, uint64(rv), ckRVText(rv))
}

// isNotFound 判断错误码是否表示「对象不存在」。
func isNotFound(rv ckULong) bool {
	return rv == ckrObjectHandleInvalid || rv == ckrKeyHandleInvalid
}
