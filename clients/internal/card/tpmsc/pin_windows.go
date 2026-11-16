//go:build windows

package tpmsc

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// 本文件通过 Smart Card Minidriver 接口修改 VSC 用户 PIN，或用 PUK 解锁 PIN。
//
// Windows 没有面向应用层的“改 PIN”API：certutil/tpmvscmgr 都不提供，
// 只能连接读卡器后直接调用卡片 minidriver（VSC 为 msclmd.dll）导出的
// CardAcquireContext，再调用它回填的 pfnCardChangeAuthenticatorEx。
//
// 注意：本实现未在真实 TPM 设备上验证过；失败时返回带 SCARD/HRESULT 的错误码。

const (
	scardShareShared         = 2
	scardProtocolT0          = 1
	scardProtocolT1          = 2
	scardAttrAtrString       = 0x00090303
	cardDataCurrentVersion   = 7
	cardDataFallbackVersion  = 6
	pinChangeFlagChangePIN   = 0x00000001
	pinChangeFlagUnblock     = 0x00000002
	roleUserPinID            = 1
	scardSuccess             = 0
	scardEInvalidParameter   = 0x80100004
	scardESharingViolation   = 0x8010000B
	scardENoSmartcard        = 0x8010000C
	scardFCommError          = 0x80100013
	scardEUnsupportedFeature = 0x80100022
	scardEWrongCHV           = 0x8010006B
	scardWCHVBlocked         = 0x8010006C
)

var (
	msclmdDLL              = windows.NewLazyDLL("msclmd.dll")
	procCardAcquireContext = msclmdDLL.NewProc("CardAcquireContext")
	procSCardConnectW      = winscardDLL.NewProc("SCardConnectW")
	procSCardDisconnect    = winscardDLL.NewProc("SCardDisconnect")
	procSCardGetAttrib     = winscardDLL.NewProc("SCardGetAttrib")
	kernel32DLL            = windows.NewLazySystemDLL("kernel32.dll")
	procGetProcessHeap     = kernel32DLL.NewProc("GetProcessHeap")
	procHeapAlloc          = kernel32DLL.NewProc("HeapAlloc")
	procHeapReAlloc        = kernel32DLL.NewProc("HeapReAlloc")
	procHeapFree           = kernel32DLL.NewProc("HeapFree")
)

// cardData 对应 cardmod.h 的 CARD_DATA v7（63 个字段）。字段顺序必须与 C 定义一致。
type cardData struct {
	dwVersion                    uint32
	pbAtr                        *byte
	cbAtr                        uint32
	pwszCardName                 *uint16
	pfnCspAlloc                  uintptr
	pfnCspReAlloc                uintptr
	pfnCspFree                   uintptr
	pfnCspCacheAddFile           uintptr
	pfnCspCacheLookupFile        uintptr
	pfnCspCacheDeleteFile        uintptr
	pvCacheContext               uintptr
	pfnCspPadData                uintptr
	hSCardCtx                    uintptr
	hScard                       uintptr
	pvVendorSpecific             uintptr
	pfnCardDeleteContext         uintptr
	pfnCardQueryCapabilities     uintptr
	pfnCardDeleteContainer       uintptr
	pfnCardCreateContainer       uintptr
	pfnCardGetContainerInfo      uintptr
	pfnCardAuthenticatePin       uintptr
	pfnCardGetChallenge          uintptr
	pfnCardAuthenticateChallenge uintptr
	pfnCardUnblockPin            uintptr
	pfnCardChangeAuthenticator   uintptr
	pfnCardDeauthenticate        uintptr
	pfnCardCreateDirectory       uintptr
	pfnCardDeleteDirectory       uintptr
	pvUnused3                    uintptr
	pvUnused4                    uintptr
	pfnCardCreateFile            uintptr
	pfnCardReadFile              uintptr
	pfnCardWriteFile             uintptr
	pfnCardDeleteFile            uintptr
	pfnCardEnumFiles             uintptr
	pfnCardGetFileInfo           uintptr
	pfnCardQueryFreeSpace        uintptr
	pfnCardQueryKeySizes         uintptr
	pfnCardSignData              uintptr
	pfnCardRSADecrypt            uintptr
	pfnCardConstructDHAgreement  uintptr
	pfnCardDeriveKey             uintptr
	pfnCardDestroyDHAgreement    uintptr
	pfnCspGetDHAgreement         uintptr
	pfnCardGetChallengeEx        uintptr
	pfnCardAuthenticateEx        uintptr
	pfnCardChangeAuthenticatorEx uintptr
	pfnCardDeauthenticateEx      uintptr
	pfnCardGetContainerProperty  uintptr
	pfnCardSetContainerProperty  uintptr
	pfnCardGetProperty           uintptr
	pfnCardSetProperty           uintptr
	pfnCspUnpadData              uintptr
	pfnMDImportSessionKey        uintptr
	pfnMDEncryptData             uintptr
	pfnCardImportSessionKey      uintptr
	pfnCardGetSharedKeyHandle    uintptr
	pfnCardGetAlgorithmProperty  uintptr
	pfnCardGetKeyProperty        uintptr
	pfnCardSetKeyProperty        uintptr
	pfnCardDestroyKey            uintptr
	pfnCardProcessEncryptedData  uintptr
	pfnCardCreateContainerEx     uintptr
}

var (
	cspAllocCallback     = syscall.NewCallback(cspAlloc)
	cspReAllocCallback   = syscall.NewCallback(cspReAlloc)
	cspFreeCallback      = syscall.NewCallback(cspFree)
	cspCacheOKCallback   = syscall.NewCallback(cspCacheOK)
	cspCacheMissCallback = syscall.NewCallback(cspCacheMiss)
	cspPadDataCallback   = syscall.NewCallback(cspPadDataUnsupported)
)

func cspAlloc(size uintptr) uintptr {
	heap, _, _ := procGetProcessHeap.Call()
	ptr, _, _ := procHeapAlloc.Call(heap, 0, size)
	return ptr
}

func cspReAlloc(addr, size uintptr) uintptr {
	heap, _, _ := procGetProcessHeap.Call()
	ptr, _, _ := procHeapReAlloc.Call(heap, 0, addr, size)
	return ptr
}

func cspFree(addr uintptr) uintptr {
	if addr == 0 {
		return 0
	}
	heap, _, _ := procGetProcessHeap.Call()
	procHeapFree.Call(heap, 0, addr)
	return 0
}

// 缓存回调：VSC 的 PIN 操作不需要缓存；返回成功/未命中，避免驱动因缓存缺失中止。
func cspCacheOK(_, _, _, _, _ uintptr) uintptr         { return scardSuccess }
func cspCacheMiss(_, _, _, _, _ uintptr) uintptr       { return scardSuccess }
func cspPadDataUnsupported(_, _, _, _ uintptr) uintptr { return scardEUnsupportedFeature }

type scardContext struct {
	ctx  uintptr
	card uintptr
}

func openSCard(readerName string) (*scardContext, error) {
	var ctx uintptr
	result, _, _ := procSCardEstablishContext.Call(scardScopeUser, 0, 0, uintptr(unsafe.Pointer(&ctx)))
	if uint32(result) != scardSuccess {
		return nil, fmt.Errorf("建立读卡器上下文失败（0x%08X）", uint32(result))
	}
	reader, err := windows.UTF16PtrFromString(readerName)
	if err != nil {
		procSCardReleaseContext.Call(ctx)
		return nil, fmt.Errorf("编码读卡器名称失败: %w", err)
	}
	var card uintptr
	var activeProtocol uint32
	result, _, _ = procSCardConnectW.Call(
		ctx,
		uintptr(unsafe.Pointer(reader)),
		scardShareShared,
		scardProtocolT0|scardProtocolT1,
		uintptr(unsafe.Pointer(&card)),
		uintptr(unsafe.Pointer(&activeProtocol)),
	)
	if uint32(result) != scardSuccess {
		procSCardReleaseContext.Call(ctx)
		return nil, mapSCardError(uint32(result), "连接 VSC 读卡器")
	}
	return &scardContext{ctx: ctx, card: card}, nil
}

func (s *scardContext) close() {
	if s.card != 0 {
		procSCardDisconnect.Call(s.card, 0)
	}
	if s.ctx != 0 {
		procSCardReleaseContext.Call(s.ctx)
	}
}

func (s *scardContext) atr() ([]byte, error) {
	var needed uint32
	result, _, _ := procSCardGetAttrib.Call(s.card, scardAttrAtrString, 0, uintptr(unsafe.Pointer(&needed)))
	if uint32(result) != scardSuccess || needed == 0 {
		return nil, fmt.Errorf("读取 VSC ATR 失败（0x%08X）", uint32(result))
	}
	buf := make([]byte, needed)
	result, _, _ = procSCardGetAttrib.Call(
		s.card,
		scardAttrAtrString,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&needed)),
	)
	if uint32(result) != scardSuccess {
		return nil, fmt.Errorf("读取 VSC ATR 失败（0x%08X）", uint32(result))
	}
	return buf[:needed], nil
}

// ChangePIN 使用旧 PIN 设置新 PIN。
func ChangePIN(ctx context.Context, readerName, oldPIN, newPIN string) error {
	return changeAuthenticator(ctx, readerName, oldPIN, newPIN, pinChangeFlagChangePIN)
}

// UnblockPIN 使用 PUK 解锁并设置新 PIN。
func UnblockPIN(ctx context.Context, readerName, puk, newPIN string) error {
	return changeAuthenticator(ctx, readerName, puk, newPIN, pinChangeFlagUnblock)
}

func changeAuthenticator(ctx context.Context, readerName, authenticator, newPIN string, flag uintptr) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if strings.TrimSpace(readerName) == "" {
		return ErrReaderUnavailable
	}
	if err := ValidatePIN(newPIN, DefaultPINPolicy()); err != nil {
		return err
	}
	if err := validatePrintableASCII(newPIN, "新 PIN"); err != nil {
		return err
	}
	if authenticator == "" {
		return fmt.Errorf("当前 PIN 或 PUK 不能为空")
	}
	if err := validatePrintableASCII(authenticator, "当前 PIN/PUK"); err != nil {
		return err
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	session, err := openSCard(readerName)
	if err != nil {
		return err
	}
	defer session.close()

	atr, err := session.atr()
	if err != nil {
		return err
	}
	if len(atr) == 0 {
		return fmt.Errorf("VSC 返回了空 ATR，无法调用 minidriver")
	}

	cardName, err := windows.UTF16PtrFromString(readerName)
	if err != nil {
		return fmt.Errorf("编码卡片名称失败: %w", err)
	}

	if err := procCardAcquireContext.Find(); err != nil {
		return fmt.Errorf("当前系统缺少 VSC minidriver（msclmd.dll）: %w", err)
	}

	oldBytes := []byte(authenticator)
	newBytes := []byte(newPIN)
	defer zeroBytes(oldBytes)
	defer zeroBytes(newBytes)

	var lastErr error
	for _, version := range []uint32{cardDataCurrentVersion, cardDataFallbackVersion} {
		cd := &cardData{
			dwVersion:             version,
			pbAtr:                 &atr[0],
			cbAtr:                 uint32(len(atr)),
			pwszCardName:          cardName,
			pfnCspAlloc:           cspAllocCallback,
			pfnCspReAlloc:         cspReAllocCallback,
			pfnCspFree:            cspFreeCallback,
			pfnCspCacheAddFile:    cspCacheOKCallback,
			pfnCspCacheLookupFile: cspCacheMissCallback,
			pfnCspCacheDeleteFile: cspCacheOKCallback,
			pfnCspPadData:         cspPadDataCallback,
			hSCardCtx:             session.ctx,
			hScard:                session.card,
		}
		result, _, _ := procCardAcquireContext.Call(uintptr(unsafe.Pointer(cd)), 0)
		if uint32(result) != scardSuccess {
			lastErr = fmt.Errorf("初始化 VSC minidriver 失败（v%d，0x%08X）", version, uint32(result))
			continue
		}
		err := callChangeAuthenticator(cd, flag, oldBytes, newBytes)
		if cd.pfnCardDeleteContext != 0 {
			syscall.SyscallN(cd.pfnCardDeleteContext, uintptr(unsafe.Pointer(cd)))
		}
		// 已经拿到 minidriver 上下文后不再换版本重试，避免同一次 PIN 操作被重复提交。
		return err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("VSC minidriver 调用失败")
	}
	return lastErr
}

func callChangeAuthenticator(cd *cardData, flag uintptr, oldBytes, newBytes []byte) error {
	if cd.pfnCardChangeAuthenticatorEx == 0 {
		return fmt.Errorf("VSC minidriver 不支持修改 PIN（缺少 pfnCardChangeAuthenticatorEx）")
	}
	var attempts uint32
	var oldPtr, newPtr uintptr
	if len(oldBytes) > 0 {
		oldPtr = uintptr(unsafe.Pointer(&oldBytes[0]))
	}
	if len(newBytes) > 0 {
		newPtr = uintptr(unsafe.Pointer(&newBytes[0]))
	}
	result, _, _ := syscall.SyscallN(
		cd.pfnCardChangeAuthenticatorEx,
		uintptr(unsafe.Pointer(cd)),
		flag,
		roleUserPinID,
		oldPtr,
		uintptr(len(oldBytes)),
		roleUserPinID,
		newPtr,
		uintptr(len(newBytes)),
		0,
		uintptr(unsafe.Pointer(&attempts)),
	)
	runtime.KeepAlive(oldBytes)
	runtime.KeepAlive(newBytes)
	runtime.KeepAlive(cd)

	if code := uint32(result); code != scardSuccess {
		return mapSCardError(code, "修改 VSC PIN")
	}
	return nil
}

func mapSCardError(code uint32, action string) error {
	switch code {
	case scardEWrongCHV:
		return fmt.Errorf("%s失败：PIN/PUK 不正确（0x%08X）", action, code)
	case scardWCHVBlocked:
		return fmt.Errorf("%s失败：PIN 已锁定，请用 PUK 解锁（0x%08X）", action, code)
	case scardENoSmartcard:
		return fmt.Errorf("%s失败：读卡器中没有卡片（0x%08X）", action, code)
	case scardESharingViolation:
		return fmt.Errorf("%s失败：卡片正被其它程序占用（0x%08X）", action, code)
	case scardFCommError:
		return fmt.Errorf("%s失败：与卡片通信中断（0x%08X）", action, code)
	case scardEInvalidParameter:
		return fmt.Errorf("%s失败：参数被卡片拒绝（0x%08X）", action, code)
	case scardEUnsupportedFeature:
		return fmt.Errorf("%s失败：卡片不支持该操作（0x%08X）", action, code)
	default:
		return fmt.Errorf("%s失败（0x%08X）", action, code)
	}
}
