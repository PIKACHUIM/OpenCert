//go:build windows

package tpmsc

import (
	"context"
	"crypto/des"
	"encoding/hex"
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	vscManagerClassID        = "16A18E86-7F6E-4C20-AD89-4FFC0DB7A96A"
	vscAdminAlgID            = 0x82
	scardScopeUser           = 0
	scardENoReadersAvailable = 0x8010002e
)

var (
	vscManagerInterface = windows.GUID{
		Data1: 0x112B1DFF, Data2: 0xD9DC, Data3: 0x41F7,
		Data4: [8]byte{0x86, 0x9F, 0xD6, 0x7F, 0xEE, 0x7C, 0xB5, 0x91},
	}
	winscardDLL               = windows.NewLazySystemDLL("winscard.dll")
	procSCardEstablishContext = winscardDLL.NewProc("SCardEstablishContext")
	procSCardReleaseContext   = winscardDLL.NewProc("SCardReleaseContext")
	procSCardListReadersByID  = winscardDLL.NewProc("SCardListReadersWithDeviceInstanceIdW")
)

func createCardPlatform(ctx context.Context, args CreateCardArgs) (*CreateCardResult, error) {
	adminKey, err := parseAdminKey(args.AdminKey)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(adminKey)
	puk := []byte(args.PUK)
	defer zeroBytes(puk)
	pin := []byte(args.PIN)
	defer zeroBytes(pin)
	kcv, err := adminKeyCheckValue(adminKey)
	if err != nil {
		return nil, err
	}
	friendlyName, err := windows.UTF16PtrFromString(args.Name)
	if err != nil {
		return nil, fmt.Errorf("编码 VSC 名称失败: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var result *CreateCardResult
	err = withVSCManager(func(manager unsafe.Pointer) error {
		var instancePtr *uint16
		var needReboot int32
		vtable := vscManagerVTable(manager)
		hresult, _, _ := syscall.SyscallN(
			vtable[3],
			uintptr(manager),
			uintptr(unsafe.Pointer(friendlyName)),
			vscAdminAlgID,
			uintptr(unsafe.Pointer(&adminKey[0])),
			uintptr(len(adminKey)),
			uintptr(unsafe.Pointer(&kcv[0])),
			uintptr(len(kcv)),
			byteSlicePointer(puk),
			uintptr(len(puk)),
			uintptr(unsafe.Pointer(&pin[0])),
			uintptr(len(pin)),
			1, // provision the filesystem required by the Base CSP and Smart Card KSP
			0, // no progress callback
			uintptr(unsafe.Pointer(&instancePtr)),
			uintptr(unsafe.Pointer(&needReboot)),
		)
		runtime.KeepAlive(adminKey)
		runtime.KeepAlive(kcv)
		runtime.KeepAlive(puk)
		runtime.KeepAlive(pin)
		runtime.KeepAlive(friendlyName)
		if hresult != 0 {
			if instancePtr != nil {
				windows.CoTaskMemFree(unsafe.Pointer(instancePtr))
			}
			return fmt.Errorf("创建 TPM VSC 失败（HRESULT 0x%08X）", uint32(hresult))
		}
		if instancePtr == nil {
			return fmt.Errorf("TPM VSC 创建成功但未返回实例 ID；请检查设备管理器后人工恢复")
		}
		instanceID := windows.UTF16PtrToString(instancePtr)
		windows.CoTaskMemFree(unsafe.Pointer(instancePtr))
		if !isValidInstanceID(instanceID) {
			return fmt.Errorf("TPM VSC 返回了无效实例 ID；请检查设备管理器后人工恢复")
		}
		result = &CreateCardResult{InstanceID: instanceID, NeedReboot: needReboot != 0}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if result != nil && !result.NeedReboot {
		readerName, discoverErr := discoverReaderNamePlatform(ctx, result.InstanceID)
		if discoverErr == nil {
			result.ReaderName = readerName
		}
	}
	return result, nil
}

func destroyCardPlatform(ctx context.Context, instanceID string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	instanceUTF16, err := windows.UTF16PtrFromString(instanceID)
	if err != nil {
		return false, fmt.Errorf("编码 TPM VSC 实例 ID 失败: %w", err)
	}
	var needReboot bool
	err = withVSCManager(func(manager unsafe.Pointer) error {
		var rebootFlag int32
		vtable := vscManagerVTable(manager)
		hresult, _, _ := syscall.SyscallN(
			vtable[4],
			uintptr(manager),
			uintptr(unsafe.Pointer(instanceUTF16)),
			0, // no progress callback
			uintptr(unsafe.Pointer(&rebootFlag)),
		)
		runtime.KeepAlive(instanceUTF16)
		if hresult != 0 {
			return fmt.Errorf("销毁 TPM VSC 失败（HRESULT 0x%08X）", uint32(hresult))
		}
		needReboot = rebootFlag != 0
		return nil
	})
	return needReboot, err
}

func discoverReaderNamePlatform(ctx context.Context, instanceID string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	deviceID, err := windows.UTF16PtrFromString(instanceID)
	if err != nil {
		return "", fmt.Errorf("编码设备实例 ID 失败: %w", err)
	}
	var cardContext uintptr
	result, _, _ := procSCardEstablishContext.Call(scardScopeUser, 0, 0, uintptr(unsafe.Pointer(&cardContext)))
	if result != 0 {
		return "", fmt.Errorf("建立 Smart Card Resource Manager 上下文失败（0x%08X）", uint32(result))
	}
	defer procSCardReleaseContext.Call(cardContext)

	var charCount uint32
	result, _, _ = procSCardListReadersByID.Call(
		cardContext,
		uintptr(unsafe.Pointer(deviceID)),
		0,
		uintptr(unsafe.Pointer(&charCount)),
	)
	runtime.KeepAlive(deviceID)
	if uint32(result) == scardENoReadersAvailable || charCount == 0 {
		return "", ErrReaderUnavailable
	}
	if result != 0 {
		return "", fmt.Errorf("读取 TPM VSC reader 列表失败（0x%08X）", uint32(result))
	}
	readers := make([]uint16, charCount)
	result, _, _ = procSCardListReadersByID.Call(
		cardContext,
		uintptr(unsafe.Pointer(deviceID)),
		uintptr(unsafe.Pointer(&readers[0])),
		uintptr(unsafe.Pointer(&charCount)),
	)
	runtime.KeepAlive(deviceID)
	runtime.KeepAlive(readers)
	if uint32(result) == scardENoReadersAvailable {
		return "", ErrReaderUnavailable
	}
	if result != 0 {
		return "", fmt.Errorf("读取 TPM VSC reader 名称失败（0x%08X）", uint32(result))
	}
	readerName := windows.UTF16ToString(readers)
	if strings.TrimSpace(readerName) == "" {
		return "", fmt.Errorf("TPM VSC reader 名称为空")
	}
	return readerName, nil
}

func withVSCManager(action func(manager unsafe.Pointer) error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := windows.CoInitializeEx(0, windows.COINIT_APARTMENTTHREADED); err != nil {
		return fmt.Errorf("初始化 TPM VSC COM 管理器失败: %w", err)
	}
	defer windows.CoUninitialize()

	moniker, err := windows.UTF16PtrFromString("Elevation:Administrator!new:{" + vscManagerClassID + "}")
	if err != nil {
		return fmt.Errorf("编码 TPM VSC COM moniker 失败: %w", err)
	}
	bindOptions := windows.BIND_OPTS3{
		CbStruct:     uint32(unsafe.Sizeof(windows.BIND_OPTS3{})),
		ClassContext: windows.CLSCTX_LOCAL_SERVER,
	}
	var manager unsafe.Pointer
	managerOut := (**uintptr)(unsafe.Pointer(&manager))
	if err := windows.CoGetObject(moniker, &bindOptions, &vscManagerInterface, managerOut); err != nil {
		return fmt.Errorf("激活 TPM VSC 管理器失败（需要管理员确认）: %w", err)
	}
	defer releaseVSCManager(manager)
	return action(manager)
}

func vscManagerVTable(manager unsafe.Pointer) *[5]uintptr {
	vtable := *(*unsafe.Pointer)(manager)
	return (*[5]uintptr)(vtable)
}

func releaseVSCManager(manager unsafe.Pointer) {
	vtable := vscManagerVTable(manager)
	_, _, _ = syscall.SyscallN(vtable[2], uintptr(manager))
}

func byteSlicePointer(value []byte) uintptr {
	if len(value) == 0 {
		return 0
	}
	return uintptr(unsafe.Pointer(&value[0]))
}

func adminKeyCheckValue(adminKey []byte) ([3]byte, error) {
	var kcv [3]byte
	cipher, err := des.NewTripleDESCipher(adminKey)
	if err != nil {
		return kcv, fmt.Errorf("创建 TPM VSC AdminKey 检查值失败: %w", err)
	}
	var zeroBlock [8]byte
	cipher.Encrypt(zeroBlock[:], zeroBlock[:])
	copy(kcv[:], zeroBlock[:3])
	return kcv, nil
}

func parseAdminKey(value string) ([]byte, error) {
	key, err := hex.DecodeString(value)
	if err != nil || len(key) != 24 {
		return nil, fmt.Errorf("AdminKey 必须是 48 位十六进制字符串（24 字节）")
	}
	return key, nil
}
