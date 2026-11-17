//go:build windows

package tpmsc

import (
	"context"
	"os"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TestManualPINChange 需要真实 TPM VSC，默认跳过。
// 用法：OCC_PIN_TEST=1 OCC_PIN_READER="Microsoft Virtual Smart Card 1" OCC_PIN_OLD=... OCC_PIN_NEW=... go test -run ManualPINChange -v
func TestManualPINChange(t *testing.T) {
	if os.Getenv("OCC_PIN_TEST") != "1" {
		t.Skip("set OCC_PIN_TEST=1 to run against a real VSC")
	}
	reader := os.Getenv("OCC_PIN_READER")
	if err := ChangePIN(context.Background(), reader, os.Getenv("OCC_PIN_OLD"), os.Getenv("OCC_PIN_NEW")); err != nil {
		t.Fatalf("ChangePIN: %v", err)
	}
	if puk := os.Getenv("OCC_PUK"); puk != "" {
		if err := UnblockPIN(context.Background(), reader, puk, os.Getenv("OCC_PIN_NEW")); err != nil {
			t.Fatalf("UnblockPIN: %v", err)
		}
	}
}

func TestManualUnblock(t *testing.T) {
	if os.Getenv("OCC_PIN_TEST") != "1" {
		t.Skip("set OCC_PIN_TEST=1 to run against a real VSC")
	}
	err := UnblockPIN(context.Background(), os.Getenv("OCC_PIN_READER"), os.Getenv("OCC_PUK"), os.Getenv("OCC_PIN_NEW"))
	t.Logf("UnblockPIN err = %v", err)

	session, serr := openSCard(os.Getenv("OCC_PIN_READER"))
	if serr != nil {
		t.Fatal(serr)
	}
	defer session.close()
	atr, _ := session.atr()
	name, _ := windows.UTF16PtrFromString(os.Getenv("OCC_PIN_READER"))
	cd := &cardData{
		dwVersion: cardDataCurrentVersion, pbAtr: &atr[0], cbAtr: uint32(len(atr)), pwszCardName: name,
		pfnCspAlloc: cspAllocCallback, pfnCspReAlloc: cspReAllocCallback, pfnCspFree: cspFreeCallback,
		pfnCspCacheAddFile: cspCacheOKCallback, pfnCspCacheLookupFile: cspCacheMissCallback,
		pfnCspCacheDeleteFile: cspCacheOKCallback, pfnCspPadData: cspPadDataCallback,
		hSCardCtx: session.ctx, hScard: session.card,
	}
	procCardAcquireContext.Call(uintptr(unsafe.Pointer(cd)), 0)
	puk := []byte(os.Getenv("OCC_PUK"))
	np := []byte(os.Getenv("OCC_PIN_NEW"))
	user, _ := windows.UTF16PtrFromString("user")
	for _, uid := range []uintptr{uintptr(unsafe.Pointer(user)), 0} {
		for _, flags := range []uintptr{0, 1} {
			r, _, _ := syscall.SyscallN(cd.pfnCardUnblockPin, uintptr(unsafe.Pointer(cd)), uid,
				uintptr(unsafe.Pointer(&puk[0])), uintptr(len(puk)),
				uintptr(unsafe.Pointer(&np[0])), uintptr(len(np)), 0, flags)
			t.Logf("unblock uid=%v flags=%d -> 0x%08X", uid != 0, flags, uint32(r))
		}
	}
}
