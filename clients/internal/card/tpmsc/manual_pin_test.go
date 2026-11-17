//go:build windows

package tpmsc

import (
	"context"
	"os"
	"testing"
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
