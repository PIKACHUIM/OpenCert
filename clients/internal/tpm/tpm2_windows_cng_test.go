//go:build windows

package tpm

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestCNGNVFilesDoNotAdvertiseHardwareNV(t *testing.T) {
	if SupportsHardwareNV(&cngProvider{provName: ncryptPlatformProvider}) {
		t.Fatal("DPAPI-backed CNG NV file was advertised as hardware TPM NV")
	}
}

func TestMockProviderDoesNotAdvertiseHardwareNV(t *testing.T) {
	if SupportsHardwareNV(NewMock()) {
		t.Fatal("in-memory mock NV was advertised as hardware TPM NV")
	}
}

func TestCNGImportKeyRejectsSoftwareFallback(t *testing.T) {
	provider := &cngProvider{}
	if _, _, err := provider.ImportKey([]byte("private-key"), nil); !errors.Is(err, ErrImportNotSupported) {
		t.Fatalf("ImportKey error = %v, want ErrImportNotSupported", err)
	}
}

func TestCNGLoadKeyRejectsLegacySoftwareKSPBlob(t *testing.T) {
	const (
		keyName = "legacy-software-key"
		auth    = "test-auth"
	)
	private, err := json.Marshal(cngWrappedKey{
		KeyName:  keyName,
		Provider: "Microsoft Software Key Storage Provider",
	})
	if err != nil {
		t.Fatal(err)
	}

	provider := &cngProvider{provName: ncryptPlatformProvider}
	wrapped := &WrappedKey{
		Private:    private,
		AuthDigest: nvAuthDigest([]byte(auth), []byte(keyName)),
	}
	if _, err := provider.LoadKey(wrapped, []byte(auth)); !errors.Is(err, ErrNotAvailable) {
		t.Fatalf("LoadKey error = %v, want ErrNotAvailable", err)
	}
}
