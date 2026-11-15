package tpmsc

import (
	"context"
	"errors"
	"runtime"
	"testing"

	"github.com/globaltrusts/client-card/internal/storage"
	"github.com/globaltrusts/client-card/pkg/pkcs11types"
)

func TestCreateCardValidCredentialsRequireWindowsProvisioning(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating a VSC requires administrator approval and TPM hardware")
	}
	result, err := CreateCard(context.Background(), CreateCardArgs{
		Name: "test-vsc", PIN: "pin-test-123", AdminKey: "0123456789abcdeffedcba98765432100011223344556677",
	})
	if !errors.Is(err, ErrProvisioningNotImplemented) {
		t.Fatalf("CreateCard error = %v, want ErrProvisioningNotImplemented", err)
	}
	if result != nil {
		t.Fatalf("CreateCard returned a result without a Windows provider: %#v", result)
	}
}

func TestCreateCardRequiresHardwareCredentials(t *testing.T) {
	if err := ValidateCreateCardArgs(CreateCardArgs{Name: "test-vsc"}); err == nil {
		t.Fatal("CreateCard accepted missing PIN and AdminKey")
	}
	if err := ValidateCreateCardArgs(CreateCardArgs{
		Name: "test-vsc", PIN: "pin-test-123", AdminKey: "not-an-admin-key",
	}); err == nil {
		t.Fatal("CreateCard accepted an invalid AdminKey")
	}
	if err := ValidateCreateCardArgs(CreateCardArgs{
		Name: "test-vsc", PIN: "pin-test-123", AdminKey: "0123456789abcdef0123456789abcdef0123456789abcdef",
	}); err == nil {
		t.Fatal("CreateCard accepted a weak 3DES AdminKey with repeated components")
	}
	if err := ValidateCreateCardArgs(CreateCardArgs{
		Name: "test-vsc", PIN: "pin-test-123", AdminKey: "0123456789abcdeffedcba98765432100011223344556677",
	}); err != nil {
		t.Fatalf("valid VSC credentials rejected: %v", err)
	}
}

func TestSmartCardKSPContainerNameIncludesReaderAndContainer(t *testing.T) {
	got := SmartCardKSPContainerName("Microsoft Virtual Smart Card 1", "container-id")
	want := `\\.\Microsoft Virtual Smart Card 1\container-id`
	if got != want {
		t.Fatalf("SmartCardKSPContainerName() = %q, want %q", got, want)
	}
}

func TestCreateCardRejectsBlankName(t *testing.T) {
	if _, err := CreateCard(context.Background(), CreateCardArgs{Name: "  "}); err == nil {
		t.Fatal("CreateCard accepted a blank name")
	}
}

func TestSlotAdvertisesNoTokenOrMechanismsAndRejectsOperations(t *testing.T) {
	slot := New(1, &storage.Card{UUID: "test-card", CardName: "test VSC"}, nil)
	if info := slot.SlotInfo(); info.TokenPresent || info.Flags&pkcs11types.CKF_TOKEN_PRESENT != 0 {
		t.Fatalf("SlotInfo advertises a token: %#v", info)
	}
	if info := slot.TokenInfo(); info.Flags != 0 {
		t.Fatalf("TokenInfo advertises token capabilities: %#v", info)
	}
	if mechanisms := slot.Mechanisms(); len(mechanisms) != 0 {
		t.Fatalf("Mechanisms = %v, want none", mechanisms)
	}
	if slot.IsLoggedIn() {
		t.Fatal("unimplemented Slot reports a logged-in session")
	}

	ctx := context.Background()
	assertUnsupported := func(operation string, err error) {
		t.Helper()
		if !errors.Is(err, pkcs11types.CKR_FUNCTION_NOT_SUPPORTED) {
			t.Errorf("%s error = %v, want CKR_FUNCTION_NOT_SUPPORTED", operation, err)
		}
	}
	assertUnsupported("Login", slot.Login(ctx, pkcs11types.CKU_USER, "any-pin"))
	assertUnsupported("Logout", slot.Logout(ctx))
	_, err := slot.FindObjects(ctx, nil)
	assertUnsupported("FindObjects", err)
	_, err = slot.GetAttributes(ctx, 1, nil)
	assertUnsupported("GetAttributes", err)
	_, err = slot.Sign(ctx, 1, pkcs11types.Mechanism{}, nil)
	assertUnsupported("Sign", err)
	_, err = slot.Decrypt(ctx, 1, pkcs11types.Mechanism{}, nil)
	assertUnsupported("Decrypt", err)
	_, err = slot.Encrypt(ctx, 1, pkcs11types.Mechanism{}, nil)
	assertUnsupported("Encrypt", err)
}

func TestDeleteCardRejectsInvalidInstanceID(t *testing.T) {
	if err := DeleteCard(context.Background(), "../../unrelated-device"); err == nil {
		t.Fatal("DeleteCard accepted an invalid instance ID")
	}
}
