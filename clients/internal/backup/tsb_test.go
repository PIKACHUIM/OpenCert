package backup

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteOpenRoundTripPlain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "card.tsb")
	files := map[string][]byte{"registry/device.reg": []byte("REGEDIT4\n"), "store/keymaps": {1, 2, 3}}
	m := &Manifest{CardName: "test-card", CardID: "0001"}
	if err := Write(path, m, files, ""); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, parts, err := Open(path, "")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if got.Format != FormatV2 || got.Protection != ProtectionNone {
		t.Fatalf("unexpected manifest: %+v", got)
	}
	if len(parts) != len(files) {
		t.Fatalf("parts = %d, want %d", len(parts), len(files))
	}
	for name, want := range files {
		if string(parts[name]) != string(want) {
			t.Fatalf("part %s mismatch", name)
		}
	}
}

func TestWriteOpenRoundTripEncrypted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "card.tsb")
	files := map[string][]byte{"store/keymaps": {9, 8, 7}}
	if err := Write(path, &Manifest{CardID: "0002"}, files, "correct horse battery staple"); err != nil {
		t.Fatalf("write: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw[:len(encryptedMagic)]) != encryptedMagic {
		t.Fatal("encrypted file does not carry TSBENC2 magic")
	}
	m, parts, err := Open(path, "correct horse battery staple")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if m.Protection != ProtectionPassphrase {
		t.Fatalf("protection = %q", m.Protection)
	}
	if string(parts["store/keymaps"]) != string(files["store/keymaps"]) {
		t.Fatal("payload mismatch")
	}
	if _, _, err := Open(path, "wrong"); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("wrong passphrase err = %v", err)
	}
	if _, _, err := Open(path, ""); err == nil {
		t.Fatal("open without passphrase succeeded")
	}
}
