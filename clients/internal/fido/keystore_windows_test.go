//go:build windows

package fido

import (
	"path/filepath"
	"testing"
)

func TestKeyStoreRoundTrip(t *testing.T) {
	store := NewKeyStore(filepath.Join(t.TempDir(), "cred.bin"))
	if _, err := store.Find([]byte("missing")); err != nil {
		t.Fatalf("find on empty store: %v", err)
	}
	cred := StoredCredential{ID: []byte("id-1"), RPID: "example.com", PrivateKey: []byte("secret")}
	if err := store.Put(cred); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := store.Find([]byte("id-1"))
	if err != nil || got == nil {
		t.Fatalf("find: got=%v err=%v", got, err)
	}
	if got.RPID != "example.com" || string(got.PrivateKey) != "secret" {
		t.Fatalf("unexpected credential: %+v", got)
	}
	counter, err := store.Increment([]byte("id-1"))
	if err != nil || counter != 1 {
		t.Fatalf("increment = %d, %v", counter, err)
	}
}
