package fido

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func callPIN(t *testing.T, svc *PINService, req map[int]any) (int, map[int]cbor.RawMessage) {
	t.Helper()
	raw, err := cbor.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	resp := svc.Handle(map[string]any{"cbor_req": base64.StdEncoding.EncodeToString(raw)})
	rv := 0
	if v, ok := resp["rv"].(int); ok {
		rv = v
	}
	if rv != 0 {
		t.Fatalf("rv = %v resp=%v", resp["rv"], resp)
	}
	data := resp["data"].(map[string]string)
	body, err := base64.StdEncoding.DecodeString(data["cbor_resp"])
	if err != nil {
		t.Fatal(err)
	}
	var m map[int]cbor.RawMessage
	if err := cbor.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	return rv, m
}

func TestClientPINSetAndGetToken(t *testing.T) {
	svc, err := NewPINService(NewPINState(nil))
	if err != nil {
		t.Fatal(err)
	}
	_, ga := callPIN(t, svc, map[int]any{1: 1, 2: PINSubGetKeyAgreement})
	serverCOSE := ga[1]

	client, err := newPinCrypto()
	if err != nil {
		t.Fatal(err)
	}
	var serverCOSEKey []byte
	if err := cbor.Unmarshal(serverCOSE, &serverCOSEKey); err != nil {
		t.Fatal(err)
	}
	key, err := client.deriveKey(serverCOSEKey)
	if err != nil {
		t.Fatal(err)
	}

	pin := []byte("1234")
	padded := make([]byte, 64)
	copy(padded, pin)
	iv := make([]byte, 16)
	enc, err := aesCBCEncrypt(key, iv, padded)
	if err != nil {
		t.Fatal(err)
	}
	newPinEnc := append(append([]byte{}, iv...), enc...)
	callPIN(t, svc, map[int]any{1: 1, 2: PINSubSetPIN, 3: client.cosePublicKey(), 5: newPinEnc})

	digest := sha256.Sum256(pin)
	hashEnc, err := aesCBCEncrypt(key, iv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	_, tok := callPIN(t, svc, map[int]any{1: 1, 2: PINSubGetPINToken, 3: client.cosePublicKey(), 6: hashEnc})
	var token []byte
	if err := cbor.Unmarshal(tok[2], &token); err != nil || len(token) != 32 {
		t.Fatalf("token = %x err=%v", token, err)
	}
	if !svc.VerifyAuth([]byte("clientDataHash"), hmacSHA256(token, []byte("clientDataHash"))[:16], 0x01) {
		t.Fatal("pinUvAuthParam should verify")
	}
	if svc.VerifyAuth([]byte("clientDataHash"), []byte("bad"), 0x01) {
		t.Fatal("bad auth param accepted")
	}
}

func TestPINStateRetryLimit(t *testing.T) {
	state := NewPINState(nil)
	if err := state.SetPIN([]byte("1234")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < PINRetries; i++ {
		if ok, _ := state.Verify([]byte("0000")); ok {
			t.Fatal("wrong PIN accepted")
		}
	}
	if state.Retries() != 0 {
		t.Fatalf("retries = %d", state.Retries())
	}
	if ok, _ := state.Verify([]byte("1234")); ok {
		t.Fatal("blocked PIN accepted")
	}
}
