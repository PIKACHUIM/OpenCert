//go:build windows

package fido

import (
	"encoding/base64"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func TestMakeCredentialAndAssertion(t *testing.T) {
	store := NewKeyStore(filepath.Join(t.TempDir(), "cred.bin"))
	hash := make([]byte, 32)
	req, _ := cbor.Marshal(map[int]any{
		1: hash,
		2: map[string]any{"id": "example.com", "name": "Example"},
		3: map[string]any{"id": []byte{1, 2, 3}, "name": "alice", "displayName": "Alice"},
		4: []any{map[string]any{"type": "public-key", "alg": -7}},
	})
	resp, err := HandleCTAP(store, CmdMakeCredential, map[string]any{"cbor_req": base64.StdEncoding.EncodeToString(req)})
	if err != nil {
		t.Fatalf("makeCredential: %v", err)
	}
	if resp["rv"] != 0 {
		t.Fatalf("makeCredential rv = %v (%v)", resp["rv"], resp)
	}
	attObj, _ := base64.StdEncoding.DecodeString(resp["data"].(map[string]string)["cbor_resp"])
	var att map[string]any
	if err := cbor.Unmarshal(attObj, &att); err != nil {
		t.Fatalf("attestation decode: %v", err)
	}
	authData, _ := att["authData"].([]byte)
	if len(authData) < 55 {
		t.Fatalf("authData too short: %d", len(authData))
	}
	credLen := int(authData[53])<<8 | int(authData[54])
	credID := authData[55 : 55+credLen]

	assertReq, _ := cbor.Marshal(map[int]any{
		1: "example.com",
		2: hash,
		3: []any{map[string]any{"type": "public-key", "id": credID}},
	})
	resp2, err := HandleCTAP(store, CmdGetAssertion, map[string]any{"cbor_req": base64.StdEncoding.EncodeToString(assertReq)})
	if err != nil || resp2["rv"] != 0 {
		t.Fatalf("getAssertion: err=%v resp=%v", err, resp2)
	}
	raw, _ := base64.StdEncoding.DecodeString(resp2["data"].(map[string]string)["cbor_resp"])
	var assertion map[int]cbor.RawMessage
	if err := cbor.Unmarshal(raw, &assertion); err != nil {
		t.Fatalf("assertion decode: %v", err)
	}
	var sig []byte
	if err := cbor.Unmarshal(assertion[3], &sig); err != nil || len(sig) == 0 {
		t.Fatalf("signature missing: %v", err)
	}
	fmt.Println("signature bytes:", len(sig))
}
