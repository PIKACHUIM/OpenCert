package fido

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func TestBuildGetInfoIsValidCBOR(t *testing.T) {
	info := BuildGetInfo()
	var decoded map[int]any
	if err := cbor.Unmarshal(info, &decoded); err != nil {
		t.Fatalf("GetInfo 不是合法 CBOR: %v", err)
	}
	versions, ok := decoded[1].([]any)
	if !ok || len(versions) != 1 || versions[0] != "FIDO_2_0" {
		t.Fatalf("versions = %v", decoded[1])
	}
	opts, ok := decoded[4].(map[any]any)
	if !ok || opts["up"] != true || opts["clientPin"] != false {
		t.Fatalf("options = %v", decoded[4])
	}
	aaguid, ok := decoded[3].([]byte)
	if !ok || len(aaguid) != 16 {
		t.Fatalf("aaguid = %v", decoded[3])
	}
	if decoded[5] != uint64(1200) && decoded[5] != int64(1200) {
		t.Fatalf("maxMsgSize = %v (%T)", decoded[5], decoded[5])
	}
}
