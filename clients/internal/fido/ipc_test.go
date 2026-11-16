package fido

import (
	"net"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		_ = Serve(server, func(cmd uint32, payload []byte) (any, error) {
			return map[string]any{"cmd": cmd, "echo": string(payload)}, nil
		})
	}()

	if err := writeFrame(client, CmdGetInfo, []byte(`{"a":1}`)); err != nil {
		t.Fatalf("write: %v", err)
	}
	cmd, body, err := readFrame(client)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if cmd != CmdGetInfo {
		t.Fatalf("cmd = 0x%04X", cmd)
	}
	if string(body) != `{"cmd":768,"echo":"{\"a\":1}"}` {
		t.Fatalf("body = %s", body)
	}
}

func TestReadFrameRejectsBadMagic(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		_, _ = server.Write([]byte{0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 2})
	}()
	if _, _, err := readFrame(client); err == nil {
		t.Fatal("expected magic error")
	}
}
