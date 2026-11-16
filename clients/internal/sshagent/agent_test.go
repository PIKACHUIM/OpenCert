package sshagent

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"net"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type testBackend struct {
	priv *rsa.PrivateKey
	pub  ssh.PublicKey
}

func (b *testBackend) Identities() ([]Identity, error) {
	return []Identity{{PublicKey: b.pub, Comment: "test-key"}}, nil
}

func (b *testBackend) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	digest := sha256.Sum256(data)
	sig, err := rsa.SignPKCS1v15(rand.Reader, b.priv, crypto.SHA256, digest[:])
	if err != nil {
		return nil, err
	}
	return &ssh.Signature{Format: "rsa-sha2-256", Blob: sig}, nil
}

func TestAgentListSignAndReadOnly(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	backend := &testBackend{priv: priv, pub: pub}

	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	go func() { _ = Serve(serverSide, backend) }()

	client := agent.NewClient(clientSide)
	keys, err := client.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 1 || keys[0].Comment != "test-key" {
		t.Fatalf("unexpected keys: %+v", keys)
	}

	payload := []byte("hello ssh agent")
	sig, err := client.Sign(keys[0], payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := pub.Verify(payload, sig); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}

	if err := client.Add(agent.AddedKey{PrivateKey: priv}); err == nil {
		t.Fatal("Add must be rejected")
	}
	if err := client.RemoveAll(); err == nil {
		t.Fatal("RemoveAll must be rejected")
	}
}
