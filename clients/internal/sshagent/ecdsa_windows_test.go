//go:build windows

package sshagent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestToSSHSignatureECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("ssh ecdsa payload")
	digest := sha256.Sum256(payload)
	der, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig, err := toSSHSignature(&key.PublicKey, pub, der)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if sig.Format != "ecdsa-sha2-nistp256" {
		t.Fatalf("format = %s", sig.Format)
	}
	if err := pub.Verify(payload, sig); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
}
