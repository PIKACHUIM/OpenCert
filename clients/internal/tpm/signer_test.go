package tpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"
)

func TestSignerSignsAndVerifies(t *testing.T) {
	for _, alg := range []KeyAlg{KeyAlgRSA2048, KeyAlgECP256} {
		t.Run(string(alg), func(t *testing.T) {
			provider := NewMock()
			auth := []byte("signer-test-auth")
			wrapped, publicKey, err := provider.CreateKey(alg, auth)
			if err != nil {
				t.Fatal(err)
			}
			signer, err := NewSigner(provider, wrapped, auth)
			if err != nil {
				t.Fatal(err)
			}
			defer signer.Close()

			digest := sha256.Sum256([]byte("CSR signer test"))
			signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
			if err != nil {
				t.Fatal(err)
			}
			switch key := publicKey.(type) {
			case *rsa.PublicKey:
				if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
					t.Fatalf("RSA signature verification failed: %v", err)
				}
			case *ecdsa.PublicKey:
				parsed, err := x509.ParsePKIXPublicKey(wrapped.Public)
				if err != nil {
					t.Fatal(err)
				}
				if parsedKey, ok := parsed.(*ecdsa.PublicKey); !ok || parsedKey.X.Cmp(key.X) != 0 || parsedKey.Y.Cmp(key.Y) != 0 {
					t.Fatal("wrapped public key changed")
				}
				if !ecdsa.VerifyASN1(key, digest[:], signature) {
					t.Fatal("ECDSA signature verification failed")
				}
			}
		})
	}
}

func TestSignerRejectsWrongAuthAndClosedSigner(t *testing.T) {
	provider := NewMock()
	wrapped, _, err := provider.CreateKey(KeyAlgRSA2048, []byte("correct-auth"))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewSigner(provider, wrapped, []byte("wrong-auth"))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("not authorized"))
	if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256); err == nil {
		t.Fatal("expected wrong authorization to fail")
	}
	if err := signer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256); err == nil {
		t.Fatal("expected closed signer to fail")
	}
}
