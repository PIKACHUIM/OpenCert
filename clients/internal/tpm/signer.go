package tpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"sync"
)

// Signer adapts a wrapped TPM key to crypto.Signer without exposing private key material.
type Signer struct {
	mu       sync.RWMutex
	provider Provider
	wrapped  *WrappedKey
	auth     []byte
	public   crypto.PublicKey
	closed   bool
}

// NewSigner creates a signer for a key previously created by the same provider.
func NewSigner(provider Provider, wrapped *WrappedKey, authValue []byte) (*Signer, error) {
	if provider == nil || !provider.Available() {
		return nil, ErrNotAvailable
	}
	if wrapped == nil || len(wrapped.Public) == 0 || len(wrapped.Private) == 0 {
		return nil, fmt.Errorf("wrapped TPM key is incomplete")
	}
	if wrapped.Backend != provider.PlatformName() {
		return nil, fmt.Errorf("wrapped TPM key backend %q does not match provider %q", wrapped.Backend, provider.PlatformName())
	}
	publicKey, err := x509.ParsePKIXPublicKey(wrapped.Public)
	if err != nil {
		return nil, fmt.Errorf("parse wrapped TPM public key: %w", err)
	}
	switch publicKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
	default:
		return nil, fmt.Errorf("unsupported TPM public key type %T", publicKey)
	}
	copyWrapped := *wrapped
	copyWrapped.Public = append([]byte(nil), wrapped.Public...)
	copyWrapped.Private = append([]byte(nil), wrapped.Private...)
	copyWrapped.AuthDigest = append([]byte(nil), wrapped.AuthDigest...)
	return &Signer{
		provider: provider,
		wrapped:  &copyWrapped,
		auth:     append([]byte(nil), authValue...),
		public:   publicKey,
	}, nil
}

// Public returns the public half of the wrapped key.
func (s *Signer) Public() crypto.PublicKey {
	return s.public
}

// Sign signs a pre-hashed digest using the TPM key and returns a standard Go signature encoding.
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil {
		return nil, fmt.Errorf("signer options are required")
	}
	scheme, hash, err := signerScheme(s.public, opts)
	if err != nil {
		return nil, err
	}
	if hash != 0 && len(digest) != hash.Size() {
		return nil, fmt.Errorf("digest length %d does not match %s", len(digest), hash)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, fmt.Errorf("TPM signer is closed")
	}

	handle, err := s.provider.LoadKey(s.wrapped, s.auth)
	if err != nil {
		return nil, fmt.Errorf("load TPM signing key: %w", err)
	}
	signature, signErr := s.provider.Sign(handle, digest, scheme)
	flushErr := s.provider.FlushHandle(handle)
	if signErr != nil {
		return nil, fmt.Errorf("TPM signing failed: %w", signErr)
	}
	if flushErr != nil {
		return nil, fmt.Errorf("flush TPM signing handle: %w", flushErr)
	}

	switch publicKey := s.public.(type) {
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(publicKey, hash, digest, signature); err != nil {
			return nil, fmt.Errorf("TPM returned an invalid RSA signature: %w", err)
		}
	case *ecdsa.PublicKey:
		signature, err = normalizeECDSASignature(publicKey, digest, signature)
		if err != nil {
			return nil, err
		}
	}
	return signature, nil
}

// Close clears the signer authorization value from memory.
func (s *Signer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.auth {
		s.auth[i] = 0
	}
	s.auth = nil
	s.closed = true
	return nil
}

func signerScheme(publicKey crypto.PublicKey, opts crypto.SignerOpts) (SignScheme, crypto.Hash, error) {
	if _, isPSS := opts.(*rsa.PSSOptions); isPSS {
		return "", 0, fmt.Errorf("RSA-PSS is not supported by this TPM signer")
	}
	hash := opts.HashFunc()
	switch hash {
	case crypto.SHA256:
	case crypto.SHA384:
	case crypto.SHA512:
	default:
		return "", 0, fmt.Errorf("unsupported TPM signing hash %v", hash)
	}

	switch publicKey.(type) {
	case *rsa.PublicKey:
		switch hash {
		case crypto.SHA256:
			return SignSchemeRSAPKCS1SHA256, hash, nil
		case crypto.SHA384:
			return SignSchemeRSAPKCS1SHA384, hash, nil
		default:
			return SignSchemeRSAPKCS1SHA512, hash, nil
		}
	case *ecdsa.PublicKey:
		switch hash {
		case crypto.SHA256:
			return SignSchemeECDSASHA256, hash, nil
		case crypto.SHA384:
			return SignSchemeECDSASHA384, hash, nil
		default:
			return SignSchemeECDSASHA512, hash, nil
		}
	default:
		return "", 0, fmt.Errorf("unsupported TPM public key type %T", publicKey)
	}
}

func normalizeECDSASignature(publicKey *ecdsa.PublicKey, digest, signature []byte) ([]byte, error) {
	var parsed struct {
		R, S *big.Int
	}
	if rest, err := asn1.Unmarshal(signature, &parsed); err == nil && len(rest) == 0 && validECDSASignature(publicKey, digest, parsed.R, parsed.S) {
		return signature, nil
	}

	size := (publicKey.Curve.Params().BitSize + 7) / 8
	if len(signature) != 2*size {
		return nil, fmt.Errorf("TPM returned an invalid ECDSA signature length: %d", len(signature))
	}
	r := new(big.Int).SetBytes(signature[:size])
	s := new(big.Int).SetBytes(signature[size:])
	if !validECDSASignature(publicKey, digest, r, s) {
		return nil, fmt.Errorf("TPM returned an invalid ECDSA signature")
	}
	return asn1.Marshal(struct{ R, S *big.Int }{R: r, S: s})
}

func validECDSASignature(publicKey *ecdsa.PublicKey, digest []byte, r, s *big.Int) bool {
	return r != nil && s != nil && ecdsa.Verify(publicKey, digest, r, s)
}
