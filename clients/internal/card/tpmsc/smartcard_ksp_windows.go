//go:build windows

package tpmsc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"runtime"
	"unsafe"

	"github.com/globaltrusts/client-card/internal/tpm"
	"golang.org/x/sys/windows"
)

const (
	ncryptReaderProperty  = "SmartCardReader"
	ncryptKSPLength       = "Length"
	ncryptKSPExportPolicy = "Export Policy"
	ncryptKSPKeyUsage     = "Key Usage"
	ncryptKSPNoExport     = 0
	ncryptKSPSigning      = 0x00000002
	ncryptKSPPKCS1Padding = 0x00000002
)

var smartCardNCrypt = windows.NewLazySystemDLL("ncrypt.dll")
var (
	procSmartOpenProvider = smartCardNCrypt.NewProc("NCryptOpenStorageProvider")
	procSmartCreateKey    = smartCardNCrypt.NewProc("NCryptCreatePersistedKey")
	procSmartSetProperty  = smartCardNCrypt.NewProc("NCryptSetProperty")
	procSmartFinalizeKey  = smartCardNCrypt.NewProc("NCryptFinalizeKey")
	procSmartOpenKey      = smartCardNCrypt.NewProc("NCryptOpenKey")
	procSmartExportKey    = smartCardNCrypt.NewProc("NCryptExportKey")
	procSmartSignHash     = smartCardNCrypt.NewProc("NCryptSignHash")
	procSmartDeleteKey    = smartCardNCrypt.NewProc("NCryptDeleteKey")
	procSmartFreeObject   = smartCardNCrypt.NewProc("NCryptFreeObject")
)

type smartCardKSP struct{}

func newSmartCardKeyProvider() SmartCardKeyProvider { return smartCardKSP{} }

func (smartCardKSP) CreateKey(ctx context.Context, readerName, containerName, keyType string) (crypto.Signer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	alg, bits, tpmAlg, err := smartCardAlgorithm(keyType)
	if err != nil {
		return nil, err
	}
	provider, err := openSmartCardProvider(readerName)
	if err != nil {
		return nil, err
	}
	defer procSmartFreeObject.Call(provider)

	keyName, err := windows.UTF16PtrFromString(SmartCardKSPContainerName(readerName, containerName))
	if err != nil {
		return nil, fmt.Errorf("encode Smart Card KSP container name: %w", err)
	}
	algorithm, err := windows.UTF16PtrFromString(alg)
	if err != nil {
		return nil, fmt.Errorf("encode Smart Card KSP algorithm: %w", err)
	}
	var key uintptr
	result, _, _ := procSmartCreateKey.Call(
		provider,
		uintptr(unsafe.Pointer(&key)),
		uintptr(unsafe.Pointer(algorithm)),
		uintptr(unsafe.Pointer(keyName)),
		0,
		0,
	)
	if result != 0 {
		return nil, fmt.Errorf("NCryptCreatePersistedKey failed: 0x%08X", result)
	}
	cleanup := func(cause error) error {
		deleteResult, _, _ := procSmartDeleteKey.Call(key, 0)
		key = 0
		if deleteResult != 0 {
			return fmt.Errorf("%w (container cleanup failed: 0x%08X)", cause, deleteResult)
		}
		return cause
	}
	if bits != 0 {
		if err := setSmartCardProperty(key, ncryptKSPLength, bits); err != nil {
			return nil, cleanup(err)
		}
	}
	if err := setSmartCardProperty(key, ncryptKSPExportPolicy, ncryptKSPNoExport); err != nil {
		return nil, cleanup(err)
	}
	if err := setSmartCardProperty(key, ncryptKSPKeyUsage, ncryptKSPSigning); err != nil {
		return nil, cleanup(err)
	}
	result, _, _ = procSmartFinalizeKey.Call(key, 0)
	if result != 0 {
		return nil, cleanup(fmt.Errorf("NCryptFinalizeKey failed: 0x%08X", result))
	}
	publicDER, err := tpm.ExportCNGPublicKey(key, tpmAlg)
	if err != nil {
		return nil, cleanup(fmt.Errorf("export VSC public key: %w", err))
	}
	publicKey, err := x509.ParsePKIXPublicKey(publicDER)
	if err != nil {
		return nil, cleanup(fmt.Errorf("parse VSC public key: %w", err))
	}
	procSmartFreeObject.Call(key)
	key = 0
	return &smartCardSigner{readerName: readerName, containerName: containerName, publicKey: publicKey}, nil
}

func (smartCardKSP) OpenKey(ctx context.Context, readerName, containerName, keyType string, publicKey crypto.PublicKey) (crypto.Signer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, _, _, err := smartCardAlgorithm(keyType); err != nil {
		return nil, err
	}
	if _, ok := publicKey.(*rsa.PublicKey); !ok {
		if _, ok := publicKey.(*ecdsa.PublicKey); !ok {
			return nil, fmt.Errorf("unsupported Smart Card KSP public key type %T", publicKey)
		}
	}
	key, provider, err := openSmartCardKey(readerName, containerName)
	if err != nil {
		return nil, err
	}
	procSmartFreeObject.Call(key)
	procSmartFreeObject.Call(provider)
	return &smartCardSigner{readerName: readerName, containerName: containerName, publicKey: publicKey}, nil
}

func (smartCardKSP) DeleteKey(ctx context.Context, readerName, containerName string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	key, provider, err := openSmartCardKey(readerName, containerName)
	if err != nil {
		return err
	}
	result, _, _ := procSmartDeleteKey.Call(key, 0)
	if result != 0 {
		procSmartFreeObject.Call(key)
		procSmartFreeObject.Call(provider)
		return fmt.Errorf("NCryptDeleteKey failed: 0x%08X", result)
	}
	procSmartFreeObject.Call(provider)
	return nil
}

type smartCardSigner struct {
	readerName    string
	containerName string
	publicKey     crypto.PublicKey
}

func (s *smartCardSigner) Public() crypto.PublicKey { return s.publicKey }
func (s *smartCardSigner) Close() error             { return nil }

func (s *smartCardSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil {
		return nil, fmt.Errorf("signer options are required")
	}
	key, provider, err := openSmartCardKey(s.readerName, s.containerName)
	if err != nil {
		return nil, err
	}
	defer procSmartFreeObject.Call(provider)
	defer procSmartFreeObject.Call(key)

	padding, err := smartCardSignaturePadding(s.publicKey, opts)
	if err != nil {
		return nil, err
	}
	if len(digest) != padding.hash.Size() {
		return nil, fmt.Errorf("digest length %d does not match %s", len(digest), padding.hash)
	}
	signature, err := ncryptSignHash(key, padding, digest)
	if err != nil {
		return nil, err
	}
	switch publicKey := s.publicKey.(type) {
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(publicKey, padding.hash, digest, signature); err != nil {
			return nil, fmt.Errorf("Smart Card KSP returned an invalid RSA signature: %w", err)
		}
	case *ecdsa.PublicKey:
		signature, err = normalizeSmartCardECDSASignature(publicKey, digest, signature)
		if err != nil {
			return nil, err
		}
	}
	return signature, nil
}

func openSmartCardProvider(readerName string) (uintptr, error) {
	providerName, err := windows.UTF16PtrFromString(SmartCardKSPProviderName)
	if err != nil {
		return 0, err
	}
	var provider uintptr
	result, _, _ := procSmartOpenProvider.Call(uintptr(unsafe.Pointer(&provider)), uintptr(unsafe.Pointer(providerName)), 0)
	if result != 0 {
		return 0, fmt.Errorf("open Microsoft Smart Card KSP failed: 0x%08X", result)
	}
	if result := setSmartCardStringProperty(provider, ncryptReaderProperty, readerName); result != nil {
		procSmartFreeObject.Call(provider)
		return 0, result
	}
	return provider, nil
}

func openSmartCardKey(readerName, containerName string) (uintptr, uintptr, error) {
	provider, err := openSmartCardProvider(readerName)
	if err != nil {
		return 0, 0, err
	}
	keyName, err := windows.UTF16PtrFromString(SmartCardKSPContainerName(readerName, containerName))
	if err != nil {
		procSmartFreeObject.Call(provider)
		return 0, 0, err
	}
	var key uintptr
	result, _, _ := procSmartOpenKey.Call(
		provider,
		uintptr(unsafe.Pointer(&key)),
		uintptr(unsafe.Pointer(keyName)),
		0,
		0,
	)
	if result != 0 {
		procSmartFreeObject.Call(provider)
		return 0, 0, fmt.Errorf("open Smart Card KSP container failed: 0x%08X", result)
	}
	return key, provider, nil
}

func setSmartCardProperty(handle uintptr, name string, value uint32) error {
	propertyName, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	var buffer [4]byte
	buffer[0] = byte(value)
	buffer[1] = byte(value >> 8)
	buffer[2] = byte(value >> 16)
	buffer[3] = byte(value >> 24)
	result, _, _ := procSmartSetProperty.Call(
		handle,
		uintptr(unsafe.Pointer(propertyName)),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
		0,
	)
	if result != 0 {
		return fmt.Errorf("NCryptSetProperty(%s) failed: 0x%08X", name, result)
	}
	return nil
}

func setSmartCardStringProperty(handle uintptr, name, value string) error {
	propertyName, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	valueUTF16, err := windows.UTF16FromString(value)
	if err != nil {
		return err
	}
	result, _, _ := procSmartSetProperty.Call(
		handle,
		uintptr(unsafe.Pointer(propertyName)),
		uintptr(unsafe.Pointer(&valueUTF16[0])),
		uintptr(len(valueUTF16)*2),
		0,
	)
	runtime.KeepAlive(valueUTF16)
	if result != 0 {
		return fmt.Errorf("NCryptSetProperty(%s) failed: 0x%08X", name, result)
	}
	return nil
}

func ncryptSignHash(key uintptr, padding *smartCardPadding, digest []byte) ([]byte, error) {
	var paddingInfo uintptr
	if padding.info.pszAlgId != nil {
		paddingInfo = uintptr(unsafe.Pointer(&padding.info))
	}
	var signatureSize uint32
	result, _, _ := procSmartSignHash.Call(key, paddingInfo, uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)), 0, 0, uintptr(unsafe.Pointer(&signatureSize)), padding.flags)
	if result != 0 {
		return nil, fmt.Errorf("NCryptSignHash(size) failed: 0x%08X", result)
	}
	if signatureSize == 0 {
		return nil, fmt.Errorf("Smart Card KSP returned an empty signature")
	}
	signature := make([]byte, signatureSize)
	result, _, _ = procSmartSignHash.Call(key, paddingInfo, uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)), uintptr(unsafe.Pointer(&signature[0])), uintptr(signatureSize), uintptr(unsafe.Pointer(&signatureSize)), padding.flags)
	if result != 0 {
		return nil, fmt.Errorf("NCryptSignHash failed: 0x%08X", result)
	}
	runtime.KeepAlive(padding)
	runtime.KeepAlive(digest)
	runtime.KeepAlive(signature)
	return signature[:signatureSize], nil
}

func smartCardAlgorithm(keyType string) (string, uint32, tpm.KeyAlg, error) {
	switch keyType {
	case "rsa2048":
		return "RSA", 2048, tpm.KeyAlgRSA2048, nil
	case "rsa3072":
		return "RSA", 3072, tpm.KeyAlgRSA3072, nil
	case "rsa4096":
		return "RSA", 4096, tpm.KeyAlgRSA4096, nil
	case "ec256":
		return "ECDSA_P256", 256, tpm.KeyAlgECP256, nil
	case "ec384":
		return "ECDSA_P384", 384, tpm.KeyAlgECP384, nil
	case "ec521":
		return "ECDSA_P521", 521, tpm.KeyAlgECP521, nil
	default:
		return "", 0, "", fmt.Errorf("unsupported Smart Card KSP key type %q", keyType)
	}
}

func smartCardSignaturePadding(publicKey crypto.PublicKey, opts crypto.SignerOpts) (*smartCardPadding, error) {
	if _, isPSS := opts.(*rsa.PSSOptions); isPSS {
		return nil, fmt.Errorf("RSA-PSS is not enabled for VSC CSR")
	}
	hash := opts.HashFunc()
	if hash != crypto.SHA256 && hash != crypto.SHA384 && hash != crypto.SHA512 {
		return nil, fmt.Errorf("unsupported Smart Card KSP signing hash %v", hash)
	}
	padding := &smartCardPadding{hash: hash}
	switch publicKey.(type) {
	case *rsa.PublicKey:
		hashName := "SHA256"
		switch hash {
		case crypto.SHA384:
			hashName = "SHA384"
		case crypto.SHA512:
			hashName = "SHA512"
		}
		name, err := windows.UTF16PtrFromString(hashName)
		if err != nil {
			return nil, fmt.Errorf("encode RSA digest name: %w", err)
		}
		padding.info.pszAlgId = name
		padding.flags = ncryptKSPPKCS1Padding
	case *ecdsa.PublicKey:
	default:
		return nil, fmt.Errorf("unsupported Smart Card KSP public key type %T", publicKey)
	}
	return padding, nil
}

type bcryptPKCS1PaddingInfo struct {
	pszAlgId *uint16
}

type smartCardPadding struct {
	info  bcryptPKCS1PaddingInfo
	flags uintptr
	hash  crypto.Hash
}

func normalizeSmartCardECDSASignature(publicKey *ecdsa.PublicKey, digest, signature []byte) ([]byte, error) {
	var parsed struct{ R, S *big.Int }
	if rest, err := asn1.Unmarshal(signature, &parsed); err == nil && len(rest) == 0 && parsed.R != nil && parsed.S != nil && ecdsa.Verify(publicKey, digest, parsed.R, parsed.S) {
		return signature, nil
	}
	size := (publicKey.Curve.Params().BitSize + 7) / 8
	if len(signature) != 2*size {
		return nil, fmt.Errorf("invalid Smart Card KSP ECDSA signature length %d", len(signature))
	}
	r := new(big.Int).SetBytes(signature[:size])
	s := new(big.Int).SetBytes(signature[size:])
	if !ecdsa.Verify(publicKey, digest, r, s) {
		return nil, fmt.Errorf("Smart Card KSP returned an invalid ECDSA signature")
	}
	return asn1.Marshal(struct{ R, S *big.Int }{R: r, S: s})
}
