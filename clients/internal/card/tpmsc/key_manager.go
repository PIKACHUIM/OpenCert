package tpmsc

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/globaltrusts/client-card/internal/storage"
	"github.com/google/uuid"
)

// SmartCardKeyProvider creates and uses persisted keys through the platform Smart Card KSP.
type SmartCardKeyProvider interface {
	CreateKey(ctx context.Context, readerName, containerName, keyType string) (crypto.Signer, error)
	OpenKey(ctx context.Context, readerName, containerName, keyType string, publicKey crypto.PublicKey) (crypto.Signer, error)
	DeleteKey(ctx context.Context, readerName, containerName string) error
}

// CSRKeyManager stores only public metadata and the Smart Card KSP container identity.
type CSRKeyManager struct {
	certRepo    *storage.CertRepo
	cardRepo    *storage.CardRepo
	keyProvider SmartCardKeyProvider
}

var ErrSmartCardKSPUnavailable = errors.New("Microsoft Smart Card Key Storage Provider is unavailable")

// NewCSRKeyManager creates a VSC CSR key manager for the current platform.
func NewCSRKeyManager(certRepo *storage.CertRepo, cardRepo *storage.CardRepo) *CSRKeyManager {
	return NewCSRKeyManagerWithProvider(certRepo, cardRepo, newSmartCardKeyProvider())
}

// NewCSRKeyManagerWithProvider injects a Smart Card KSP for tests or platform integration.
func NewCSRKeyManagerWithProvider(certRepo *storage.CertRepo, cardRepo *storage.CardRepo, provider SmartCardKeyProvider) *CSRKeyManager {
	return &CSRKeyManager{certRepo: certRepo, cardRepo: cardRepo, keyProvider: provider}
}

// CreateCSRKey creates a non-exportable key in the selected VSC and stores its public key only.
func (m *CSRKeyManager) CreateCSRKey(ctx context.Context, card *storage.Card, _ []byte, keyType string) (string, crypto.Signer, error) {
	if m.certRepo == nil || m.cardRepo == nil || m.keyProvider == nil {
		return "", nil, ErrSmartCardKSPUnavailable
	}
	if card == nil || card.SlotType != storage.SlotTypeTPMSC || card.SecurityLevel != storage.SecurityLevelHigh {
		return "", nil, fmt.Errorf("CSR key requires a high-security TPM VSC")
	}
	if card.TPMSCInstanceID == "" || card.TPMSCReaderName == "" || card.TPMSCState != storage.TPMSCStateReady {
		return "", nil, ErrReaderUnavailable
	}
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}

	containerName := uuid.NewString()
	signer, err := m.keyProvider.CreateKey(ctx, card.TPMSCReaderName, containerName, keyType)
	if err != nil {
		return "", nil, fmt.Errorf("create VSC key container: %w", err)
	}
	closer, ok := signer.(interface{ Close() error })
	if !ok {
		deleteErr := m.keyProvider.DeleteKey(context.WithoutCancel(ctx), card.TPMSCReaderName, containerName)
		if deleteErr != nil {
			return "", nil, fmt.Errorf("Smart Card KSP signer cannot be closed; key cleanup failed: %v", deleteErr)
		}
		return "", nil, fmt.Errorf("Smart Card KSP signer does not support secure close")
	}

	publicDER, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		_ = closer.Close()
		cleanupErr := m.keyProvider.DeleteKey(context.WithoutCancel(ctx), card.TPMSCReaderName, containerName)
		if cleanupErr != nil {
			return "", nil, fmt.Errorf("marshal VSC public key: %w (container cleanup failed: %v)", err, cleanupErr)
		}
		return "", nil, fmt.Errorf("marshal VSC public key: %w", err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	record := &storage.Certificate{
		UUID:        containerName,
		SlotType:    storage.SlotTypeTPMSC,
		CardUUID:    card.UUID,
		CertType:    storage.CertTypeInternal,
		KeyType:     keyType,
		CertContent: publicPEM,
	}
	if err := m.certRepo.Create(ctx, record); err != nil {
		_ = closer.Close()
		cleanupErr := m.keyProvider.DeleteKey(context.WithoutCancel(ctx), card.TPMSCReaderName, containerName)
		if cleanupErr != nil {
			return "", nil, fmt.Errorf("save VSC key record: %w (container cleanup failed: %v)", err, cleanupErr)
		}
		return "", nil, fmt.Errorf("save VSC key record: %w", err)
	}
	return record.UUID, signer, nil
}

// DeleteCSRKey deletes an unissued VSC key container and its internal database record.
func (m *CSRKeyManager) DeleteCSRKey(ctx context.Context, certUUID string) error {
	record, err := m.loadKeyRecord(ctx, certUUID)
	if err != nil || record == nil {
		return err
	}
	if record.CertType != storage.CertTypeInternal {
		return fmt.Errorf("refusing to delete a non-internal VSC CSR key record")
	}
	return m.DeleteKeyRecord(ctx, record.CardUUID, certUUID)
}

// DeleteKeyRecord deletes an internal or issued VSC key and its persisted KSP container.
func (m *CSRKeyManager) DeleteKeyRecord(ctx context.Context, cardUUID, certUUID string) error {
	record, err := m.loadKeyRecord(ctx, certUUID)
	if err != nil || record == nil {
		return err
	}
	if record.CertType != storage.CertTypeInternal && record.CertType != storage.CertTypeX509 {
		return fmt.Errorf("refusing to delete a non-certificate VSC key record")
	}
	if record.CardUUID != cardUUID {
		return fmt.Errorf("VSC key record does not belong to the requested card")
	}
	cleanupCtx := context.WithoutCancel(ctx)
	card, err := m.cardRepo.GetByUUID(cleanupCtx, record.CardUUID)
	if err != nil {
		return fmt.Errorf("load VSC card for key cleanup: %w", err)
	}
	if card == nil {
		return fmt.Errorf("VSC card for key cleanup does not exist")
	}
	if card.SlotType != storage.SlotTypeTPMSC || card.TPMSCReaderName == "" || card.TPMSCInstanceID == "" {
		return ErrReaderUnavailable
	}
	if err := m.keyProvider.DeleteKey(cleanupCtx, card.TPMSCReaderName, record.UUID); err != nil {
		return fmt.Errorf("delete VSC key container: %w", err)
	}
	if err := m.certRepo.Delete(cleanupCtx, record.UUID); err != nil {
		return fmt.Errorf("delete VSC key record: %w", err)
	}
	return nil
}

func (m *CSRKeyManager) loadKeyRecord(ctx context.Context, certUUID string) (*storage.Certificate, error) {
	if m.certRepo == nil || m.cardRepo == nil || m.keyProvider == nil {
		return nil, ErrSmartCardKSPUnavailable
	}
	record, err := m.certRepo.GetByUUID(context.WithoutCancel(ctx), certUUID)
	if err != nil {
		return nil, fmt.Errorf("load VSC key record: %w", err)
	}
	if record == nil {
		return nil, nil
	}
	if record.SlotType != storage.SlotTypeTPMSC {
		return nil, fmt.Errorf("record is not a TPM VSC key")
	}
	return record, nil
}

// OpenSigner opens an issued or pending VSC key for a single cryptographic operation.
func (m *CSRKeyManager) OpenSigner(ctx context.Context, record *storage.Certificate) (crypto.Signer, error) {
	if m.cardRepo == nil || m.keyProvider == nil || record == nil || record.SlotType != storage.SlotTypeTPMSC ||
		(record.CertType != storage.CertTypeInternal && record.CertType != storage.CertTypeX509) {
		return nil, ErrSmartCardKSPUnavailable
	}
	card, err := m.cardRepo.GetByUUID(ctx, record.CardUUID)
	if err != nil {
		return nil, fmt.Errorf("load VSC card: %w", err)
	}
	if card == nil || card.SlotType != storage.SlotTypeTPMSC || card.SecurityLevel != storage.SecurityLevelHigh ||
		card.TPMSCInstanceID == "" || card.TPMSCReaderName == "" || card.TPMSCState != storage.TPMSCStateReady {
		return nil, ErrReaderUnavailable
	}
	publicKey, err := parseStoredPublicKey(record.CertContent)
	if err != nil {
		return nil, err
	}
	return m.keyProvider.OpenKey(ctx, card.TPMSCReaderName, record.UUID, record.KeyType, publicKey)
}

func parseStoredPublicKey(content []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(content)
	if block == nil {
		return nil, fmt.Errorf("VSC key record has no public key PEM")
	}
	if block.Type == "CERTIFICATE" {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse VSC certificate: %w", err)
		}
		return cert.PublicKey, nil
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse VSC public key: %w", err)
	}
	return publicKey, nil
}
