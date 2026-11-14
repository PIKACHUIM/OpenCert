package pki_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/globaltrusts/client-card/internal/card/local"
	"github.com/globaltrusts/client-card/internal/pki"
	"github.com/globaltrusts/client-card/internal/storage"
	"github.com/globaltrusts/client-card/pkg/pkcs11types"
)

func TestCreateAndSaveSmartcardCSRStoresMatchingPublicKey(t *testing.T) {
	ctx := context.Background()
	db, err := storage.Open(filepath.Join(t.TempDir(), "csr-test.db"))
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	userRepo := storage.NewUserRepo(db)
	user := &storage.User{
		UserType:    storage.UserTypeLocal,
		Username:    "csr-test-user",
		DisplayName: "CSR test user",
		Enabled:     true,
	}
	if err := userRepo.Create(ctx, user); err != nil {
		t.Fatalf("create test user: %v", err)
	}
	cardRepo := storage.NewCardRepo(db)
	certRepo := storage.NewCertRepo(db)
	csrRepo := storage.NewCSRRepo(db)
	const pin = "test-card-pin"
	card, err := local.CreateCard(ctx, cardRepo, user.UUID, "CSR test card", pin, "", "")
	if err != nil {
		t.Fatalf("create local card: %v", err)
	}

	record, err := pki.CreateAndSaveCSR(ctx, csrRepo, certRepo, cardRepo, &pki.CreateCSRRequest{
		CommonName:   "csr.example.test",
		KeyType:      "ec256",
		KeyStorage:   storage.KeyStorageSmartcard,
		CardUUID:     card.UUID,
		CardPassword: pin,
	})
	if err != nil {
		t.Fatalf("create smartcard CSR: %v", err)
	}

	keyRecord, err := certRepo.GetByUUID(ctx, string(record.PrivateKeyEnc))
	if err != nil || keyRecord == nil {
		t.Fatalf("load CSR private-key record: key=%v err=%v", keyRecord, err)
	}
	csrBlock, _ := pem.Decode([]byte(record.CSRPEM))
	if csrBlock == nil {
		t.Fatal("CSR record does not contain PEM")
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("verify CSR signature: %v", err)
	}
	wantPublicKey, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		t.Fatalf("marshal CSR public key: %v", err)
	}
	gotPublicKey := local.ExtractPublicKeyDER(keyRecord.CertContent)
	if !bytes.Equal(gotPublicKey, wantPublicKey) {
		t.Fatalf("stored key record public key does not match the CSR public key")
	}
	if keyRecord.CertType != storage.CertTypeInternal || string(record.PrivateKeyEnc) != keyRecord.UUID {
		t.Fatalf("pending CSR key was not stored as a hidden key reference: key=%#v csr_ref=%q", keyRecord, record.PrivateKeyEnc)
	}
	visible, err := certRepo.ListByCardPublic(ctx, card.UUID)
	if err != nil || len(visible) != 0 {
		t.Fatalf("pending CSR key should not appear as an issued certificate: visible=%d err=%v", len(visible), err)
	}
	stats, err := certRepo.CountGroupedByCard(ctx)
	if err != nil {
		t.Fatalf("count visible card certificates: %v", err)
	}
	if stat := stats[card.UUID]; stat != nil && *stat != (storage.CertStats{}) {
		t.Fatalf("pending CSR key should not affect certificate counts: %+v", stat)
	}

	slot := local.New(1, card, certRepo)
	if err := slot.Login(ctx, pkcs11types.CKU_USER, pin); err != nil {
		t.Fatalf("unlock local card: %v", err)
	}
	defer slot.Logout(ctx)
	masterKey := slot.MasterKey()
	defer wipeTestBytes(masterKey)
	privateDER, err := local.DecryptPrivateKey(masterKey, keyRecord)
	if err != nil {
		t.Fatalf("decrypt locally stored CSR key: %v", err)
	}
	defer wipeTestBytes(privateDER)
	privateKey, err := x509.ParsePKCS8PrivateKey(privateDER)
	if err != nil {
		t.Fatalf("parse locally stored CSR key: %v", err)
	}
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		t.Fatalf("private key %T does not implement crypto.Signer", privateKey)
	}
	certificateTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               csr.Subject,
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, certificateTemplate, certificateTemplate, csr.PublicKey, signer)
	if err != nil {
		t.Fatalf("create certificate for binding: %v", err)
	}
	bound, err := local.NewKeyManager(certRepo, cardRepo).BindCertificateToKey(ctx, card.UUID, certificateDER, "CSR binding test")
	if err != nil {
		t.Fatalf("bind issued certificate to its CSR key: %v", err)
	}
	if bound.UUID != keyRecord.UUID || bound.CertType != storage.CertTypeX509 ||
		!bytes.Equal(local.ExtractPublicKeyDER(bound.CertContent), wantPublicKey) {
		t.Fatalf("bound certificate does not retain the CSR key: %#v", bound)
	}
	visible, err = certRepo.ListByCardPublic(ctx, card.UUID)
	if err != nil || len(visible) != 1 {
		t.Fatalf("bound certificate should be visible: visible=%d err=%v", len(visible), err)
	}
	stats, err = certRepo.CountGroupedByCard(ctx)
	if err != nil || stats[card.UUID] == nil || stats[card.UUID].X509 != 1 {
		t.Fatalf("bound certificate should count as one X.509 certificate: stats=%+v err=%v", stats[card.UUID], err)
	}
}

func TestCreateAndSaveSmartcardCSRRejectsUnimplementedHardwareCards(t *testing.T) {
	ctx := context.Background()
	db, err := storage.Open(filepath.Join(t.TempDir(), "csr-hardware-test.db"))
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	userRepo := storage.NewUserRepo(db)
	user := &storage.User{UserType: storage.UserTypeLocal, Username: "hardware-csr-test", DisplayName: "Hardware CSR test", Enabled: true}
	if err := userRepo.Create(ctx, user); err != nil {
		t.Fatalf("create test user: %v", err)
	}
	cardRepo := storage.NewCardRepo(db)
	certRepo := storage.NewCertRepo(db)
	csrRepo := storage.NewCSRRepo(db)

	for _, testCase := range []struct {
		name     string
		slotType storage.SlotType
		level    storage.SecurityLevel
	}{
		{name: "high local card", slotType: storage.SlotTypeLocal, level: storage.SecurityLevelHigh},
		{name: "TPM2 card", slotType: storage.SlotTypeTPM2, level: storage.SecurityLevelHigh},
		{name: "TPM VSC record", slotType: storage.SlotTypeTPMSC, level: storage.SecurityLevelHigh},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			card := &storage.Card{
				SlotType: testCase.slotType, CardName: testCase.name, UserUUID: user.UUID,
				Enabled: true, SecurityLevel: testCase.level,
			}
			if err := cardRepo.Create(ctx, card); err != nil {
				t.Fatalf("create test card: %v", err)
			}
			_, err := pki.CreateAndSaveCSR(ctx, csrRepo, certRepo, cardRepo, &pki.CreateCSRRequest{
				CommonName: "hardware.example.test", KeyStorage: storage.KeyStorageSmartcard,
				CardUUID: card.UUID, CardPassword: "unused",
			})
			if !errors.Is(err, pki.ErrHardwareCSRProviderUnavailable) {
				t.Fatalf("CreateAndSaveCSR error = %v, want ErrHardwareCSRProviderUnavailable", err)
			}
		})
	}
}

func wipeTestBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
