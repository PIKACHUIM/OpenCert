package pki_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/globaltrusts/client-card/internal/card/local"
	"github.com/globaltrusts/client-card/internal/card/tpmsc"
	"github.com/globaltrusts/client-card/internal/pki"
	"github.com/globaltrusts/client-card/internal/storage"
	"github.com/globaltrusts/client-card/internal/tpm"
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

func TestHighSecurityTPMCSRSigningAndIssuanceBinding(t *testing.T) {
	ctx := context.Background()
	db, err := storage.Open(filepath.Join(t.TempDir(), "tpm-csr-test.db"))
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	userRepo := storage.NewUserRepo(db)
	user := &storage.User{UserType: storage.UserTypeLocal, Username: "tpm-csr-test", DisplayName: "TPM CSR test", Enabled: true}
	if err := userRepo.Create(ctx, user); err != nil {
		t.Fatalf("create test user: %v", err)
	}
	cardRepo := storage.NewCardRepo(db)
	certRepo := storage.NewCertRepo(db)
	csrRepo := storage.NewCSRRepo(db)
	provider := testHardwareKeyProvider{MockProvider: tpm.NewMock()}
	const pin = "tpm-csr-test-pin"
	cardResult, err := local.CreateCardWithCredsAndTPM(ctx, cardRepo, provider, local.CreateCardArgs{
		UserUUID: user.UUID, CardName: "TPM CSR test card", PIN: pin,
		SecurityLevel: storage.SecurityLevelHigh,
	})
	if err != nil {
		t.Fatalf("create high-security card: %v", err)
	}
	card := cardResult.Card
	keyManager := local.NewKeyManagerWithTPM(certRepo, cardRepo, provider)

	csrRecord, err := pki.CreateAndSaveCSRWithHardwareKeyManager(ctx, csrRepo, certRepo, cardRepo, keyManager, &pki.CreateCSRRequest{
		CommonName: "tpm.example.test", KeyType: "ec256", DigestType: "sha256",
		KeyStorage: storage.KeyStorageSmartcard, CardUUID: card.UUID, CardPassword: pin,
	})
	if err != nil {
		t.Fatalf("create TPM-backed CSR: %v", err)
	}
	keyRecord, err := certRepo.GetByUUID(ctx, string(csrRecord.PrivateKeyEnc))
	if err != nil || keyRecord == nil {
		t.Fatalf("load TPM key record: key=%v err=%v", keyRecord, err)
	}
	if keyRecord.CertType != storage.CertTypeInternal || len(keyRecord.TPMWrappedBlob) == 0 || len(keyRecord.PrivateData) != 0 {
		t.Fatalf("TPM CSR private key was not stored as a hidden wrapped key: %#v", keyRecord)
	}
	csrBlock, _ := pem.Decode([]byte(csrRecord.CSRPEM))
	if csrBlock == nil {
		t.Fatal("CSR record does not contain PEM")
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		t.Fatalf("parse TPM CSR: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("verify TPM CSR signature: %v", err)
	}
	wantPublicKey, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		t.Fatalf("marshal CSR public key: %v", err)
	}
	if !bytes.Equal(local.ExtractPublicKeyDER(keyRecord.CertContent), wantPublicKey) {
		t.Fatal("TPM key record public key does not match CSR public key")
	}
	visible, err := certRepo.ListByCardPublic(ctx, card.UUID)
	if err != nil || len(visible) != 0 {
		t.Fatalf("pending TPM CSR key should remain hidden: visible=%d err=%v", len(visible), err)
	}

	caRepo := storage.NewCARepo(db)
	ca, err := pki.CreateAndSaveCA(ctx, caRepo, &pki.CreateCARequest{
		Name: "TPM CSR test CA", CommonName: "TPM CSR test CA", KeyType: "ec256", ValidityYears: 1,
	})
	if err != nil {
		t.Fatalf("create test CA: %v", err)
	}
	issued, err := pki.IssueCertFromCSR(ctx, csrRepo, caRepo, storage.NewPKICertRepo(db), certRepo, &pki.IssueCertFromCSRRequest{
		CSRUUID: csrRecord.UUID, CAUUID: ca.UUID, ValidityDays: 30,
	})
	if err != nil {
		t.Fatalf("issue certificate from TPM CSR: %v", err)
	}
	if !issued.HasPrivateKey || string(issued.PrivateKeyEnc) != keyRecord.UUID {
		t.Fatalf("issued certificate lost TPM key reference: %#v", issued)
	}
	bound, err := certRepo.GetByUUID(ctx, keyRecord.UUID)
	if err != nil || bound == nil {
		t.Fatalf("load issued TPM key record: key=%v err=%v", bound, err)
	}
	if bound.CertType != storage.CertTypeX509 || !bytes.Equal(local.ExtractPublicKeyDER(bound.CertContent), wantPublicKey) {
		t.Fatalf("issued certificate was not bound to the TPM key: %#v", bound)
	}
	visible, err = certRepo.ListByCardPublic(ctx, card.UUID)
	if err != nil || len(visible) != 1 {
		t.Fatalf("issued TPM certificate should be visible: visible=%d err=%v", len(visible), err)
	}

	slot := local.NewWithTPM(1, card, certRepo, cardRepo, provider)
	if err := slot.Login(ctx, pkcs11types.CKU_USER, pin); err != nil {
		t.Fatalf("unlock TPM card: %v", err)
	}
	defer slot.Logout(ctx)
	masterKey := slot.MasterKey()
	defer wipeTestBytes(masterKey)
	signer, err := keyManager.NewTPMSigner(ctx, keyRecord.UUID, masterKey)
	if err != nil {
		t.Fatalf("reopen TPM key signer: %v", err)
	}
	defer signer.Close()
	digest := sha256.Sum256([]byte("post-issuance TPM signing test"))
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("sign after certificate binding: %v", err)
	}
	publicKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || !ecdsa.VerifyASN1(publicKey, digest[:], signature) {
		t.Fatal("post-issuance TPM signature did not verify with the issued public key")
	}
	if err := keyManager.DeleteTPMKeyRecord(ctx, card.UUID, keyRecord.UUID); err != nil {
		t.Fatalf("delete bound TPM key: %v", err)
	}
	deleted, err := certRepo.GetByUUID(ctx, keyRecord.UUID)
	if err != nil || deleted != nil {
		t.Fatalf("deleted TPM key record still exists: key=%v err=%v", deleted, err)
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

func TestTPMSCCSRUsesSmartCardKeyProviderAndBindsIssuedCertificate(t *testing.T) {
	ctx := context.Background()
	db, err := storage.Open(filepath.Join(t.TempDir(), "tpmsc-csr-test.db"))
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	user := &storage.User{UserType: storage.UserTypeLocal, Username: "tpmsc-csr-test", DisplayName: "TPMSC CSR test", Enabled: true}
	if err := storage.NewUserRepo(db).Create(ctx, user); err != nil {
		t.Fatalf("create test user: %v", err)
	}
	cardRepo := storage.NewCardRepo(db)
	certRepo := storage.NewCertRepo(db)
	csrRepo := storage.NewCSRRepo(db)
	card := &storage.Card{
		SlotType: storage.SlotTypeTPMSC, CardName: "VSC CSR test", UserUUID: user.UUID,
		Enabled: true, SecurityLevel: storage.SecurityLevelHigh,
		TPMSCInstanceID: `ROOT\SMARTCARDREADER\0008`, TPMSCReaderName: "VSC CSR reader",
		TPMSCState: storage.TPMSCStateReady,
	}
	if err := cardRepo.Create(ctx, card); err != nil {
		t.Fatalf("create VSC card record: %v", err)
	}
	keyProvider := &testVSCKeyProvider{keys: make(map[string]*ecdsa.PrivateKey)}
	keyManager := tpmsc.NewCSRKeyManagerWithProvider(certRepo, cardRepo, keyProvider)
	csrRecord, err := pki.CreateAndSaveCSRWithHardwareKeyManager(ctx, csrRepo, certRepo, cardRepo, keyManager, &pki.CreateCSRRequest{
		CommonName: "vsc.example.test", KeyType: "ec256", DigestType: "sha256",
		KeyStorage: storage.KeyStorageSmartcard, CardUUID: card.UUID,
	})
	if err != nil {
		t.Fatalf("create VSC CSR without a local card password: %v", err)
	}
	csrBlock, _ := pem.Decode([]byte(csrRecord.CSRPEM))
	if csrBlock == nil {
		t.Fatal("VSC CSR record does not contain PEM")
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		t.Fatalf("parse VSC CSR: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("verify VSC CSR signature: %v", err)
	}
	keyRecord, err := certRepo.GetByUUID(ctx, string(csrRecord.PrivateKeyEnc))
	if err != nil || keyRecord == nil {
		t.Fatalf("load VSC key record: key=%v err=%v", keyRecord, err)
	}
	if keyRecord.SlotType != storage.SlotTypeTPMSC || keyRecord.CertType != storage.CertTypeInternal || len(keyRecord.PrivateData) != 0 {
		t.Fatalf("VSC private key was not kept in its hardware provider: %#v", keyRecord)
	}
	wantPublicKey, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		t.Fatalf("marshal VSC CSR public key: %v", err)
	}
	if !bytes.Equal(local.ExtractPublicKeyDER(keyRecord.CertContent), wantPublicKey) {
		t.Fatal("VSC CSR public key does not match the persisted key record")
	}

	caRepo := storage.NewCARepo(db)
	ca, err := pki.CreateAndSaveCA(ctx, caRepo, &pki.CreateCARequest{
		Name: "VSC test CA", CommonName: "VSC test CA", KeyType: "ec256", ValidityYears: 1,
	})
	if err != nil {
		t.Fatalf("create test CA: %v", err)
	}
	issued, err := pki.IssueCertFromCSR(ctx, csrRepo, caRepo, storage.NewPKICertRepo(db), certRepo, &pki.IssueCertFromCSRRequest{
		CSRUUID: csrRecord.UUID, CAUUID: ca.UUID, ValidityDays: 30,
	})
	if err != nil {
		t.Fatalf("issue certificate from VSC CSR: %v", err)
	}
	if !issued.HasPrivateKey || string(issued.PrivateKeyEnc) != keyRecord.UUID {
		t.Fatalf("issued certificate lost VSC key reference: %#v", issued)
	}
	bound, err := certRepo.GetByUUID(ctx, keyRecord.UUID)
	if err != nil || bound == nil || bound.CertType != storage.CertTypeX509 {
		t.Fatalf("issued certificate was not bound to the VSC key: record=%v err=%v", bound, err)
	}
	signer, err := keyManager.OpenSigner(ctx, bound)
	if err != nil {
		t.Fatalf("reopen VSC signer after issuance: %v", err)
	}
	closer := signer.(interface{ Close() error })
	defer closer.Close()
	digest := sha256.Sum256([]byte("VSC post-issuance signing test"))
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("sign with the bound VSC key: %v", err)
	}
	publicKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || !ecdsa.VerifyASN1(publicKey, digest[:], signature) {
		t.Fatal("VSC KSP signature did not verify with the issued public key")
	}
}

type testVSCKeyProvider struct {
	mu   sync.Mutex
	keys map[string]*ecdsa.PrivateKey
}

func (p *testVSCKeyProvider) CreateKey(_ context.Context, _, container, keyType string) (crypto.Signer, error) {
	if keyType != "ec256" {
		return nil, fmt.Errorf("unsupported test key type %q", keyType)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.keys[container] = key
	p.mu.Unlock()
	return &testCloseableSigner{Signer: key}, nil
}

func (p *testVSCKeyProvider) OpenKey(_ context.Context, _, container, _ string, _ crypto.PublicKey) (crypto.Signer, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := p.keys[container]
	if key == nil {
		return nil, fmt.Errorf("test VSC key %q not found", container)
	}
	return &testCloseableSigner{Signer: key}, nil
}

func (p *testVSCKeyProvider) DeleteKey(_ context.Context, _, container string) error {
	p.mu.Lock()
	delete(p.keys, container)
	p.mu.Unlock()
	return nil
}

type testCloseableSigner struct{ crypto.Signer }

func (*testCloseableSigner) Close() error { return nil }

type testHardwareKeyProvider struct {
	*tpm.MockProvider
}

func (testHardwareKeyProvider) HardwareKeyGenerationAvailable() bool { return true }

func wipeTestBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
