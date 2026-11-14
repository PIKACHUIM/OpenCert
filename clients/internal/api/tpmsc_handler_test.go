package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/globaltrusts/client-card/internal/card/local"
	"github.com/globaltrusts/client-card/internal/storage"
	"github.com/globaltrusts/client-card/internal/tpm"
)

func newTPMSCTestServer(t *testing.T) (*Server, *storage.User) {
	t.Helper()
	srv := newTestAuthServer(t)
	srv.cardRepo = storage.NewCardRepo(srv.db)
	srv.certRepo = storage.NewCertRepo(srv.db)
	srv.csrRepo = storage.NewCSRRepo(srv.db)

	passwordHash, err := hashPassword("test-user-password")
	if err != nil {
		t.Fatalf("hash test password: %v", err)
	}
	user := &storage.User{
		UserType:     storage.UserTypeLocal,
		Role:         "user",
		Username:     "tpmsc-test-user",
		DisplayName:  "TPMSC test user",
		Enabled:      true,
		PasswordHash: passwordHash,
	}
	if err := srv.userRepo.Create(context.Background(), user); err != nil {
		t.Fatalf("create test user: %v", err)
	}
	return srv, user
}

func createTPMSCRecord(t *testing.T, srv *Server, user *storage.User) *storage.Card {
	t.Helper()
	card := &storage.Card{
		SlotType:      storage.SlotTypeTPMSC,
		CardName:      "existing VSC record",
		UserUUID:      user.UUID,
		Enabled:       true,
		SecurityLevel: storage.SecurityLevelHigh,
	}
	if err := srv.cardRepo.Create(context.Background(), card); err != nil {
		t.Fatalf("create test card record: %v", err)
	}
	return card
}

func assertTPMSCNotImplemented(t *testing.T, recorder *httptest.ResponseRecorder) {
	t.Helper()
	if recorder.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusNotImplemented, recorder.Body.String())
	}
	var response Response
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !strings.Contains(response.Message, "Provider") {
		t.Fatalf("message does not explain the missing provider: %q", response.Message)
	}
}

func TestHandleCreateMediumCardRejectsSoftwareNVProvider(t *testing.T) {
	srv, user := newTPMSCTestServer(t)
	srv.tpmProvider = tpm.NewMock()
	body := `{"slot_type":"local","card_name":"medium card","user_uuid":"` + user.UUID + `","user_password":"test-user-password","pin":"test-card-pin","security_level":"medium"}`
	req := httptest.NewRequest(http.MethodPost, "/api/cards", strings.NewReader(body))
	recorder := httptest.NewRecorder()
	srv.handleCreateCard(recorder, req)

	if recorder.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusNotImplemented, recorder.Body.String())
	}
	cards, err := srv.cardRepo.ListAll(req.Context())
	if err != nil || len(cards) != 0 {
		t.Fatalf("unsupported medium card should not be persisted: cards=%d err=%v", len(cards), err)
	}
}

func TestHandleCreateCardTPMSCRequiresExplicitAdminKey(t *testing.T) {
	srv, user := newTPMSCTestServer(t)
	body := `{"slot_type":"tpmsc","card_name":"new VSC","user_uuid":"` + user.UUID + `","user_password":"test-user-password","pin":"pin-test-123","security_level":"high"}`
	req := httptest.NewRequest(http.MethodPost, "/api/cards", strings.NewReader(body))
	recorder := httptest.NewRecorder()
	srv.handleCreateCard(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "pin-test-123") {
		t.Fatalf("response leaked a submitted credential: %s", recorder.Body.String())
	}
	cards, err := srv.cardRepo.ListAll(req.Context())
	if err != nil {
		t.Fatalf("list card records: %v", err)
	}
	if len(cards) != 0 {
		t.Fatalf("invalid VSC request left %d local records", len(cards))
	}
}

func TestHandleCreateTPMSCUnavailableDoesNotPersistIntent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("TPM VSC creation requires an interactive Windows TPM environment")
	}
	srv, user := newTPMSCTestServer(t)
	body := `{"slot_type":"tpmsc","card_name":"VSC test","user_uuid":"` + user.UUID + `","user_password":"test-user-password","pin":"pin-test-123","admin_key":"0123456789abcdeffedcba98765432100011223344556677","security_level":"high"}`
	req := httptest.NewRequest(http.MethodPost, "/api/cards", strings.NewReader(body))
	recorder := httptest.NewRecorder()
	srv.handleCreateCard(recorder, req)
	if recorder.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusNotImplemented, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "pin-test-123") || strings.Contains(recorder.Body.String(), "0123456789abcdef") {
		t.Fatalf("response leaked a VSC credential: %s", recorder.Body.String())
	}
	cards, err := srv.cardRepo.ListAll(req.Context())
	if err != nil || len(cards) != 0 {
		t.Fatalf("unavailable VSC provisioning left metadata: cards=%d err=%v", len(cards), err)
	}
}

func TestHandleDeleteCardTPMSCPreservesRecord(t *testing.T) {
	srv, user := newTPMSCTestServer(t)
	card := createTPMSCRecord(t, srv, user)
	body := `{"user_uuid":"` + user.UUID + `","user_password":"test-user-password"}`
	req := httptest.NewRequest(http.MethodDelete, "/api/cards/"+card.UUID, strings.NewReader(body))
	req.SetPathValue("uuid", card.UUID)
	recorder := httptest.NewRecorder()
	srv.handleDeleteCard(recorder, req)

	if recorder.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusConflict, recorder.Body.String())
	}
	stored, err := srv.cardRepo.GetByUUID(req.Context(), card.UUID)
	if err != nil || stored == nil {
		t.Fatalf("TPMSC record was removed: stored=%v err=%v", stored, err)
	}
}

func TestHandleKeyGenTPMSCRejectsBeforeLocalKeyPath(t *testing.T) {
	srv, user := newTPMSCTestServer(t)
	card := createTPMSCRecord(t, srv, user)
	req := httptest.NewRequest(http.MethodPost, "/api/cards/"+card.UUID+"/keygen", strings.NewReader(`{"card_password":"unused","key_type":"rsa2048"}`))
	req.SetPathValue("card_uuid", card.UUID)
	recorder := httptest.NewRecorder()
	srv.handleKeyGen(recorder, req)

	assertTPMSCNotImplemented(t, recorder)
}

func TestHandleListCertsTPMSCListsPublicDatabaseRecords(t *testing.T) {
	srv, user := newTPMSCTestServer(t)
	card := createTPMSCRecord(t, srv, user)
	req := httptest.NewRequest(http.MethodGet, "/api/cards/"+card.UUID+"/certs", nil)
	req.SetPathValue("card_uuid", card.UUID)
	recorder := httptest.NewRecorder()
	srv.handleListCerts(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var response struct {
		Data []json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(response.Data) != 0 {
		t.Fatalf("new VSC record unexpectedly has public certificates: %d", len(response.Data))
	}
}

func TestHandleDeleteCertRemovesPersistedTPMKey(t *testing.T) {
	srv, user := newTPMSCTestServer(t)
	provider := testHardwareKeyProvider{MockProvider: tpm.NewMock()}
	srv.tpmProvider = provider
	const pin = "high-card-pin"
	cardResult, err := local.CreateCardWithCredsAndTPM(context.Background(), srv.cardRepo, provider, local.CreateCardArgs{
		UserUUID: user.UUID, CardName: "high card", PIN: pin, SecurityLevel: storage.SecurityLevelHigh,
	})
	if err != nil {
		t.Fatalf("create high-security card: %v", err)
	}
	card := cardResult.Card
	slot := local.NewWithTPM(1, card, srv.certRepo, srv.cardRepo, provider)
	if err := slot.Login(context.Background(), 1, pin); err != nil {
		t.Fatalf("unlock high-security card: %v", err)
	}
	masterKey := slot.MasterKey()
	keyManager := local.NewKeyManagerWithTPM(srv.certRepo, srv.cardRepo, provider)
	key, err := keyManager.GenerateKeyPair(context.Background(), local.KeyGenRequest{
		CardUUID: card.UUID, CertType: storage.CertTypeX509, KeyType: "ec256",
	}, masterKey, card)
	wipeTestSecret(masterKey)
	if err := slot.Logout(context.Background()); err != nil {
		t.Fatalf("logout high-security card: %v", err)
	}
	if err != nil {
		t.Fatalf("create TPM key record: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/cards/"+card.UUID+"/certs/"+key.CertUUID, nil)
	req.SetPathValue("card_uuid", card.UUID)
	req.SetPathValue("uuid", key.CertUUID)
	recorder := httptest.NewRecorder()
	srv.handleDeleteCert(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("delete status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	deleted, err := srv.certRepo.GetByUUID(req.Context(), key.CertUUID)
	if err != nil || deleted != nil {
		t.Fatalf("TPM key record remains after deletion: key=%v err=%v", deleted, err)
	}
}

type testHardwareKeyProvider struct {
	*tpm.MockProvider
}

func (testHardwareKeyProvider) HardwareKeyGenerationAvailable() bool { return true }

func wipeTestSecret(secret []byte) {
	for i := range secret {
		secret[i] = 0
	}
}

func TestHandleCreateCSRHighLocalCardUsesTPMProvider(t *testing.T) {
	srv, user := newTPMSCTestServer(t)
	provider := testHardwareKeyProvider{MockProvider: tpm.NewMock()}
	srv.tpmProvider = provider
	const pin = "high-card-csr-pin"
	cardResult, err := local.CreateCardWithCredsAndTPM(context.Background(), srv.cardRepo, provider, local.CreateCardArgs{
		UserUUID: user.UUID, CardName: "high CSR card", PIN: pin, SecurityLevel: storage.SecurityLevelHigh,
	})
	if err != nil {
		t.Fatalf("create high-security card: %v", err)
	}
	card := cardResult.Card
	body := `{"common_name":"hardware-csr.example.test","key_type":"ec256","key_storage":"smartcard","card_uuid":"` + card.UUID + `","card_password":"` + pin + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/pki/csr", strings.NewReader(body))
	recorder := httptest.NewRecorder()
	srv.handleCreateCSR(recorder, req)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("create CSR status = %d, want %d: %s", recorder.Code, http.StatusCreated, recorder.Body.String())
	}
	records, total, err := srv.csrRepo.List(req.Context(), 1, 10)
	if err != nil || total != 1 || len(records) != 1 {
		t.Fatalf("list created CSR: records=%d total=%d err=%v", len(records), total, err)
	}
	stored, err := srv.csrRepo.GetByUUID(req.Context(), records[0].UUID)
	if err != nil || stored == nil {
		t.Fatalf("load created CSR details: record=%v err=%v", stored, err)
	}
	key, err := srv.certRepo.GetByUUID(req.Context(), string(stored.PrivateKeyEnc))
	if err != nil || key == nil || len(key.TPMWrappedBlob) == 0 || len(key.PrivateData) != 0 {
		t.Fatalf("CSR did not store a wrapped TPM key record: key=%v err=%v", key, err)
	}
}

func TestHandleCreateCSRTPMSCRejectsSoftwareKeyGeneration(t *testing.T) {
	srv, user := newTPMSCTestServer(t)
	card := createTPMSCRecord(t, srv, user)
	body := `{"common_name":"vsc.example.test","key_storage":"smartcard","card_uuid":"` + card.UUID + `","card_password":"unused"}`
	req := httptest.NewRequest(http.MethodPost, "/api/pki/csr", strings.NewReader(body))
	recorder := httptest.NewRecorder()
	srv.handleCreateCSR(recorder, req)

	assertTPMSCNotImplemented(t, recorder)
}
