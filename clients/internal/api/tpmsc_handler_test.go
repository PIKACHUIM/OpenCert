package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

func TestHandleCreateCardTPMSCRejectsWithoutLeakingCredentials(t *testing.T) {
	srv, user := newTPMSCTestServer(t)
	body := `{"slot_type":"tpmsc","card_name":"new VSC","user_uuid":"` + user.UUID + `","user_password":"test-user-password","pin":"12345678","security_level":"high"}`
	req := httptest.NewRequest(http.MethodPost, "/api/cards", strings.NewReader(body))
	recorder := httptest.NewRecorder()
	srv.handleCreateCard(recorder, req)

	assertTPMSCNotImplemented(t, recorder)
	if strings.Contains(recorder.Body.String(), "12345678") {
		t.Fatalf("response leaked a default credential: %s", recorder.Body.String())
	}
	cards, err := srv.cardRepo.ListAll(req.Context())
	if err != nil {
		t.Fatalf("list card records: %v", err)
	}
	if len(cards) != 0 {
		t.Fatalf("VSC create left %d local records; want no side effects", len(cards))
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

	assertTPMSCNotImplemented(t, recorder)
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

func TestHandleListCertsTPMSCRejectsEnumeration(t *testing.T) {
	srv, user := newTPMSCTestServer(t)
	card := createTPMSCRecord(t, srv, user)
	req := httptest.NewRequest(http.MethodGet, "/api/cards/"+card.UUID+"/certs", nil)
	req.SetPathValue("card_uuid", card.UUID)
	recorder := httptest.NewRecorder()
	srv.handleListCerts(recorder, req)

	assertTPMSCNotImplemented(t, recorder)
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
