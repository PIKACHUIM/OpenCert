package storage_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/globaltrusts/client-card/internal/storage"
)

func TestTPMSCMetadataRoundTripsThroughCardRepository(t *testing.T) {
	ctx := context.Background()
	db, err := storage.Open(filepath.Join(t.TempDir(), "tpmsc.db"))
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	user := &storage.User{UserType: storage.UserTypeLocal, Username: "tpmsc-metadata", DisplayName: "TPMSC metadata", Enabled: true}
	if err := storage.NewUserRepo(db).Create(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	cards := storage.NewCardRepo(db)
	want := &storage.Card{
		SlotType: storage.SlotTypeTPMSC, CardName: "VSC test", UserUUID: user.UUID,
		Enabled: true, SecurityLevel: storage.SecurityLevelHigh,
		TPMSCInstanceID: `ROOT\SMARTCARDREADER\0007`,
		TPMSCReaderName: "Microsoft Virtual Smart Card 7",
		TPMSCState:      "ready",
	}
	if err := cards.Create(ctx, want); err != nil {
		t.Fatalf("create VSC card record: %v", err)
	}

	assertMetadata := func(card *storage.Card) {
		t.Helper()
		if card.TPMSCInstanceID != want.TPMSCInstanceID || card.TPMSCReaderName != want.TPMSCReaderName || card.TPMSCState != want.TPMSCState {
			t.Fatalf("VSC metadata changed: got instance=%q reader=%q state=%q", card.TPMSCInstanceID, card.TPMSCReaderName, card.TPMSCState)
		}
	}
	got, err := cards.GetByUUID(ctx, want.UUID)
	if err != nil || got == nil {
		t.Fatalf("get card: card=%v err=%v", got, err)
	}
	assertMetadata(got)
	prefix, err := cards.GetByUUIDPrefix(ctx, want.UUID[:12])
	if err != nil || prefix == nil {
		t.Fatalf("get card by prefix: card=%v err=%v", prefix, err)
	}
	assertMetadata(prefix)
	for name, list := range map[string]func() ([]*storage.Card, error){
		"user": func() ([]*storage.Card, error) { return cards.ListByUser(ctx, user.UUID) },
		"all":  func() ([]*storage.Card, error) { return cards.ListAll(ctx) },
	} {
		items, err := list()
		if err != nil || len(items) != 1 {
			t.Fatalf("list %s cards: count=%d err=%v", name, len(items), err)
		}
		assertMetadata(items[0])
	}

	got.TPMSCState = "pending_reboot"
	if err := cards.Update(ctx, got); err != nil {
		t.Fatalf("update VSC state: %v", err)
	}
	updated, err := cards.GetByUUID(ctx, want.UUID)
	if err != nil || updated == nil || updated.TPMSCState != "pending_reboot" {
		t.Fatalf("updated state was not persisted: card=%v err=%v", updated, err)
	}
}
