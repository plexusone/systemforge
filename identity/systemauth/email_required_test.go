package systemauth

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent/enttest"
	"github.com/plexusone/systemforge/identity/ent/principal"
	principalsvc "github.com/plexusone/systemforge/identity/principal"
)

// TestHumansStillRequireEmail verifies that making the email column
// nullable did not open any existing creation path to humans without one:
// only managed principals may omit an email (ADR-005).
func TestHumansStillRequireEmail(t *testing.T) {
	ctx := context.Background()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	s := NewEntStorage(db)

	if err := s.CreateHuman(ctx, &HumanPrincipal{DisplayName: "No Email", Active: true}); !errors.Is(err, ErrEmailRequired) {
		t.Errorf("CreateHuman without email error = %v, want ErrEmailRequired", err)
	}
	h := &HumanPrincipal{Email: "ada@example.com", Active: true}
	if err := s.CreateHuman(ctx, h); err != nil {
		t.Fatalf("CreateHuman: %v", err)
	}
	h.Email = ""
	if err := s.UpdateHuman(ctx, h); !errors.Is(err, ErrEmailRequired) {
		t.Errorf("UpdateHuman clearing email error = %v, want ErrEmailRequired", err)
	}
	if _, err := principalsvc.NewService(db).CreateHuman(ctx, principalsvc.CreateHumanInput{DisplayName: "No Email"}); !errors.Is(err, principalsvc.ErrEmailRequired) {
		t.Errorf("principal.CreateHuman without email error = %v, want ErrEmailRequired", err)
	}
	if n, err := db.Principal.Query().Where(principal.TypeEQ(principal.TypeHuman)).Count(ctx); err != nil || n != 1 {
		t.Errorf("human principals = %d, %v; want 1", n, err)
	}

	// The schema itself admits several humans without an email.
	for range 2 {
		id := uuid.New()
		if _, err := db.Principal.Create().SetID(id).SetType(principal.TypeHuman).SetIdentifier("human:" + id.String()).SetDisplayName("Learner").Save(ctx); err != nil {
			t.Fatalf("principal: %v", err)
		}
		if _, err := db.Human.Create().SetPrincipalID(id).Save(ctx); err != nil {
			t.Fatalf("human without email: %v", err)
		}
	}
}
