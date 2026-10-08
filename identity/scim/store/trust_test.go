package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	"github.com/plexusone/systemforge/identity/ent/human"
	"github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/scim"
	"github.com/plexusone/systemforge/identity/scim/store"
	"github.com/plexusone/systemforge/identity/systemauth"
)

func newTrustingStore(t *testing.T, trust bool) (*store.EntStore, *ent.Client) {
	t.Helper()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	cfg := store.DefaultConfig()
	cfg.TrustProvisionedEmail = trust
	return store.NewEntStore(db, cfg), db
}

func emailVerified(t *testing.T, db *ent.Client, email string) bool {
	t.Helper()
	h, err := db.Human.Query().Where(human.EmailEqualFold(email)).Only(context.Background())
	if err != nil {
		t.Fatalf("human %s: %v", email, err)
	}
	return h.EmailVerifiedAt != nil
}

// TestTrustProvisionedEmailLinksSocialLogin verifies that with the option
// on, a social login for a provisioned email links to the same principal.
func TestTrustProvisionedEmailLinksSocialLogin(t *testing.T) {
	ctx := context.Background()
	s, db := newTrustingStore(t, true)
	u, err := s.CreateUser(ctx, &scim.User{UserName: "lin@example.com", DisplayName: "Lin"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if !emailVerified(t, db, "lin@example.com") {
		t.Fatal("provisioned email not marked verified with TrustProvisionedEmail")
	}

	p, err := systemauth.ResolveExternalLogin(ctx, systemauth.NewEntPrincipalDirectory(db), systemauth.ExternalLogin{
		Provider: "google", Subject: "g-lin", Email: "lin@example.com", EmailVerified: true,
	}, time.Now())
	if err != nil {
		t.Fatalf("social login: %v", err)
	}
	if p.ID.String() != u.ID {
		t.Errorf("social login principal = %s, want the provisioned user %s", p.ID, u.ID)
	}
	if n, err := db.Principal.Query().Where(principal.TypeEQ(principal.TypeHuman)).Count(ctx); err != nil || n != 1 {
		t.Errorf("human principals = %d, %v; want 1", n, err)
	}
}

// TestChangedEmailDoesNotInheritVerification verifies that verification
// follows the address: changing a verified email clears it by default, and
// re-verifies it when provisioned emails are trusted.
func TestChangedEmailDoesNotInheritVerification(t *testing.T) {
	ctx := context.Background()
	for _, trust := range []bool{false, true} {
		s, db := newTrustingStore(t, trust)
		u, err := s.CreateUser(ctx, &scim.User{UserName: "old@example.com"})
		if err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		// Mark the original address verified, as a social login would.
		if _, err := db.Human.Update().
			Where(human.EmailEQ("old@example.com")).
			SetEmailVerifiedAt(time.Now()).
			Save(ctx); err != nil {
			t.Fatalf("verify: %v", err)
		}

		if _, err := s.UpdateUser(ctx, u.ID, &scim.User{UserName: "new@example.com"}); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		if got := emailVerified(t, db, "new@example.com"); got != trust {
			t.Errorf("trust=%v: changed email verified = %v, want %v", trust, got, trust)
		}

		// Re-sending the same address, in any case, is not a change.
		if _, err := db.Human.Update().
			Where(human.EmailEQ("new@example.com")).
			SetEmailVerifiedAt(time.Now()).
			Save(ctx); err != nil {
			t.Fatalf("verify: %v", err)
		}
		if _, err := s.UpdateUser(ctx, u.ID, &scim.User{UserName: "NEW@example.com"}); err != nil {
			t.Fatalf("UpdateUser same address: %v", err)
		}
		if !emailVerified(t, db, "new@example.com") {
			t.Errorf("trust=%v: verification cleared for an unchanged address", trust)
		}
	}
}
