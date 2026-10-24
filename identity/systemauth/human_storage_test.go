package systemauth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	credsvc "github.com/plexusone/systemforge/identity/credential"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/enttest"
)

func newHumanTestDB(t *testing.T) *ent.Client {
	t.Helper()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	return db
}

// humanStorageContract is the behavior every Storage implementation must
// provide for human principals.
func humanStorageContract(t *testing.T, s Storage) {
	t.Helper()
	ctx := context.Background()

	h := &HumanPrincipal{Email: "Ada@Example.com", DisplayName: "Ada", GivenName: "Ada", Active: true, EmailVerified: true}
	if err := s.CreateHuman(ctx, h); err != nil {
		t.Fatalf("CreateHuman: %v", err)
	}
	if h.ID == uuid.Nil {
		t.Fatal("CreateHuman did not assign an ID")
	}

	got, err := s.GetHuman(ctx, h.ID)
	if err != nil {
		t.Fatalf("GetHuman: %v", err)
	}
	if got.Email != "Ada@Example.com" || got.DisplayName != "Ada" || got.GivenName != "Ada" || !got.Active || !got.EmailVerified {
		t.Errorf("GetHuman = %+v", got)
	}

	if got, err := s.GetHumanByEmail(ctx, "ada@example.com"); err != nil || got.ID != h.ID {
		t.Errorf("GetHumanByEmail (case-insensitive) = %v, %v; want %s", got, err, h.ID)
	}

	if err := s.CreateHuman(ctx, &HumanPrincipal{Email: "ada@example.com", Active: true}); !errors.Is(err, ErrPrincipalExists) {
		t.Errorf("duplicate email CreateHuman error = %v, want ErrPrincipalExists", err)
	}

	if err := s.LinkExternalIdentity(ctx, h.ID, "github", "123"); err != nil {
		t.Fatalf("LinkExternalIdentity: %v", err)
	}
	if err := s.LinkExternalIdentity(ctx, h.ID, "github", "123"); err != nil {
		t.Errorf("relinking the same identity: %v", err)
	}
	other := &HumanPrincipal{Email: "grace@example.com", Active: true}
	if err := s.CreateHuman(ctx, other); err != nil {
		t.Fatalf("CreateHuman other: %v", err)
	}
	if err := s.LinkExternalIdentity(ctx, other.ID, "github", "123"); !errors.Is(err, ErrExternalIdentityExists) {
		t.Errorf("linking a taken identity error = %v, want ErrExternalIdentityExists", err)
	}
	if err := s.LinkExternalIdentity(ctx, uuid.New(), "github", "999"); !errors.Is(err, ErrPrincipalNotFound) {
		t.Errorf("linking to a missing principal error = %v, want ErrPrincipalNotFound", err)
	}
	if got, err := s.GetHumanByExternalIdentity(ctx, "github", "123"); err != nil || got.ID != h.ID {
		t.Errorf("GetHumanByExternalIdentity = %v, %v; want %s", got, err, h.ID)
	}

	got.DisplayName = "Ada Lovelace"
	got.FamilyName = "Lovelace"
	got.EmailVerified = false
	got.Active = false
	if err := s.UpdateHuman(ctx, got); err != nil {
		t.Fatalf("UpdateHuman: %v", err)
	}
	updated, err := s.GetHuman(ctx, h.ID)
	if err != nil {
		t.Fatalf("GetHuman after update: %v", err)
	}
	if updated.DisplayName != "Ada Lovelace" || updated.FamilyName != "Lovelace" || updated.EmailVerified || updated.Active {
		t.Errorf("after UpdateHuman = %+v", updated)
	}
	collide := *other
	collide.Email = "ADA@example.com"
	if err := s.UpdateHuman(ctx, &collide); !errors.Is(err, ErrPrincipalExists) {
		t.Errorf("UpdateHuman to a taken email error = %v, want ErrPrincipalExists", err)
	}
	if err := s.UpdateHuman(ctx, &HumanPrincipal{ID: uuid.New(), Email: "x@example.com"}); !errors.Is(err, ErrPrincipalNotFound) {
		t.Errorf("UpdateHuman missing error = %v, want ErrPrincipalNotFound", err)
	}

	if err := s.DeleteHuman(ctx, h.ID); err != nil {
		t.Fatalf("DeleteHuman: %v", err)
	}
	if _, err := s.GetHuman(ctx, h.ID); !errors.Is(err, ErrPrincipalNotFound) {
		t.Errorf("GetHuman after delete error = %v, want ErrPrincipalNotFound", err)
	}
	if _, err := s.GetHumanByExternalIdentity(ctx, "github", "123"); !errors.Is(err, ErrPrincipalNotFound) {
		t.Errorf("external identity survived delete: %v", err)
	}
	if err := s.DeleteHuman(ctx, h.ID); !errors.Is(err, ErrPrincipalNotFound) {
		t.Errorf("second DeleteHuman error = %v, want ErrPrincipalNotFound", err)
	}
}

func TestHumanStorageMemory(t *testing.T) {
	humanStorageContract(t, NewMemoryStorage())
}

func TestHumanStorageEnt(t *testing.T) {
	humanStorageContract(t, NewEntStorage(newHumanTestDB(t)))
}

// TestSocialThenPasswordLoginIsOnePrincipal covers the defect the single
// identity root fixes: a person who first signs in with a social provider
// and later sets a password must authenticate as the same principal.
func TestSocialThenPasswordLoginIsOnePrincipal(t *testing.T) {
	ctx := context.Background()
	db := newHumanTestDB(t)

	social, err := ResolveExternalLogin(ctx, NewEntPrincipalDirectory(db), ExternalLogin{
		Provider: "google", Subject: "g-1", Email: "lin@example.com", EmailVerified: true, Name: "Lin",
	}, time.Now())
	if err != nil {
		t.Fatalf("social login: %v", err)
	}

	creds := credsvc.NewService(db)
	if err := creds.CreatePassword(ctx, credsvc.CreatePasswordInput{PrincipalID: social.ID, Password: "correct horse battery"}); err != nil {
		t.Fatalf("CreatePassword: %v", err)
	}

	providers := NewProvidersFromStorage(NewEntStorage(db), WithProviderPasswordVerifier(creds.VerifyPassword))
	session, err := providers.Authentication.Authenticate(ctx, &AuthenticateRequest{
		Method: AuthMethodPassword, Identifier: "LIN@example.com", Password: "correct horse battery",
	})
	if err != nil {
		t.Fatalf("password login: %v", err)
	}
	if session.Identity == nil || session.Identity.ID != social.ID {
		t.Errorf("password login principal = %v, want social principal %s", session.Identity, social.ID)
	}

	if _, err := providers.Authentication.Authenticate(ctx, &AuthenticateRequest{
		Method: AuthMethodPassword, Identifier: "lin@example.com", Password: "wrong",
	}); err == nil {
		t.Error("password login with a wrong password succeeded")
	}
}

// emailChangeContract verifies that verification belongs to an address:
// changing a human's email leaves the new one unverified even when the
// caller's copy still says verified, so it is neither found by
// FindByVerifiedEmail nor claimed as verified, while a case-only change
// keeps it.
func emailChangeContract(t *testing.T, s Storage, dir PrincipalDirectory) {
	t.Helper()
	ctx := context.Background()
	h := &HumanPrincipal{Email: "ada@example.com", DisplayName: "Ada", Active: true, EmailVerified: true}
	if err := s.CreateHuman(ctx, h); err != nil {
		t.Fatalf("CreateHuman: %v", err)
	}

	loaded, err := s.GetHuman(ctx, h.ID)
	if err != nil {
		t.Fatalf("GetHuman: %v", err)
	}
	loaded.Email = "Ada@Example.com"
	if err := s.UpdateHuman(ctx, loaded); err != nil {
		t.Fatalf("case-only UpdateHuman: %v", err)
	}
	if got, err := s.GetHuman(ctx, h.ID); err != nil || !got.EmailVerified {
		t.Errorf("after a case-only change = %+v, %v; want still verified", got, err)
	}

	loaded.Email = "victim@example.com"
	if !loaded.EmailVerified {
		t.Fatal("loaded copy is not verified")
	}
	if err := s.UpdateHuman(ctx, loaded); err != nil {
		t.Fatalf("UpdateHuman: %v", err)
	}
	got, err := s.GetHuman(ctx, h.ID)
	if err != nil {
		t.Fatalf("GetHuman: %v", err)
	}
	if got.Email != "victim@example.com" || got.EmailVerified {
		t.Errorf("after an email change = %+v; want the new email, unverified", got)
	}
	if dir != nil {
		if p, err := dir.FindByVerifiedEmail(ctx, "victim@example.com"); !errors.Is(err, ErrPrincipalNotFound) {
			t.Errorf("FindByVerifiedEmail(new address) = %+v, %v; want ErrPrincipalNotFound", p, err)
		}
	}

	// Once proven, the new address is marked verified with a second update.
	got.EmailVerified = true
	if err := s.UpdateHuman(ctx, got); err != nil {
		t.Fatalf("UpdateHuman verifying: %v", err)
	}
	if got, err := s.GetHuman(ctx, h.ID); err != nil || !got.EmailVerified {
		t.Errorf("after verifying = %+v, %v; want verified", got, err)
	}
}

func TestEmailChangeClearsVerificationMemory(t *testing.T) {
	emailChangeContract(t, NewMemoryStorage(), nil)
}

func TestEmailChangeClearsVerificationEnt(t *testing.T) {
	db := newHumanTestDB(t)
	emailChangeContract(t, NewEntStorage(db), NewEntPrincipalDirectory(db))
}

func TestFederationSyncLinksAndResolves(t *testing.T) {
	ctx := context.Background()
	s := NewEntStorage(newHumanTestDB(t))
	h := NewDefaultIdentitySyncHandler(s)

	existing := &HumanPrincipal{Email: "kim@example.com", DisplayName: "Kim", Active: true}
	if err := s.CreateHuman(ctx, existing); err != nil {
		t.Fatalf("seed: %v", err)
	}

	fedID := uuid.New()
	sync := func(action string, gi GlobalIdentity) *IdentitySyncResponse {
		t.Helper()
		gi.ID = fedID
		resp, err := h.SyncIdentity(ctx, &IdentitySyncRequest{Action: action, Identity: &gi})
		if err != nil {
			t.Fatalf("%s: %v", action, err)
		}
		return resp
	}

	// create adopts the existing principal with the same email and links it.
	if resp := sync("create", GlobalIdentity{Email: "KIM@example.com", DisplayName: "Kim"}); resp.Status != "synced" || resp.LocalPrincipalID != existing.ID {
		t.Fatalf("create = %+v, want synced to %s", resp, existing.ID)
	}

	// update resolves through the federation link, not the email.
	if resp := sync("update", GlobalIdentity{Email: "kim.new@example.com", DisplayName: "Kim N", Status: "active"}); resp.Status != "synced" || resp.LocalPrincipalID != existing.ID {
		t.Fatalf("update = %+v", resp)
	}
	got, err := s.GetHuman(ctx, existing.ID)
	if err != nil {
		t.Fatalf("GetHuman: %v", err)
	}
	if got.Email != "kim.new@example.com" || got.DisplayName != "Kim N" || !got.Active {
		t.Errorf("after update = %+v", got)
	}

	// delete deactivates.
	if resp := sync("delete", GlobalIdentity{}); resp.Status != "synced" {
		t.Fatalf("delete = %+v", resp)
	}
	if got, err := s.GetHuman(ctx, existing.ID); err != nil || got.Active {
		t.Errorf("after delete = %+v, %v; want inactive", got, err)
	}

	// delete of an identity that was never linked is already gone.
	fedID = uuid.New()
	if resp := sync("delete", GlobalIdentity{}); resp.Status != "synced" {
		t.Errorf("delete of unlinked identity = %+v, want synced", resp)
	}
	// update of an unlinked identity fails.
	if resp := sync("update", GlobalIdentity{Email: "nobody@example.com"}); resp.Status != "failed" {
		t.Errorf("update of unlinked identity = %+v, want failed", resp)
	}
}
