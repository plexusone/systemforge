package systemauth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/internal/syncrec"
)

func TestSocialSignupRegistersPrincipalAndOrganizationWithSyncer(t *testing.T) {
	ctx := context.Background()
	db := openTestEnt(t)
	rec := syncrec.New()
	dir := NewEntPrincipalDirectory(db, WithDirectoryAuthzSyncer(rec))

	p, err := ResolveExternalLogin(ctx, dir, ExternalLogin{Provider: "github", Subject: "1", Email: "kim@example.com", EmailVerified: true, Username: "kim"}, time.Now())
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	org := db.Organization.Query().OnlyX(ctx)
	want := []string{
		"RegisterPrincipal:" + p.ID.String(),
		"RegisterOrganization:" + org.ID.String() + ":" + p.ID.String(),
	}
	if got := rec.Calls(); len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("syncer calls = %v, want %v", got, want)
	}

	// A repeat login registers nothing more.
	if _, err := ResolveExternalLogin(ctx, dir, ExternalLogin{Provider: "github", Subject: "1", Email: "kim@example.com", EmailVerified: true, Username: "kim"}, time.Now()); err != nil {
		t.Fatalf("second login: %v", err)
	}
	if got := rec.Calls(); len(got) != 2 {
		t.Errorf("repeat login synced again: %v", got)
	}
}

func TestSocialSignupRollbackRegistersNothing(t *testing.T) {
	ctx := context.Background()
	db := openTestEnt(t)
	seedHuman(t, db, "kim@example.com", false) // unverified: login cannot link, create hits the email conflict
	rec := syncrec.New()
	dir := NewEntPrincipalDirectory(db, WithDirectoryAuthzSyncer(rec))

	_, err := ResolveExternalLogin(ctx, dir, ExternalLogin{Provider: "github", Subject: "9", Email: "kim@example.com", EmailVerified: true, Username: "kim"}, time.Now())
	if err == nil {
		t.Fatal("expected the email conflict")
	}
	if got := rec.Calls(); len(got) != 0 {
		t.Errorf("a rolled-back signup was synced: %v", got)
	}
}

func TestSocialLoginBackfillRegistersOrganization(t *testing.T) {
	ctx := context.Background()
	db := openTestEnt(t)
	rec := syncrec.New()
	dir := NewEntPrincipalDirectory(db, WithDirectoryAuthzSyncer(rec))
	existing := seedHuman(t, db, "old@example.com", true)
	login := ExternalLogin{Provider: "github", Subject: "55", Email: "old@example.com", EmailVerified: true, Username: "oldtimer"}
	if err := dir.LinkExternalIdentity(ctx, existing, login); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveExternalLogin(ctx, dir, login, time.Now()); err != nil {
		t.Fatalf("login: %v", err)
	}
	org := db.Organization.Query().OnlyX(ctx)
	want := "RegisterOrganization:" + org.ID.String() + ":" + existing.String()
	if got := rec.Calls(); len(got) != 1 || got[0] != want {
		t.Errorf("syncer calls = %v, want [%s]", got, want)
	}
}

func TestSocialSignupSyncFailureModes(t *testing.T) {
	ctx := context.Background()
	login := ExternalLogin{Provider: "github", Subject: "1", Email: "kim@example.com", EmailVerified: true, Username: "kim"}

	t.Run("eventual logs and succeeds", func(t *testing.T) {
		db := openTestEnt(t)
		rec := syncrec.New()
		rec.Err = errors.New("authz down")
		dir := NewEntPrincipalDirectory(db, WithDirectoryAuthzSyncer(rec))
		if _, err := ResolveExternalLogin(ctx, dir, login, time.Now()); err != nil {
			t.Fatalf("login: %v", err)
		}
		assertCounts(t, db, 1, 1, 1, 1, 1)
	})

	t.Run("strict reports the failure and keeps the rows", func(t *testing.T) {
		db := openTestEnt(t)
		rec := syncrec.New()
		rec.Err = errors.New("authz down")
		dir := NewEntPrincipalDirectory(db, WithDirectoryAuthzSyncer(rec), WithDirectorySyncMode(authz.SyncModeStrict))
		if _, err := ResolveExternalLogin(ctx, dir, login, time.Now()); err == nil {
			t.Fatal("expected the sync failure")
		}
		assertCounts(t, db, 1, 1, 1, 1, 1)
	})
}
