package systemauth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/credential"
	"github.com/plexusone/systemforge/identity/ent/enttest"
)

// TestLoginTokenPolicy verifies that the deployment's login token
// settings apply, defaults fill unset ones, and a client's own default
// lifetime replaces the deployment's.
func TestLoginTokenPolicy(t *testing.T) {
	ctx := context.Background()
	schoolYear := Duration(300 * 24 * time.Hour)
	learning := managedClient("learning", true)
	learning.LoginTokenTTL = &schoolYear
	clients := []ClientConfig{learning, managedClient("ordinary", true)}

	srv, err := NewEmbedded(Config{
		Issuer:            testIssuer,
		Clients:           clients,
		ManagedPrincipals: &ManagedPrincipalsConfig{Enabled: true, SingleUseTokenTTL: Duration(time.Hour)},
	})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}

	got, err := srv.LoginTokenPolicy(ctx, "ordinary")
	if err != nil {
		t.Fatalf("LoginTokenPolicy: %v", err)
	}
	want := credential.LoginTokenPolicy{
		DefaultTTL:   credential.DefaultLoginTokenTTL,
		MaxTTL:       credential.DefaultLoginTokenMaxTTL,
		SingleUseTTL: time.Hour,
	}
	if got != want {
		t.Errorf("ordinary policy = %+v, want %+v", got, want)
	}

	got, err = srv.LoginTokenPolicy(ctx, "learning")
	if err != nil {
		t.Fatalf("LoginTokenPolicy: %v", err)
	}
	want.DefaultTTL = schoolYear.Duration()
	if got != want {
		t.Errorf("learning policy = %+v, want %+v", got, want)
	}

	if _, err := srv.LoginTokenPolicy(ctx, "unknown"); !errors.Is(err, ErrClientNotFound) {
		t.Errorf("unknown client error = %v, want ErrClientNotFound", err)
	}
}

// TestClientLoginTokenTTLPersists verifies that a client's login token
// lifetime round-trips through Ent storage and can be cleared.
func TestClientLoginTokenTTLPersists(t *testing.T) {
	ctx := context.Background()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	s := NewEntStorage(db, WithDefaultOwner(createTestOwner(t, db)))

	ttl := Duration(90 * 24 * time.Hour)
	cfg := managedClient("learning", true)
	cfg.LoginTokenTTL = &ttl
	c, err := NewClientFromConfig(cfg)
	if err != nil {
		t.Fatalf("NewClientFromConfig: %v", err)
	}
	if err := s.CreateClient(ctx, c); err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	got, err := s.GetClientByID(ctx, "learning")
	if err != nil {
		t.Fatalf("GetClientByID: %v", err)
	}
	if got.LoginTokenTTL == nil || *got.LoginTokenTTL != ttl.Duration() {
		t.Fatalf("stored TTL = %v, want %v", got.LoginTokenTTL, ttl.Duration())
	}

	got.LoginTokenTTL = nil
	if err := s.UpdateClient(ctx, got); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}
	if got, err := s.GetClientByID(ctx, "learning"); err != nil || got.LoginTokenTTL != nil {
		t.Errorf("TTL after clearing = %v, %v; want nil", got.LoginTokenTTL, err)
	}
}
