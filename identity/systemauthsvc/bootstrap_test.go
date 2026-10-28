package systemauthsvc_test

import (
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent/oauthapp"
	"github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/systemauth"
	"github.com/plexusone/systemforge/identity/systemauthsvc"
)

// TestStaticClientsOwnedBySystemServicePrincipal verifies that statically
// configured clients are owned by a service principal and that repeated
// starts reuse the same principal.
func TestStaticClientsOwnedBySystemServicePrincipal(t *testing.T) {
	dbCfg := &systemauth.DatabaseConfig{Driver: "sqlite", DSN: sqliteDSN(t)}
	cfg := &systemauthsvc.Config{
		Issuer:   "https://auth.example.com",
		Tokens:   prodTokens,
		DPoP:     prodDPoP,
		Database: dbCfg,
		Clients: []systemauth.ClientConfig{{
			ID: "web", Type: "public", Name: "Web",
			RedirectURIs:  []string{"https://app.example.com/callback"},
			GrantTypes:    []string{"authorization_code"},
			ResponseTypes: []string{"code"},
			Scopes:        []string{"openid"},
		}},
	}
	opts := systemauthsvc.Options{SigningKey: testKey(t), Logger: discardLogger(), Migrate: true}

	for i := range 2 {
		s, err := systemauthsvc.New(t.Context(), cfg, opts)
		if err != nil {
			t.Fatalf("start %d: %v", i+1, err)
		}
		if err := s.Close(); err != nil {
			t.Fatalf("close %d: %v", i+1, err)
		}
	}

	db, err := systemauthsvc.OpenDatabase(dbCfg)
	if err != nil {
		t.Fatalf("OpenDatabase: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	})
	ctx := t.Context()

	wantID := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	p, err := db.Client.Principal.Query().
		Where(principal.IDEQ(wantID)).
		WithServicePrincipal().
		Only(ctx)
	if err != nil {
		t.Fatalf("system principal: %v", err)
	}
	if p.Type != principal.TypeService {
		t.Errorf("system principal type = %q, want %q", p.Type, principal.TypeService)
	}
	if p.Edges.ServicePrincipal == nil {
		t.Error("system principal has no service extension")
	}

	n, err := db.Client.Principal.Query().
		Where(principal.TypeEQ(principal.TypeService)).
		Count(ctx)
	if err != nil {
		t.Fatalf("count service principals: %v", err)
	}
	if n != 1 {
		t.Errorf("service principals after two starts = %d, want 1", n)
	}

	app, err := db.Client.OAuthApp.Query().
		Where(oauthapp.ClientIDEQ("web")).
		WithOwner().
		Only(ctx)
	if err != nil {
		t.Fatalf("static client: %v", err)
	}
	if app.Edges.Owner == nil || app.Edges.Owner.ID != wantID {
		t.Errorf("static client owner = %v, want principal %s", app.Edges.Owner, wantID)
	}
}
