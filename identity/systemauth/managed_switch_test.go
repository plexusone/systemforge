package systemauth

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent/enttest"
)

func managedClient(id string, managed bool) ClientConfig {
	return ClientConfig{
		ID: id, Type: "public", Name: id,
		RedirectURIs:      []string{testRPCB},
		GrantTypes:        []string{"authorization_code"},
		ResponseTypes:     []string{"code"},
		Scopes:            []string{"openid"},
		ManagedPrincipals: managed,
	}
}

// TestManagedPrincipalsAllowedRequiresBothSwitches verifies that managed
// principals are allowed only when the deployment and the client both opt
// in, and are off by default.
func TestManagedPrincipalsAllowedRequiresBothSwitches(t *testing.T) {
	ctx := context.Background()
	clients := []ClientConfig{managedClient("learning", true), managedClient("ordinary", false)}

	off, err := NewEmbedded(Config{Issuer: testIssuer, Clients: clients})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	if ok, err := off.ManagedPrincipalsAllowed(ctx, "learning"); err != nil || ok {
		t.Errorf("deployment off, client on = %v, %v; want false", ok, err)
	}

	on, err := NewEmbedded(Config{Issuer: testIssuer, Clients: clients, ManagedPrincipals: &ManagedPrincipalsConfig{Enabled: true}})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	for _, tc := range []struct {
		client string
		want   bool
	}{
		{"learning", true},
		{"ordinary", false},
		{"unknown", false},
	} {
		if ok, err := on.ManagedPrincipalsAllowed(ctx, tc.client); err != nil || ok != tc.want {
			t.Errorf("deployment on, client %q = %v, %v; want %v", tc.client, ok, err, tc.want)
		}
	}
}

// TestClientManagedPrincipalsFlagPersists verifies that the per-client
// switch round-trips through Ent storage and defaults to off.
func TestClientManagedPrincipalsFlagPersists(t *testing.T) {
	ctx := context.Background()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	s := NewEntStorage(db, WithDefaultOwner(createTestOwner(t, db)))

	c, err := NewClientFromConfig(managedClient("learning", true))
	if err != nil {
		t.Fatalf("NewClientFromConfig: %v", err)
	}
	if err := s.CreateClient(ctx, c); err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	got, err := s.GetClientByID(ctx, "learning")
	if err != nil || !got.ManagedPrincipalsEnabled {
		t.Fatalf("stored flag = %+v, %v; want enabled", got, err)
	}

	got.ManagedPrincipalsEnabled = false
	if err := s.UpdateClient(ctx, got); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}
	if got, err := s.GetClientByID(ctx, "learning"); err != nil || got.ManagedPrincipalsEnabled {
		t.Errorf("flag after disabling = %+v, %v; want disabled", got, err)
	}

	plain, err := NewClientFromConfig(managedClient("ordinary", false))
	if err != nil {
		t.Fatalf("NewClientFromConfig: %v", err)
	}
	if err := s.CreateClient(ctx, plain); err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	if got, err := s.GetClientByID(ctx, "ordinary"); err != nil || got.ManagedPrincipalsEnabled {
		t.Errorf("default flag = %+v, %v; want disabled", got, err)
	}
}
