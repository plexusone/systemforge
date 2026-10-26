package systemauthsvc_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	cf "github.com/plexusone/connectforge"
	"github.com/plexusone/connectforge/provider"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/connections"
	"github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/organization"
	"github.com/plexusone/systemforge/identity/systemauth"
	"github.com/plexusone/systemforge/identity/systemauthsvc"
	"github.com/plexusone/systemforge/keys"
)

const rootKeyEnv = "SF_TEST_CONNECTIONS_ROOT_KEY"

func connectionsConfig(t *testing.T) *systemauthsvc.Config {
	t.Helper()
	t.Setenv(rootKeyEnv, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	return &systemauthsvc.Config{
		Issuer:   "https://auth.example.com",
		Database: &systemauth.DatabaseConfig{Driver: "sqlite", DSN: sqliteDSN(t)},
		Connections: &systemauth.ConnectionsConfig{
			KeysDir: filepath.Join(t.TempDir(), "keys"),
			Vault:   "env://",
			RootKey: rootKeyEnv,
		},
	}
}

func TestConnectionsAreServedWhenConfigured(t *testing.T) {
	cfg := connectionsConfig(t)
	if err := systemauthsvc.Migrate(t.Context(), cfg); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	s, err := systemauthsvc.New(t.Context(), cfg, systemauthsvc.Options{
		SigningKey: testKey(t), Logger: discardLogger(), Migrate: true, Providers: provider.NewRegistry(),
	})
	if err != nil {
		t.Fatal(err)
	}
	closeService(t, s)
	if s.Connections() == nil || s.Connections().Broker == nil {
		t.Fatal("connections not enabled")
	}

	org := "/api/v1/organizations/00000000-0000-0000-0000-000000000001/connections"
	for _, rt := range [][2]string{
		{http.MethodGet, connections.ProvidersPath},
		{http.MethodGet, org},
		{http.MethodPost, org + "/x/test"},
		{http.MethodDelete, org + "/x"},
	} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest(rt[0], rt[1], nil))
		if w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") == "" {
			t.Errorf("%s %s without a token: %d", rt[0], rt[1], w.Code)
		}
	}

	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.RunJobs(ctx) }()
	select {
	case err := <-done:
		// Ending the context is how RunJobs is stopped, so its context
		// error is the expected result; anything else is a failure.
		if err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
			t.Fatalf("RunJobs: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunJobs did not stop when its context ended")
	}
}

func TestConnectionsAreOffByDefault(t *testing.T) {
	s, err := systemauthsvc.New(t.Context(), &systemauthsvc.Config{Issuer: "https://auth.example.com"},
		systemauthsvc.Options{Dev: true, Logger: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	closeService(t, s)
	if s.Connections() != nil {
		t.Fatal("connections enabled without configuration")
	}
	if err := s.RunJobs(t.Context()); err != nil {
		t.Fatalf("RunJobs with nothing to run: %v", err)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, connections.ProvidersPath, nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("providers route without connections: %d", w.Code)
	}
}

func TestConnectionsConfigErrors(t *testing.T) {
	opts := systemauthsvc.Options{SigningKey: testKey(t), Logger: discardLogger(), Migrate: true}

	cfg := connectionsConfig(t)
	cfg.Connections.RootKey = ""
	if _, err := systemauthsvc.New(t.Context(), cfg, opts); err == nil {
		t.Error("missing root_key accepted")
	}

	cfg = connectionsConfig(t)
	cfg.Connections.RootKey = "SF_TEST_UNSET_ROOT_KEY"
	if _, err := systemauthsvc.New(t.Context(), cfg, opts); err == nil {
		t.Error("unset root key accepted")
	}

	cfg = connectionsConfig(t)
	cfg.Authz = authz.ModeConfig{Mode: authz.ModeReBAC, Engine: authz.EngineSpiceDB}
	if _, err := systemauthsvc.New(t.Context(), cfg, opts); err == nil {
		t.Error("connections with rebac accepted")
	}

	// A file vault that would keep the root key inside the keys directory,
	// where a backup of the keyring would carry it too.
	cfg = connectionsConfig(t)
	cfg.Connections.Vault = "file://" + cfg.Connections.KeysDir
	cfg.Connections.RootKey = "root"
	if _, err := systemauthsvc.New(t.Context(), cfg, opts); !errors.Is(err, keys.ErrRootKeyInKeysDir) {
		t.Errorf("root key in the keys directory: err = %v", err)
	}

	cfg = connectionsConfig(t)
	cfg.Database = nil
	if _, err := systemauthsvc.New(t.Context(), cfg, systemauthsvc.Options{Dev: true, Logger: discardLogger()}); err == nil {
		t.Error("connections without a database accepted")
	}
}

// TestConnectionGrantsComposeWithTheAuthorizer checks the whole path with the
// real grant service and role-based provider: a member may only view a
// connection until a contributor grant lets them use it, and revoking the
// grant takes that back.
func TestConnectionGrantsComposeWithTheAuthorizer(t *testing.T) {
	ctx := t.Context()
	cfg := connectionsConfig(t)
	if err := systemauthsvc.Migrate(ctx, cfg); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	vocab := authz.NewVocabularyRegistry()
	s, err := systemauthsvc.New(ctx, cfg, systemauthsvc.Options{
		SigningKey: testKey(t), Logger: discardLogger(), Migrate: true, Vocabularies: vocab,
	})
	if err != nil {
		t.Fatal(err)
	}
	closeService(t, s)
	conns := s.Connections()
	if conns == nil || conns.Grants == nil {
		t.Fatal("connections or the grant service are missing")
	}
	if _, ok := vocab.Get(connections.App); !ok {
		t.Fatal("the connections vocabulary was not registered")
	}

	db := s.EntClient()
	person := func() uuid.UUID {
		p, err := db.Principal.Create().SetType(principal.TypeHuman).
			SetIdentifier(uuid.NewString() + "@example.com").SetDisplayName("P").Save(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return p.ID
	}
	owner, member := person(), person()
	orgs := organization.NewService(db)
	org, err := orgs.Create(ctx, organization.CreateOrganizationInput{
		Name: "Org", Slug: "org-" + uuid.NewString()[:8], OrgType: organization.OrgTypeTeam, OwnerPrincipalID: &owner,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.PrincipalMembership.Create().SetPrincipalID(member).SetOrganizationID(org.ID).
		SetRole("member").Save(ctx); err != nil {
		t.Fatal(err)
	}

	connID := uuid.New()
	conn := cf.Connection{ID: connID.String(), Owner: connections.OwnerFor(org.ID), Revision: 1}
	who := cf.Principal{Kind: cf.PrincipalUser, ID: member.String()}
	allowed := func(a cf.Action) bool {
		t.Helper()
		err := conns.Authorizer.Allowed(ctx, who, a, conn)
		switch {
		case err == nil:
			return true
		case errors.Is(err, cf.ErrDenied):
			return false
		}
		t.Fatalf("authorize %s: %v", a, err)
		return false
	}
	if !allowed(cf.ActionView) || allowed(cf.ActionUse) || allowed(cf.ActionManage) {
		t.Fatal("a member should only view a connection before any grant")
	}

	ref := authz.ResourceRef{Type: string(connections.ResourceType), ID: connID.String(), OrganizationID: org.ID}
	if err := conns.Grants.GrantResourceRole(ctx, member, ref, "contributor", owner); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if !allowed(cf.ActionUse) || allowed(cf.ActionManage) {
		t.Fatal("a contributor grant should allow use, not manage")
	}
	if err := conns.Grants.GrantResourceRole(ctx, member, ref, "maintainer", owner); err != nil {
		t.Fatal(err)
	}
	if !allowed(cf.ActionManage) || !allowed(cf.ActionShare) {
		t.Fatal("a maintainer grant should allow manage and share")
	}
	if err := conns.Grants.RevokeResourceRole(ctx, member, ref); err != nil {
		t.Fatal(err)
	}
	if allowed(cf.ActionUse) {
		t.Fatal("use survived the revoke")
	}

	// A resource type outside a registered application is refused.
	bad := authz.ResourceRef{Type: "unregistered_thing", ID: connID.String(), OrganizationID: org.ID}
	if err := conns.Grants.GrantResourceRole(ctx, member, bad, "viewer", owner); err == nil {
		t.Fatal("a grant on an unregistered application's type was accepted")
	}
}
