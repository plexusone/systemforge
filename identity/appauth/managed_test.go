package appauth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/appauth"
	entprincipal "github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/managedprincipal"
	"github.com/plexusone/systemforge/identity/managedprincipal/mpclient"
	"github.com/plexusone/systemforge/identity/relyingparty"
	"github.com/plexusone/systemforge/identity/systemauth"
	"github.com/plexusone/systemforge/identity/systemauthsvc"
)

// newManagedEnv is newEnv over a packaged SystemAuth (systemauthsvc) with
// a database and managed principals enabled, so the application can call
// the managed-principal API. SystemAuth requires DPoP nonces, and the
// application asks for managedprincipal.Scope at sign-in.
func newManagedEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, mux: http.NewServeMux()}
	var handler http.Handler
	saSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(saSrv.Close)
	e.app = httptest.NewServer(e.mux)
	t.Cleanup(e.app.Close)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := systemauthsvc.New(t.Context(), &systemauthsvc.Config{
		Issuer:   saSrv.URL,
		Database: &systemauth.DatabaseConfig{Driver: "sqlite", DSN: "file:" + filepath.Join(t.TempDir(), "systemauth.db") + "?_fk=1"},
		Clients: []systemauth.ClientConfig{{
			ID: "app", Secret: clientSecret, Type: "confidential", Name: "App",
			RedirectURIs:      []string{e.app.URL + "/bff/auth/callback"},
			GrantTypes:        []string{"authorization_code", "refresh_token"},
			ResponseTypes:     []string{"code"},
			Scopes:            []string{"openid", "profile", "email", "offline_access", managedprincipal.Scope},
			ManagedPrincipals: true,
		}},
		Features:          systemauth.FeatureConfig{RequirePKCE: true, EnableJWTAccessTokens: true},
		DPoP:              systemauth.DPoPConfig{RequireNonce: true, NonceSecret: strings.Repeat("s", 32)},
		ManagedPrincipals: &systemauth.ManagedPrincipalsConfig{Enabled: true},
	}, systemauthsvc.Options{
		Dev: true, SigningKey: key, Migrate: true,
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		ServerOptions: []systemauth.Option{systemauth.WithSessionProvider(headerSession{})},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := svc.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	handler = svc.Handler()

	// The manager: a person with an account.
	manager := uuid.New()
	db := svc.EntClient()
	if _, err := db.Principal.Create().SetID(manager).SetType(entprincipal.TypeHuman).
		SetIdentifier("dev@example.com").SetDisplayName("Dev").SetActive(true).Save(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Human.Create().SetPrincipalID(manager).SetEmail("dev@example.com").SetEmailVerifiedAt(time.Now()).Save(t.Context()); err != nil {
		t.Fatal(err)
	}

	e.issuer, e.user = saSrv.URL, manager.String()
	e.cfg = appauth.Config{
		Issuer: saSrv.URL, ClientID: "app", ClientSecret: clientSecret,
		PublicURL: e.app.URL, DPoPKey: newKeyPEM(t),
		Scopes: []string{managedprincipal.Scope},
	}
	e.principals = relyingparty.NewMemoryPrincipalStore()
	e.sessions = relyingparty.NewMemorySessionStore()
	e.states = relyingparty.NewMemoryLoginStateStore()
	e.auth = e.newAuth(t)
	e.mux.Handle("/bff/", e.auth.Handler())
	return e
}

// The application creates a managed principal for the signed-in person
// through the managed-principal API, with the session's token presented
// by Transport; without Transport the bound token is refused.
func TestCreateManagedPrincipalThroughTransport(t *testing.T) {
	e := newManagedEnv(t)
	cookie := e.signIn()
	ctx := context.Background()
	tok, err := e.auth.SessionToken(e.request(http.MethodGet, "/api/me", withCookie(cookie)))
	if err != nil {
		t.Fatal(err)
	}
	api := e.issuer + systemauthsvc.ManagedPrincipalsPath

	mp := mpclient.New(api, &http.Client{Transport: e.auth.Transport(nil)})
	id, err := mp.Create(ctx, tok, mpclient.CreateInput{DisplayName: "Kid", Role: mpclient.RoleGuardian})
	if err != nil {
		t.Fatalf("create through Transport: %v", err)
	}
	list, err := mp.List(ctx, tok, uuid.Nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].PrincipalID != id || list[0].DisplayName != "Kid" {
		t.Fatalf("managed principals = %+v, want the one created", list)
	}

	// The same token without proofs is refused.
	plain := mpclient.New(api, http.DefaultClient)
	if _, err := plain.Create(ctx, tok, mpclient.CreateInput{DisplayName: "Other", Role: mpclient.RoleGuardian}); !errors.Is(err, mpclient.ErrUnauthorized) {
		t.Fatalf("create without Transport: %v, want ErrUnauthorized", err)
	}
}
