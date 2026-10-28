package serviceaccountcmd_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plexusone/systemforge/identity/appauth"
	"github.com/plexusone/systemforge/identity/relyingparty"
	"github.com/plexusone/systemforge/identity/requestprincipal"
	"github.com/plexusone/systemforge/identity/serviceclient"
	"github.com/plexusone/systemforge/identity/systemauth"
)

// whoami is what the application's API answers: who called and the roles
// it holds in the application.
type whoami struct {
	Type  string            `json:"type"`
	Roles map[string]string `json:"roles"` // organization ID -> billing role
}

// TestServiceAccountEndToEnd sets up a service account with the commands,
// calls an application's API with serviceclient, and sees access follow the
// account's role and state.
func TestServiceAccountEndToEnd(t *testing.T) {
	w := newWorld(t)

	var sa *systemauth.Server
	saSrv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) { sa.ServeHTTP(rw, r) }))
	t.Cleanup(saSrv.Close)
	var err error
	sa, err = systemauth.NewEmbedded(systemauth.Config{
		Issuer:   saSrv.URL,
		Features: systemauth.FeatureConfig{EnableJWTAccessTokens: true},
		OAuth:    systemauth.OAuthConfig{JWTBearer: systemauth.JWTBearerConfig{Enabled: true}},
	},
		systemauth.WithStorage(systemauth.NewEntStorage(w.db, systemauth.WithDefaultOwner(w.owner))),
		systemauth.WithOrgsSource(systemauth.NewEntOrgsSource(w.db, w.roles)),
	)
	if err != nil {
		t.Fatal(err)
	}

	// The application: an API that accepts service accounts and keeps the
	// organizations where the caller holds a billing role.
	mux := http.NewServeMux()
	app := httptest.NewServer(mux)
	t.Cleanup(app.Close)
	auth, err := appauth.New(t.Context(), appauth.Config{
		Issuer: saSrv.URL, ClientID: "billing-app", PublicURL: app.URL, DPoPKey: dpopKeyPEM(t),
	}, appauth.Options{
		Principals: relyingparty.NewMemoryPrincipalStore(), ServiceAccounts: true, Application: "billing",
	})
	if err != nil {
		t.Fatal(err)
	}
	mux.Handle("/api/whoami", auth.Middleware(true)(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		p, ok := requestprincipal.FromContext(r.Context())
		if !ok {
			http.Error(rw, "no principal", http.StatusInternalServerError)
			return
		}
		out := whoami{Type: string(p.Type), Roles: map[string]string{}}
		if native, ok := p.Native.(*relyingparty.AuthenticatedPrincipal); ok {
			for _, m := range native.Memberships {
				out.Roles[m.OrganizationID] = m.Applications["billing"]
			}
		}
		if err := json.NewEncoder(rw).Encode(out); err != nil {
			t.Error(err)
		}
	})))

	// The operator: three commands.
	account := w.newAccount()
	w.mustRun("role", "grant", account, "--app", "billing", "--role", "viewer")
	keyID, keyFile := w.addKey(account)

	// The workload: a key file and three values.
	call := func() (int, whoami) {
		t.Helper()
		key, err := serviceclient.LoadPrivateKey(keyFile)
		if err != nil {
			t.Fatal(err)
		}
		c, err := serviceclient.New(t.Context(), serviceclient.Config{Issuer: saSrv.URL, Account: account, KeyID: keyID, PrivateKey: key})
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, app.URL+"/api/whoami", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := c.HTTPClient().Do(req)
		if err != nil {
			return 0, whoami{} // the token exchange was refused
		}
		defer func() {
			if err := resp.Body.Close(); err != nil {
				t.Error(err)
			}
		}()
		var who whoami
		if resp.StatusCode == http.StatusOK {
			if err := json.NewDecoder(resp.Body).Decode(&who); err != nil {
				t.Fatal(err)
			}
		}
		return resp.StatusCode, who
	}

	code, who := call()
	if code != http.StatusOK || who.Type != "service" || len(who.Roles) != 1 {
		t.Fatalf("with a viewer role: %d %+v", code, who)
	}
	for _, role := range who.Roles {
		if role != "viewer" {
			t.Errorf("role %q, want viewer", role)
		}
	}

	// Without the role, the next token carries no billing organization.
	w.mustRun("role", "remove", account, "--app", "billing")
	if code, who := call(); code != http.StatusOK || len(who.Roles) != 0 {
		t.Errorf("after removing the role: %d %+v", code, who)
	}

	// A disabled account gets no token at all.
	w.mustRun("disable", account)
	if code, _ := call(); code != 0 {
		t.Errorf("disabled account: %d", code)
	}

	// Tokens were issued to the account; deleting it still succeeds, since
	// issued tokens name their subject without a foreign key.
	w.mustRun("delete", account)
	if _, err := w.run("show", account); err == nil {
		t.Error("deleted account still shown")
	}
}

func dpopKeyPEM(t *testing.T) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}
