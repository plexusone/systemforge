package systemauthsvc_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/grokify/goauth/dpop"
	"golang.org/x/oauth2"

	entprincipal "github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/managedprincipal"
	"github.com/plexusone/systemforge/identity/managedprincipal/mpclient"
	"github.com/plexusone/systemforge/identity/relyingparty"
	"github.com/plexusone/systemforge/identity/systemauth"
	"github.com/plexusone/systemforge/identity/systemauthsvc"
)

const (
	mpIssuer   = "https://auth.example.test"
	mpCallback = "https://app.example.test/auth/callback"
)

// handlerTransport serves every request with h, standing in for a network.
type handlerTransport struct{ h http.Handler }

func (t handlerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	t.h.ServeHTTP(w, r)
	return w.Result(), nil
}

func managedPrincipalsService(t *testing.T, enabled bool, scopes ...string) *systemauthsvc.Service {
	t.Helper()
	return newManagedPrincipalsService(t, enabled, systemauth.DPoPConfig{}, scopes...)
}

func newManagedPrincipalsService(t *testing.T, enabled bool, dpopCfg systemauth.DPoPConfig, scopes ...string) *systemauthsvc.Service {
	t.Helper()
	cfg := &systemauthsvc.Config{
		Issuer:   mpIssuer,
		Database: &systemauth.DatabaseConfig{Driver: "sqlite", DSN: sqliteDSN(t)},
		Clients: []systemauth.ClientConfig{{
			ID: "app", Type: "public", Name: "App",
			RedirectURIs:      []string{mpCallback},
			GrantTypes:        []string{"authorization_code", "refresh_token"},
			ResponseTypes:     []string{"code"},
			Scopes:            append([]string{"openid", "profile", "email"}, scopes...),
			ManagedPrincipals: true,
		}},
		Features: systemauth.FeatureConfig{RequirePKCE: true},
		DPoP:     dpopCfg,
	}
	if enabled {
		cfg.ManagedPrincipals = &systemauth.ManagedPrincipalsConfig{Enabled: true}
		// Login is the test header session; consent is not under test.
		// Browser login, here for login tokens, takes the setting.
		cfg.SocialLogin = &systemauth.SocialLoginConfig{}
	}
	svc, err := systemauthsvc.New(t.Context(), cfg, systemauthsvc.Options{
		Dev:           true,
		SigningKey:    testKey(t),
		Logger:        discardLogger(),
		Migrate:       true,
		ServerOptions: []systemauth.Option{systemauth.WithSessionProvider(headerSession{})},
	})
	if err != nil {
		t.Fatal(err)
	}
	closeService(t, svc)
	return svc
}

// addManager creates an active human with an email, able to manage.
func addManager(t *testing.T, svc *systemauthsvc.Service, email string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	id := uuid.New()
	db := svc.EntClient()
	if _, err := db.Principal.Create().SetID(id).SetType(entprincipal.TypeHuman).
		SetIdentifier(email).SetDisplayName("Manager").SetActive(true).Save(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Human.Create().SetPrincipalID(id).SetEmail(email).Save(ctx); err != nil {
		t.Fatal(err)
	}
	return id
}

// mpDPoP is the DPoP key the test relying party binds its tokens to.
var mpDPoP = sync.OnceValues(dpop.GenerateKeyPair)

func mpDPoPKey(t *testing.T) *dpop.KeyPair {
	t.Helper()
	kp, err := mpDPoP()
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

// accessToken signs principal in to the app client and returns its access
// token for scopes.
func accessToken(t *testing.T, svc *systemauthsvc.Service, principal uuid.UUID, scopes ...string) string {
	t.Helper()
	_, token := relyingPartySignIn(t, svc, principal, scopes...)
	return token
}

// relyingPartySignIn signs principal in to the app client and returns the
// relying party and its access token for scopes.
func relyingPartySignIn(t *testing.T, svc *systemauthsvc.Service, principal uuid.UUID, scopes ...string) (*relyingparty.Client, string) {
	t.Helper()
	hc := &http.Client{
		Transport:     handlerTransport{svc.Handler()},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	rp, err := relyingparty.NewClientWithMetadata(relyingparty.Config{
		Issuer: mpIssuer, ClientID: "app", RedirectURL: mpCallback, HTTPClient: hc,
		Scopes: append([]string{"openid"}, scopes...), DPoPKey: mpDPoPKey(t),
	}, svc.Metadata())
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	verifier := oauth2.GenerateVerifier()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rp.AuthCodeURL("state-123456", "nonce-123456", verifier), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Test-User", principal.String())
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	cb, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || cb.Query().Get("code") == "" {
		t.Fatalf("authorize: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	tok, err := rp.Exchange(ctx, cb.Query().Get("code"), verifier)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	return rp, tok.AccessToken
}

func callAPI(t *testing.T, svc *systemauthsvc.Service, token, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	r := httptest.NewRequest(method, mpIssuer+path, &buf)
	if token != "" {
		// The token is bound to the test DPoP key: present it with a proof.
		proof, err := dpop.CreateProofWithOptions(mpDPoPKey(t), method, mpIssuer+path, dpop.ProofOptions{AccessToken: token})
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Authorization", "DPoP "+token)
		r.Header.Set("DPoP", proof)
	}
	w := httptest.NewRecorder()
	svc.Handler().ServeHTTP(w, r)
	return w
}

// TestManagedPrincipalsAPIEndToEnd creates a managed principal with a
// manager's access token, issues it a login token, and signs it in with
// that token, as a relying party in another process would.
func TestManagedPrincipalsAPIEndToEnd(t *testing.T) {
	svc := managedPrincipalsService(t, true, managedprincipal.Scope)
	if svc.ManagedPrincipals() == nil {
		t.Fatal("managed principals not enabled")
	}
	teacher := addManager(t, svc, "teacher@example.com")
	token := accessToken(t, svc, teacher, managedprincipal.Scope)

	w := callAPI(t, svc, token, http.MethodPost, systemauthsvc.ManagedPrincipalsPath+"/", managedprincipal.CreateRequest{
		DisplayName: "Robin",
		Managers:    []managedprincipal.ManagerView{{PrincipalID: teacher, Role: managedprincipal.RoleEducator}},
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control %q", w.Header().Get("Cache-Control"))
	}
	var created struct {
		ID uuid.UUID `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	w = callAPI(t, svc, token, http.MethodGet, systemauthsvc.ManagedPrincipalsPath, nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), created.ID.String()) {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}

	w = callAPI(t, svc, token, http.MethodPost, systemauthsvc.ManagedPrincipalsPath+"/"+created.ID.String()+"/login-tokens",
		managedprincipal.IssueLoginTokenRequest{SingleUse: true})
	if w.Code != http.StatusCreated {
		t.Fatalf("issue login token: %d %s", w.Code, w.Body)
	}
	var issued managedprincipal.IssuedLoginToken
	if err := json.Unmarshal(w.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}

	exchange := func() *httptest.ResponseRecorder {
		form := url.Values{"token": {issued.Token}, "client_id": {"app"}}
		r := httptest.NewRequest(http.MethodPost, mpIssuer+systemauth.LoginTokenPath, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", mpIssuer)
		w := httptest.NewRecorder()
		svc.Handler().ServeHTTP(w, r)
		return w
	}
	if w := exchange(); w.Code != http.StatusSeeOther || len(w.Result().Cookies()) == 0 {
		t.Fatalf("login token exchange: %d %s", w.Code, w.Body)
	}
	if w := exchange(); w.Code != http.StatusUnauthorized {
		t.Fatalf("single-use token reused: %d", w.Code)
	}
}

func TestManagedPrincipalsAPIAuthorization(t *testing.T) {
	svc := managedPrincipalsService(t, true, managedprincipal.Scope)
	teacher := addManager(t, svc, "teacher@example.com")
	path := systemauthsvc.ManagedPrincipalsPath

	w := callAPI(t, svc, "", http.MethodGet, path, nil)
	if w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("no token: %d %q", w.Code, w.Header().Get("WWW-Authenticate"))
	}
	if w := callAPI(t, svc, "not-a-token", http.MethodGet, path, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("unknown token: %d", w.Code)
	}
	// A token without the scope is refused before any operation.
	plain := accessToken(t, svc, teacher, "profile")
	w = callAPI(t, svc, plain, http.MethodGet, path, nil)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Header().Get("WWW-Authenticate"), "insufficient_scope") {
		t.Fatalf("missing scope: %d %q", w.Code, w.Header().Get("WWW-Authenticate"))
	}
}

func TestManagedPrincipalsAPIIsOffByDefault(t *testing.T) {
	svc := managedPrincipalsService(t, false)
	if svc.ManagedPrincipals() != nil {
		t.Fatal("managed principals enabled without configuration")
	}
	for _, p := range []string{systemauthsvc.ManagedPrincipalsPath, systemauthsvc.ManagedPrincipalsPath + "/x/login-tokens"} {
		if w := callAPI(t, svc, "", http.MethodGet, p, nil); w.Code != http.StatusNotFound {
			t.Errorf("%s: %d", p, w.Code)
		}
	}
	form := url.Values{"token": {"SFLTX"}, "client_id": {"app"}}
	r := httptest.NewRequest(http.MethodPost, mpIssuer+systemauth.LoginTokenPath, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", mpIssuer)
	w := httptest.NewRecorder()
	svc.Handler().ServeHTTP(w, r)
	if w.Code == http.StatusSeeOther || w.Code == http.StatusUnauthorized {
		t.Errorf("login token endpoint served without managed principals: %d", w.Code)
	}
}

// TestManagedPrincipalsAPIThroughTheRelyingParty calls the API with mpclient
// and a session's DPoP-bound token, as an application does for the person
// signed in to it: mpclient sends the token as Bearer, which SystemAuth
// refuses for a bound token, and the relying party's Transport presents it
// with a proof instead, also when SystemAuth requires nonces.
func TestManagedPrincipalsAPIThroughTheRelyingParty(t *testing.T) {
	for name, dpopCfg := range map[string]systemauth.DPoPConfig{
		"without nonces": {},
		"with nonces":    {RequireNonce: true, NonceSecret: strings.Repeat("n", 32)},
	} {
		t.Run(name, func(t *testing.T) {
			svc := newManagedPrincipalsService(t, true, dpopCfg, managedprincipal.Scope)
			teacher := addManager(t, svc, "teacher@example.com")
			rp, token := relyingPartySignIn(t, svc, teacher, managedprincipal.Scope)
			ctx := t.Context()
			network := handlerTransport{svc.Handler()}
			api := mpIssuer + systemauthsvc.ManagedPrincipalsPath

			// Sent as mpclient sends it, the bound token is refused.
			plain := mpclient.New(api, &http.Client{Transport: network})
			if _, err := plain.List(ctx, token, uuid.Nil, 10); !errors.Is(err, mpclient.ErrUnauthorized) {
				t.Fatalf("a bound token as Bearer: %v", err)
			}

			mp := mpclient.New(api, &http.Client{Transport: rp.Transport(network)})
			id, err := mp.Create(ctx, token, mpclient.CreateInput{DisplayName: "Robin", Role: mpclient.RoleEducator})
			if err != nil {
				t.Fatalf("create: %v", err)
			}
			list, err := mp.List(ctx, token, uuid.Nil, 10)
			if err != nil || len(list) != 1 || list[0].PrincipalID != id {
				t.Fatalf("list: %+v %v", list, err)
			}
			if _, err := mp.IssueLoginToken(ctx, token, id, mpclient.IssueLoginTokenInput{SingleUse: true}); err != nil {
				t.Fatalf("issue login token: %v", err)
			}
		})
	}
}
