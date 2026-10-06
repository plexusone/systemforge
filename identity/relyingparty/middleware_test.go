package relyingparty

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/apikey"
)

type fakeAPIKeys map[string]*apikey.APIKey

func (f fakeAPIKeys) Validate(_ context.Context, key string) (*apikey.APIKey, error) {
	k, ok := f[key]
	if !ok {
		return nil, apikey.ErrKeyNotFound
	}
	return k, nil
}

type failingAPIKeys struct{}

func (failingAPIKeys) Validate(context.Context, string) (*apikey.APIKey, error) {
	return nil, errors.New("database down")
}

func runBearer(t *testing.T, cfg BearerConfig, decorate func(*http.Request)) (*httptest.ResponseRecorder, *AuthenticatedPrincipal) {
	t.Helper()
	var got *AuthenticatedPrincipal
	h := BearerMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := PrincipalFromContext(r.Context())
		if !ok {
			t.Error("no principal in context")
		}
		got = p
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/things", nil)
	decorate(req)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w, got
}

func withBearer(token string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) }
}

func TestBearerMiddlewareJWT(t *testing.T) {
	fake := newFakeSystemAuth(t)
	client := fake.client(t)
	store := NewMemoryPrincipalStore()
	p, err := store.AddPrincipal(Principal{Email: "octo@example.com", EmailVerified: true, Active: true, SFPrincipalID: fake.subject})
	if err != nil {
		t.Fatal(err)
	}
	orgA, orgB := uuid.NewString(), uuid.NewString()
	for _, org := range []string{orgA, orgB} {
		if err := store.AddMembership(p.ID, Membership{OrganizationID: org, Role: "member"}); err != nil {
			t.Fatal(err)
		}
	}
	cfg := BearerConfig{Tokens: client, Principals: store}

	w, got := runBearer(t, cfg, withBearer(fake.accessJWT(fake.subject, testClientID, []string{"openid", "things:read"}, time.Minute)))
	if w.Code != http.StatusOK || got.ID != p.ID || got.Method != AuthMethodAccessToken || got.Subject != fake.subject ||
		!got.HasScope("things:read") || len(got.Memberships) != 2 || got.Type != "human" {
		t.Fatalf("JWT principal: %d %+v", w.Code, got)
	}

	// Unknown subject (never signed in to the app): 401.
	w, _ = runBearer(t, cfg, withBearer(fake.accessJWT("unknown", testClientID, nil, time.Minute)))
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Header().Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Errorf("unknown subject: %d %q", w.Code, w.Header().Get("WWW-Authenticate"))
	}

	// Client-credentials token: only with AllowClientTokens.
	clientTok := fake.accessJWT("svc", "svc", []string{"things:read"}, time.Minute)
	if w, _ := runBearer(t, cfg, withBearer(clientTok)); w.Code != http.StatusUnauthorized {
		t.Errorf("client token accepted by default: %d", w.Code)
	}
	cfg.AllowClientTokens = true
	w, got = runBearer(t, cfg, withBearer(clientTok))
	if w.Code != http.StatusOK || got.Type != "client" || got.ID != "svc" {
		t.Errorf("client token: %d %+v", w.Code, got)
	}

	// Expired, foreign-key-signed and foreign-issuer tokens: 401.
	expired := fake.accessJWT(fake.subject, testClientID, nil, -2*time.Minute)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	realKey := fake.key
	fake.key = other
	forged := fake.accessJWT(fake.subject, testClientID, nil, time.Minute)
	fake.key = realKey
	for name, tok := range map[string]string{"expired": expired, "forged": forged, "garbage": "a.b.c"} {
		if w, _ := runBearer(t, cfg, withBearer(tok)); w.Code != http.StatusUnauthorized {
			t.Errorf("%s token: %d", name, w.Code)
		}
	}

	// No credentials: bare challenge.
	w, _ = runBearer(t, cfg, func(*http.Request) {})
	if w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") != `Bearer realm="api"` {
		t.Errorf("anonymous: %d %q", w.Code, w.Header().Get("WWW-Authenticate"))
	}
	// Other schemes are rejected.
	w, _ = runBearer(t, cfg, func(r *http.Request) { r.Header.Set("Authorization", "Basic Zm9vOmJhcg==") })
	if w.Code != http.StatusUnauthorized {
		t.Errorf("basic auth: %d", w.Code)
	}

	// Inactive principals are rejected.
	inactive, err := store.AddPrincipal(Principal{Email: "gone@example.com", Active: false, SFPrincipalID: "gone"})
	if err != nil {
		t.Fatal(err)
	}
	if w, _ := runBearer(t, cfg, withBearer(fake.accessJWT(inactive.SFPrincipalID, testClientID, nil, time.Minute))); w.Code != http.StatusUnauthorized {
		t.Errorf("inactive principal: %d", w.Code)
	}
}

func TestBearerMiddlewareAudience(t *testing.T) {
	fake := newFakeSystemAuth(t)
	//nolint:gosec // G101: test configuration, no credentials
	client, err := NewClient(t.Context(), Config{
		Issuer: fake.srv.URL, ClientID: testClientID, RedirectURL: testCallback, AccessTokenAudience: "https://api.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.VerifyAccessToken(t.Context(), fake.accessJWT(fake.subject, testClientID, nil, time.Minute)); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("token without required audience: %v", err)
	}
}

func TestBearerMiddlewareAPIKey(t *testing.T) {
	store := NewMemoryPrincipalStore()
	p, err := store.AddPrincipal(Principal{Email: "octo@example.com", Active: true, Type: "service"})
	if err != nil {
		t.Fatal(err)
	}
	orgA := uuid.New()
	for _, org := range []string{orgA.String(), uuid.NewString()} {
		if err := store.AddMembership(p.ID, Membership{OrganizationID: org, Role: "admin"}); err != nil {
			t.Fatal(err)
		}
	}
	keyID := uuid.New()
	keys := fakeAPIKeys{
		"sf_live_scoped": {ID: keyID, OwnerID: uuid.MustParse(p.ID), OrganizationID: &orgA, Scopes: []string{"things:write"}},
		"sf_live_orphan": {ID: uuid.New(), OwnerID: uuid.New()},
	}
	cfg := BearerConfig{APIKeys: keys, Principals: store}

	for name, decorate := range map[string]func(*http.Request){
		"bearer":    withBearer("sf_live_scoped"),
		"x-api-key": func(r *http.Request) { r.Header.Set("X-API-Key", "sf_live_scoped") },
	} {
		w, got := runBearer(t, cfg, decorate)
		if w.Code != http.StatusOK || got.Method != AuthMethodAPIKey || got.ID != p.ID || got.Type != "service" ||
			got.APIKeyID != keyID.String() || !got.HasScope("things:write") {
			t.Fatalf("%s: %d %+v", name, w.Code, got)
		}
		if len(got.Memberships) != 1 || got.Memberships[0].OrganizationID != orgA.String() {
			t.Errorf("%s: memberships not scoped to the key's organization: %+v", name, got.Memberships)
		}
	}
	for _, key := range []string{"sf_live_unknown", "sf_live_orphan"} {
		if w, _ := runBearer(t, cfg, withBearer(key)); w.Code != http.StatusUnauthorized {
			t.Errorf("%s: %d", key, w.Code)
		}
	}
	// Storage failures are 500s, not authentication failures.
	if w, _ := runBearer(t, BearerConfig{APIKeys: failingAPIKeys{}, Principals: store}, withBearer("sf_live_x")); w.Code != http.StatusInternalServerError {
		t.Errorf("validator error: %d", w.Code)
	}
	// JWTs are rejected when no verifier is configured.
	if w, _ := runBearer(t, cfg, withBearer("a.b.c")); w.Code != http.StatusUnauthorized {
		t.Errorf("JWT without verifier: %d", w.Code)
	}
}

func TestBearerMiddlewareSessionFallback(t *testing.T) {
	h := newHarness(t)
	sess := h.sessionCookie()
	cfg := BearerConfig{Tokens: h.bff.cfg.Client, Principals: h.store, Sessions: h.bff}
	w, got := runBearer(t, cfg, func(r *http.Request) { r.AddCookie(sess) })
	if w.Code != http.StatusOK || got.Method != AuthMethodSession {
		t.Fatalf("session fallback: %d %+v", w.Code, got)
	}
}

func TestKeySetPicksUpRotatedKey(t *testing.T) {
	fake := newFakeSystemAuth(t)
	client := fake.client(t)
	client.keys.minRefresh = 0
	store := NewMemoryPrincipalStore()
	if _, err := store.AddPrincipal(Principal{Active: true, SFPrincipalID: fake.subject}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.VerifyAccessToken(t.Context(), fake.accessJWT(fake.subject, testClientID, nil, time.Minute)); err != nil {
		t.Fatalf("initial key: %v", err)
	}
	// SystemAuth rotates to a new key and key ID.
	next, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	fake.key, fake.kid = next, "k2"
	fake.mu.Unlock()
	if _, err := client.VerifyAccessToken(t.Context(), fake.accessJWT(fake.subject, testClientID, nil, time.Minute)); err != nil {
		t.Fatalf("rotated key: %v", err)
	}
}

func TestNewClientValidation(t *testing.T) {
	fake := newFakeSystemAuth(t)
	for name, cfg := range map[string]Config{
		"no issuer":    {ClientID: "a", RedirectURL: testCallback},
		"no client":    {Issuer: fake.srv.URL, RedirectURL: testCallback},
		"relative cb":  {Issuer: fake.srv.URL, ClientID: "a", RedirectURL: "/cb"},
		"no openid":    {Issuer: fake.srv.URL, ClientID: "a", RedirectURL: testCallback, Scopes: []string{"email"}},
		"wrong issuer": {Issuer: fake.srv.URL + "/other", ClientID: "a", RedirectURL: testCallback},
	} {
		if _, err := NewClient(t.Context(), cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
