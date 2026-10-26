package relyingparty

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/grokify/goauth/dpop"
)

const dpopTestBase = "https://api.example.com"

type memoryReplayCache struct {
	mu   sync.Mutex
	seen map[string]bool
}

func (c *memoryReplayCache) Use(_ context.Context, key string, _ time.Time) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen[key] {
		return true, nil
	}
	c.seen[key] = true
	return false, nil
}

func (f *fakeSystemAuth) boundAccessJWT(sub, jkt string) string {
	now := time.Now()
	return f.sign(gojwt.MapClaims{
		"iss": f.srv.URL, "sub": sub, "client_id": testClientID,
		"exp": now.Add(time.Minute).Unix(), "iat": now.Unix(), "jti": fmt.Sprint(now.UnixNano()),
		"cnf": map[string]any{"jkt": jkt},
	})
}

func dpopProof(t *testing.T, kp *dpop.KeyPair, method, path, token string) string {
	t.Helper()
	p, err := dpop.CreateProofWithOptions(kp, method, dpopTestBase+path, dpop.ProofOptions{AccessToken: token})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestBearerMiddlewareDPoP(t *testing.T) {
	fake := newFakeSystemAuth(t)
	store := NewMemoryPrincipalStore()
	if _, err := store.AddPrincipal(Principal{Email: "octo@example.com", EmailVerified: true, Active: true, SFPrincipalID: fake.subject}); err != nil {
		t.Fatal(err)
	}
	kp, err := dpop.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	other, err := dpop.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	bound := fake.boundAccessJWT(fake.subject, kp.Thumbprint)
	plain := fake.accessJWT(fake.subject, testClientID, nil, time.Minute)

	// withoutDPoP is a legacy configuration accepting only unbound tokens.
	withoutDPoP := BearerConfig{Tokens: fake.client(t), Principals: store, AllowBearerTokens: true}
	withDPoP := BearerConfig{Tokens: fake.client(t), Principals: store}
	withDPoP.DPoP = &DPoPConfig{ReplayCache: &memoryReplayCache{seen: map[string]bool{}}, BaseURL: dpopTestBase}

	const path = "/api/v1/things"
	req := func(scheme, token, proof string) func(*http.Request) {
		return func(r *http.Request) {
			r.Header.Set("Authorization", scheme+" "+token)
			if proof != "" {
				r.Header.Set("DPoP", proof)
			}
		}
	}

	// A bound token never works as a bearer token, with or without DPoP
	// enabled.
	for name, cfg := range map[string]BearerConfig{"without DPoP": withoutDPoP, "with DPoP": withDPoP} {
		if w := runBearerQuiet(t, cfg, req("Bearer", bound, "")); w.Code != http.StatusUnauthorized {
			t.Errorf("%s: bound token as Bearer: %d, want 401", name, w.Code)
		}
	}
	// The DPoP scheme is not accepted unless DPoP is configured.
	if w := runBearerQuiet(t, withoutDPoP, req("DPoP", bound, dpopProof(t, kp, "GET", path, bound))); w.Code != http.StatusUnauthorized {
		t.Errorf("DPoP scheme without DPoPConfig: %d, want 401", w.Code)
	}

	// A valid proof from the bound key is accepted once.
	proof := dpopProof(t, kp, "GET", path, bound)
	w, got := runBearer(t, withDPoP, req("DPoP", bound, proof))
	if w.Code != http.StatusOK || got.Subject != fake.subject || got.Method != AuthMethodAccessToken {
		t.Fatalf("valid DPoP request: %d %+v", w.Code, got)
	}
	if w := runBearerQuiet(t, withDPoP, req("DPoP", bound, proof)); w.Code != http.StatusUnauthorized {
		t.Errorf("replayed proof: %d, want 401", w.Code)
	}

	for name, decorate := range map[string]func(*http.Request){
		"no proof":                 req("DPoP", bound, ""),
		"proof from another key":   req("DPoP", bound, dpopProof(t, other, "GET", path, bound)),
		"proof for another URI":    req("DPoP", bound, dpopProof(t, kp, "GET", "/api/v1/other", bound)),
		"proof for another method": req("DPoP", bound, dpopProof(t, kp, "POST", path, bound)),
		"proof for another token":  req("DPoP", bound, dpopProof(t, kp, "GET", path, plain)),
		"unbound token with DPoP":  req("DPoP", plain, dpopProof(t, kp, "GET", path, plain)),
	} {
		w := runBearerQuiet(t, withDPoP, decorate)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s: %d, want 401", name, w.Code)
		}
		if !strings.Contains(strings.Join(w.Header().Values("WWW-Authenticate"), ","), "DPoP") {
			t.Errorf("%s: no DPoP challenge", name)
		}
	}

	// An unbound token is refused by default, and accepted as a bearer
	// token only with the explicit AllowBearerTokens opt-in.
	if w := runBearerQuiet(t, withDPoP, req("Bearer", plain, "")); w.Code != http.StatusUnauthorized {
		t.Errorf("unbound bearer token by default: %d, want 401", w.Code)
	}
	withBoth := withDPoP
	withBoth.AllowBearerTokens = true
	if w, _ := runBearer(t, withBoth, req("Bearer", plain, "")); w.Code != http.StatusOK {
		t.Errorf("unbound bearer token with AllowBearerTokens: %d, want 200", w.Code)
	}
	if w, _ := runBearer(t, withoutDPoP, req("Bearer", plain, "")); w.Code != http.StatusOK {
		t.Errorf("unbound bearer token, legacy configuration: %d, want 200", w.Code)
	}
}

// TestBearerMiddlewareRequiresDPoPConfig verifies that accepting access
// tokens needs DPoP proof checking unless bearer tokens are explicitly
// allowed.
func TestBearerMiddlewareRequiresDPoPConfig(t *testing.T) {
	fake := newFakeSystemAuth(t)
	cfg := BearerConfig{Tokens: fake.client(t), Principals: NewMemoryPrincipalStore()}
	for name, build := range map[string]func(){
		"BearerMiddleware":        func() { BearerMiddleware(cfg) },
		"NewRequestAuthenticator": func() { NewRequestAuthenticator(cfg) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s accepted access tokens without DPoP or AllowBearerTokens", name)
				}
			}()
			build()
		}()
	}
	// API keys alone need neither.
	BearerMiddleware(BearerConfig{Principals: NewMemoryPrincipalStore()})
}

// runBearerQuiet runs the middleware for a request that is expected to be
// refused; reaching the handler records 200.
func runBearerQuiet(t *testing.T, cfg BearerConfig, decorate func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	h := BearerMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest(http.MethodGet, "/api/v1/things", nil)
	decorate(r)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestRequestAuthenticatorDPoP(t *testing.T) {
	fake := newFakeSystemAuth(t)
	store := NewMemoryPrincipalStore()
	if _, err := store.AddPrincipal(Principal{Email: "octo@example.com", EmailVerified: true, Active: true, SFPrincipalID: fake.subject}); err != nil {
		t.Fatal(err)
	}
	kp, err := dpop.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	bound := fake.boundAccessJWT(fake.subject, kp.Thumbprint)
	a := NewRequestAuthenticator(BearerConfig{
		Tokens: fake.client(t), Principals: store,
		DPoP: &DPoPConfig{ReplayCache: &memoryReplayCache{seen: map[string]bool{}}, BaseURL: dpopTestBase},
	})

	r := httptest.NewRequest(http.MethodGet, "/api/v1/things", nil)
	r.Header.Set("Authorization", "Bearer "+bound)
	if _, err := a.Authenticate(r); err == nil {
		t.Error("bound token as Bearer accepted")
	}
	r.Header.Set("Authorization", "DPoP "+bound)
	r.Header.Set("DPoP", dpopProof(t, kp, "GET", "/api/v1/things", bound))
	if rp, err := a.Authenticate(r); err != nil || rp.Subject != fake.subject {
		t.Errorf("DPoP request: %+v, %v", rp, err)
	}
}
