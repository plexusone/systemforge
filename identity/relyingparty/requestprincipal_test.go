package relyingparty

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/plexusone/systemforge/identity/requestprincipal"
)

func TestRequestAuthenticator(t *testing.T) {
	fake := newFakeSystemAuth(t)
	store := NewMemoryPrincipalStore()
	human, err := store.AddPrincipal(Principal{Email: "octo@example.com", EmailVerified: true, Active: true, SFPrincipalID: fake.subject})
	if err != nil {
		t.Fatal(err)
	}
	tokens := fake.clientWith(t, func(c *Config) {
		c.AcceptedClientIDs = []string{testClientID, "svc-client"}
	})
	auth := NewRequestAuthenticator(BearerConfig{Tokens: tokens, Principals: store, AllowClientTokens: true, AllowBearerTokens: true})

	authenticate := func(decorate func(*http.Request)) (*requestprincipal.RequestPrincipal, error) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/things", nil)
		decorate(req)
		return auth.Authenticate(req)
	}

	p, err := authenticate(withBearer(fake.accessJWT(fake.subject, testClientID, []string{"things:read"}, time.Minute)))
	if err != nil || p.PrincipalID != human.ID || p.Type != requestprincipal.TypeHuman || p.Protocol != requestprincipal.ProtocolOIDC ||
		p.Subject != fake.subject || !p.HasScope("things:read") || p.Proof.Method != string(AuthMethodAccessToken) {
		t.Fatalf("access token: %+v %v", p, err)
	}
	if native, ok := p.Native.(*AuthenticatedPrincipal); !ok || native.ID != human.ID {
		t.Errorf("native: %T", p.Native)
	}

	p, err = authenticate(withBearer(fake.accessJWT("svc-client", "svc-client", nil, time.Minute)))
	if err != nil || p.Type != requestprincipal.TypeApplication {
		t.Fatalf("client token: %+v %v", p, err)
	}

	// No credentials: left to the next authenticator. An API key header is
	// not a credential.
	if _, err := authenticate(func(*http.Request) {}); !errors.Is(err, requestprincipal.ErrNoCredentials) {
		t.Errorf("anonymous: %v", err)
	}
	if _, err := authenticate(func(r *http.Request) { r.Header.Set("X-API-Key", "sf_live_svc") }); !errors.Is(err, requestprincipal.ErrNoCredentials) {
		t.Errorf("X-API-Key: %v", err)
	}

	// Invalid credentials: a bearer challenge.
	_, err = authenticate(withBearer("sf_live_unknown"))
	var authErr *requestprincipal.Error
	if !errors.As(err, &authErr) || authErr.Status != http.StatusUnauthorized ||
		!strings.Contains(authErr.Header.Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Errorf("API key as bearer token: %v", err)
	}

	// Storage failures stay internal errors.
	broken := NewRequestAuthenticator(BearerConfig{Tokens: tokens, Principals: store, Memberships: failingMemberships{}, AllowBearerTokens: true})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+fake.accessJWT(fake.subject, testClientID, nil, time.Minute))
	if _, err := broken.Authenticate(req); err == nil || errors.As(err, &authErr) {
		t.Errorf("storage failure: %v", err)
	}

	h := http.Header{}
	auth.Challenge(h)
	if h.Get("WWW-Authenticate") != `Bearer realm="api"` {
		t.Errorf("challenge: %v", h)
	}
}

// A session cookie on a cross-origin write is a valid credential on an
// invalid request: a 403 without a challenge, not a 401 that would make
// the client sign in again.
func TestRequestAuthenticatorCrossOriginSession(t *testing.T) {
	h := newHarness(t)
	cookie := h.sessionCookie()
	auth := NewRequestAuthenticator(BearerConfig{Principals: h.store, Sessions: h.bff})

	same := jsonPost("/api/v1/things", cookie)
	if p, err := auth.Authenticate(same); err != nil || p.Protocol != requestprincipal.ProtocolSession {
		t.Fatalf("same-origin write: %+v %v", p, err)
	}

	cross := jsonPost("/api/v1/things", cookie)
	cross.Header.Set("Origin", "https://evil.example")
	_, err := auth.Authenticate(cross)
	var authErr *requestprincipal.Error
	if !errors.As(err, &authErr) || authErr.Status != http.StatusForbidden || authErr.Code != "CSRF_REJECTED" {
		t.Fatalf("cross-origin write: %v", err)
	}
	if authErr.Header.Get("WWW-Authenticate") != "" {
		t.Errorf("cross-origin write challenged: %v", authErr.Header)
	}
}
