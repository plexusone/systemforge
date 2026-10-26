package relyingparty

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/requestprincipal"
)

func TestRequestAuthenticator(t *testing.T) {
	fake := newFakeSystemAuth(t)
	store := NewMemoryPrincipalStore()
	human, err := store.AddPrincipal(Principal{Email: "octo@example.com", EmailVerified: true, Active: true, SFPrincipalID: fake.subject})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := store.AddPrincipal(Principal{Email: "svc@example.com", Active: true, Type: "service"})
	if err != nil {
		t.Fatal(err)
	}
	keyID := uuid.New()
	keys := fakeAPIKeys{"sf_live_svc": {ID: keyID, OwnerID: uuid.MustParse(svc.ID), Scopes: []string{"things:write"}}}
	auth := NewRequestAuthenticator(BearerConfig{Tokens: fake.clientWith(t, func(c *Config) {
		c.AcceptedClientIDs = []string{testClientID, "svc-client"}
	}), APIKeys: keys, Principals: store, AllowClientTokens: true, AllowBearerTokens: true})

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

	p, err = authenticate(func(r *http.Request) { r.Header.Set("X-API-Key", "sf_live_svc") })
	if err != nil || p.Type != requestprincipal.TypeService || p.Protocol != requestprincipal.ProtocolAPIKey || p.Proof.TokenID != keyID.String() {
		t.Fatalf("API key: %+v %v", p, err)
	}

	p, err = authenticate(withBearer(fake.accessJWT("svc-client", "svc-client", nil, time.Minute)))
	if err != nil || p.Type != requestprincipal.TypeApplication {
		t.Fatalf("client token: %+v %v", p, err)
	}

	// No credentials: left to the next authenticator.
	if _, err := authenticate(func(*http.Request) {}); !errors.Is(err, requestprincipal.ErrNoCredentials) {
		t.Errorf("anonymous: %v", err)
	}

	// Invalid credentials: a bearer challenge.
	_, err = authenticate(withBearer("sf_live_unknown"))
	var authErr *requestprincipal.Error
	if !errors.As(err, &authErr) || authErr.Status != http.StatusUnauthorized ||
		!strings.Contains(authErr.Header.Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Errorf("invalid key: %v", err)
	}

	// Storage failures stay internal errors.
	broken := NewRequestAuthenticator(BearerConfig{APIKeys: failingAPIKeys{}, Principals: store})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-API-Key", "sf_live_x")
	if _, err := broken.Authenticate(req); err == nil || errors.As(err, &authErr) {
		t.Errorf("storage failure: %v", err)
	}

	h := http.Header{}
	auth.Challenge(h)
	if h.Get("WWW-Authenticate") != `Bearer realm="api"` {
		t.Errorf("challenge: %v", h)
	}
}
