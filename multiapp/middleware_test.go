package multiapp

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/grokify/goauth/dpop"

	"github.com/plexusone/systemforge/session/jwt"
	"github.com/plexusone/systemforge/session/middleware"
)

func newAppTokenService(t *testing.T) *jwt.Service {
	t.Helper()
	cfg := jwt.DefaultConfig()
	cfg.Secret = []byte("a-test-secret-that-is-long-enough-for-hs256")
	cfg.Issuer = "test"
	cfg.Audience = []string{"platform"}
	svc, err := jwt.NewService(cfg)
	if err != nil {
		t.Fatalf("jwt.NewService: %v", err)
	}
	return svc
}

// bearerDPoP is the DPoP configuration of tests that use unbound bearer
// tokens: the explicit opt-in.
func bearerDPoP() middleware.DPoPConfig {
	return middleware.DPoPConfig{ReplayCache: middleware.NewMemoryReplayCache(), AllowBearer: true}
}

func authHandler(t *testing.T, cfg MiddlewareConfig) http.Handler {
	t.Helper()
	mw, err := AuthMiddleware(cfg)
	if err != nil {
		t.Fatalf("AuthMiddleware: %v", err)
	}
	return mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
}

// serveAs sends token as Bearer, with an app context for appID.
func serveAs(t *testing.T, cfg MiddlewareConfig, appID, token string) int {
	t.Helper()
	return serveRequest(t, authHandler(t, cfg), appID, "Bearer "+token).Code
}

func serveRequest(t *testing.T, h http.Handler, appID, authorization string, proofs ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/items", nil)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	for _, p := range proofs {
		req.Header.Add("DPoP", p)
	}
	req = req.WithContext(WithAppContext(req.Context(), &AppContext{AppID: appID, AppSlug: appID}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// A token addressed to one app must not authenticate a request routed to
// another app, even when both apps verify with the same key and issuer.
func TestAuthMiddleware_AppAudiencesBindTokenToApp(t *testing.T) {
	svc := newAppTokenService(t)
	cfg := MiddlewareConfig{
		JWTService:   svc,
		RequireAuth:  true,
		DPoP:         bearerDPoP(),
		AppAudiences: func(app *AppContext) []string { return []string{"app:" + app.AppID} },
	}

	tokenForA, err := svc.GenerateAccessTokenWithOptions(uuid.New(), "u@example.com", "U",
		jwt.TokenOptions{Audience: []string{"app:a"}})
	if err != nil {
		t.Fatalf("GenerateAccessTokenWithOptions: %v", err)
	}

	if got := serveAs(t, cfg, "a", tokenForA); got != http.StatusOK {
		t.Errorf("token for app a on app a: status %d, want 200", got)
	}
	if got := serveAs(t, cfg, "b", tokenForA); got != http.StatusUnauthorized {
		t.Errorf("token for app a on app b: status %d, want 401", got)
	}

	// A token with no app audience is refused once binding is configured.
	plain, err := svc.GenerateAccessToken(uuid.New(), "u@example.com", "U")
	if err != nil {
		t.Fatalf("GenerateAccessToken: %v", err)
	}
	if got := serveAs(t, cfg, "a", plain); got != http.StatusUnauthorized {
		t.Errorf("unbound token with binding configured: status %d, want 401", got)
	}
}

// Without AppAudiences a token is bound to the routed app's ID by default.
func TestAuthMiddleware_DefaultBindsTokenToAppID(t *testing.T) {
	svc := newAppTokenService(t)
	cfg := MiddlewareConfig{JWTService: svc, RequireAuth: true, DPoP: bearerDPoP()}

	forA, err := svc.GenerateAccessTokenWithOptions(uuid.New(), "u@example.com", "U",
		jwt.TokenOptions{Audience: []string{"a"}})
	if err != nil {
		t.Fatalf("GenerateAccessTokenWithOptions: %v", err)
	}
	if got := serveAs(t, cfg, "a", forA); got != http.StatusOK {
		t.Errorf("token for app a on app a: status %d, want 200", got)
	}
	if got := serveAs(t, cfg, "b", forA); got != http.StatusUnauthorized {
		t.Errorf("token for app a on app b: status %d, want 401", got)
	}

	// A token addressed only to the shared service is not bound to an app.
	platform, err := svc.GenerateAccessToken(uuid.New(), "u@example.com", "U")
	if err != nil {
		t.Fatalf("GenerateAccessToken: %v", err)
	}
	if got := serveAs(t, cfg, "a", platform); got != http.StatusUnauthorized {
		t.Errorf("unbound token on app a: status %d, want 401", got)
	}
}

// AllowCrossAppTokens accepts a token addressed to the service in any app.
func TestAuthMiddleware_AllowCrossAppTokens(t *testing.T) {
	svc := newAppTokenService(t)
	cfg := MiddlewareConfig{JWTService: svc, RequireAuth: true, AllowCrossAppTokens: true, DPoP: bearerDPoP()}
	platform, err := svc.GenerateAccessToken(uuid.New(), "u@example.com", "U")
	if err != nil {
		t.Fatalf("GenerateAccessToken: %v", err)
	}
	for _, app := range []string{"a", "b"} {
		if got := serveAs(t, cfg, app, platform); got != http.StatusOK {
			t.Errorf("app %s: status %d, want 200", app, got)
		}
	}
}

// A DPoP-bound token must not pass as a bearer token, even with the
// bearer opt-in.
func TestAuthMiddleware_RejectsDPoPBoundTokenAsBearer(t *testing.T) {
	svc := newAppTokenService(t)
	cfg := MiddlewareConfig{JWTService: svc, RequireAuth: true, DPoP: bearerDPoP()}

	bound, err := svc.GenerateAccessTokenWithOptions(uuid.New(), "u@example.com", "U",
		jwt.TokenOptions{Audience: []string{"a"}, DPoPThumbprint: "test-thumbprint"})
	if err != nil {
		t.Fatalf("GenerateAccessTokenWithOptions: %v", err)
	}
	if got := serveAs(t, cfg, "a", bound); got != http.StatusUnauthorized {
		t.Errorf("DPoP-bound token as Bearer: status %d, want 401", got)
	}
}

// AuthMiddleware requires DPoP by default: a bound token with a valid
// proof for the external URL is accepted once, and an unbound bearer
// token is refused unless DPoP.AllowBearer is set.
func TestAuthMiddleware_RequiresDPoP(t *testing.T) {
	const base = "https://apps.example.com/api"
	svc := newAppTokenService(t)
	kp, err := dpop.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	other, err := dpop.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	h := authHandler(t, MiddlewareConfig{
		JWTService:  svc,
		RequireAuth: true,
		DPoP:        middleware.DPoPConfig{ReplayCache: middleware.NewMemoryReplayCache(), BaseURL: base},
	})
	bound, err := svc.GenerateAccessTokenWithOptions(uuid.New(), "u@example.com", "U",
		jwt.TokenOptions{Audience: []string{"a"}, DPoPThumbprint: kp.Thumbprint})
	if err != nil {
		t.Fatal(err)
	}
	proof := func(kp *dpop.KeyPair, uri, token string) string {
		t.Helper()
		p, err := dpop.CreateProofWithOptions(kp, http.MethodGet, uri, dpop.ProofOptions{AccessToken: token})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}

	valid := proof(kp, base+"/items", bound)
	if w := serveRequest(t, h, "a", "DPoP "+bound, valid); w.Code != http.StatusOK {
		t.Fatalf("valid proof: %d %s", w.Code, w.Body)
	}
	for name, tc := range map[string]struct {
		app, authz string
		proofs     []string
	}{
		"replayed":                  {"a", "DPoP " + bound, []string{valid}},
		"no proof":                  {"a", "DPoP " + bound, nil},
		"other key":                 {"a", "DPoP " + bound, []string{proof(other, base+"/items", bound)}},
		"request host htu":          {"a", "DPoP " + bound, []string{proof(kp, "http://example.com/items", bound)}},
		"no ath":                    {"a", "DPoP " + bound, []string{proof(kp, base+"/items", "")}},
		"bound token as Bearer":     {"a", "Bearer " + bound, []string{proof(kp, base+"/items", bound)}},
		"token for another app":     {"b", "DPoP " + bound, []string{proof(kp, base+"/items", bound)}},
		"no credentials":            {"a", "", nil},
		"unsupported authorization": {"a", "Basic dXNlcjpwYXNz", nil},
	} {
		w := serveRequest(t, h, tc.app, tc.authz, tc.proofs...)
		if w.Code != http.StatusUnauthorized || !strings.HasPrefix(w.Header().Get("WWW-Authenticate"), "DPoP ") {
			t.Errorf("%s: %d %q", name, w.Code, w.Header().Get("WWW-Authenticate"))
		}
	}

	unbound, err := svc.GenerateAccessTokenWithOptions(uuid.New(), "u@example.com", "U",
		jwt.TokenOptions{Audience: []string{"a"}})
	if err != nil {
		t.Fatal(err)
	}
	if w := serveRequest(t, h, "a", "Bearer "+unbound); w.Code != http.StatusUnauthorized {
		t.Errorf("unbound bearer token without the opt-in: %d", w.Code)
	}
}

// Without RequireAuth a request without credentials passes without
// claims; one with a bad token is still refused.
func TestAuthMiddleware_OptionalAuth(t *testing.T) {
	h := authHandler(t, MiddlewareConfig{JWTService: newAppTokenService(t), DPoP: middleware.DPoPConfig{ReplayCache: middleware.NewMemoryReplayCache()}})
	if w := serveRequest(t, h, "a", ""); w.Code != http.StatusOK {
		t.Errorf("no credentials: %d", w.Code)
	}
	if w := serveRequest(t, h, "a", "Bearer not-a-token"); w.Code != http.StatusUnauthorized {
		t.Errorf("bad token: %d", w.Code)
	}
}

func TestAuthMiddleware_Configuration(t *testing.T) {
	if _, err := AuthMiddleware(MiddlewareConfig{DPoP: bearerDPoP()}); !errors.Is(err, ErrJWTServiceRequired) {
		t.Errorf("no JWT service: %v", err)
	}
	if _, err := AuthMiddleware(MiddlewareConfig{JWTService: newAppTokenService(t)}); !errors.Is(err, middleware.ErrReplayCacheRequired) {
		t.Errorf("no replay cache: %v", err)
	}
}
