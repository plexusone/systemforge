package multiapp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/session/jwt"
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

func serveAs(t *testing.T, cfg MiddlewareConfig, appID, token string) int {
	t.Helper()
	h := AuthMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req = req.WithContext(WithAppContext(req.Context(), &AppContext{AppID: appID, AppSlug: appID}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code
}

// A token addressed to one app must not authenticate a request routed to
// another app, even when both apps verify with the same key and issuer.
func TestAuthMiddleware_AppAudiencesBindTokenToApp(t *testing.T) {
	svc := newAppTokenService(t)
	cfg := MiddlewareConfig{
		JWTService:   svc,
		RequireAuth:  true,
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

// Without AppAudiences the middleware keeps its previous behavior, relying on
// per-app signing keys for isolation.
func TestAuthMiddleware_NoAppAudiencesAcceptsAnyValidToken(t *testing.T) {
	svc := newAppTokenService(t)
	token, err := svc.GenerateAccessToken(uuid.New(), "u@example.com", "U")
	if err != nil {
		t.Fatalf("GenerateAccessToken: %v", err)
	}
	cfg := MiddlewareConfig{JWTService: svc, RequireAuth: true}
	if got := serveAs(t, cfg, "a", token); got != http.StatusOK {
		t.Errorf("status %d, want 200", got)
	}
}
