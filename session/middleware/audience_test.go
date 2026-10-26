package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/session/jwt"
)

// TestHTTPAuthForAudience verifies that a route serving browser sessions
// refuses the narrowly scoped tokens minted for API clients.
func TestHTTPAuthForAudience(t *testing.T) {
	svc, err := jwt.NewService(&jwt.Config{
		Secret:             []byte("test-secret-key-at-least-32-bytes-long"),
		Algorithm:          "HS256",
		Audience:           []string{"test-app"},
		Issuer:             "test-issuer",
		AccessTokenExpiry:  time.Minute,
		RefreshTokenExpiry: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	pid := uuid.New()
	browser, err := svc.GenerateBFFTokenPair(pid, "kim@example.com", "Kim")
	if err != nil {
		t.Fatalf("GenerateTokenPair: %v", err)
	}
	api, err := svc.GenerateAPIToken(pid, "kim@example.com", "Kim", []string{"read"}, time.Minute)
	if err != nil {
		t.Fatalf("GenerateAPIToken: %v", err)
	}

	reached := 0
	handler := HTTPAuthBearerForAudience(svc, jwt.AudienceBFF)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached++
		w.WriteHeader(http.StatusNoContent)
	}))
	call := func(token string) int {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w.Code
	}
	if code := call(browser.AccessToken); code != http.StatusNoContent {
		t.Errorf("browser token: %d", code)
	}
	if code := call(api); code != http.StatusUnauthorized {
		t.Errorf("API token on a browser route: %d, want 401", code)
	}
	if code := call(""); code != http.StatusUnauthorized {
		t.Errorf("no token: %d", code)
	}
	if reached != 1 {
		t.Errorf("handler reached %d times, want 1", reached)
	}
}
