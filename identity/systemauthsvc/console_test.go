package systemauthsvc_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/plexusone/systemforge/console"
	"github.com/plexusone/systemforge/identity/systemauth"
	"github.com/plexusone/systemforge/identity/systemauthsvc"
)

func consoleConfig(t *testing.T, webDir string) *systemauthsvc.Config {
	t.Helper()
	return &systemauthsvc.Config{
		Issuer:   "https://auth.example.com",
		Database: &systemauth.DatabaseConfig{Driver: "sqlite", DSN: sqliteDSN(t)},
		SocialLogin: &systemauth.SocialLoginConfig{
			SkipConsent: true,
			GitHub:      &systemauth.SocialProviderConfig{ClientID: "gh", ClientSecret: "gh-secret"},
		},
		Console: &systemauth.ConsoleConfig{WebDir: webDir},
	}
}

func TestConsoleIsServed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<title>Console</title>"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := systemauthsvc.New(t.Context(), consoleConfig(t, dir), systemauthsvc.Options{SigningKey: testKey(t), Logger: discardLogger(), Migrate: true})
	if err != nil {
		t.Fatal(err)
	}
	closeService(t, s)

	// Without a session, the session says so and a page sends the person to
	// sign in.
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, console.SessionPath, nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"authenticated":false`) {
		t.Fatalf("session: %d %s", rec.Code, rec.Body)
	}
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/console/orgs", nil))
	if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), systemauth.LoginPath+"?return_to=") {
		t.Fatalf("page: %d %s", rec.Code, rec.Header().Get("Location"))
	}
}

func TestConsoleNeedsSocialLogin(t *testing.T) {
	cfg := consoleConfig(t, "")
	cfg.SocialLogin = nil
	_, err := systemauthsvc.New(t.Context(), cfg, systemauthsvc.Options{SigningKey: testKey(t), Logger: discardLogger(), Migrate: true})
	if !errors.Is(err, systemauth.ErrInvalidConsoleConfig) {
		t.Fatalf("a console without social login: %v", err)
	}
}

func TestConsoleNeedsItsPages(t *testing.T) {
	_, err := systemauthsvc.New(t.Context(), consoleConfig(t, t.TempDir()), systemauthsvc.Options{SigningKey: testKey(t), Logger: discardLogger(), Migrate: true})
	if err == nil || !strings.Contains(err.Error(), "index.html") {
		t.Fatalf("a web directory without index.html: %v", err)
	}
}
