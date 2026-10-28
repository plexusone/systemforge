package systemauthsvc_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/grokify/goauth/dpop"

	"github.com/plexusone/systemforge/identity/systemauth"
	"github.com/plexusone/systemforge/identity/systemauthsvc"
	"github.com/plexusone/systemforge/session/middleware"
)

// syncBuffer is a log destination safe for concurrent writes.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// productionClients are a confidential client using the client_credentials
// grant and one registered with the bearer-token exception.
func productionClients() []systemauth.ClientConfig {
	return []systemauth.ClientConfig{
		{ID: "svc", Type: "confidential", Name: "Service", Secret: "svc-secret",
			GrantTypes: []string{"client_credentials"}, Scopes: []string{"read"}},
		{ID: "legacy", Type: "confidential", Name: "Legacy", Secret: "legacy-secret",
			GrantTypes: []string{"client_credentials"}, Scopes: []string{"read"}, AllowBearerTokens: true},
	}
}

// clientCredentials requests a token for client id with a DPoP proof and
// returns the status and the OAuth error, if any.
func clientCredentials(t *testing.T, h http.Handler, issuer, id, secret string) (int, string) {
	t.Helper()
	kp, err := dpop.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := dpop.CreateProofWithOptions(kp, http.MethodPost, issuer+"/oauth/token", dpop.ProofOptions{})
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {secret}, "scope": {"read"}}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", proof)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("token response not JSON (%d): %s", w.Code, w.Body.String())
	}
	return w.Code, body.Error
}

// TestProductionRefusesAtTheTokenEndpoint verifies that, in production,
// the client_credentials grant with a shared secret and clients registered
// at runtime with allow_bearer_tokens are refused per request.
func TestProductionRefusesAtTheTokenEndpoint(t *testing.T) {
	cfg := &systemauthsvc.Config{
		Issuer:   "https://auth.example.com",
		Tokens:   prodTokens,
		DPoP:     prodDPoP,
		Database: &systemauth.DatabaseConfig{Driver: "sqlite", DSN: sqliteDSN(t)},
		Clients:  productionClients()[:1],
	}
	s, err := systemauthsvc.New(t.Context(), cfg, systemauthsvc.Options{SigningKey: testKey(t), Logger: discardLogger(), Migrate: true})
	if err != nil {
		t.Fatal(err)
	}
	closeService(t, s)
	if code, oauthErr := clientCredentials(t, s.Handler(), cfg.Issuer, "svc", "svc-secret"); code != http.StatusBadRequest || oauthErr != "unauthorized_client" {
		t.Errorf("client_credentials: %d %q", code, oauthErr)
	}

	// A client registered after startup with the bearer-token exception.
	legacy, err := systemauth.NewClientFromConfig(productionClients()[1])
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Server().Storage().CreateClient(t.Context(), legacy); err != nil {
		t.Fatal(err)
	}
	if code, oauthErr := clientCredentials(t, s.Handler(), cfg.Issuer, "legacy", "legacy-secret"); code != http.StatusBadRequest || oauthErr != "unauthorized_client" {
		t.Errorf("bearer-token client: %d %q", code, oauthErr)
	}
}

// TestProductionWaivers verifies that each production check is waived by
// name, and that every waiver is logged at startup as a warning.
func TestProductionWaivers(t *testing.T) {
	logs := &syncBuffer{}
	cfg := &systemauthsvc.Config{
		Issuer:   "https://auth.example.com",
		DPoP:     systemauth.DPoPConfig{SingleInstance: true},
		Database: &systemauth.DatabaseConfig{Driver: "sqlite", DSN: sqliteDSN(t)},
		Clients:  productionClients(),
		Production: systemauth.ProductionConfig{Allow: []string{
			systemauth.AllowEphemeralHMACSecret,
			systemauth.AllowClientSecretClientCredentials,
			systemauth.AllowBearerTokenClients,
		}},
	}
	s, err := systemauthsvc.New(t.Context(), cfg, systemauthsvc.Options{
		SigningKey: testKey(t), Migrate: true,
		Logger: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn})),
	})
	if err != nil {
		t.Fatalf("waived checks: %v", err)
	}
	closeService(t, s)
	out := logs.String()
	for _, want := range []string{
		`level=WARN msg="production check waived" check=ephemeral_hmac_secret`,
		`level=WARN msg="production check waived" check=client_secret_client_credentials`,
		`level=WARN msg="production check waived" check=bearer_token_clients`,
		`level=WARN msg="DPoP replay cache is per instance (dpop.single_instance)`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("startup log lacks %q:\n%s", want, out)
		}
	}
	if code, oauthErr := clientCredentials(t, s.Handler(), cfg.Issuer, "svc", "svc-secret"); code != http.StatusOK {
		t.Errorf("waived client_credentials: %d %q", code, oauthErr)
	}
	if code, oauthErr := clientCredentials(t, s.Handler(), cfg.Issuer, "legacy", "legacy-secret"); code != http.StatusOK {
		t.Errorf("waived bearer-token client: %d %q", code, oauthErr)
	}

	// An unknown waiver is a configuration error.
	bad := *cfg
	bad.Production.Allow = []string{"insecure_everything"}
	if s, err := systemauthsvc.New(t.Context(), &bad, systemauthsvc.Options{SigningKey: testKey(t), Logger: discardLogger()}); err == nil {
		closeService(t, s)
		t.Error("an unknown production.allow name was accepted")
	}
}

// TestProductionReplayCache verifies that a shared replay cache, from the
// configuration or injected, meets the replay-cache check without
// dpop.single_instance.
func TestProductionReplayCache(t *testing.T) {
	base := systemauthsvc.Config{
		Issuer:   "https://auth.example.com",
		Tokens:   prodTokens,
		Database: &systemauth.DatabaseConfig{Driver: "sqlite", DSN: "file::memory:"},
	}
	opts := systemauthsvc.Options{SigningKey: testKey(t)}

	if err := systemauthsvc.CheckProduction(&base, opts); err == nil || !strings.Contains(err.Error(), "dpop.single_instance") {
		t.Errorf("no replay cache: %v", err)
	}
	redis := base
	redis.DPoP.ReplayCacheRedisURL = "redis://127.0.0.1:6379/0"
	if err := systemauthsvc.CheckProduction(&redis, opts); err != nil {
		t.Errorf("Redis replay cache: %v", err)
	}
	injected := opts
	injected.DPoPReplayCache = middleware.NewMemoryReplayCache()
	if err := systemauthsvc.CheckProduction(&base, injected); err != nil {
		t.Errorf("injected replay cache: %v", err)
	}
	single := base
	single.DPoP.SingleInstance = true
	if err := systemauthsvc.CheckProduction(&single, opts); err != nil {
		t.Errorf("single instance: %v", err)
	}
}

// TestDevModeServesWaivableGrants verifies that development mode refuses
// neither the client_credentials grant nor bearer-token clients.
func TestDevModeServesWaivableGrants(t *testing.T) {
	cfg := &systemauthsvc.Config{Issuer: "http://localhost:8081", Clients: productionClients()}
	s, err := systemauthsvc.New(t.Context(), cfg, systemauthsvc.Options{Dev: true, Logger: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	closeService(t, s)
	for _, id := range []string{"svc", "legacy"} {
		if code, oauthErr := clientCredentials(t, s.Handler(), cfg.Issuer, id, id+"-secret"); code != http.StatusOK {
			t.Errorf("%s: %d %q", id, code, oauthErr)
		}
	}
}
