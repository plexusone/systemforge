package systemauthsvc_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"golang.org/x/oauth2"

	"github.com/plexusone/systemforge/identity/relyingparty"
	"github.com/plexusone/systemforge/identity/systemauth"
	"github.com/plexusone/systemforge/identity/systemauthsvc"
	"github.com/plexusone/systemforge/internal/pgtest"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func keyPEM(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func sqliteDSN(t *testing.T) string {
	t.Helper()
	return "file:" + filepath.Join(t.TempDir(), "systemauth.db") + "?_fk=1"
}

func closeService(t *testing.T, s *systemauthsvc.Service) {
	t.Helper()
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
}

func TestLoadConfigOverrides(t *testing.T) {
	t.Setenv("TEST_DB_PATH", filepath.Join(t.TempDir(), "x.db"))
	path := filepath.Join(t.TempDir(), "systemauth.yaml")
	if err := os.WriteFile(path, []byte("issuer: https://file.example.com\nkeys:\n  key_id: file-kid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pemKey := keyPEM(t, testKey(t))
	cfg, err := systemauthsvc.LoadConfig(path,
		systemauthsvc.WithIssuer("https://auth.example.com"),
		systemauthsvc.WithDefaultIssuer("http://localhost:8080"),
		systemauthsvc.WithDatabase("sqlite", "file:${TEST_DB_PATH}"),
		systemauthsvc.WithDefaultSigningKeyPEM(pemKey),
		systemauthsvc.WithKeyID(""),
	)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Issuer != "https://auth.example.com" || cfg.Keys.KeyID != "file-kid" || cfg.Keys.PrivateKeyPEM != pemKey {
		t.Errorf("overrides: issuer %q kid %q pem set %v", cfg.Issuer, cfg.Keys.KeyID, cfg.Keys.PrivateKeyPEM != "")
	}
	if cfg.Database == nil || cfg.Database.DSN != "file:"+os.Getenv("TEST_DB_PATH") {
		t.Errorf("database: %+v", cfg.Database)
	}
	if cfg.Tokens.AccessTokenLifetime == 0 {
		t.Error("defaults not applied")
	}

	// A key file override replaces a PEM key; a default PEM then does not apply.
	cfg, err = systemauthsvc.LoadConfig("",
		systemauthsvc.WithDefaultIssuer("http://localhost:8080"),
		systemauthsvc.WithSigningKeyFile("/run/secrets/key.pem"),
		systemauthsvc.WithDefaultSigningKeyPEM(pemKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Issuer != "http://localhost:8080" || cfg.Keys.PrivateKeyFile != "/run/secrets/key.pem" || cfg.Keys.PrivateKeyPEM != "" {
		t.Errorf("no-file config: %+v", cfg.Keys)
	}

	if _, err := systemauthsvc.LoadConfig("", systemauthsvc.WithDatabase("sqlite", "")); err == nil {
		t.Error("driver without DSN accepted")
	}
	if _, err := systemauthsvc.LoadConfig(""); err == nil {
		t.Error("config without issuer accepted")
	}
}

func TestLoadConfigOverrideSuppliesIssuer(t *testing.T) {
	t.Setenv("TEST_KID", "env-kid")
	path := filepath.Join(t.TempDir(), "systemauth.yaml")
	if err := os.WriteFile(path, []byte("keys:\n  key_id: ${TEST_KID}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := systemauthsvc.LoadConfig(path, systemauthsvc.WithDefaultIssuer("http://localhost:8080"))
	if err != nil {
		t.Fatalf("issuer from override: %v", err)
	}
	if cfg.Issuer != "http://localhost:8080" || cfg.Keys.KeyID != "env-kid" || cfg.Tokens.AccessTokenLifetime == 0 {
		t.Errorf("config: issuer %q kid %q access %v", cfg.Issuer, cfg.Keys.KeyID, cfg.Tokens.AccessTokenLifetime)
	}
	if _, err := systemauthsvc.LoadConfig(path); !errors.Is(err, systemauth.ErrMissingIssuer) {
		t.Errorf("no issuer anywhere: %v, want ErrMissingIssuer", err)
	}
}

func TestLoadConfigBytes(t *testing.T) {
	t.Setenv("TEST_BYTES_SECRET", "s3cret")
	yamlCfg := "keys:\n  key_id: inline-kid\nclients:\n  - id: app\n    secret: ${TEST_BYTES_SECRET}\n"
	jsonCfg := `{"keys":{"key_id":"inline-kid"},"clients":[{"id":"app","secret":"${TEST_BYTES_SECRET}"}]}`
	for _, tc := range []struct {
		name, format, data string
	}{
		{"yaml", "yaml", yamlCfg},
		{"yml", "yml", yamlCfg},
		{"json", "json", jsonCfg},
		{"detect yaml", "", yamlCfg},
		{"detect json", "", "\n  " + jsonCfg},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := systemauthsvc.LoadConfigBytes([]byte(tc.data), tc.format,
				systemauthsvc.WithDefaultIssuer("https://auth.example.com"),
				systemauthsvc.WithKeyID("override-kid"),
			)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Issuer != "https://auth.example.com" || cfg.Keys.KeyID != "override-kid" {
				t.Errorf("overrides: issuer %q kid %q", cfg.Issuer, cfg.Keys.KeyID)
			}
			if len(cfg.Clients) != 1 || cfg.Clients[0].ID != "app" || cfg.Clients[0].Secret != "s3cret" {
				t.Errorf("env expansion: %+v", cfg.Clients)
			}
			if cfg.Tokens.AccessTokenLifetime == 0 || cfg.Keys.Algorithm == "" {
				t.Error("defaults not applied")
			}
		})
	}

	// Empty data starts from an empty configuration.
	cfg, err := systemauthsvc.LoadConfigBytes(nil, "", systemauthsvc.WithIssuer("https://auth.example.com"))
	if err != nil || cfg.Issuer != "https://auth.example.com" {
		t.Errorf("empty data: %v %+v", err, cfg)
	}

	// Validation still runs after the overrides.
	if _, err := systemauthsvc.LoadConfigBytes([]byte(yamlCfg), "yaml"); !errors.Is(err, systemauth.ErrMissingIssuer) {
		t.Errorf("missing issuer: %v, want ErrMissingIssuer", err)
	}
	bad := "issuer: https://auth.example.com\ntokens:\n  refresh_token_lifetime: 48h\n  refresh_token_absolute_lifetime: 24h\n"
	if _, err := systemauthsvc.LoadConfigBytes([]byte(bad), "yaml",
		systemauthsvc.WithIssuer("https://other.example.com")); !errors.Is(err, systemauth.ErrInvalidConfig) {
		t.Errorf("invalid lifetimes: %v, want ErrInvalidConfig", err)
	}
	if _, err := systemauthsvc.LoadConfigBytes([]byte(yamlCfg), "toml"); err == nil {
		t.Error("unsupported format accepted")
	}
	if _, err := systemauthsvc.LoadConfigBytes([]byte("{"), "json"); err == nil {
		t.Error("malformed JSON accepted")
	}
	if _, err := systemauthsvc.LoadConfigBytes([]byte(yamlCfg), "",
		systemauthsvc.WithDatabase("sqlite", "")); err == nil {
		t.Error("failing override accepted")
	}
}

func TestProductionRefusals(t *testing.T) {
	key := testKey(t)
	good := func() *systemauthsvc.Config {
		return &systemauthsvc.Config{
			Issuer:   "https://auth.example.com",
			Database: &systemauth.DatabaseConfig{Driver: "sqlite", DSN: sqliteDSN(t)},
		}
	}
	tests := []struct {
		name   string
		mutate func(*systemauthsvc.Config, *systemauthsvc.Options)
		want   string
	}{
		{"no signing key", func(_ *systemauthsvc.Config, o *systemauthsvc.Options) { o.SigningKey = nil }, "signing key"},
		{"http issuer", func(c *systemauthsvc.Config, _ *systemauthsvc.Options) { c.Issuer = "http://auth.example.com" }, "https"},
		{"no database", func(c *systemauthsvc.Config, _ *systemauthsvc.Options) { c.Database = nil }, "persistent database"},
		{"insecure cookies", func(c *systemauthsvc.Config, _ *systemauthsvc.Options) {
			c.SocialLogin = &systemauth.SocialLoginConfig{InsecureCookies: true}
		}, "insecure_cookies"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := good()
			opts := systemauthsvc.Options{SigningKey: key, Logger: discardLogger(), Migrate: true}
			tt.mutate(cfg, &opts)
			s, err := systemauthsvc.New(t.Context(), cfg, opts)
			if err == nil {
				closeService(t, s)
				t.Fatal("started")
			}
			if !errors.Is(err, systemauthsvc.ErrNotProductionReady) || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q: want ErrNotProductionReady mentioning %q", err, tt.want)
			}
		})
	}

	// Every missing requirement is reported at once.
	err := systemauthsvc.CheckProduction(&systemauthsvc.Config{Issuer: "http://x"}, systemauthsvc.Options{})
	for _, want := range []string{"signing key", "https", "database"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("CheckProduction %v does not mention %q", err, want)
		}
	}

	// The production configuration starts.
	s, err := systemauthsvc.New(t.Context(), good(), systemauthsvc.Options{SigningKey: key, Logger: discardLogger(), Migrate: true})
	if err != nil {
		t.Fatalf("production config: %v", err)
	}
	closeService(t, s)
	if s.StorageName() != "sqlite" || s.Issuer() != "https://auth.example.com" {
		t.Errorf("storage %q issuer %q", s.StorageName(), s.Issuer())
	}
}

func TestDevMode(t *testing.T) {
	cfg := &systemauthsvc.Config{
		Issuer:      "http://localhost:8081",
		SocialLogin: &systemauth.SocialLoginConfig{InsecureCookies: true, GitHub: &systemauth.SocialProviderConfig{ClientID: "id", ClientSecret: "secret"}},
	}
	s, err := systemauthsvc.New(t.Context(), cfg, systemauthsvc.Options{Dev: true, Logger: discardLogger()})
	if err != nil {
		t.Fatalf("dev: %v", err)
	}
	closeService(t, s)
	if s.StorageName() != "in-memory" || s.EntClient() != nil || s.KeyID() == "" {
		t.Errorf("storage %q kid %q", s.StorageName(), s.KeyID())
	}
	if err := s.Ready(t.Context()); err != nil {
		t.Errorf("ready: %v", err)
	}
	if err := s.Migrate(t.Context()); err != nil {
		t.Errorf("migrate in memory: %v", err)
	}
	// The caller's config is not modified.
	if cfg.Tokens.AccessTokenLifetime != 0 {
		t.Error("New mutated the caller's config")
	}
}

func TestMigrateIdempotent(t *testing.T) {
	cfg := &systemauthsvc.Config{
		Issuer:   "https://auth.example.com",
		Database: &systemauth.DatabaseConfig{Driver: "sqlite", DSN: sqliteDSN(t)},
		Clients: []systemauth.ClientConfig{{
			ID: "web", Type: "public", Name: "Web",
			RedirectURIs:  []string{"https://app.example.com/callback"},
			GrantTypes:    []string{"authorization_code"},
			ResponseTypes: []string{"code"},
			Scopes:        []string{"openid"},
		}},
	}
	opts := systemauthsvc.Options{SigningKey: testKey(t), Logger: discardLogger()}

	// Without migrations the schema is missing.
	if s, err := systemauthsvc.New(t.Context(), cfg, opts); err == nil {
		closeService(t, s)
		t.Fatal("started on an empty database without migrating")
	}

	if err := systemauthsvc.Migrate(t.Context(), cfg); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if err := systemauthsvc.Migrate(t.Context(), cfg); err != nil {
		t.Fatalf("Migrate again: %v", err)
	}

	// Restarts with migration enabled re-register the static client.
	opts.Migrate = true
	for i := range 2 {
		s, err := systemauthsvc.New(t.Context(), cfg, opts)
		if err != nil {
			t.Fatalf("start %d: %v", i+1, err)
		}
		if err := s.Migrate(t.Context()); err != nil {
			t.Errorf("Service.Migrate: %v", err)
		}
		if c, err := s.Server().GetClient("web"); err != nil || c == nil {
			t.Errorf("static client: %v", err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		if err := s.Close(); err != nil {
			t.Errorf("second close: %v", err)
		}
	}

	if err := systemauthsvc.Migrate(t.Context(), &systemauthsvc.Config{Issuer: "https://x"}); err == nil {
		t.Error("Migrate without a database succeeded")
	}
}

func TestPostgresMigrateIdempotent(t *testing.T) {
	dsn := pgtest.DSN(t)
	cfg := &systemauthsvc.Config{
		Issuer:   "https://auth.example.com",
		Database: &systemauth.DatabaseConfig{Driver: "postgres", DSN: dsn},
	}
	opts := systemauthsvc.Options{SigningKey: testKey(t), Logger: discardLogger(), Migrate: true}
	for i := range 2 {
		s, err := systemauthsvc.New(t.Context(), cfg, opts)
		if err != nil {
			t.Fatalf("start %d: %v", i+1, err)
		}
		if err := s.Migrate(t.Context()); err != nil {
			t.Errorf("Service.Migrate: %v", err)
		}
		if err := s.Ready(t.Context()); err != nil {
			t.Errorf("ready: %v", err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMetadataMatchesDiscovery(t *testing.T) {
	s, err := systemauthsvc.New(t.Context(), &systemauthsvc.Config{Issuer: "https://auth.example.com"},
		systemauthsvc.Options{Dev: true, Logger: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	closeService(t, s)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("discovery: %d", w.Code)
	}
	var served relyingparty.Metadata
	if err := json.Unmarshal(w.Body.Bytes(), &served); err != nil {
		t.Fatal(err)
	}
	if served != s.Metadata() {
		t.Errorf("Metadata() = %+v, served %+v", s.Metadata(), served)
	}
	var full systemauth.OpenIDConfiguration
	if err := json.Unmarshal(w.Body.Bytes(), &full); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(full, s.Discovery()) {
		t.Errorf("Discovery() = %+v, served %+v", s.Discovery(), full)
	}
}

func TestInjectedDatabase(t *testing.T) {
	db, err := sql.Open("sqlite3", sqliteDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	cfg := &systemauthsvc.Config{Issuer: "https://auth.example.com"}
	opts := systemauthsvc.Options{SigningKey: testKey(t), Logger: discardLogger(), DB: db, Migrate: true}

	if _, err := systemauthsvc.New(t.Context(), cfg, opts); err == nil {
		t.Fatal("DB without DBDialect accepted")
	}
	opts.DBDialect = "sqlite"
	s, err := systemauthsvc.New(t.Context(), cfg, opts)
	if err != nil {
		t.Fatalf("injected DB: %v", err)
	}
	if err := s.Ready(t.Context()); err != nil {
		t.Errorf("ready: %v", err)
	}
	// Close leaves the injected pool open.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := db.PingContext(t.Context()); err != nil {
		t.Errorf("injected DB closed by Service.Close: %v", err)
	}

	// An injected Ent client works too, and readiness follows the database.
	es, err := systemauthsvc.New(t.Context(), cfg, systemauthsvc.Options{
		SigningKey: testKey(t), Logger: discardLogger(), EntClient: s.EntClient(),
	})
	if err != nil {
		t.Fatalf("injected Ent client: %v", err)
	}
	if es.StorageName() != "ent" {
		t.Errorf("storage %q", es.StorageName())
	}
	if err := es.Ready(t.Context()); err != nil {
		t.Errorf("ready: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := es.Ready(t.Context()); err == nil {
		t.Error("ready after the database closed")
	}
	w := httptest.NewRecorder()
	es.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, systemauth.ReadyzPath, nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("readyz after database loss: %d", w.Code)
	}
}

// headerSession authenticates SystemAuth requests by a test header,
// standing in for social login.
type headerSession struct{}

func (headerSession) GetAuthenticatedUser(r *http.Request) string { return r.Header.Get("X-Test-User") }
func (headerSession) RedirectToLogin(string) string               { return "/login" }
func (headerSession) HasConsent(context.Context, string, string, []string) bool {
	return true
}
func (headerSession) RedirectToConsent(string) string { return "/consent" }
func (headerSession) SaveConsent(context.Context, string, string, []string) error {
	return nil
}
func (headerSession) GetUserClaims(_ context.Context, userID string, _ []string) map[string]any {
	return map[string]any{"sub": userID, "email": "dev@example.com", "email_verified": true, "name": "Dev"}
}

// TestEmbedInHostBinary mounts the service in a host handler that routes
// by Host header next to an application, and runs a login with a relying
// party built from Service.Metadata (no discovery request).
func TestEmbedInHostBinary(t *testing.T) {
	ts := httptest.NewUnstartedServer(nil)
	t.Cleanup(ts.Close)
	_, port, err := net.SplitHostPort(ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	authHost := "auth.example.test:" + port
	issuer := "http://" + authHost
	const callback = "https://app.example.test/auth/callback"

	svc, err := systemauthsvc.New(t.Context(), &systemauthsvc.Config{
		Issuer:   issuer,
		Database: &systemauth.DatabaseConfig{Driver: "sqlite", DSN: sqliteDSN(t)},
		Clients: []systemauth.ClientConfig{{
			ID: "app", Type: "public", Name: "App",
			RedirectURIs:  []string{callback},
			GrantTypes:    []string{"authorization_code", "refresh_token"},
			ResponseTypes: []string{"code"},
			Scopes:        []string{"openid", "profile", "email", "offline_access"},
		}},
		Features: systemauth.FeatureConfig{RequirePKCE: true},
	}, systemauthsvc.Options{
		Dev:           true, // http issuer on a test listener
		SigningKey:    testKey(t),
		Logger:        discardLogger(),
		Migrate:       true,
		ServerOptions: []systemauth.Option{systemauth.WithSessionProvider(headerSession{})},
	})
	if err != nil {
		t.Fatal(err)
	}
	closeService(t, svc)

	// The host binary: one listener, routed by Host header.
	var mu sync.Mutex
	var authPaths []string
	ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != authHost {
			http.Error(w, "application", http.StatusTeapot)
			return
		}
		mu.Lock()
		authPaths = append(authPaths, r.URL.Path)
		mu.Unlock()
		svc.Handler().ServeHTTP(w, r)
	})
	ts.Start()

	// Every host name resolves to the test listener.
	dialer := &net.Dialer{}
	httpClient := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, ts.Listener.Addr().String())
		},
	}}
	t.Cleanup(httpClient.CloseIdleConnections)

	rp, err := relyingparty.NewClientWithMetadata(relyingparty.Config{
		Issuer: issuer, ClientID: "app", RedirectURL: callback, HTTPClient: httpClient,
	}, svc.Metadata())
	if err != nil {
		t.Fatal(err)
	}

	ctx := t.Context()
	state, nonce, verifier := "embed-login-state", "embed-login-nonce", oauth2.GenerateVerifier()
	authReq, err := http.NewRequestWithContext(ctx, http.MethodGet, rp.AuthCodeURL(state, nonce, verifier), nil)
	if err != nil {
		t.Fatal(err)
	}
	authReq.Header.Set("X-Test-User", "00000000-0000-0000-0000-0000000000aa")
	noRedirect := *httpClient
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := noRedirect.Do(authReq)
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	cb, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || !strings.HasPrefix(cb.String(), callback) || cb.Query().Get("state") != state || cb.Query().Get("code") == "" {
		t.Fatalf("authorize: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}

	tok, err := rp.Exchange(ctx, cb.Query().Get("code"), verifier)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	rawID, _ := tok.Extra("id_token").(string)
	claims, err := rp.VerifyIDToken(ctx, rawID, nonce)
	if err != nil {
		t.Fatalf("verify ID token: %v", err)
	}
	if claims.Subject != "00000000-0000-0000-0000-0000000000aa" {
		t.Errorf("sub %q", claims.Subject)
	}

	mu.Lock()
	defer mu.Unlock()
	for _, p := range authPaths {
		if p == "/.well-known/openid-configuration" {
			t.Error("relying party fetched the discovery document")
		}
	}
	if len(authPaths) == 0 {
		t.Error("no requests reached SystemAuth")
	}
}
