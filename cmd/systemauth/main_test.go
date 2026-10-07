package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/plexusone/systemforge/identity/systemauth"
	"github.com/plexusone/systemforge/identity/systemauthsvc"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func testKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func TestNormalizeArgs(t *testing.T) {
	got := normalizeArgs([]string{"-addr", "127.0.0.1:8081", "-config=/etc/x.yaml", "-c", "y", "--dev", "serve", "--", "-zz"})
	want := []string{"--addr", "127.0.0.1:8081", "--config=/etc/x.yaml", "-c", "y", "--dev", "serve", "--", "-zz"}
	if !slices.Equal(got, want) {
		t.Errorf("normalizeArgs = %v", got)
	}
}

// parse runs the root command's flag parsing and env application without
// serving.
func parse(t *testing.T, args ...string) *options {
	t.Helper()
	opts := &options{}
	cmd := newRootCmdWithOptions(opts)
	cmd.RunE = func(*cobra.Command, []string) error { return nil }
	cmd.SetArgs(normalizeArgs(args))
	cmd.SetOut(io.Discard)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	return opts
}

func TestFlagsFromEnvironment(t *testing.T) {
	t.Setenv("SYSTEMAUTH_ADDR", "127.0.0.1:9000")
	t.Setenv("SYSTEMAUTH_DEV", "true")
	t.Setenv("SYSTEMAUTH_KEY_ID", "env-kid")

	opts := parse(t)
	if opts.addr != "127.0.0.1:9000" || !opts.dev || opts.keyID != "env-kid" {
		t.Errorf("env not applied: %+v", opts)
	}
	// Command-line flags win over the environment.
	opts = parse(t, "-addr", "127.0.0.1:8081")
	if opts.addr != "127.0.0.1:8081" {
		t.Errorf("flag did not override env: %q", opts.addr)
	}
}

func TestProductionRequirements(t *testing.T) {
	_, err := newApp(t.Context(), &options{issuer: "http://auth.example.com", addr: ":0", migrate: true}, discardLogger())
	if err == nil {
		t.Fatal("started without key, database and https issuer")
	}
	for _, want := range []string{"signing key", "https", "database"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}

	// Dev mode relaxes them (ephemeral key, in-memory storage).
	a, err := newApp(t.Context(), &options{dev: true, addr: ":8081", migrate: true}, discardLogger())
	if err != nil {
		t.Fatalf("dev mode: %v", err)
	}
	closeApp(t, a)
	if a.Issuer() != "http://localhost:8081" || a.StorageName() != "in-memory" {
		t.Errorf("dev defaults: %q %q", a.Issuer(), a.StorageName())
	}
}

func TestProductionServerWithKeyFromEnv(t *testing.T) {
	t.Setenv(signingKeyEnv, testKeyPEM(t))
	dbPath := filepath.Join(t.TempDir(), "systemauth.db")
	opts := &options{
		issuer:   "https://auth.example.com",
		addr:     "127.0.0.1:8081",
		keyID:    "prod-1",
		dbDriver: "sqlite",
		dbDSN:    "file:" + dbPath + "?_fk=1",
		migrate:  true,
	}
	a, err := newApp(t.Context(), opts, discardLogger())
	if err != nil {
		t.Fatalf("newApp: %v", err)
	}
	closeApp(t, a)
	if a.KeyID() != "prod-1" || a.StorageName() != "sqlite" {
		t.Errorf("key id %q storage %q", a.KeyID(), a.StorageName())
	}

	get := func(path string) (int, map[string]any) {
		w := httptest.NewRecorder()
		a.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		var body map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s: %v %s", path, err, w.Body.String())
		}
		return w.Code, body
	}
	if code, body := get("/.well-known/jwks.json"); code != http.StatusOK || !strings.Contains(toJSON(t, body), `"kid":"prod-1"`) {
		t.Errorf("jwks: %d %v", code, body)
	}
	if code, body := get("/healthz"); code != http.StatusOK || body["status"] != "ok" {
		t.Errorf("healthz: %d %v", code, body)
	}
	if code, body := get("/readyz"); code != http.StatusOK || toJSON(t, body["checks"]) != `{"database":"ok"}` {
		t.Errorf("readyz: %d %v", code, body)
	}

	// A lost database makes the server unready.
	if err := a.EntClient().Close(); err != nil {
		t.Fatal(err)
	}
	if code, body := get("/readyz"); code != http.StatusServiceUnavailable || body["status"] != "unavailable" {
		t.Errorf("readyz after db loss: %d %v", code, body)
	}
}

// closeApp closes the service when the test ends.
func closeApp(t *testing.T, a *systemauthsvc.Service) {
	t.Helper()
	t.Cleanup(func() {
		if err := a.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
}

func toJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSigningKeyFileAndRotationKeyID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, []byte(testKeyPEM(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(&options{issuer: "https://auth.example.com", signingKeyFile: path})
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Keys.LoadSigningKey(); err != nil {
		t.Fatal(err)
	}
	s, err := systemauth.NewEmbedded(*cfg, systemauth.WithLogger(discardLogger()))
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	thumb, err := systemauth.KeyThumbprint(cfg.Keys.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Keys.PrivateKey == nil || s.KeyID() != thumb {
		t.Errorf("default kid %q, want thumbprint %q", s.KeyID(), thumb)
	}

	// A bad key file fails fast.
	bad := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(bad, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err = loadConfig(&options{issuer: "https://auth.example.com", signingKeyFile: bad})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := systemauth.NewEmbedded(*cfg, systemauth.WithLogger(discardLogger())); err == nil {
		t.Error("invalid key file accepted")
	}
}
