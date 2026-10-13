package systemauthsvc_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/plexusone/connectionforge/provider"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/connections"
	"github.com/plexusone/systemforge/identity/systemauth"
	"github.com/plexusone/systemforge/identity/systemauthsvc"
)

const rootKeyEnv = "SF_TEST_CONNECTIONS_ROOT_KEY"

func connectionsConfig(t *testing.T) *systemauthsvc.Config {
	t.Helper()
	t.Setenv(rootKeyEnv, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	return &systemauthsvc.Config{
		Issuer:   "https://auth.example.com",
		Database: &systemauth.DatabaseConfig{Driver: "sqlite", DSN: sqliteDSN(t)},
		Connections: &systemauth.ConnectionsConfig{
			KeysDir: filepath.Join(t.TempDir(), "keys"),
			Vault:   "env://",
			RootKey: rootKeyEnv,
		},
	}
}

func TestConnectionsAreServedWhenConfigured(t *testing.T) {
	cfg := connectionsConfig(t)
	if err := systemauthsvc.Migrate(t.Context(), cfg); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	s, err := systemauthsvc.New(t.Context(), cfg, systemauthsvc.Options{
		SigningKey: testKey(t), Logger: discardLogger(), Migrate: true, Providers: provider.NewRegistry(),
	})
	if err != nil {
		t.Fatal(err)
	}
	closeService(t, s)
	if s.Connections() == nil || s.Connections().Broker == nil {
		t.Fatal("connections not enabled")
	}

	org := "/api/v1/organizations/00000000-0000-0000-0000-000000000001/connections"
	for _, rt := range [][2]string{
		{http.MethodGet, connections.ProvidersPath},
		{http.MethodGet, org},
		{http.MethodPost, org + "/x/test"},
		{http.MethodDelete, org + "/x"},
	} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest(rt[0], rt[1], nil))
		if w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") == "" {
			t.Errorf("%s %s without a token: %d", rt[0], rt[1], w.Code)
		}
	}

	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.RunJobs(ctx) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RunJobs did not stop when its context ended")
	}
}

func TestConnectionsAreOffByDefault(t *testing.T) {
	s, err := systemauthsvc.New(t.Context(), &systemauthsvc.Config{Issuer: "https://auth.example.com"},
		systemauthsvc.Options{Dev: true, Logger: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	closeService(t, s)
	if s.Connections() != nil {
		t.Fatal("connections enabled without configuration")
	}
	if err := s.RunJobs(t.Context()); err != nil {
		t.Fatalf("RunJobs with nothing to run: %v", err)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, connections.ProvidersPath, nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("providers route without connections: %d", w.Code)
	}
}

func TestConnectionsConfigErrors(t *testing.T) {
	opts := systemauthsvc.Options{SigningKey: testKey(t), Logger: discardLogger(), Migrate: true}

	cfg := connectionsConfig(t)
	cfg.Connections.RootKey = ""
	if _, err := systemauthsvc.New(t.Context(), cfg, opts); err == nil {
		t.Error("missing root_key accepted")
	}

	cfg = connectionsConfig(t)
	cfg.Connections.RootKey = "SF_TEST_UNSET_ROOT_KEY"
	if _, err := systemauthsvc.New(t.Context(), cfg, opts); err == nil {
		t.Error("unset root key accepted")
	}

	cfg = connectionsConfig(t)
	cfg.Authz = authz.ModeConfig{Mode: authz.ModeReBAC, Engine: authz.EngineSpiceDB}
	if _, err := systemauthsvc.New(t.Context(), cfg, opts); err == nil {
		t.Error("connections with rebac accepted")
	}

	cfg = connectionsConfig(t)
	cfg.Database = nil
	if _, err := systemauthsvc.New(t.Context(), cfg, systemauthsvc.Options{Dev: true, Logger: discardLogger()}); err == nil {
		t.Error("connections without a database accepted")
	}
}
