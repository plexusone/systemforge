package main

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/plexusone/systemforge/internal/pgtest"
)

// TestPostgresRestartKeepsSocialLoginState starts the server twice on the
// same PostgreSQL database (a restart, or a second replica) with social
// login and a static client configured, and checks the social login
// tables exist. Skipped unless SF_TEST_PG_DSN is set.
func TestPostgresRestartKeepsSocialLoginState(t *testing.T) {
	dsn := pgtest.DSN(t)
	t.Setenv(signingKeyEnv, testKeyPEM(t))
	cfgPath := filepath.Join(t.TempDir(), "systemauth.yaml")
	cfg := `issuer: https://auth.example.com
clients:
  - id: web
    type: public
    name: Web
    redirect_uris: ["https://app.example.com/callback"]
    grant_types: ["authorization_code", "refresh_token"]
    response_types: ["code"]
    scopes: ["openid", "profile", "email"]
social_login:
  github:
    client_id: gh-id
    client_secret: gh-secret
  allowed_redirect_origins: ["https://app.example.com"]
`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := &options{configFile: cfgPath, addr: "127.0.0.1:8081", dbDriver: "postgres", dbDSN: dsn, migrate: true}

	for i := range 2 {
		a, err := newApp(t.Context(), opts, discardLogger())
		if err != nil {
			t.Fatalf("start %d: %v", i+1, err)
		}
		if err := a.Close(); err != nil {
			t.Fatalf("close %d: %v", i+1, err)
		}
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	for _, table := range []string{"sf_login_sessions", "sf_login_states", "sf_consent_grants"} {
		var exists bool
		if err := db.QueryRowContext(context.Background(), "SELECT to_regclass($1) IS NOT NULL", table).Scan(&exists); err != nil {
			t.Fatalf("checking %s: %v", table, err)
		}
		if !exists {
			t.Errorf("table %s was not created", table)
		}
	}
}
