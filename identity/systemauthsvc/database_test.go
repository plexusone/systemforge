package systemauthsvc_test

import (
	"bytes"
	"database/sql"
	"slices"
	"strings"
	"testing"

	"github.com/plexusone/systemforge/identity/systemauth"
	"github.com/plexusone/systemforge/identity/systemauthsvc"
)

func TestOpenDatabaseDrivers(t *testing.T) {
	if !slices.Contains(sql.Drivers(), "pgx") || !slices.Contains(sql.Drivers(), "sqlite3") {
		t.Fatalf("drivers not registered: %v", sql.Drivers())
	}
	// Opening is lazy: a postgres DSN yields a client without connecting.
	//nolint:gosec // G101: dummy DSN for a closed local port
	db, err := systemauthsvc.OpenDatabase(&systemauth.DatabaseConfig{Driver: "postgres", DSN: "postgres://u:p@127.0.0.1:1/x?sslmode=disable"})
	if err != nil {
		t.Fatalf("postgres: %v", err)
	}
	if err := db.DB.PingContext(t.Context()); err == nil {
		t.Error("ping to closed port succeeded")
	}
	if err := db.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
	for _, driver := range []string{"mysql", "oracle"} {
		if _, err := systemauthsvc.OpenDatabase(&systemauth.DatabaseConfig{Driver: driver, DSN: "x"}); err == nil {
			t.Errorf("%s accepted", driver)
		}
	}
}

func TestNewLogger(t *testing.T) {
	var buf bytes.Buffer
	logger, err := systemauthsvc.NewLogger(&buf, "warn", "json")
	if err != nil {
		t.Fatal(err)
	}
	logger.Info("hidden")
	logger.Warn("shown")
	if out := buf.String(); strings.Contains(out, "hidden") || !strings.Contains(out, `"msg":"shown"`) {
		t.Errorf("output %q", out)
	}
	if _, err := systemauthsvc.NewLogger(&buf, "loud", "text"); err == nil {
		t.Error("invalid level accepted")
	}
	if _, err := systemauthsvc.NewLogger(&buf, "info", "xml"); err == nil {
		t.Error("invalid format accepted")
	}
}
