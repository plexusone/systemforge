package systemauthsvc_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/systemauth"
	"github.com/plexusone/systemforge/identity/systemauthsvc"
	"github.com/plexusone/systemforge/internal/pgtest"
)

func createHuman(ctx context.Context, db *ent.Client, email string) error {
	id := uuid.New()
	if _, err := db.Principal.Create().
		SetID(id).
		SetType(principal.TypeHuman).
		SetIdentifier(email).
		SetDisplayName(email).
		Save(ctx); err != nil {
		return err
	}
	_, err := db.Human.Create().SetPrincipalID(id).SetEmail(email).Save(ctx)
	return err
}

// TestPostgresHumanEmailIsCaseInsensitivelyUnique verifies that migrating
// a PostgreSQL database creates the lower(email) unique index, so the
// database itself rejects two humans whose emails differ only in case,
// even when a writer bypasses the application-level check.
func TestPostgresHumanEmailIsCaseInsensitivelyUnique(t *testing.T) {
	dbCfg := &systemauth.DatabaseConfig{Driver: "postgres", DSN: pgtest.DSN(t)}
	cfg := &systemauthsvc.Config{Issuer: "https://auth.example.com", Database: dbCfg}
	for i := range 2 {
		if err := systemauthsvc.Migrate(t.Context(), cfg); err != nil {
			t.Fatalf("Migrate %d: %v", i+1, err)
		}
	}

	db, err := systemauthsvc.OpenDatabase(dbCfg)
	if err != nil {
		t.Fatalf("OpenDatabase: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	ctx := t.Context()

	if err := createHuman(ctx, db.Client, "Ada@Example.com"); err != nil {
		t.Fatalf("first human: %v", err)
	}
	err = createHuman(ctx, db.Client, "ada@example.com")
	if err == nil {
		t.Fatal("a second human whose email differs only in case was accepted")
	}
	if !ent.IsConstraintError(err) {
		t.Errorf("error = %v, want a unique constraint violation", err)
	}
}
