// Package pgschema applies PostgreSQL-only schema objects that Ent's schema
// definitions cannot express, such as expression indexes. Apply it after
// Ent's migration, and only against PostgreSQL.
package pgschema

import (
	"context"
	"database/sql"
	"fmt"
)

// HumanEmailIndex is the unique index on lower(email) in sf_humans. The
// column's own unique constraint is case-sensitive, while every email
// lookup is case-insensitive, so this index is what prevents two humans
// whose emails differ only in case.
const HumanEmailIndex = "sf_humans_email_lower_key"

// Execer runs a statement. *sql.DB, *sql.Tx, and the identity Ent client
// all satisfy it.
type Execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

var statements = []string{
	"CREATE UNIQUE INDEX IF NOT EXISTS " + HumanEmailIndex + " ON sf_humans (lower(email))",
}

// Apply creates the PostgreSQL-only schema objects. It is idempotent. It
// fails if existing rows violate an index, for example two humans whose
// emails differ only in case; resolve those rows and run it again.
func Apply(ctx context.Context, db Execer) error {
	for _, stmt := range statements {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("pgschema: %s: %w", stmt, err)
		}
	}
	return nil
}
