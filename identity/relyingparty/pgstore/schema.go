package pgstore

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
)

// Table names used by this package.
const (
	// SessionsTable holds relying-party browser sessions.
	SessionsTable = "sf_rp_sessions"
	// LoginStatesTable holds in-flight logins.
	LoginStatesTable = "sf_rp_login_states"
)

// SchemaSQL is the idempotent PostgreSQL schema for the stores. EnsureSchema
// applies it; applications with their own migration tool can copy it.
//
//go:embed schema.sql
var SchemaSQL string

// schemaLockID is the advisory lock serializing concurrent EnsureSchema
// calls from several instances starting at once.
const schemaLockID = 0x73665f72705f7331 // "sf_rp_s1"

// EnsureSchema creates the store tables and indexes when they do not
// exist. It is safe to call on every start and from several instances.
func EnsureSchema(ctx context.Context, db *sql.DB) (err error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("pgstore: beginning schema transaction: %w", err)
	}
	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
				err = errors.Join(err, fmt.Errorf("pgstore: rolling back: %w", rbErr))
			}
		}
	}()
	if _, err = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", int64(schemaLockID)); err != nil {
		return fmt.Errorf("pgstore: locking schema: %w", err)
	}
	if _, err = tx.ExecContext(ctx, SchemaSQL); err != nil {
		return fmt.Errorf("pgstore: applying schema: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("pgstore: committing schema: %w", err)
	}
	return nil
}
