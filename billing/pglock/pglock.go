// Package pglock is a payforge.Locker that holds across instances, with a
// PostgreSQL transaction-scoped advisory lock.
//
// Lock opens a transaction on a connection of its own and takes
// pg_advisory_xact_lock on a 64-bit hash of the key; unlock rolls the
// transaction back, which releases the lock. The work under the lock runs
// on other connections; the transaction exists only to hold the lock.
// Because the lock belongs to a transaction rather than a session, it
// cannot outlive its connection: a connection that breaks releases it, and
// it is never left held on a connection returned to the pool.
//
// Set the same Locker on payforge.Lifecycle.Locker, the payforge Stripe
// client's Config.Locker and billing's configs, so webhooks and checkouts
// for one organization exclude each other. The lock is not reentrant: never
// take a key while already holding it.
//
// It is PostgreSQL only, which is why it is a package of its own: the rest
// of billing runs on any Ent dialect.
package pglock

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/plexusone/payforge"
)

// prefix keeps these keys apart from other advisory locks in the database.
const prefix = "sf-billing:"

// Locker implements payforge.Locker on PostgreSQL.
type Locker struct {
	db  *sql.DB
	log *slog.Logger
}

var _ payforge.Locker = (*Locker)(nil)

// New returns a Locker on db, which must be PostgreSQL. A failure to
// release a lock, which the database also releases when the connection
// ends, is logged to logger, or slog.Default() when it is nil. New panics
// on a nil db, a programming error.
//
// Each held lock uses one connection from db's pool until it is released,
// so size the pool for the concurrent webhook deliveries and checkouts
// plus the work they do.
func New(db *sql.DB, logger *slog.Logger) *Locker {
	if db == nil {
		panic("pglock: New needs a database")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Locker{db: db, log: logger}
}

// Lock implements payforge.Locker. Waiting ends with ctx; once held, the
// lock lasts until unlock is called, whatever happens to ctx.
func (l *Locker) Lock(ctx context.Context, key string) (func(), error) {
	// The transaction outlives ctx: a request ending must not release the
	// lock while the work under it is still running.
	tx, err := l.db.BeginTx(context.WithoutCancel(ctx), nil)
	if err != nil {
		return nil, fmt.Errorf("pglock: begin: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", prefix+key); err != nil {
		if rerr := tx.Rollback(); rerr != nil && !errors.Is(rerr, sql.ErrTxDone) {
			err = errors.Join(err, rerr)
		}
		return nil, fmt.Errorf("pglock: lock: %w", err)
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
				l.log.Error("pglock: releasing a lock; the database releases it when the connection closes", "error", err)
			}
		})
	}, nil
}
