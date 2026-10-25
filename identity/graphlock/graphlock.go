// Package graphlock serializes the transactions that remove relationships
// from the authorization graph with the graph reconciler's repairs.
//
// A revocation removes the relationship from the graph inside the
// transaction that changes the database, after the database change and
// before the commit, holding the lock of every principal and organization
// whose relationships it removes. The reconciler (authz/mode) writes a
// missing relationship back only in a transaction holding the same locks,
// after reading the rows again. Whichever runs second sees the other's
// result: the reconciler cannot restore a relationship a revocation is
// removing, and a revocation cannot be undone by a repair already under
// way.
//
// The locks are PostgreSQL transaction-scoped advisory locks, released when
// the transaction ends. SQLite has no advisory locks; Lock does nothing
// there, so the guarantee needs PostgreSQL.
package graphlock

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
)

// Key prefixes. Organization keys sort before principal keys, so every
// transaction takes an organization's lock before a principal's.
const (
	orgPrefix       = "sf-authz-graph:o:"
	principalPrefix = "sf-authz-graph:p:"
)

// Organization is the lock key of an organization's relationships.
func Organization(id uuid.UUID) string { return orgPrefix + id.String() }

// Principal is the lock key of a principal's relationships: those it holds
// in organizations, applications and resources, its platform
// administration, and the manager relations on it.
func Principal(id uuid.UUID) string { return principalPrefix + id.String() }

// Lock takes the transaction-scoped locks named by keys, in sorted order so
// that two transactions locking overlapping sets cannot deadlock. The locks
// are held until tx commits or rolls back. On SQLite it does nothing.
func Lock(ctx context.Context, tx *ent.Tx, keys ...string) error {
	keys = slices.Clone(keys)
	slices.Sort(keys)
	keys = slices.Compact(keys)
	for _, k := range keys {
		_, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", k)
		if err == nil {
			continue
		}
		// SQLite reports the missing function when it prepares the
		// statement, which leaves its transaction usable.
		if strings.Contains(err.Error(), "no such function") {
			return nil
		}
		return fmt.Errorf("graphlock: locking %s: %w", k, err)
	}
	return nil
}

// Grant writes to the graph the access a committed change granted, without
// undoing a revocation that committed since. It runs write in a
// transaction holding the locks named by keys; write reads the rows again
// through c, the transaction's client, and writes only the relationships
// they still call for (package identity/graphstate). A revocation holding
// one of the locks finishes first, so write sees its result; one that
// starts later waits for write, and removes what it wrote.
//
// The transaction only reads and is rolled back when write returns. Grant
// returns write's error, joined with a failure to end the transaction.
// Lock it with the same keys as the reconciler's repair of the
// relationship: the organization and the principal for a relationship on
// an organization, its facet or a resource in it, the principal alone for
// platform administration, and both principals for a manager relation.
func Grant(ctx context.Context, client *ent.Client, keys []string, write func(ctx context.Context, c *ent.Client) error) (err error) {
	tx, err := client.Tx(ctx)
	if err != nil {
		return fmt.Errorf("graphlock: starting transaction: %w", err)
	}
	defer func() {
		if rerr := tx.Rollback(); rerr != nil {
			err = errors.Join(err, fmt.Errorf("graphlock: ending transaction: %w", rerr))
		}
	}()
	if err = Lock(ctx, tx, keys...); err != nil {
		return err
	}
	return write(ctx, tx.Client())
}
