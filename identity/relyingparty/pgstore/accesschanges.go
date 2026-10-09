package pgstore

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/plexusone/systemforge/identity/relyingparty"
)

// AccessChangesTable is the table SystemAuth records access changes in
// (identity/ent/schema AccessChange). A relying party that shares
// SystemAuth's database reads it directly; it is not created here.
const AccessChangesTable = "sf_access_changes"

// accessChangesPageSize is how many rows one query reads.
const accessChangesPageSize = 1000

// AccessChangeSource reads access changes from a database that holds
// SystemAuth's sf_access_changes table, for relyingparty.NewAccessChangePoller
// and relyingparty.Replay in replicas of a monolith that share the database
// (ADR-010 decision 4). It issues one indexed query per call, keyset-paged
// by (changed_at, id).
type AccessChangeSource struct {
	db *sql.DB
}

// NewAccessChangeSource returns a source reading db, which must be a
// PostgreSQL database opened with the pgx stdlib driver.
func NewAccessChangeSource(db *sql.DB) *AccessChangeSource {
	return &AccessChangeSource{db: db}
}

// AccessChangesSince implements relyingparty.AccessChangeSource.
func (s *AccessChangeSource) AccessChangesSince(ctx context.Context, since time.Time) ([]relyingparty.AccessChange, error) {
	const columns = `SELECT id::text, principal_id::text, COALESCE(organization_id::text, ''), changed_at, reason FROM ` + AccessChangesTable
	// The first page is strictly after since; later pages continue after
	// the last row read, by (changed_at, id), so rows sharing a timestamp
	// are neither skipped nor repeated across a page boundary.
	const first = columns + ` WHERE changed_at > $1 ORDER BY changed_at, id::text LIMIT $2`
	const next = columns + ` WHERE (changed_at, id::text) > ($1, $2) ORDER BY changed_at, id::text LIMIT $3`
	var out []relyingparty.AccessChange
	afterTime, afterID := since.UTC(), ""
	for {
		var rows *sql.Rows
		var err error
		if afterID == "" {
			rows, err = s.db.QueryContext(ctx, first, afterTime, accessChangesPageSize)
		} else {
			rows, err = s.db.QueryContext(ctx, next, afterTime, afterID, accessChangesPageSize)
		}
		if err != nil {
			return nil, fmt.Errorf("pgstore: reading access changes: %w", err)
		}
		n := 0
		for rows.Next() {
			var id string
			var c relyingparty.AccessChange
			if err := rows.Scan(&id, &c.PrincipalID, &c.OrganizationID, &c.ChangedAt, &c.Reason); err != nil {
				return nil, closeWith(rows, fmt.Errorf("pgstore: scanning access change: %w", err))
			}
			out = append(out, c)
			afterTime, afterID = c.ChangedAt, id
			n++
		}
		if err := rows.Err(); err != nil {
			return nil, closeWith(rows, fmt.Errorf("pgstore: reading access changes: %w", err))
		}
		if err := rows.Close(); err != nil {
			return nil, fmt.Errorf("pgstore: closing access changes: %w", err)
		}
		if n < accessChangesPageSize {
			return out, nil
		}
	}
}

// closeWith closes rows and returns err, joined with a close failure.
func closeWith(rows *sql.Rows, err error) error {
	if cerr := rows.Close(); cerr != nil {
		return fmt.Errorf("%w (closing rows: %v)", err, cerr)
	}
	return err
}

var _ relyingparty.AccessChangeSource = (*AccessChangeSource)(nil)
