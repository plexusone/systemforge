// Package accesschange records and announces reductions of a principal's
// access (ADR-010).
//
// Access tokens are self-contained JWTs, so a relying party cannot see that
// a principal was removed from an organization, lost an application role or
// was deactivated until the token expires. SystemAuth therefore writes an
// access-change record in the transaction that makes the change (Record),
// and after commit announces it to a Sink (Publish). A relying party
// refuses tokens issued before a recorded change, which closes the window
// to one request in the same process, one polling interval on a replica,
// and the delivery time across a process boundary; the token lifetime
// remains the fallback bound.
//
// Rows are kept only as long as a token issued before the change could
// still be valid anywhere; Prune removes older ones.
package accesschange

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/accesschange"
)

// Reason says why access changed.
type Reason string

// Reasons, matching the sf_access_changes enum.
const (
	// MembershipRemoved: the principal was removed from, or deactivated
	// in, an organization.
	MembershipRemoved Reason = "membership_removed"
	// OrgRoleChanged: the principal's organization role changed.
	OrgRoleChanged Reason = "org_role_changed"
	// AppRoleChanged: an application role was changed or removed.
	AppRoleChanged Reason = "app_role_changed"
	// GrantReduced: a resource grant was reduced or removed (ADR-008).
	GrantReduced Reason = "grant_reduced"
	// Deactivated: the principal was deactivated.
	Deactivated Reason = "deactivated"
	// SessionsRevoked: the principal's sessions or tokens were revoked.
	SessionsRevoked Reason = "sessions_revoked"
)

// Valid reports whether r is one of the defined reasons.
func (r Reason) Valid() bool {
	return accesschange.ReasonValidator(accesschange.Reason(r)) == nil
}

// Change is one recorded access change.
type Change struct {
	// PrincipalID is the principal whose access changed.
	PrincipalID uuid.UUID
	// OrganizationID scopes the change to one organization; nil means
	// every organization.
	OrganizationID *uuid.UUID
	// ChangedAt is when the change was recorded, on the server clock. It
	// is set by Record; callers leave it zero.
	ChangedAt time.Time
	// Reason says why access changed.
	Reason Reason
}

// Sink receives access changes after the transaction that recorded them
// commits. Implementations must be safe for concurrent use and must not
// block: a revocation cache writes to memory, and a back-channel sender
// queues. relyingparty.RevocationCache is adapted to a Sink by
// relyingparty.AccessChangeSink.
type Sink interface {
	AccessChange(Change)
}

// SinkFunc adapts a function to Sink.
type SinkFunc func(Change)

// AccessChange implements Sink.
func (f SinkFunc) AccessChange(c Change) { f(c) }

// Record writes c to sf_access_changes inside tx and returns it with
// ChangedAt set. Call it in the transaction that makes the change, so the
// record exists if and only if the change does, then hand the result to
// Publish after the commit.
func Record(ctx context.Context, tx *ent.Tx, c Change) (Change, error) {
	if c.PrincipalID == uuid.Nil {
		return Change{}, errors.New("accesschange: principal is required")
	}
	if !c.Reason.Valid() {
		return Change{}, fmt.Errorf("accesschange: unknown reason %q", c.Reason)
	}
	c.ChangedAt = time.Now().UTC()
	create := tx.AccessChange.Create().
		SetPrincipalID(c.PrincipalID).
		SetChangedAt(c.ChangedAt).
		SetReason(accesschange.Reason(c.Reason))
	if c.OrganizationID != nil {
		create.SetOrganizationID(*c.OrganizationID)
	}
	if _, err := create.Save(ctx); err != nil {
		return Change{}, fmt.Errorf("accesschange: recording: %w", err)
	}
	return c, nil
}

// Publish announces changes to sink after their transaction committed. A
// nil sink is ignored, so services without one need no checks.
func Publish(sink Sink, changes ...Change) {
	if sink == nil {
		return
	}
	for _, c := range changes {
		sink.AccessChange(c)
	}
}

// Since lists the changes recorded after since, oldest first, up to limit
// (0 means 1000). Times are compared in UTC, as they are stored, which
// SQLite needs because it compares timestamps as text. A poller or the replay endpoint reads with it.
func Since(ctx context.Context, client *ent.Client, since time.Time, limit int) ([]Change, error) {
	if limit <= 0 {
		limit = 1000
	}
	rows, err := client.AccessChange.Query().
		Where(accesschange.ChangedAtGT(since.UTC())).
		Order(ent.Asc(accesschange.FieldChangedAt), ent.Asc(accesschange.FieldID)).
		Limit(limit).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("accesschange: reading changes: %w", err)
	}
	out := make([]Change, len(rows))
	for i, r := range rows {
		out[i] = Change{PrincipalID: r.PrincipalID, OrganizationID: r.OrganizationID, ChangedAt: r.ChangedAt, Reason: Reason(r.Reason)}
	}
	return out, nil
}

// Prune deletes the changes recorded before cutoff and reports how many it
// deleted. A change matters only while a token issued before it could be
// valid, so cutoff is the maximum access-token lifetime plus the
// relying-party clock-skew margin before now, with some slack for
// pollers: Retention is that.
func Prune(ctx context.Context, client *ent.Client, cutoff time.Time) (int, error) {
	n, err := client.AccessChange.Delete().Where(accesschange.ChangedAtLT(cutoff.UTC())).Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("accesschange: pruning: %w", err)
	}
	return n, nil
}

// Retention is how long a change is kept: the maximum access-token
// lifetime, the largest clock-skew margin a relying party is expected to
// use, and an hour of slack for pollers and replay that are behind.
const Retention = 15*time.Minute + time.Minute + time.Hour

// PruneExpired deletes the changes older than Retention.
func PruneExpired(ctx context.Context, client *ent.Client) (int, error) {
	return Prune(ctx, client, time.Now().Add(-Retention))
}
