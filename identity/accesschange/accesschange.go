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
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/accesschange"
	"github.com/plexusone/systemforge/identity/relyingparty"
)

// Access-token lifetimes (ADR-010 decision 1). Lifetime is the fallback
// bound on how long a change can go unseen, so it is short by default and
// capped.
const (
	// DefaultAccessTokenLifetime is the access-token lifetime when none is
	// configured.
	DefaultAccessTokenLifetime = 10 * time.Minute
	// MaxAccessTokenLifetime is the longest access-token lifetime a
	// deployment, client or application may configure.
	MaxAccessTokenLifetime = 15 * time.Minute
)

// ClampAccessTokenLifetime returns d limited to MaxAccessTokenLifetime. A
// non-positive d returns DefaultAccessTokenLifetime.
func ClampAccessTokenLifetime(d time.Duration) time.Duration {
	switch {
	case d <= 0:
		return DefaultAccessTokenLifetime
	case d > MaxAccessTokenLifetime:
		return MaxAccessTokenLifetime
	}
	return d
}

// Reason says why access changed.
//
// The reasons form an open registry: the constants below are the complete
// list, sf_access_changes stores the value as a plain string, and Record
// rejects any value that is not registered. Adding a reason is therefore a
// code and documentation change with no migration: declare the constant,
// add it to Reasons, and add a row to the reason table in
// docs/design/architecture/authorization.md. TestRegistry fails when a
// constant is missing from Reasons, a reason has no documentation row, or a
// call site passes a value that is not registered.
//
// Reasons are wire values: they appear in the back-channel access_change
// event and in GET /access-changes, so a value is never renamed or reused
// for a different meaning. Relying parties treat the reason as opaque, so a
// reason added later does not break an older relying party.
type Reason string

// Reasons.
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
	// ManagementGranted: the principal came under management and gave up
	// the capabilities a managed principal does not hold (ADR-009).
	ManagementGranted Reason = "management_granted"
	// ManagementEnded: the principal's management ended and its own
	// capabilities were restored (ADR-009).
	ManagementEnded Reason = "management_ended"
)

// registry is the complete list of reasons. A reason is valid if and only
// if it is listed here.
var registry = []Reason{
	MembershipRemoved,
	OrgRoleChanged,
	AppRoleChanged,
	GrantReduced,
	Deactivated,
	SessionsRevoked,
	ManagementGranted,
	ManagementEnded,
}

// Reasons returns the registered reasons.
func Reasons() []Reason {
	return slices.Clone(registry)
}

// Valid reports whether r is a registered reason.
func (r Reason) Valid() bool {
	return slices.Contains(registry, r)
}

// Validate returns an error naming r when it is not a registered reason.
func (r Reason) Validate() error {
	if r.Valid() {
		return nil
	}
	return fmt.Errorf("accesschange: unknown reason %q: register it in accesschange.Reasons and document it in the authorization architecture page", string(r))
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

// ChangeRecorder takes a change as its parts. relyingparty.RevocationCache
// implements it, which keeps the relying-party package free of the identity
// store that this one depends on.
type ChangeRecorder interface {
	RecordChange(principalID, organizationID string, changedAt time.Time, reason string)
}

// ToSink adapts a ChangeRecorder, such as a relyingparty.RevocationCache,
// to a Sink, so one cache can be passed to every service's
// WithAccessChangeSink option and read by the relying parties of the same
// process.
func ToSink(r ChangeRecorder) Sink {
	return SinkFunc(func(c Change) {
		org := ""
		if c.OrganizationID != nil {
			org = c.OrganizationID.String()
		}
		r.RecordChange(c.PrincipalID.String(), org, c.ChangedAt, string(c.Reason))
	})
}

// Record writes c to sf_access_changes inside tx and returns it with
// ChangedAt set. Call it in the transaction that makes the change, so the
// record exists if and only if the change does, then hand the result to
// Publish after the commit.
func Record(ctx context.Context, tx *ent.Tx, c Change) (Change, error) {
	if c.PrincipalID == uuid.Nil {
		return Change{}, errors.New("accesschange: principal is required")
	}
	if err := c.Reason.Validate(); err != nil {
		return Change{}, err
	}
	c.ChangedAt = time.Now().UTC()
	create := tx.AccessChange.Create().
		SetPrincipalID(c.PrincipalID).
		SetChangedAt(c.ChangedAt).
		SetReason(string(c.Reason))
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
const Retention = MaxAccessTokenLifetime + time.Minute + time.Hour

// PruneExpired deletes the changes older than Retention.
func PruneExpired(ctx context.Context, client *ent.Client) (int, error) {
	return Prune(ctx, client, time.Now().Add(-Retention))
}

// Source reads changes through an Ent client, for replicas of a monolith
// that share SystemAuth's database and already hold a client. It
// implements relyingparty.AccessChangeSource. relyingparty/pgstore offers
// the same over plain database/sql.
type Source struct {
	client *ent.Client
}

// NewSource returns a Source reading client.
func NewSource(client *ent.Client) *Source { return &Source{client: client} }

// AccessChangesSince implements relyingparty.AccessChangeSource.
func (s *Source) AccessChangesSince(ctx context.Context, since time.Time) ([]relyingparty.AccessChange, error) {
	var out []relyingparty.AccessChange
	for {
		page, err := Since(ctx, s.client, since, 1000)
		if err != nil {
			return nil, err
		}
		for _, c := range page {
			org := ""
			if c.OrganizationID != nil {
				org = c.OrganizationID.String()
			}
			out = append(out, relyingparty.AccessChange{PrincipalID: c.PrincipalID.String(), OrganizationID: org, ChangedAt: c.ChangedAt, Reason: string(c.Reason)})
		}
		if len(page) < 1000 {
			return out, nil
		}
		// Rows with the newest timestamp may continue on the next page;
		// recording a change twice is harmless.
		next := page[len(page)-1].ChangedAt.Add(-time.Nanosecond)
		if !next.After(since) {
			// A full page of changes sharing one timestamp cannot be
			// advanced past; the poller re-reads that moment next time.
			return out, nil
		}
		since = next
	}
}

// List implements the reader systemauth serves GET /access-changes from:
// up to limit changes after since, oldest first.
func (s *Source) List(ctx context.Context, since time.Time, limit int) ([]Change, error) {
	return Since(ctx, s.client, since, limit)
}
