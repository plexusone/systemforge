package relyingparty

import (
	"sync"
	"time"
)

// Revocation timing (ADR-010).
const (
	// DefaultSkewMargin is the default clock-skew margin of a
	// RevocationCache.
	DefaultSkewMargin = 30 * time.Second
	// MinSkewMargin is the smallest margin a RevocationCache accepts; a
	// smaller configured value is raised to it. It is enough where clocks
	// are NTP-disciplined.
	MinSkewMargin = 15 * time.Second
	// DefaultMaxTokenLifetime is the longest access-token lifetime
	// SystemAuth issues. Entries are kept that long, plus the margin,
	// after the change: past that moment no token issued before the change
	// can still be valid at any verifier.
	DefaultMaxTokenLifetime = 15 * time.Minute
)

// AccessChange is a reduction of a principal's access, as SystemAuth
// announces it (ADR-010).
type AccessChange struct {
	// PrincipalID is the SystemAuth principal, the token's sub.
	PrincipalID string
	// OrganizationID scopes the change to one organization; empty means
	// every organization.
	OrganizationID string
	// ChangedAt is when SystemAuth recorded the change, on its clock.
	ChangedAt time.Time
	// Reason says why access changed, such as membership_removed or
	// deactivated. It is opaque here: SystemAuth's registry of reasons grows
	// without a migration, so a value this package does not know is not an
	// error.
	Reason string
}

// AccessChangeSink receives access changes. RevocationCache implements it;
// the replica poller and the back-channel receiver feed one.
type AccessChangeSink interface {
	Record(AccessChange)
}

// RevocationCache remembers recent access changes so a relying party can
// refuse access tokens issued before them (ADR-010). It is keyed by
// principal, and by organization for organization-scoped changes.
//
// A token is accepted only if its iat is at or after the change plus the
// clock-skew margin; a token stamped inside the margin is treated as
// issued before the change. Refusing is cheap and recoverable: the client
// refreshes and gets claims that reflect the change.
//
// An entry is dropped once the change plus the maximum token lifetime plus
// the margin has passed, so the cache holds only the changes of the last
// token lifetime. In a modular monolith one RevocationCache is shared by
// SystemAuth, which records into it, and every relying party, which reads
// it; both use the same clock, so the margin is moot there but applied
// uniformly. It is safe for concurrent use.
type RevocationCache struct {
	margin   time.Duration
	maxLife  time.Duration
	now      func() time.Time
	mu       sync.RWMutex
	entries  map[string]*revocation
	lastSwep time.Time

	// suspect mode (ADR-010 decision 6): changes made while this cache was
	// not listening are unknown, so no token issued before suspectSince is
	// trusted until a replay succeeds.
	suspect      bool
	suspectSince time.Time
}

// revocation is what the cache knows about one principal.
type revocation struct {
	all  time.Time            // latest change across every organization
	orgs map[string]time.Time // latest organization-scoped changes
	max  time.Time            // latest of all and orgs
}

// CacheOption configures a RevocationCache.
type CacheOption func(*RevocationCache)

// WithSkewMargin sets the clock-skew margin. Values below MinSkewMargin
// are raised to it.
func WithSkewMargin(d time.Duration) CacheOption {
	return func(c *RevocationCache) { c.margin = max(d, MinSkewMargin) }
}

// WithMaxTokenLifetime sets the longest access-token lifetime the cache
// must cover, DefaultMaxTokenLifetime by default.
func WithMaxTokenLifetime(d time.Duration) CacheOption {
	return func(c *RevocationCache) {
		if d > 0 {
			c.maxLife = d
		}
	}
}

// WithClock sets the clock that decides when entries expire. For tests.
func WithClock(now func() time.Time) CacheOption {
	return func(c *RevocationCache) { c.now = now }
}

// WithSuspectStart starts the cache in suspect mode, for a relying party
// that restarts or runs in a separate process: until Replay (or a first
// poll) succeeds, only tokens issued at least one margin after the cache
// was created are accepted, so a restart never widens the window in which a
// revoked token is honored.
func WithSuspectStart() CacheOption {
	return func(c *RevocationCache) { c.suspect = true }
}

// NewRevocationCache returns an empty cache.
func NewRevocationCache(opts ...CacheOption) *RevocationCache {
	c := &RevocationCache{
		margin:  DefaultSkewMargin,
		maxLife: DefaultMaxTokenLifetime,
		now:     time.Now,
		entries: map[string]*revocation{},
	}
	for _, o := range opts {
		o(c)
	}
	if c.suspect {
		c.suspectSince = c.now()
	}
	return c
}

// MarkSuspect puts the cache in suspect mode from now: tokens issued
// before now plus the margin are refused until ClearSuspect, which Replay
// and a successful first poll call.
func (c *RevocationCache) MarkSuspect() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.suspect, c.suspectSince = true, c.now()
}

// ClearSuspect ends suspect mode.
func (c *RevocationCache) ClearSuspect() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.suspect, c.suspectSince = false, time.Time{}
}

// Suspect reports whether the cache is in suspect mode.
func (c *RevocationCache) Suspect() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.suspect
}

// Margin returns the clock-skew margin in effect.
func (c *RevocationCache) Margin() time.Duration { return c.margin }

// Record remembers a change. It keeps the latest change per principal and
// organization, so recording the same change twice, or out of order, is
// harmless. A change with no principal or no time is ignored, as is one
// already past its retention.
func (c *RevocationCache) Record(ch AccessChange) {
	if ch.PrincipalID == "" || ch.ChangedAt.IsZero() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if c.expired(ch.ChangedAt, now) {
		return
	}
	e := c.entries[ch.PrincipalID]
	if e == nil {
		e = &revocation{}
		c.entries[ch.PrincipalID] = e
	}
	if ch.OrganizationID == "" {
		if ch.ChangedAt.After(e.all) {
			e.all = ch.ChangedAt
		}
	} else {
		if e.orgs == nil {
			e.orgs = map[string]time.Time{}
		}
		if ch.ChangedAt.After(e.orgs[ch.OrganizationID]) {
			e.orgs[ch.OrganizationID] = ch.ChangedAt
		}
	}
	if ch.ChangedAt.After(e.max) {
		e.max = ch.ChangedAt
	}
	c.sweepLocked(now)
}

// RecordChange records a change from its parts. It lets a package that
// cannot import relyingparty, such as accesschange, feed the cache through
// an interface.
func (c *RevocationCache) RecordChange(principalID, organizationID string, changedAt time.Time, reason string) {
	c.Record(AccessChange{PrincipalID: principalID, OrganizationID: organizationID, ChangedAt: changedAt, Reason: reason})
}

// Accept reports whether a token issued at iat for principalID may be
// used. orgID is the organization the request addresses; when it is empty
// the token is checked against every change to the principal, in any
// organization, which is conservative: it refuses a token for a change that
// may not concern the request, and the client's refresh sets it right.
// A token with a zero iat is accepted only if the principal has no
// recorded change.
func (c *RevocationCache) Accept(principalID, orgID string, iat time.Time) bool {
	changed := c.ChangedAt(principalID, orgID)
	if changed.IsZero() {
		return true
	}
	return !iat.Before(changed.Add(c.margin))
}

// ChangedAt returns the latest unexpired change recorded for the principal
// (in the organization, or in any when orgID is empty), or the zero time.
// In suspect mode it is no earlier than the moment suspect mode began.
func (c *RevocationCache) ChangedAt(principalID, orgID string) time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var changed time.Time
	if e := c.entries[principalID]; e != nil {
		if orgID == "" {
			changed = e.max
		} else {
			changed = e.all
			if t := e.orgs[orgID]; t.After(changed) {
				changed = t
			}
		}
		if !changed.IsZero() && c.expired(changed, c.now()) {
			changed = time.Time{}
		}
	}
	// In suspect mode an unknown change may have happened at any time
	// before the cache started listening.
	if c.suspect && c.suspectSince.After(changed) {
		changed = c.suspectSince
	}
	return changed
}

// ValidFrom returns the earliest iat Accept would take for the principal:
// the latest change plus the margin, or the zero time when there is none.
func (c *RevocationCache) ValidFrom(principalID, orgID string) time.Time {
	changed := c.ChangedAt(principalID, orgID)
	if changed.IsZero() {
		return time.Time{}
	}
	return changed.Add(c.margin)
}

// Len returns the number of principals with a remembered change.
func (c *RevocationCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Sweep drops the entries that are past their retention. Record does it at
// most once a second; call Sweep from a ticker if changes are rare and
// memory matters.
func (c *RevocationCache) Sweep() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweepLocked(c.now())
}

// expired reports whether a change at t no longer matters at now.
func (c *RevocationCache) expired(t, now time.Time) bool {
	return now.After(t.Add(c.maxLife + c.margin))
}

func (c *RevocationCache) sweepLocked(now time.Time) {
	if now.Sub(c.lastSwep) < time.Second {
		return
	}
	c.lastSwep = now
	for id, e := range c.entries {
		for org, t := range e.orgs {
			if c.expired(t, now) {
				delete(e.orgs, org)
			}
		}
		if c.expired(e.all, now) {
			e.all = time.Time{}
		}
		e.max = e.all
		for _, t := range e.orgs {
			if t.After(e.max) {
				e.max = t
			}
		}
		if e.max.IsZero() {
			delete(c.entries, id)
		}
	}
}

var _ AccessChangeSink = (*RevocationCache)(nil)
