package systemauth

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/consentgrant"
	"github.com/plexusone/systemforge/identity/ent/loginsession"
	"github.com/plexusone/systemforge/identity/ent/loginstate"
	"github.com/plexusone/systemforge/identity/oauthclient"
)

// DefaultStoreCleanupInterval is how often the Ent-backed social login
// stores opportunistically delete expired rows while handling writes.
const DefaultStoreCleanupInterval = 5 * time.Minute

// EntStoreOption configures the Ent-backed social login stores.
type EntStoreOption func(*entStoreConfig)

type entStoreConfig struct {
	cleanupInterval time.Duration
	now             func() time.Time
}

// WithCleanupInterval sets how often a store deletes expired rows while
// handling writes. Zero or negative disables opportunistic cleanup; call
// DeleteExpired from a scheduled job instead.
func WithCleanupInterval(d time.Duration) EntStoreOption {
	return func(c *entStoreConfig) { c.cleanupInterval = d }
}

// withStoreClock overrides the clock (tests).
func withStoreClock(now func() time.Time) EntStoreOption {
	return func(c *entStoreConfig) { c.now = now }
}

func newEntStoreConfig(opts []EntStoreOption) entStoreConfig {
	c := entStoreConfig{cleanupInterval: DefaultStoreCleanupInterval, now: time.Now}
	for _, opt := range opts {
		opt(&c)
	}
	// Times are stored and compared in UTC: SQLite compares them as text.
	clock := c.now
	c.now = func() time.Time { return clock().UTC() }
	return c
}

// cleanupGate rate-limits opportunistic expired-row cleanup per instance.
type cleanupGate struct {
	interval time.Duration
	mu       sync.Mutex
	next     time.Time
}

// due reports whether a cleanup should run now, and if so schedules the next.
func (g *cleanupGate) due(now time.Time) bool {
	if g.interval <= 0 {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if now.Before(g.next) {
		return false
	}
	g.next = now.Add(g.interval)
	return true
}

// maybeCleanup runs deleteExpired when the gate allows. A cleanup failure
// does not fail the caller's write: it is logged and retried next interval.
func maybeCleanup(ctx context.Context, g *cleanupGate, now time.Time, store string, deleteExpired func(context.Context) (int, error)) {
	if !g.due(now) {
		return
	}
	if _, err := deleteExpired(ctx); err != nil {
		LoggerFromContext(ctx).Warn("deleting expired rows", "store", store, "error", err)
	}
}

// EntLoginSessionStore is a LoginSessionStore backed by the sf_login_sessions
// table. Only token hashes are stored. It is safe for concurrent use and
// shared by every SystemAuth instance using the same database.
type EntLoginSessionStore struct {
	db   *ent.Client
	now  func() time.Time
	gate *cleanupGate
}

// NewEntLoginSessionStore creates a login session store on client.
func NewEntLoginSessionStore(client *ent.Client, opts ...EntStoreOption) *EntLoginSessionStore {
	c := newEntStoreConfig(opts)
	return &EntLoginSessionStore{db: client, now: c.now, gate: &cleanupGate{interval: c.cleanupInterval}}
}

// Create implements LoginSessionStore.
func (s *EntLoginSessionStore) Create(ctx context.Context, token string, session LoginSession) error {
	if token == "" {
		return errors.New("systemauth: empty login session token")
	}
	maybeCleanup(ctx, s.gate, s.now(), "login_sessions", s.DeleteExpired)
	err := s.db.LoginSession.Create().
		SetTokenHash(hashSessionToken(token)).
		SetPrincipalID(session.PrincipalID).
		SetProvider(session.Provider).
		SetCreatedAt(session.CreatedAt.UTC()).
		SetExpiresAt(session.ExpiresAt.UTC()).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("creating login session: %w", err)
	}
	return nil
}

// Get implements LoginSessionStore.
func (s *EntLoginSessionStore) Get(ctx context.Context, token string) (LoginSession, error) {
	row, err := s.db.LoginSession.Query().
		Where(
			loginsession.TokenHashEQ(hashSessionToken(token)),
			loginsession.ExpiresAtGT(s.now()),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return LoginSession{}, ErrLoginSessionNotFound
		}
		return LoginSession{}, fmt.Errorf("getting login session: %w", err)
	}
	return LoginSession{
		PrincipalID: row.PrincipalID,
		Provider:    row.Provider,
		CreatedAt:   row.CreatedAt,
		ExpiresAt:   row.ExpiresAt,
	}, nil
}

// Delete implements LoginSessionStore.
func (s *EntLoginSessionStore) Delete(ctx context.Context, token string) error {
	if _, err := s.db.LoginSession.Delete().
		Where(loginsession.TokenHashEQ(hashSessionToken(token))).
		Exec(ctx); err != nil {
		return fmt.Errorf("deleting login session: %w", err)
	}
	return nil
}

// DeleteExpired removes expired sessions and returns how many were removed.
func (s *EntLoginSessionStore) DeleteExpired(ctx context.Context) (int, error) {
	n, err := s.db.LoginSession.Delete().
		Where(loginsession.ExpiresAtLTE(s.now())).
		Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("deleting expired login sessions: %w", err)
	}
	return n, nil
}

var _ LoginSessionStore = (*EntLoginSessionStore)(nil)

// EntLoginStateStore is an oauthclient.StateStore backed by the
// sf_login_states table. Only a hash of the state value is stored. Take is
// single-use across instances: a row is returned only to the caller whose
// delete removed it.
type EntLoginStateStore struct {
	db   *ent.Client
	now  func() time.Time
	gate *cleanupGate
}

// NewEntLoginStateStore creates a login state store on client.
func NewEntLoginStateStore(client *ent.Client, opts ...EntStoreOption) *EntLoginStateStore {
	c := newEntStoreConfig(opts)
	return &EntLoginStateStore{db: client, now: c.now, gate: &cleanupGate{interval: c.cleanupInterval}}
}

// Put implements oauthclient.StateStore.
func (s *EntLoginStateStore) Put(ctx context.Context, state string, data oauthclient.StateData, ttl time.Duration) error {
	if state == "" {
		return errors.New("systemauth: empty login state")
	}
	now := s.now()
	maybeCleanup(ctx, s.gate, now, "login_states", s.DeleteExpired)
	err := s.db.LoginState.Create().
		SetStateHash(hashSessionToken(state)).
		SetProvider(data.Provider).
		SetRedirectURL(data.RedirectURL).
		SetNonce(data.Nonce).
		SetPkceVerifier(data.PKCEVerifier).
		SetExpiresAt(now.Add(ttl)).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("storing login state: %w", err)
	}
	return nil
}

// Take implements oauthclient.StateStore.
func (s *EntLoginStateStore) Take(ctx context.Context, state string) (oauthclient.StateData, error) {
	row, err := s.db.LoginState.Query().
		Where(loginstate.StateHashEQ(hashSessionToken(state))).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return oauthclient.StateData{}, oauthclient.ErrInvalidState
		}
		return oauthclient.StateData{}, fmt.Errorf("reading login state: %w", err)
	}
	// Only the caller whose delete removes the row may use it; concurrent
	// takers observe zero affected rows.
	n, err := s.db.LoginState.Delete().Where(loginstate.IDEQ(row.ID)).Exec(ctx)
	if err != nil {
		return oauthclient.StateData{}, fmt.Errorf("consuming login state: %w", err)
	}
	if n != 1 || !s.now().Before(row.ExpiresAt) {
		return oauthclient.StateData{}, oauthclient.ErrInvalidState
	}
	return oauthclient.StateData{
		Provider:     row.Provider,
		RedirectURL:  row.RedirectURL,
		Nonce:        row.Nonce,
		PKCEVerifier: row.PkceVerifier,
	}, nil
}

// DeleteExpired removes expired login states and returns how many were
// removed.
func (s *EntLoginStateStore) DeleteExpired(ctx context.Context) (int, error) {
	n, err := s.db.LoginState.Delete().
		Where(loginstate.ExpiresAtLTE(s.now())).
		Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("deleting expired login states: %w", err)
	}
	return n, nil
}

var _ oauthclient.StateStore = (*EntLoginStateStore)(nil)

// EntConsentStore is a ConsentStore backed by the sf_consent_grants table,
// one row per granted scope.
type EntConsentStore struct {
	db *ent.Client
}

// NewEntConsentStore creates a consent store on client.
func NewEntConsentStore(client *ent.Client) *EntConsentStore {
	return &EntConsentStore{db: client}
}

func uniqueScopes(scopes []string) []string {
	out := slices.Clone(scopes)
	slices.Sort(out)
	return slices.Compact(out)
}

// HasConsent implements ConsentStore. With no scopes it reports whether any
// grant exists for the pair.
func (s *EntConsentStore) HasConsent(ctx context.Context, principalID, clientID string, scopes []string) (bool, error) {
	want := uniqueScopes(scopes)
	q := s.db.ConsentGrant.Query().Where(
		consentgrant.PrincipalIDEQ(principalID),
		consentgrant.ClientIDEQ(clientID),
	)
	if len(want) == 0 {
		ok, err := q.Exist(ctx)
		if err != nil {
			return false, fmt.Errorf("checking consent: %w", err)
		}
		return ok, nil
	}
	n, err := q.Where(consentgrant.ScopeIn(want...)).Count(ctx)
	if err != nil {
		return false, fmt.Errorf("checking consent: %w", err)
	}
	return n == len(want), nil
}

// SaveConsent implements ConsentStore. Already granted scopes are kept.
func (s *EntConsentStore) SaveConsent(ctx context.Context, principalID, clientID string, scopes []string) error {
	want := uniqueScopes(scopes)
	if len(want) == 0 {
		return nil
	}
	builders := make([]*ent.ConsentGrantCreate, 0, len(want))
	for _, scope := range want {
		builders = append(builders, s.db.ConsentGrant.Create().
			SetPrincipalID(principalID).
			SetClientID(clientID).
			SetScope(scope))
	}
	err := s.db.ConsentGrant.CreateBulk(builders...).
		OnConflictColumns(consentgrant.FieldPrincipalID, consentgrant.FieldClientID, consentgrant.FieldScope).
		DoNothing().
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("saving consent: %w", err)
	}
	return nil
}

// RevokeConsent implements ConsentStore.
func (s *EntConsentStore) RevokeConsent(ctx context.Context, principalID, clientID string) error {
	if _, err := s.db.ConsentGrant.Delete().Where(
		consentgrant.PrincipalIDEQ(principalID),
		consentgrant.ClientIDEQ(clientID),
	).Exec(ctx); err != nil {
		return fmt.Errorf("revoking consent: %w", err)
	}
	return nil
}

var _ ConsentStore = (*EntConsentStore)(nil)
