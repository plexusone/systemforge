package pgstore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/plexusone/systemforge/identity/relyingparty"
)

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// base holds what both stores share.
type base struct {
	db     *sql.DB
	keys   *keyring
	logger *slog.Logger
	now    func() time.Time

	cleanupInterval time.Duration
	cleanupMu       sync.Mutex
	nextCleanup     time.Time
}

func newBase(db *sql.DB, opts []Option) (*base, error) {
	if db == nil {
		return nil, errors.New("pgstore: nil *sql.DB")
	}
	c := newConfig(opts)
	keys, err := newKeyring(c)
	if err != nil {
		return nil, err
	}
	return &base{db: db, keys: keys, logger: c.logger, now: c.now, cleanupInterval: c.cleanupInterval}, nil
}

// maybeCleanup deletes expired rows at most once per cleanup interval per
// store instance. Failures do not fail the caller's write; they are logged
// and retried next interval.
func (b *base) maybeCleanup(ctx context.Context, store string, deleteExpired func(context.Context) (int, error)) {
	if b.cleanupInterval <= 0 {
		return
	}
	now := b.now()
	b.cleanupMu.Lock()
	due := !now.Before(b.nextCleanup)
	if due {
		b.nextCleanup = now.Add(b.cleanupInterval)
	}
	b.cleanupMu.Unlock()
	if !due {
		return
	}
	if _, err := deleteExpired(ctx); err != nil {
		b.logger.WarnContext(ctx, "pgstore: deleting expired rows", "store", store, "error", err)
	}
}

// deleteExpiredSQL holds the expired-row cleanup statement per table.
var deleteExpiredSQL = map[string]string{
	SessionsTable:    `DELETE FROM sf_rp_sessions WHERE expires_at <= $1`,
	LoginStatesTable: `DELETE FROM sf_rp_login_states WHERE expires_at <= $1`,
}

func (b *base) deleteExpired(ctx context.Context, table string) (int, error) {
	res, err := b.db.ExecContext(ctx, deleteExpiredSQL[table], b.now())
	if err != nil {
		return 0, fmt.Errorf("pgstore: deleting expired %s: %w", table, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("pgstore: deleting expired %s: %w", table, err)
	}
	return int(n), nil
}

// sessionSecrets is the encrypted part of a session row.
type sessionSecrets struct {
	AccessToken  string         `json:"accessToken,omitempty"`
	RefreshToken string         `json:"refreshToken,omitempty"`
	IDToken      string         `json:"idToken,omitempty"`
	Claims       map[string]any `json:"claims,omitempty"`
}

// SessionStore is a relyingparty.SessionStore on PostgreSQL (table
// sf_rp_sessions). It is safe for concurrent use and shared by every
// instance on the same database.
type SessionStore struct {
	*base
}

// NewSessionStore creates a session store on db. It refuses to start
// without WithEncryptionKey unless WithInsecurePlaintext is given. The
// schema must exist (see EnsureSchema).
func NewSessionStore(db *sql.DB, opts ...Option) (*SessionStore, error) {
	b, err := newBase(db, opts)
	if err != nil {
		return nil, err
	}
	return &SessionStore{base: b}, nil
}

func (s *SessionStore) sealSecrets(tokenHash string, sess relyingparty.Session) (string, []byte, error) {
	//nolint:gosec // G117: the marshaled secrets are sealed with AES-256-GCM below before storage
	plain, err := json.Marshal(sessionSecrets{
		AccessToken:  sess.AccessToken,
		RefreshToken: sess.RefreshToken,
		IDToken:      sess.IDToken,
		Claims:       sess.Claims,
	})
	if err != nil {
		return "", nil, fmt.Errorf("pgstore: encoding session secrets: %w", err)
	}
	return s.keys.seal(SessionsTable, tokenHash, plain)
}

func nullTime(t time.Time) sql.NullTime {
	return sql.NullTime{Time: t, Valid: !t.IsZero()}
}

// Create implements relyingparty.SessionStore.
func (s *SessionStore) Create(ctx context.Context, token string, sess relyingparty.Session) error {
	if token == "" {
		return errors.New("pgstore: empty session token")
	}
	s.maybeCleanup(ctx, SessionsTable, s.DeleteExpired)
	th := hashToken(token)
	keyID, sealed, err := s.sealSecrets(th, sess)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO sf_rp_sessions
		(token_hash, principal_id, subject, sid, key_id, secrets, access_token_expires_at, created_at, expires_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		th, sess.PrincipalID, sess.Subject, sess.SID, keyID, sealed,
		nullTime(sess.AccessTokenExpiresAt), sess.CreatedAt, sess.ExpiresAt, s.now())
	if err != nil {
		return fmt.Errorf("pgstore: creating session: %w", err)
	}
	return nil
}

// Get implements relyingparty.SessionStore. A row that fails decryption
// (tampered, or sealed with a key no longer configured) is reported as an
// error matching both relyingparty.ErrSessionNotFound, so the user is
// treated as signed out, and ErrDecrypt or ErrUnknownKeyID; it is logged.
func (s *SessionStore) Get(ctx context.Context, token string) (relyingparty.Session, error) {
	th := hashToken(token)
	var (
		sess      relyingparty.Session
		keyID     string
		sealed    []byte
		atExpires sql.NullTime
	)
	err := s.db.QueryRowContext(ctx, `SELECT principal_id, subject, sid, key_id, secrets,
		access_token_expires_at, created_at, expires_at
		FROM sf_rp_sessions WHERE token_hash = $1 AND expires_at > $2`, th, s.now()).
		Scan(&sess.PrincipalID, &sess.Subject, &sess.SID, &keyID, &sealed, &atExpires, &sess.CreatedAt, &sess.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return relyingparty.Session{}, relyingparty.ErrSessionNotFound
	}
	if err != nil {
		return relyingparty.Session{}, fmt.Errorf("pgstore: getting session: %w", err)
	}
	plain, err := s.keys.open(SessionsTable, th, keyID, sealed)
	if err != nil {
		s.logger.WarnContext(ctx, "pgstore: session secrets could not be decrypted", "key_id", keyID, "error", err)
		return relyingparty.Session{}, fmt.Errorf("%w: %w", relyingparty.ErrSessionNotFound, err)
	}
	var sec sessionSecrets
	if err := json.Unmarshal(plain, &sec); err != nil {
		return relyingparty.Session{}, fmt.Errorf("pgstore: decoding session secrets: %w", err)
	}
	sess.AccessToken, sess.RefreshToken, sess.IDToken, sess.Claims = sec.AccessToken, sec.RefreshToken, sec.IDToken, sec.Claims
	if atExpires.Valid {
		sess.AccessTokenExpiresAt = atExpires.Time
	}
	return sess, nil
}

// Update implements relyingparty.SessionStore. The secrets are re-sealed
// with the current encryption key.
func (s *SessionStore) Update(ctx context.Context, token string, sess relyingparty.Session) error {
	th := hashToken(token)
	keyID, sealed, err := s.sealSecrets(th, sess)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `UPDATE sf_rp_sessions SET
		principal_id = $2, subject = $3, sid = $4, key_id = $5, secrets = $6,
		access_token_expires_at = $7, created_at = $8, expires_at = $9, updated_at = $10
		WHERE token_hash = $1`,
		th, sess.PrincipalID, sess.Subject, sess.SID, keyID, sealed,
		nullTime(sess.AccessTokenExpiresAt), sess.CreatedAt, sess.ExpiresAt, s.now())
	if err != nil {
		return fmt.Errorf("pgstore: updating session: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("pgstore: updating session: %w", err)
	}
	if n == 0 {
		return relyingparty.ErrSessionNotFound
	}
	return nil
}

// Delete implements relyingparty.SessionStore.
func (s *SessionStore) Delete(ctx context.Context, token string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM sf_rp_sessions WHERE token_hash = $1`, hashToken(token)); err != nil {
		return fmt.Errorf("pgstore: deleting session: %w", err)
	}
	return nil
}

// DeleteBySubject implements relyingparty.SessionStore.
func (s *SessionStore) DeleteBySubject(ctx context.Context, subject string) (int, error) {
	if subject == "" {
		return 0, nil
	}
	return s.deleteWhere(ctx, "subject", `DELETE FROM sf_rp_sessions WHERE subject = $1`, subject)
}

// DeleteBySID implements relyingparty.SessionStore.
func (s *SessionStore) DeleteBySID(ctx context.Context, sid string) (int, error) {
	if sid == "" {
		return 0, nil
	}
	return s.deleteWhere(ctx, "sid", `DELETE FROM sf_rp_sessions WHERE sid = $1`, sid)
}

// deleteWhere runs a session delete statement and returns the row count.
func (s *SessionStore) deleteWhere(ctx context.Context, column, query, value string) (int, error) {
	res, err := s.db.ExecContext(ctx, query, value)
	if err != nil {
		return 0, fmt.Errorf("pgstore: deleting sessions by %s: %w", column, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("pgstore: deleting sessions by %s: %w", column, err)
	}
	return int(n), nil
}

// DeleteExpired removes expired sessions and returns how many were removed.
func (s *SessionStore) DeleteExpired(ctx context.Context) (int, error) {
	return s.deleteExpired(ctx, SessionsTable)
}

var _ relyingparty.SessionStore = (*SessionStore)(nil)

// loginPayload is the encrypted part of a login state row.
type loginPayload struct {
	Nonce    string `json:"nonce,omitempty"`
	Verifier string `json:"verifier,omitempty"`
	ReturnTo string `json:"returnTo,omitempty"`
}

// LoginStateStore is a relyingparty.LoginStateStore on PostgreSQL (table
// sf_rp_login_states). Take is atomic and single-use across instances.
type LoginStateStore struct {
	*base
}

// NewLoginStateStore creates a login state store on db. Key options are
// the same as for NewSessionStore.
func NewLoginStateStore(db *sql.DB, opts ...Option) (*LoginStateStore, error) {
	b, err := newBase(db, opts)
	if err != nil {
		return nil, err
	}
	return &LoginStateStore{base: b}, nil
}

// Put implements relyingparty.LoginStateStore.
func (s *LoginStateStore) Put(ctx context.Context, state string, data relyingparty.LoginState) error {
	if state == "" {
		return errors.New("pgstore: empty login state")
	}
	s.maybeCleanup(ctx, LoginStatesTable, s.DeleteExpired)
	sh := hashToken(state)
	plain, err := json.Marshal(loginPayload{Nonce: data.Nonce, Verifier: data.Verifier, ReturnTo: data.ReturnTo})
	if err != nil {
		return fmt.Errorf("pgstore: encoding login state: %w", err)
	}
	keyID, sealed, err := s.keys.seal(LoginStatesTable, sh, plain)
	if err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO sf_rp_login_states (state_hash, key_id, payload, expires_at)
		VALUES ($1, $2, $3, $4)`, sh, keyID, sealed, data.ExpiresAt); err != nil {
		return fmt.Errorf("pgstore: storing login state: %w", err)
	}
	return nil
}

// Take implements relyingparty.LoginStateStore. The row is deleted and
// returned in one statement, so concurrent callers cannot both use it.
func (s *LoginStateStore) Take(ctx context.Context, state string) (relyingparty.LoginState, error) {
	sh := hashToken(state)
	var (
		keyID  string
		sealed []byte
		data   relyingparty.LoginState
	)
	err := s.db.QueryRowContext(ctx, `DELETE FROM sf_rp_login_states WHERE state_hash = $1
		RETURNING key_id, payload, expires_at`, sh).Scan(&keyID, &sealed, &data.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return relyingparty.LoginState{}, relyingparty.ErrInvalidState
	}
	if err != nil {
		return relyingparty.LoginState{}, fmt.Errorf("pgstore: taking login state: %w", err)
	}
	if !s.now().Before(data.ExpiresAt) {
		return relyingparty.LoginState{}, relyingparty.ErrInvalidState
	}
	plain, err := s.keys.open(LoginStatesTable, sh, keyID, sealed)
	if err != nil {
		s.logger.WarnContext(ctx, "pgstore: login state could not be decrypted", "key_id", keyID, "error", err)
		return relyingparty.LoginState{}, fmt.Errorf("%w: %w", relyingparty.ErrInvalidState, err)
	}
	var p loginPayload
	if err := json.Unmarshal(plain, &p); err != nil {
		return relyingparty.LoginState{}, fmt.Errorf("pgstore: decoding login state: %w", err)
	}
	data.Nonce, data.Verifier, data.ReturnTo = p.Nonce, p.Verifier, p.ReturnTo
	return data, nil
}

// DeleteExpired removes expired login states and returns how many were
// removed.
func (s *LoginStateStore) DeleteExpired(ctx context.Context) (int, error) {
	return s.deleteExpired(ctx, LoginStatesTable)
}

var _ relyingparty.LoginStateStore = (*LoginStateStore)(nil)
