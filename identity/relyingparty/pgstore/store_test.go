package pgstore

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/relyingparty"
	"github.com/plexusone/systemforge/identity/relyingparty/storetest"
	"github.com/plexusone/systemforge/internal/pgtest"
)

// openDB returns a scratch database with the schema applied, skipping when
// SF_TEST_PG_DSN is unset.
func openDB(t *testing.T) *sql.DB {
	t.Helper()
	db := pgtest.Open(t)
	if err := EnsureSchema(context.Background(), db); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}
	return db
}

func newSessions(t *testing.T, db *sql.DB, opts ...Option) *SessionStore {
	t.Helper()
	s, err := NewSessionStore(db, opts...)
	if err != nil {
		t.Fatalf("NewSessionStore: %v", err)
	}
	return s
}

func newStates(t *testing.T, db *sql.DB, opts ...Option) *LoginStateStore {
	t.Helper()
	s, err := NewLoginStateStore(db, opts...)
	if err != nil {
		t.Fatalf("NewLoginStateStore: %v", err)
	}
	return s
}

func TestSessionStoreConformance(t *testing.T) {
	db := openDB(t)
	key := randomKey(t)
	t.Run("encrypted", func(t *testing.T) {
		storetest.SessionStore(t, func(t *testing.T) relyingparty.SessionStore {
			return newSessions(t, db, WithEncryptionKey("k1", key))
		})
	})
	t.Run("insecure-plaintext", func(t *testing.T) {
		storetest.SessionStore(t, func(t *testing.T) relyingparty.SessionStore {
			return newSessions(t, db, WithInsecurePlaintext())
		})
	})
}

func TestLoginStateStoreConformance(t *testing.T) {
	db := openDB(t)
	key := randomKey(t)
	storetest.LoginStateStore(t, func(t *testing.T) relyingparty.LoginStateStore {
		return newStates(t, db, WithEncryptionKey("k1", key))
	})
}

func TestEnsureSchemaIdempotentAndConcurrent(t *testing.T) {
	db := pgtest.Open(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- EnsureSchema(ctx, db)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent EnsureSchema: %v", err)
		}
	}
	if err := EnsureSchema(ctx, db); err != nil {
		t.Fatalf("repeat EnsureSchema: %v", err)
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM pg_indexes
		WHERE tablename IN ('sf_rp_sessions', 'sf_rp_login_states') AND indexname LIKE '%_idx'`).Scan(&n); err != nil {
		t.Fatalf("counting indexes: %v", err)
	}
	if n != 4 {
		t.Fatalf("indexes = %d, want 4", n)
	}
}

// TestSessionSecretsNotStoredInPlaintext reads the raw row and checks no
// token, claim or the session token appears in it.
func TestSessionSecretsNotStoredInPlaintext(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()
	s := newSessions(t, db, WithEncryptionKey("k1", randomKey(t)))
	tok := "cookie-" + uuid.NewString()
	sess := storetest.NewSession(uuid.NewString(), uuid.NewString())
	if err := s.Create(ctx, tok, sess); err != nil {
		t.Fatalf("Create: %v", err)
	}
	var tokenHash, keyID string
	var secrets []byte
	if err := db.QueryRowContext(ctx, `SELECT token_hash, key_id, secrets FROM sf_rp_sessions`).Scan(&tokenHash, &keyID, &secrets); err != nil {
		t.Fatalf("reading row: %v", err)
	}
	if tokenHash == tok || keyID != "k1" {
		t.Fatalf("row token_hash=%q key_id=%q", tokenHash, keyID)
	}
	for _, secret := range []string{sess.AccessToken, sess.RefreshToken, sess.IDToken, "user@example.com", tok} {
		if bytes.Contains(secrets, []byte(secret)) {
			t.Fatalf("plaintext %q found in stored secrets", secret)
		}
	}

	var stateRow []byte
	st := newStates(t, db, WithEncryptionKey("k1", randomKey(t)))
	if err := st.Put(ctx, "state-1", relyingparty.LoginState{Verifier: "pkce-verifier-xyz", Nonce: "nonce-xyz", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT payload FROM sf_rp_login_states`).Scan(&stateRow); err != nil {
		t.Fatalf("reading state row: %v", err)
	}
	if bytes.Contains(stateRow, []byte("pkce-verifier-xyz")) || bytes.Contains(stateRow, []byte("nonce-xyz")) {
		t.Fatal("login state stored in plaintext")
	}
}

func TestSessionStoreTamperDetection(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()
	s := newSessions(t, db, WithEncryptionKey("k1", randomKey(t)))
	tokA, tokB := uuid.NewString(), uuid.NewString()
	for _, tok := range []string{tokA, tokB} {
		if err := s.Create(ctx, tok, storetest.NewSession(uuid.NewString(), "")); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}

	// Flip one ciphertext byte of A.
	if _, err := db.ExecContext(ctx, `UPDATE sf_rp_sessions
		SET secrets = set_byte(secrets, 20, get_byte(secrets, 20) # 1) WHERE token_hash = $1`, hashToken(tokA)); err != nil {
		t.Fatalf("tampering: %v", err)
	}
	_, err := s.Get(ctx, tokA)
	if !errors.Is(err, ErrDecrypt) || !errors.Is(err, relyingparty.ErrSessionNotFound) {
		t.Fatalf("tampered Get err = %v, want ErrDecrypt and ErrSessionNotFound", err)
	}

	// Copy B's (valid) ciphertext into A's row.
	if _, err := db.ExecContext(ctx, `UPDATE sf_rp_sessions
		SET secrets = (SELECT secrets FROM sf_rp_sessions WHERE token_hash = $2) WHERE token_hash = $1`,
		hashToken(tokA), hashToken(tokB)); err != nil {
		t.Fatalf("swapping: %v", err)
	}
	if _, err := s.Get(ctx, tokA); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("swapped Get err = %v, want ErrDecrypt", err)
	}
	if _, err := s.Get(ctx, tokB); err != nil {
		t.Fatalf("untouched row: %v", err)
	}
}

func TestSessionStoreKeyRotation(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()
	k1, k2 := randomKey(t), randomKey(t)
	tok := uuid.NewString()
	sess := storetest.NewSession(uuid.NewString(), "")

	if err := newSessions(t, db, WithEncryptionKey("k1", k1)).Create(ctx, tok, sess); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Rotated instance: new key, old key decrypt-only.
	rotated := newSessions(t, db, WithEncryptionKey("k2", k2), WithDecryptionKey("k1", k1))
	got, err := rotated.Get(ctx, tok)
	if err != nil {
		t.Fatalf("Get with decrypt-only key: %v", err)
	}
	storetest.AssertSessionEqual(t, got, sess)

	// A server not yet holding k2 cannot read rows sealed with it.
	sess.RefreshToken = "rt-after-refresh"
	if err := rotated.Update(ctx, tok, sess); err != nil {
		t.Fatalf("Update: %v", err)
	}
	var keyID string
	if err := db.QueryRowContext(ctx, `SELECT key_id FROM sf_rp_sessions WHERE token_hash = $1`, hashToken(tok)).Scan(&keyID); err != nil {
		t.Fatalf("reading key_id: %v", err)
	}
	if keyID != "k2" {
		t.Fatalf("key_id after Update = %q, want k2", keyID)
	}
	if _, err := newSessions(t, db, WithEncryptionKey("k1", k1)).Get(ctx, tok); !errors.Is(err, ErrUnknownKeyID) {
		t.Fatalf("Get with only the old key err = %v, want ErrUnknownKeyID", err)
	}

	// Old key retired.
	got, err = newSessions(t, db, WithEncryptionKey("k2", k2)).Get(ctx, tok)
	if err != nil {
		t.Fatalf("Get after retiring k1: %v", err)
	}
	storetest.AssertSessionEqual(t, got, sess)
}

func TestLoginStateTamperDetection(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()
	s := newStates(t, db, WithEncryptionKey("k1", randomKey(t)))
	if err := s.Put(ctx, "st", relyingparty.LoginState{Verifier: "v", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE sf_rp_login_states SET payload = set_byte(payload, 20, get_byte(payload, 20) # 1)`); err != nil {
		t.Fatalf("tampering: %v", err)
	}
	_, err := s.Take(ctx, "st")
	if !errors.Is(err, ErrDecrypt) || !errors.Is(err, relyingparty.ErrInvalidState) {
		t.Fatalf("tampered Take err = %v, want ErrDecrypt and ErrInvalidState", err)
	}
}

func TestDeleteExpiredAndOpportunisticCleanup(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()
	now := time.Now()
	clock := func(c *config) { c.now = func() time.Time { return now } }
	key := WithEncryptionKey("k1", randomKey(t))
	sessions := newSessions(t, db, key, clock, WithCleanupInterval(time.Minute))
	states := newStates(t, db, key, clock, WithCleanupInterval(0))

	create := func(exp time.Duration) {
		t.Helper()
		sess := storetest.NewSession(uuid.NewString(), "")
		sess.ExpiresAt = now.Add(exp)
		if err := sessions.Create(ctx, uuid.NewString(), sess); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := states.Put(ctx, uuid.NewString(), relyingparty.LoginState{ExpiresAt: now.Add(exp)}); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}
	count := func(table string) int {
		t.Helper()
		var n int
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		return n
	}

	create(-time.Second) // first write: cleanup runs before the insert
	create(time.Hour)    // within the interval: no cleanup
	if count(SessionsTable) != 2 {
		t.Fatalf("sessions = %d, want 2", count(SessionsTable))
	}
	now = now.Add(2 * time.Minute)
	create(time.Hour) // interval elapsed: the expired session is removed
	if n := count(SessionsTable); n != 2 {
		t.Fatalf("sessions after opportunistic cleanup = %d, want 2", n)
	}

	// States have opportunistic cleanup disabled; DeleteExpired removes
	// the expired one explicitly.
	if n, err := states.DeleteExpired(ctx); err != nil || n != 1 {
		t.Fatalf("states.DeleteExpired = %d, %v; want 1", n, err)
	}
	now = now.Add(2 * time.Hour)
	if n, err := sessions.DeleteExpired(ctx); err != nil || n != 2 {
		t.Fatalf("sessions.DeleteExpired = %d, %v; want 2", n, err)
	}
}

// TestStoresSharedAcrossInstances checks that separate store values (as in
// separate replicas) see each other's rows and share single-use state.
func TestStoresSharedAcrossInstances(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()
	key := WithEncryptionKey("k1", randomKey(t))
	a, b := newStates(t, db, key), newStates(t, db, key)
	if err := a.Put(ctx, "shared", relyingparty.LoginState{Verifier: "v", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := b.Take(ctx, "shared"); err != nil {
		t.Fatalf("Take on other instance: %v", err)
	}
	if _, err := a.Take(ctx, "shared"); !errors.Is(err, relyingparty.ErrInvalidState) {
		t.Fatalf("reuse err = %v, want ErrInvalidState", err)
	}

	sa, sb := newSessions(t, db, key), newSessions(t, db, key)
	sess := storetest.NewSession(uuid.NewString(), "sid-1")
	if err := sa.Create(ctx, "tok", sess); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if n, err := sb.DeleteBySID(ctx, "sid-1"); err != nil || n != 1 {
		t.Fatalf("DeleteBySID on other instance = %d, %v", n, err)
	}
	if _, err := sa.Get(ctx, "tok"); !errors.Is(err, relyingparty.ErrSessionNotFound) {
		t.Fatalf("Get after back-channel delete err = %v", err)
	}
}
