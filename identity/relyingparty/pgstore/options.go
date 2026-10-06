// Package pgstore provides PostgreSQL-backed relying-party stores: a
// relyingparty.SessionStore and a relyingparty.LoginStateStore that survive
// restarts and are shared by every instance of the application.
//
// The stores use database/sql; open the database with the pgx stdlib
// driver (import _ "github.com/jackc/pgx/v5/stdlib", driver name "pgx").
// They need the tables in SchemaSQL, created by EnsureSchema.
//
// Session tokens and OAuth state values are stored only as SHA-256 hashes.
// SystemAuth access, refresh and ID tokens, the session's claims, and the
// login nonce and PKCE verifier are encrypted at rest with AES-256-GCM
// under a caller-supplied key. Keys rotate by adding a new encryption key
// and keeping the old one as a decryption key until every row sealed with
// it has expired or been rewritten.
package pgstore

import (
	"log/slog"
	"time"
)

// DefaultCleanupInterval is how often a store deletes expired rows while
// handling writes.
const DefaultCleanupInterval = 5 * time.Minute

type namedKey struct {
	id  string
	key []byte
}

type config struct {
	encKey            *namedKey
	decKeys           []namedKey
	insecurePlaintext bool
	cleanupInterval   time.Duration
	logger            *slog.Logger
	now               func() time.Time
}

// Option configures a store.
type Option func(*config)

// WithEncryptionKey sets the key that seals new and updated rows, and can
// open rows sealed with it. key must be KeySize (32) bytes; id names it in
// each row (for example "2026-q4" or "k2") and must be stable.
func WithEncryptionKey(id string, key []byte) Option {
	return func(c *config) { c.encKey = &namedKey{id: id, key: key} }
}

// WithDecryptionKey adds a decrypt-only key, typically the previous
// encryption key during rotation. Rows it opens are re-sealed with the
// encryption key when next updated.
func WithDecryptionKey(id string, key []byte) Option {
	return func(c *config) { c.decKeys = append(c.decKeys, namedKey{id: id, key: key}) }
}

// WithInsecurePlaintext allows constructing a store without an encryption
// key; secrets are then stored unencrypted. For local development only.
// When an encryption key is also given, new rows are still encrypted.
func WithInsecurePlaintext() Option {
	return func(c *config) { c.insecurePlaintext = true }
}

// WithCleanupInterval sets how often a store deletes expired rows while
// handling writes. Zero or negative disables opportunistic cleanup; call
// DeleteExpired from a scheduled job instead.
func WithCleanupInterval(d time.Duration) Option {
	return func(c *config) { c.cleanupInterval = d }
}

// WithLogger sets the logger for background failures (opportunistic
// cleanup) and decryption failures. Default: slog.Default().
func WithLogger(l *slog.Logger) Option {
	return func(c *config) { c.logger = l }
}

func newConfig(opts []Option) *config {
	c := &config{cleanupInterval: DefaultCleanupInterval, logger: slog.Default(), now: time.Now}
	for _, opt := range opts {
		opt(c)
	}
	if c.logger == nil {
		c.logger = slog.Default()
	}
	return c
}
