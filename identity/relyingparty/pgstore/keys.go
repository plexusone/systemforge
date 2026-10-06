package pgstore

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
)

// DefaultKeyID names the encryption key when Keys.KeyID is empty.
const DefaultKeyID = "k1"

// Environment variable suffixes read by KeysFromEnv. Each is appended to the
// application's prefix, e.g. prefix "MYAPP_" reads MYAPP_SESSION_KEY.
const (
	EnvSessionKey           = "SESSION_KEY"
	EnvSessionKeyID         = "SESSION_KEY_ID"
	EnvSessionKeyPrevious   = "SESSION_KEY_PREVIOUS"
	EnvSessionKeyPreviousID = "SESSION_KEY_PREVIOUS_ID"
)

// ErrNoSessionKey is returned by Keys.Options when no encryption key is set.
var ErrNoSessionKey = errors.New("pgstore: session encryption key is required")

// Keys is the encryption-key configuration for the relying-party stores, in
// the encoded form an application holds in its environment or secret
// manager. Keys are KeySize bytes encoded as hex or base64 (see DecodeKey).
//
// Rotation: set the new key as Key (with a new KeyID), move the old one to
// PreviousKey/PreviousKeyID, and drop the previous key once the session
// lifetime has passed. Rows sealed with the previous key are re-sealed with
// the new one when next updated.
type Keys struct {
	// KeyID names Key in each sealed row. Default: DefaultKeyID.
	KeyID string
	// Key seals new and updated rows (required).
	Key string
	// PreviousKeyID names PreviousKey; required when PreviousKey is set and
	// must differ from KeyID.
	PreviousKeyID string
	// PreviousKey is a decrypt-only key kept during rotation (optional).
	PreviousKey string
}

// KeysFromEnv reads Keys from environment variables named prefix plus the
// Env* suffixes, e.g. KeysFromEnv("MYAPP_") reads MYAPP_SESSION_KEY,
// MYAPP_SESSION_KEY_ID, MYAPP_SESSION_KEY_PREVIOUS and
// MYAPP_SESSION_KEY_PREVIOUS_ID. It does not validate; Options does.
func KeysFromEnv(prefix string) Keys {
	return Keys{
		KeyID:         os.Getenv(prefix + EnvSessionKeyID),
		Key:           os.Getenv(prefix + EnvSessionKey),
		PreviousKeyID: os.Getenv(prefix + EnvSessionKeyPreviousID),
		PreviousKey:   os.Getenv(prefix + EnvSessionKeyPrevious),
	}
}

// Options validates the keys and returns the matching store options. It
// returns ErrNoSessionKey when Key is empty, and wraps ErrInvalidKey when a
// key does not decode to KeySize bytes.
func (k Keys) Options() ([]Option, error) {
	if k.Key == "" {
		return nil, ErrNoSessionKey
	}
	key, err := DecodeKey(k.Key)
	if err != nil {
		return nil, fmt.Errorf("session key: %w", err)
	}
	id := k.KeyID
	if id == "" {
		id = DefaultKeyID
	}
	opts := []Option{WithEncryptionKey(id, key)}
	if k.PreviousKey == "" {
		if k.PreviousKeyID != "" {
			return nil, errors.New("pgstore: previous session key ID set without a previous key")
		}
		return opts, nil
	}
	if k.PreviousKeyID == "" {
		return nil, errors.New("pgstore: previous session key requires its key ID")
	}
	if k.PreviousKeyID == id {
		return nil, fmt.Errorf("pgstore: previous session key ID %q must differ from the current key ID", id)
	}
	prev, err := DecodeKey(k.PreviousKey)
	if err != nil {
		return nil, fmt.Errorf("previous session key: %w", err)
	}
	return append(opts, WithDecryptionKey(k.PreviousKeyID, prev)), nil
}

// Stores bundles the durable session and login-state stores a relying
// party passes to relyingparty.BFFConfig (Sessions, LoginStates).
type Stores struct {
	Sessions    *SessionStore
	LoginStates *LoginStateStore
}

// NewStores validates keys and builds both stores over db. Extra options
// (e.g. WithLogger, WithCleanupInterval) apply to both. The tables must
// already exist; create them with EnsureSchema from the application's
// setup or migration step, which typically runs as a more privileged role
// than the serving connection.
func NewStores(db *sql.DB, keys Keys, opts ...Option) (*Stores, error) {
	keyOpts, err := keys.Options()
	if err != nil {
		return nil, err
	}
	all := append(keyOpts, opts...)
	sessions, err := NewSessionStore(db, all...)
	if err != nil {
		return nil, fmt.Errorf("session store: %w", err)
	}
	loginStates, err := NewLoginStateStore(db, all...)
	if err != nil {
		return nil, fmt.Errorf("login state store: %w", err)
	}
	return &Stores{Sessions: sessions, LoginStates: loginStates}, nil
}
