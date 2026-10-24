package bff

import (
	"context"
	"errors"
)

var (
	// ErrSessionNotFound is returned when a session is not found.
	ErrSessionNotFound = errors.New("session not found")
	// ErrSessionExpired is returned when a session has expired.
	ErrSessionExpired = errors.New("session expired")
	// ErrInvalidSession is returned when a session is invalid.
	ErrInvalidSession = errors.New("invalid session")
	// ErrStoreRequired is returned when a store is not provided.
	ErrStoreRequired = errors.New("session store is required")
	// ErrOriginsRequired is returned when no allowed origins are provided.
	ErrOriginsRequired = errors.New("allowed origins are required for CSRF protection")
)

// Store defines the interface for session storage.
// Implementations must be safe for concurrent use.
type Store interface {
	// Create stores a new session and returns the session ID.
	Create(ctx context.Context, session *Session) error

	// Get retrieves a session by ID.
	// Returns ErrSessionNotFound if the session doesn't exist.
	// Returns ErrSessionExpired if the session has expired.
	Get(ctx context.Context, id string) (*Session, error)

	// Update updates an existing session.
	// Returns ErrSessionNotFound if the session doesn't exist.
	Update(ctx context.Context, session *Session) error

	// Delete removes a session by ID.
	// Returns ErrSessionNotFound if the session doesn't exist.
	Delete(ctx context.Context, id string) error

	// DeleteByUserID removes all sessions for a user.
	// Returns the number of sessions deleted.
	DeleteByUserID(ctx context.Context, userID string) (int, error)

	// Touch updates the LastAccessedAt timestamp.
	// This is used to track session activity without modifying other fields.
	Touch(ctx context.Context, id string) error

	// Cleanup removes expired sessions.
	// Returns the number of sessions removed.
	Cleanup(ctx context.Context) (int, error)

	// Close closes the store and releases any resources.
	Close() error
}

// StoreConfig contains common configuration for session stores.
type StoreConfig struct {
	// CleanupInterval is how often to run automatic cleanup.
	// Set to 0 to disable automatic cleanup.
	CleanupInterval int

	// MaxSessions is the maximum number of sessions to store (0 = unlimited).
	MaxSessions int

	// EncryptionKey is not read by any store.
	//
	// Deprecated: set EntStoreConfig.Sealer for EntStore or
	// OmniStorageConfig.Sealer for OmniStorageStore. MemoryStore keeps
	// sessions in process memory and does not encrypt them.
	EncryptionKey []byte
}

// DefaultStoreConfig returns sensible default configuration.
func DefaultStoreConfig() StoreConfig {
	return StoreConfig{
		CleanupInterval: 300, // 5 minutes in seconds
		MaxSessions:     0,   // unlimited
	}
}
