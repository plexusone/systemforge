package bff

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
)

// EntClientInterface abstracts the Ent client to avoid import cycles.
// Apps implement this interface wrapping their generated Ent client.
// The wrapper must persist every field of Session it is given, including
// TokenType, which decides whether the proxy presents the access token
// with the DPoP or the Bearer scheme.
//
// Example implementation:
//
//	type EntClientWrapper struct {
//	    client *ent.Client
//	}
//
//	func (w *EntClientWrapper) CreateBFFSession(ctx context.Context, session *bff.Session) error {
//	    _, err := w.client.BFFSession.Create().
//	        SetID(session.ID).
//	        SetUserID(session.UserID).
//	        // ... set other fields
//	        Save(ctx)
//	    return err
//	}
type EntClientInterface interface {
	// CreateBFFSession stores a new session.
	CreateBFFSession(ctx context.Context, session *Session) error

	// GetBFFSession retrieves a session by ID.
	// Returns ErrSessionNotFound if not found.
	GetBFFSession(ctx context.Context, id string) (*Session, error)

	// UpdateBFFSession updates an existing session.
	UpdateBFFSession(ctx context.Context, session *Session) error

	// DeleteBFFSession removes a session by ID.
	DeleteBFFSession(ctx context.Context, id string) error

	// DeleteBFFSessionsByUserID removes all sessions for a user.
	// Returns the number of sessions deleted.
	DeleteBFFSessionsByUserID(ctx context.Context, userID uuid.UUID) (int, error)

	// TouchBFFSession updates the LastAccessedAt timestamp.
	TouchBFFSession(ctx context.Context, id string) error

	// CleanupExpiredBFFSessions removes expired sessions.
	// Returns the number of sessions removed.
	CleanupExpiredBFFSessions(ctx context.Context, limit int) (int, error)
}

// EntStoreConfig configures the Ent-backed session store.
type EntStoreConfig struct {
	// Client is the Ent client wrapper.
	// Apps must provide a wrapper that implements EntClientInterface.
	Client EntClientInterface

	// Sealer encrypts the access token, refresh token and DPoP key pair
	// before they reach the database. Each value is bound to its session ID
	// and field, so a ciphertext copied to another row or column does not
	// open. Use NewKeyringSealer to rotate keys (keep the active key N and
	// the previous key N-1 in the ring), or NewKeysSealer for a keyforge
	// purpose key. Either Sealer or EncryptionKey is required.
	Sealer SessionSealer

	// EncryptionKey is a single 32-byte AES-256 key. Without a Sealer the
	// store seals with it under the key ID EntStoreDefaultKeyID, which is
	// equivalent to NewKeyringSealer(EntStoreDefaultKeyID, {EntStoreDefaultKeyID:
	// EncryptionKey}). Whenever it is set, the store also opens values that
	// earlier versions wrote with it (without key ID or session binding);
	// such values are sealed again on the session's next update. Keep it set
	// until those sessions have expired, as long as it is N or N-1 in the
	// keyring.
	EncryptionKey []byte

	// CleanupInterval is how often to run automatic cleanup.
	// Set to 0 to disable automatic cleanup.
	CleanupInterval time.Duration

	// CleanupBatchSize limits sessions deleted per cleanup run.
	// Default is 100 if not specified.
	CleanupBatchSize int
}

// EntStoreDefaultKeyID is the key ID EntStore seals under when it is
// given only EntStoreConfig.EncryptionKey. Keep the same key under this ID
// in a KeyringSealer when moving to key rotation.
const EntStoreDefaultKeyID = "default"

// entSealAADPrefix versions the associated data of sealed EntStore fields.
const entSealAADPrefix = "systemforge/bff-ent-session/v1"

// EntStore implements Store using Ent.
type EntStore struct {
	config EntStoreConfig
	sealer SessionSealer
	// legacy opens values written before sessions were sealed with key IDs
	// and session binding; nil when EncryptionKey is unset.
	legacy  *Encryptor
	cleanup *time.Ticker
	done    chan struct{}
}

// NewEntStore creates a new Ent-backed session store.
func NewEntStore(config EntStoreConfig) (*EntStore, error) {
	if config.Client == nil {
		return nil, errors.New("client is required")
	}
	if config.Sealer == nil && config.EncryptionKey == nil {
		return nil, ErrSealerRequired
	}

	var legacy *Encryptor
	if config.EncryptionKey != nil {
		var err error
		legacy, err = NewEncryptor(config.EncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("creating encryptor: %w", err)
		}
	}
	sealer := config.Sealer
	if sealer == nil {
		var err error
		sealer, err = NewKeyringSealer(EntStoreDefaultKeyID, map[string][]byte{EntStoreDefaultKeyID: config.EncryptionKey})
		if err != nil {
			return nil, fmt.Errorf("creating sealer: %w", err)
		}
	}

	if config.CleanupBatchSize <= 0 {
		config.CleanupBatchSize = 100
	}

	store := &EntStore{
		config: config,
		sealer: sealer,
		legacy: legacy,
		done:   make(chan struct{}),
	}

	if config.CleanupInterval > 0 {
		store.startCleanup()
	}

	return store, nil
}

// Create stores a new session.
func (s *EntStore) Create(ctx context.Context, session *Session) error {
	// Encrypt tokens before storage
	encryptedSession, err := s.encryptSession(ctx, session)
	if err != nil {
		return fmt.Errorf("encrypting session: %w", err)
	}

	return s.config.Client.CreateBFFSession(ctx, encryptedSession)
}

// Get retrieves a session by ID.
func (s *EntStore) Get(ctx context.Context, id string) (*Session, error) {
	session, err := s.config.Client.GetBFFSession(ctx, id)
	if err != nil {
		return nil, err
	}

	// Check expiration
	if session.IsExpired() {
		return nil, ErrSessionExpired
	}

	// Decrypt tokens
	decryptedSession, err := s.decryptSession(ctx, session)
	if err != nil {
		return nil, fmt.Errorf("decrypting session: %w", err)
	}

	return decryptedSession, nil
}

// Update updates an existing session.
func (s *EntStore) Update(ctx context.Context, session *Session) error {
	// Encrypt tokens before storage
	encryptedSession, err := s.encryptSession(ctx, session)
	if err != nil {
		return fmt.Errorf("encrypting session: %w", err)
	}

	encryptedSession.UpdatedAt = time.Now()
	return s.config.Client.UpdateBFFSession(ctx, encryptedSession)
}

// Delete removes a session by ID.
func (s *EntStore) Delete(ctx context.Context, id string) error {
	return s.config.Client.DeleteBFFSession(ctx, id)
}

// DeleteByUserID removes all sessions for a user.
func (s *EntStore) DeleteByUserID(ctx context.Context, userID string) (int, error) {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return 0, fmt.Errorf("invalid user ID: %w", err)
	}
	return s.config.Client.DeleteBFFSessionsByUserID(ctx, uid)
}

// Touch updates the LastAccessedAt timestamp.
func (s *EntStore) Touch(ctx context.Context, id string) error {
	return s.config.Client.TouchBFFSession(ctx, id)
}

// Cleanup removes expired sessions.
func (s *EntStore) Cleanup(ctx context.Context) (int, error) {
	return s.config.Client.CleanupExpiredBFFSessions(ctx, s.config.CleanupBatchSize)
}

// Close stops the cleanup goroutine.
func (s *EntStore) Close() error {
	if s.cleanup != nil {
		s.cleanup.Stop()
		close(s.done)
	}
	return nil
}

// startCleanup starts the background cleanup goroutine.
func (s *EntStore) startCleanup() {
	s.cleanup = time.NewTicker(s.config.CleanupInterval)
	go func() {
		for {
			select {
			case <-s.cleanup.C:
				// Run cleanup in a background context
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				if _, err := s.Cleanup(ctx); err != nil {
					slog.Default().ErrorContext(ctx, "bff: cleaning up expired sessions", "error", err)
				}
				cancel()
			case <-s.done:
				return
			}
		}
	}()
}

// sealAAD binds a sealed field to one session and one field.
func entSealAAD(sessionID, field string) []byte {
	return []byte(entSealAADPrefix + "\x00" + field + "\x00" + sessionID)
}

// Field names bound into the associated data.
const (
	entFieldAccessToken  = "access_token"
	entFieldRefreshToken = "refresh_token"
	entFieldDPoPKeyPair  = "dpop_key_pair"
)

func (s *EntStore) seal(ctx context.Context, sessionID, field string, plaintext []byte) ([]byte, error) {
	sealed, err := s.sealer.Seal(ctx, plaintext, entSealAAD(sessionID, field))
	if err != nil {
		return nil, fmt.Errorf("sealing %s: %w", field, err)
	}
	return sealed, nil
}

// open decrypts a sealed field, falling back to the legacy format written
// by earlier versions when EncryptionKey is set.
func (s *EntStore) open(ctx context.Context, sessionID, field string, sealed []byte) ([]byte, error) {
	plaintext, err := s.sealer.Open(ctx, sealed, entSealAAD(sessionID, field))
	if err == nil {
		return plaintext, nil
	}
	if s.legacy != nil {
		if pt, lerr := s.legacy.Decrypt(sealed); lerr == nil {
			return pt, nil
		}
	}
	return nil, fmt.Errorf("opening %s: %w", field, err)
}

// encryptSession encrypts the tokens in a session.
// Returns a new Session with encrypted token fields.
func (s *EntStore) encryptSession(ctx context.Context, session *Session) (*Session, error) {
	// Make a copy to avoid modifying the original
	encrypted := *session

	accessEncrypted, err := s.seal(ctx, session.ID, entFieldAccessToken, []byte(session.AccessToken))
	if err != nil {
		return nil, err
	}
	refreshEncrypted, err := s.seal(ctx, session.ID, entFieldRefreshToken, []byte(session.RefreshToken))
	if err != nil {
		return nil, err
	}

	// The client wrapper stores the sealed bytes, read through
	// EncryptedAccessToken and friends.
	encrypted.AccessToken = ""
	encrypted.RefreshToken = ""
	encrypted.encryptedAccessToken = accessEncrypted
	encrypted.encryptedRefreshToken = refreshEncrypted

	if len(session.DPoPKeyPairJSON) > 0 {
		dpopEncrypted, err := s.seal(ctx, session.ID, entFieldDPoPKeyPair, session.DPoPKeyPairJSON)
		if err != nil {
			return nil, err
		}
		encrypted.DPoPKeyPairJSON = nil
		encrypted.encryptedDPoPKeyPair = dpopEncrypted
	}

	return &encrypted, nil
}

// decryptSession decrypts the tokens in a session.
// Returns a new Session with decrypted token fields.
func (s *EntStore) decryptSession(ctx context.Context, session *Session) (*Session, error) {
	// Make a copy to avoid modifying the original
	decrypted := *session

	if len(session.encryptedAccessToken) > 0 {
		accessToken, err := s.open(ctx, session.ID, entFieldAccessToken, session.encryptedAccessToken)
		if err != nil {
			return nil, err
		}
		decrypted.AccessToken = string(accessToken)
	}

	if len(session.encryptedRefreshToken) > 0 {
		refreshToken, err := s.open(ctx, session.ID, entFieldRefreshToken, session.encryptedRefreshToken)
		if err != nil {
			return nil, err
		}
		decrypted.RefreshToken = string(refreshToken)
	}

	if len(session.encryptedDPoPKeyPair) > 0 {
		dpopKeyPair, err := s.open(ctx, session.ID, entFieldDPoPKeyPair, session.encryptedDPoPKeyPair)
		if err != nil {
			return nil, err
		}
		decrypted.DPoPKeyPairJSON = dpopKeyPair
	}

	// Clear encrypted fields
	decrypted.encryptedAccessToken = nil
	decrypted.encryptedRefreshToken = nil
	decrypted.encryptedDPoPKeyPair = nil

	return &decrypted, nil
}

// Verify EntStore implements Store interface.
var _ Store = (*EntStore)(nil)
