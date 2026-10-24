package bff

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/plexusone/omnistorage-core/kvs"
	kvsredis "github.com/plexusone/omnistorage-core/kvs/backend/redis"
	omnisession "github.com/plexusone/omnistorage-core/session"
	sessionkvs "github.com/plexusone/omnistorage-core/session/backend/kvs"
	sessionmemory "github.com/plexusone/omnistorage-core/session/backend/memory"
)

// OmniStorageConfig configures the omnistorage-backed session store.
type OmniStorageConfig struct {
	// Backend is the storage backend: "memory" or "redis".
	Backend string

	// RedisURL is the Redis connection URL (required for redis backend).
	RedisURL string

	// SiteID identifies which site/service this store handles.
	// Used for multi-site isolation (e.g., "billing", "admin", "dashboard").
	// When set, every session written is tagged with it and a session
	// tagged for another site is not found. Required for the redis
	// backend, since several applications may share one Redis: without it
	// they would accept each other's session IDs.
	SiteID string

	// MaxSessionSize is the maximum serialized session size in bytes.
	MaxSessionSize int

	// MaxSessionsPerUser limits concurrent sessions per user.
	// When exceeded, oldest sessions are automatically evicted.
	// Set to 0 for no limit.
	MaxSessionsPerUser int

	// DefaultTTL is the default session TTL.
	DefaultTTL time.Duration

	// CleanupInterval is how often to run automatic cleanup.
	CleanupInterval time.Duration

	// KeyPrefix is the prefix for session keys.
	KeyPrefix string

	// ControlOptions are optional settings for the controlled store wrapper.
	// Use omnisession.WithLogger() and omnisession.WithViolationHandler().
	ControlOptions []omnisession.ControlOption

	// Sealer encrypts the session's tokens, DPoP key pair and other
	// BFF fields before they are written, bound to the session ID and
	// SiteID. Required for the redis backend and NewOmniStorageStoreWithKVS
	// unless InsecurePlaintext is set; optional for the in-process memory
	// backend. Once set, sessions stored in plaintext are rejected.
	Sealer SessionSealer

	// InsecurePlaintext stores tokens and DPoP private keys unencrypted
	// when no Sealer is set, so anyone who can read the backend (or its
	// snapshots and replicas) can use them. For local development only.
	InsecurePlaintext bool
}

// DefaultOmniStorageConfig returns sensible defaults.
func DefaultOmniStorageConfig() OmniStorageConfig {
	return OmniStorageConfig{
		Backend:         "memory",
		MaxSessionSize:  1024 * 1024, // 1MB
		DefaultTTL:      24 * time.Hour,
		CleanupInterval: 5 * time.Minute,
		KeyPrefix:       "session:",
	}
}

// ErrSiteIDRequired is returned by NewOmniStorageStore for a shared
// backend (redis) configured without OmniStorageConfig.SiteID.
var ErrSiteIDRequired = errors.New("bff: OmniStorageConfig.SiteID is required for a shared session backend")

// ErrSealerRequired is returned for a persistent session store configured
// without a way to encrypt session secrets: an OmniStorageStore without
// OmniStorageConfig.Sealer or InsecurePlaintext, or an EntStore without
// EntStoreConfig.Sealer or EncryptionKey.
var ErrSealerRequired = errors.New("bff: a session sealer is required for a persistent session store")

const (
	// omniDataPlain holds the BFF fields as JSON when no sealer is set.
	omniDataPlain = "_bff"
	// omniDataSealed holds the sealed BFF fields, base64-encoded.
	omniDataSealed = "_bff_sealed"
	// omniSealAADPrefix versions the associated data of sealed sessions.
	omniSealAADPrefix = "systemforge/bff-session/v1"
)

// OmniStorageStore adapts omnistorage session storage to the systemforge Store interface.
type OmniStorageStore struct {
	store  omnisession.Store
	siteID string
	sealer SessionSealer
}

// NewOmniStorageStore creates a new omnistorage-backed session store.
func NewOmniStorageStore(cfg OmniStorageConfig) (*OmniStorageStore, error) {
	omniCfg := omnisession.Config{
		SiteID:             cfg.SiteID,
		MaxSessionSize:     cfg.MaxSessionSize,
		MaxSessionsPerUser: cfg.MaxSessionsPerUser,
		DefaultTTL:         cfg.DefaultTTL,
		CleanupInterval:    cfg.CleanupInterval,
		KeyPrefix:          cfg.KeyPrefix,
	}

	var store omnisession.Store

	switch cfg.Backend {
	case "redis":
		if cfg.RedisURL == "" {
			return nil, ErrStoreRequired
		}
		if cfg.SiteID == "" {
			return nil, ErrSiteIDRequired
		}
		if cfg.Sealer == nil && !cfg.InsecurePlaintext {
			return nil, ErrSealerRequired
		}

		// Create Redis KVS backend
		redisStore, err := kvsredis.New(kvsredis.Config{
			URL:       cfg.RedisURL,
			KeyPrefix: cfg.KeyPrefix,
		})
		if err != nil {
			return nil, err
		}

		// Wrap with session adapter and controls
		store = sessionkvs.NewWithControls(redisStore, omniCfg, cfg.ControlOptions...)

	case "memory", "":
		store = sessionmemory.NewWithControls(omniCfg, cfg.ControlOptions...)

	default:
		return nil, ErrInvalidSession
	}

	return &OmniStorageStore{store: store, siteID: cfg.SiteID, sealer: cfg.Sealer}, nil
}

// NewOmniStorageStoreWithKVS creates a store using a pre-configured KVS
// backend. Since the backend may be shared and persistent, it requires
// SiteID (ErrSiteIDRequired) and a Sealer unless InsecurePlaintext is set
// (ErrSealerRequired).
func NewOmniStorageStoreWithKVS(backend kvs.ListableStore, cfg OmniStorageConfig) (*OmniStorageStore, error) {
	if cfg.SiteID == "" {
		return nil, ErrSiteIDRequired
	}
	if cfg.Sealer == nil && !cfg.InsecurePlaintext {
		return nil, ErrSealerRequired
	}
	omniCfg := omnisession.Config{
		SiteID:             cfg.SiteID,
		MaxSessionSize:     cfg.MaxSessionSize,
		MaxSessionsPerUser: cfg.MaxSessionsPerUser,
		DefaultTTL:         cfg.DefaultTTL,
		CleanupInterval:    cfg.CleanupInterval,
		KeyPrefix:          cfg.KeyPrefix,
	}
	store := sessionkvs.NewWithControls(backend, omniCfg, cfg.ControlOptions...)
	return &OmniStorageStore{store: store, siteID: cfg.SiteID, sealer: cfg.Sealer}, nil
}

// Create stores a new session.
func (s *OmniStorageStore) Create(ctx context.Context, session *Session) error {
	omniSession, err := s.toOmniSession(ctx, session)
	if err != nil {
		return err
	}
	return s.store.Create(ctx, omniSession)
}

// Get retrieves a session by ID.
func (s *OmniStorageStore) Get(ctx context.Context, id string) (*Session, error) {
	omniSession, err := s.store.Get(ctx, id)
	if err != nil {
		return nil, mapError(err)
	}
	return s.fromOmniSession(ctx, omniSession)
}

// Update updates an existing session.
func (s *OmniStorageStore) Update(ctx context.Context, session *Session) error {
	omniSession, err := s.toOmniSession(ctx, session)
	if err != nil {
		return err
	}
	return mapError(s.store.Update(ctx, omniSession))
}

// Delete removes a session by ID.
func (s *OmniStorageStore) Delete(ctx context.Context, id string) error {
	return mapError(s.store.Delete(ctx, id))
}

// DeleteByUserID removes all sessions for a user.
func (s *OmniStorageStore) DeleteByUserID(ctx context.Context, userID string) (int, error) {
	count, err := s.store.DeleteByUserID(ctx, userID)
	return count, mapError(err)
}

// Touch updates the LastAccessedAt timestamp.
func (s *OmniStorageStore) Touch(ctx context.Context, id string) error {
	return mapError(s.store.Touch(ctx, id))
}

// Cleanup removes expired sessions.
// Note: For Redis, cleanup is handled automatically via TTL.
func (s *OmniStorageStore) Cleanup(ctx context.Context) (int, error) {
	// omnistorage handles cleanup automatically
	return 0, nil
}

// Close closes the store.
func (s *OmniStorageStore) Close() error {
	return s.store.Close()
}

// sessionData holds the systemforge-specific session fields as JSON.
type sessionData struct {
	AccessToken           string            `json:"access_token,omitempty"`
	RefreshToken          string            `json:"refresh_token,omitempty"`
	AccessTokenExpiresAt  time.Time         `json:"access_token_expires_at,omitempty"`
	RefreshTokenExpiresAt time.Time         `json:"refresh_token_expires_at,omitempty"`
	DPoPKeyPairJSON       []byte            `json:"dpop_key_pair,omitempty"`
	DPoPThumbprint        string            `json:"dpop_thumbprint,omitempty"`
	Metadata              map[string]string `json:"metadata,omitempty"`
	IPAddress             string            `json:"ip_address,omitempty"`
	UserAgent             string            `json:"user_agent,omitempty"`
}

// sealAAD binds sealed data to one session of one site, so a ciphertext
// copied to another session's record does not open.
func (st *OmniStorageStore) sealAAD(sessionID string) []byte {
	return []byte(omniSealAADPrefix + "\x00" + st.siteID + "\x00" + sessionID)
}

// toOmniSession converts a systemforge Session to omnistorage Session,
// tagged with the store's SiteID: every write must carry it, or the next
// Get under site isolation would treat the session as another site's. The
// BFF fields are sealed when the store has a sealer.
func (st *OmniStorageStore) toOmniSession(ctx context.Context, s *Session) (*omnisession.Session, error) {
	// Store systemforge-specific fields in Data
	data := sessionData{
		AccessToken:           s.AccessToken,
		RefreshToken:          s.RefreshToken,
		AccessTokenExpiresAt:  s.AccessTokenExpiresAt,
		RefreshTokenExpiresAt: s.RefreshTokenExpiresAt,
		DPoPKeyPairJSON:       s.DPoPKeyPairJSON,
		DPoPThumbprint:        s.DPoPThumbprint,
		Metadata:              s.Metadata,
		IPAddress:             s.IPAddress,
		UserAgent:             s.UserAgent,
	}

	dataBytes, err := json.Marshal(data) //nolint:gosec // G117: Internal session storage, not API response
	if err != nil {
		return nil, err
	}

	stored := map[string]any{omniDataPlain: string(dataBytes)}
	if st.sealer != nil {
		sealed, err := st.sealer.Seal(ctx, dataBytes, st.sealAAD(s.ID))
		if err != nil {
			return nil, fmt.Errorf("bff: sealing session: %w", err)
		}
		stored = map[string]any{omniDataSealed: base64.StdEncoding.EncodeToString(sealed)}
	}

	return &omnisession.Session{
		ID:             s.ID,
		UserID:         s.UserID,
		OrganizationID: s.OrganizationID,
		SiteID:         st.siteID,
		Data:           stored,
		CreatedAt:      s.CreatedAt,
		UpdatedAt:      s.UpdatedAt,
		LastAccessedAt: s.LastAccessedAt,
		ExpiresAt:      s.ExpiresAt,
	}, nil
}

// fromOmniSession converts an omnistorage Session to systemforge Session.
// With a sealer, only sealed BFF fields are accepted: a plaintext record
// (written before sealing was enabled, or planted in the backend) is
// rejected with ErrInvalidSession.
func (st *OmniStorageStore) fromOmniSession(ctx context.Context, os *omnisession.Session) (*Session, error) {
	s := &Session{
		ID:             os.ID,
		UserID:         os.UserID,
		OrganizationID: os.OrganizationID,
		CreatedAt:      os.CreatedAt,
		UpdatedAt:      os.UpdatedAt,
		LastAccessedAt: os.LastAccessedAt,
		ExpiresAt:      os.ExpiresAt,
	}

	raw, err := st.bffData(ctx, os)
	if err != nil {
		return nil, err
	}
	var data sessionData
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("%w: decoding session data: %v", ErrInvalidSession, err)
	}
	s.AccessToken = data.AccessToken
	s.RefreshToken = data.RefreshToken
	s.AccessTokenExpiresAt = data.AccessTokenExpiresAt
	s.RefreshTokenExpiresAt = data.RefreshTokenExpiresAt
	s.DPoPKeyPairJSON = data.DPoPKeyPairJSON
	s.DPoPThumbprint = data.DPoPThumbprint
	s.Metadata = data.Metadata
	s.IPAddress = data.IPAddress
	s.UserAgent = data.UserAgent

	return s, nil
}

// bffData returns the stored BFF fields as JSON, opening them if sealed.
func (st *OmniStorageStore) bffData(ctx context.Context, os *omnisession.Session) ([]byte, error) {
	if st.sealer == nil {
		plain, ok := os.Data[omniDataPlain].(string)
		if !ok {
			return nil, fmt.Errorf("%w: no session data (sealed data needs a Sealer)", ErrInvalidSession)
		}
		return []byte(plain), nil
	}
	encoded, ok := os.Data[omniDataSealed].(string)
	if !ok {
		return nil, fmt.Errorf("%w: session data is not sealed", ErrInvalidSession)
	}
	sealed, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: decoding sealed session data: %v", ErrInvalidSession, err)
	}
	raw, err := st.sealer.Open(ctx, sealed, st.sealAAD(os.ID))
	if err != nil {
		return nil, fmt.Errorf("%w: opening sealed session data: %v", ErrInvalidSession, err)
	}
	return raw, nil
}

// mapError maps omnistorage errors to systemforge errors.
func mapError(err error) error {
	if err == nil {
		return nil
	}
	switch err {
	case omnisession.ErrNotFound:
		return ErrSessionNotFound
	case omnisession.ErrExpired:
		return ErrSessionExpired
	case omnisession.ErrInvalidSession:
		return ErrInvalidSession
	default:
		return err
	}
}
