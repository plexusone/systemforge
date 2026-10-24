package bff

import (
	"context"
	"encoding/json"
	"errors"
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

// OmniStorageStore adapts omnistorage session storage to the systemforge Store interface.
type OmniStorageStore struct {
	store  omnisession.Store
	siteID string
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

	return &OmniStorageStore{store: store, siteID: cfg.SiteID}, nil
}

// NewOmniStorageStoreWithKVS creates a store using a pre-configured KVS backend.
func NewOmniStorageStoreWithKVS(backend kvs.ListableStore, cfg OmniStorageConfig) *OmniStorageStore {
	omniCfg := omnisession.Config{
		SiteID:             cfg.SiteID,
		MaxSessionSize:     cfg.MaxSessionSize,
		MaxSessionsPerUser: cfg.MaxSessionsPerUser,
		DefaultTTL:         cfg.DefaultTTL,
		CleanupInterval:    cfg.CleanupInterval,
		KeyPrefix:          cfg.KeyPrefix,
	}
	store := sessionkvs.NewWithControls(backend, omniCfg, cfg.ControlOptions...)
	return &OmniStorageStore{store: store, siteID: cfg.SiteID}
}

// Create stores a new session.
func (s *OmniStorageStore) Create(ctx context.Context, session *Session) error {
	omniSession, err := s.toOmniSession(session)
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
	return fromOmniSession(omniSession)
}

// Update updates an existing session.
func (s *OmniStorageStore) Update(ctx context.Context, session *Session) error {
	omniSession, err := s.toOmniSession(session)
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

// toOmniSession converts a systemforge Session to omnistorage Session,
// tagged with the store's SiteID: every write must carry it, or the next
// Get under site isolation would treat the session as another site's.
func (st *OmniStorageStore) toOmniSession(s *Session) (*omnisession.Session, error) {
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

	return &omnisession.Session{
		ID:             s.ID,
		UserID:         s.UserID,
		OrganizationID: s.OrganizationID,
		SiteID:         st.siteID,
		Data: map[string]any{
			"_bff": string(dataBytes),
		},
		CreatedAt:      s.CreatedAt,
		UpdatedAt:      s.UpdatedAt,
		LastAccessedAt: s.LastAccessedAt,
		ExpiresAt:      s.ExpiresAt,
	}, nil
}

// fromOmniSession converts an omnistorage Session to systemforge Session.
func fromOmniSession(os *omnisession.Session) (*Session, error) {
	s := &Session{
		ID:             os.ID,
		UserID:         os.UserID,
		OrganizationID: os.OrganizationID,
		CreatedAt:      os.CreatedAt,
		UpdatedAt:      os.UpdatedAt,
		LastAccessedAt: os.LastAccessedAt,
		ExpiresAt:      os.ExpiresAt,
	}

	// Extract systemforge-specific fields from Data
	if os.Data != nil {
		if bffData, ok := os.Data["_bff"].(string); ok {
			var data sessionData
			if err := json.Unmarshal([]byte(bffData), &data); err == nil {
				s.AccessToken = data.AccessToken
				s.RefreshToken = data.RefreshToken
				s.AccessTokenExpiresAt = data.AccessTokenExpiresAt
				s.RefreshTokenExpiresAt = data.RefreshTokenExpiresAt
				s.DPoPKeyPairJSON = data.DPoPKeyPairJSON
				s.DPoPThumbprint = data.DPoPThumbprint
				s.Metadata = data.Metadata
				s.IPAddress = data.IPAddress
				s.UserAgent = data.UserAgent
			}
		}
	}

	return s, nil
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
