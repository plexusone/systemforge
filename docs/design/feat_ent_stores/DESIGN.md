# TRD: Ent Store Implementations

> **Status**: Draft
> **Target**: SystemForge v0.5.0

## Overview

Technical design for Ent-backed implementations of SystemForge's BFF session store and API key store interfaces.

## Architecture

### Store Hierarchy

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        SystemForge (Library)                                   │
├─────────────────────────────────┬───────────────────────────────────────────┤
│     session/bff/store.go        │      identity/apikey/service.go           │
│                                 │                                           │
│     type Store interface {      │      type Store interface {               │
│       Create(...)               │        Create(...)                        │
│       Get(...)                  │        GetByPrefix(...)                   │
│       Update(...)               │        GetByID(...)                       │
│       Delete(...)               │        ListByOwner(...)                   │
│       ...                       │        ...                                │
│     }                           │      }                                    │
└────────────────┬────────────────┴───────────────────┬───────────────────────┘
                 │                                    │
                 ▼                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                     SystemForge Ent Stores (New)                              │
├─────────────────────────────────┬───────────────────────────────────────────┤
│   session/bff/store_ent.go      │   identity/apikey/store_ent.go            │
│                                 │                                           │
│   type EntStore struct {        │   type EntStore struct {                  │
│     client *ent.Client          │     client *ent.Client                    │
│     config EntStoreConfig       │     config EntStoreConfig                 │
│   }                             │   }                                       │
│                                 │                                           │
│   func NewEntStore(...) Store   │   func NewEntStore(...) Store             │
└────────────────┬────────────────┴───────────────────┬───────────────────────┘
                 │                                    │
                 ▼                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        App-Level Ent Schema                                  │
├─────────────────────────────────┬───────────────────────────────────────────┤
│   internal/ent/schema/          │   internal/ent/schema/                    │
│   bff_session.go                │   api_token.go                            │
│                                 │                                           │
│   Uses mixin from:              │   Uses mixin from:                        │
│   systemforge/identity/ent/mixin  │   systemforge/identity/ent/mixin            │
└─────────────────────────────────┴───────────────────────────────────────────┘
```

## Schema Design

### BFF Session Schema

```go
// identity/ent/mixin/bff_session.go

package mixin

import (
    "time"
    "entgo.io/ent"
    "entgo.io/ent/schema/field"
    "entgo.io/ent/schema/index"
    "entgo.io/ent/schema/mixin"
)

// BFFSession provides common fields for BFF session entities.
type BFFSession struct {
    mixin.Schema
}

// Fields of the BFFSession mixin.
func (BFFSession) Fields() []ent.Field {
    return []ent.Field{
        field.String("id").
            NotEmpty().
            Unique().
            Immutable().
            Comment("Unique session identifier"),

        field.UUID("user_id", uuid.UUID{}).
            Comment("Owner of this session"),

        field.UUID("organization_id", uuid.UUID{}).
            Optional().
            Nillable().
            Comment("Organization context (optional)"),

        field.Bytes("access_token_encrypted").
            Sensitive().
            Comment("Encrypted access token"),

        field.Bytes("refresh_token_encrypted").
            Sensitive().
            Comment("Encrypted refresh token"),

        field.Time("access_token_expires_at").
            Comment("When the access token expires"),

        field.Time("refresh_token_expires_at").
            Comment("When the refresh token expires"),

        field.Bytes("dpop_key_pair_encrypted").
            Optional().
            Sensitive().
            Comment("Encrypted DPoP key pair (if DPoP enabled)"),

        field.String("dpop_thumbprint").
            Optional().
            MaxLen(64).
            Comment("DPoP JWK thumbprint"),

        field.String("ip_address").
            Optional().
            MaxLen(45).
            Comment("Client IP address"),

        field.String("user_agent").
            Optional().
            MaxLen(500).
            Comment("Client User-Agent"),

        field.JSON("metadata", map[string]string{}).
            Optional().
            Comment("Additional session metadata"),

        field.Time("last_accessed_at").
            Default(time.Now).
            Comment("When the session was last accessed"),

        field.Time("expires_at").
            Comment("When the session expires completely"),

        field.Time("created_at").
            Default(time.Now).
            Immutable(),

        field.Time("updated_at").
            Default(time.Now).
            UpdateDefault(time.Now),
    }
}

// Indexes of the BFFSession mixin.
func (BFFSession) Indexes() []ent.Index {
    return []ent.Index{
        index.Fields("user_id"),
        index.Fields("expires_at"),
        index.Fields("organization_id"),
    }
}
```

### API Key Schema

```go
// identity/ent/mixin/api_key.go

package mixin

import (
    "time"
    "entgo.io/ent"
    "entgo.io/ent/schema/field"
    "entgo.io/ent/schema/index"
    "entgo.io/ent/schema/mixin"
)

// APIKey provides common fields for API key entities.
type APIKey struct {
    mixin.Schema
}

// Fields of the APIKey mixin.
func (APIKey) Fields() []ent.Field {
    return []ent.Field{
        field.UUID("id", uuid.UUID{}).
            Default(uuid.New).
            Immutable(),

        field.String("name").
            NotEmpty().
            MaxLen(100).
            Comment("User-provided name for identification"),

        field.String("prefix").
            NotEmpty().
            MaxLen(20).
            Comment("Visible prefix for identification (e.g., sf_live_xxxx)"),

        field.String("key_hash").
            NotEmpty().
            MaxLen(64).
            Sensitive().
            Comment("SHA-256 hash of the full key"),

        field.UUID("owner_id", uuid.UUID{}).
            Comment("User who owns this key"),

        field.UUID("organization_id", uuid.UUID{}).
            Optional().
            Nillable().
            Comment("Organization scope (optional)"),

        field.Strings("scopes").
            Default([]string{}).
            Comment("Granted permission scopes"),

        field.String("description").
            Optional().
            MaxLen(500).
            Comment("User-provided description"),

        field.Enum("environment").
            Values("live", "test").
            Default("live").
            Comment("Key environment"),

        field.Time("expires_at").
            Optional().
            Nillable().
            Comment("When the key expires (NULL = never)"),

        field.Time("last_used_at").
            Optional().
            Nillable().
            Comment("When the key was last used"),

        field.String("last_used_ip").
            Optional().
            MaxLen(45).
            Comment("IP that last used the key"),

        field.Bool("revoked").
            Default(false).
            Comment("Whether the key is revoked"),

        field.Time("revoked_at").
            Optional().
            Nillable().
            Comment("When the key was revoked"),

        field.String("revoked_reason").
            Optional().
            MaxLen(500).
            Comment("Why the key was revoked"),

        field.JSON("metadata", map[string]string{}).
            Optional().
            Comment("Additional key metadata"),

        field.Time("created_at").
            Default(time.Now).
            Immutable(),

        field.Time("updated_at").
            Default(time.Now).
            UpdateDefault(time.Now),
    }
}

// Indexes of the APIKey mixin.
func (APIKey) Indexes() []ent.Index {
    return []ent.Index{
        index.Fields("owner_id"),
        index.Fields("organization_id"),
        index.Fields("prefix"),
        index.Fields("key_hash").Unique(),
        index.Fields("environment"),
    }
}
```

## Store Implementations

### BFF Session Ent Store

```go
// session/bff/store_ent.go

package bff

import (
    "context"
    "time"
)

// EntStoreConfig configures the Ent-backed session store.
type EntStoreConfig struct {
    // Client is the Ent client (type varies by app).
    // Apps must provide a wrapper that implements EntClientInterface.
    Client EntClientInterface

    // EncryptionKey for encrypting tokens at rest.
    // Must be 32 bytes for AES-256.
    EncryptionKey []byte

    // CleanupInterval is how often to run automatic cleanup.
    // Set to 0 to disable automatic cleanup.
    CleanupInterval time.Duration

    // CleanupBatchSize limits sessions deleted per cleanup run.
    CleanupBatchSize int
}

// EntClientInterface abstracts the Ent client to avoid import cycles.
// Apps implement this interface wrapping their generated Ent client.
type EntClientInterface interface {
    CreateBFFSession(ctx context.Context, session *Session) error
    GetBFFSession(ctx context.Context, id string) (*Session, error)
    UpdateBFFSession(ctx context.Context, session *Session) error
    DeleteBFFSession(ctx context.Context, id string) error
    DeleteBFFSessionsByUserID(ctx context.Context, userID string) (int, error)
    TouchBFFSession(ctx context.Context, id string) error
    CleanupExpiredBFFSessions(ctx context.Context, limit int) (int, error)
}

// EntStore implements Store using Ent.
type EntStore struct {
    config    EntStoreConfig
    encryptor *Encryptor
    cleanup   *time.Ticker
    done      chan struct{}
}

// NewEntStore creates a new Ent-backed session store.
func NewEntStore(config EntStoreConfig) (*EntStore, error) {
    // Validation and setup...
}

// Create stores a new session.
func (s *EntStore) Create(ctx context.Context, session *Session) error {
    // Encrypt tokens before storage
    // Call client.CreateBFFSession
}

// Get retrieves a session by ID.
func (s *EntStore) Get(ctx context.Context, id string) (*Session, error) {
    // Fetch from database
    // Decrypt tokens
    // Check expiration
}

// ... other methods
```

### API Key Ent Store

```go
// identity/apikey/store_ent.go

package apikey

import (
    "context"
)

// EntStoreConfig configures the Ent-backed API key store.
type EntStoreConfig struct {
    // Client is the Ent client wrapper.
    Client EntClientInterface
}

// EntClientInterface abstracts the Ent client.
type EntClientInterface interface {
    CreateAPIKey(ctx context.Context, key *APIKey, keyHash string) error
    GetAPIKeyByPrefix(ctx context.Context, prefix string) (*APIKey, string, error)
    GetAPIKeyByID(ctx context.Context, id uuid.UUID) (*APIKey, error)
    ListAPIKeysByOwner(ctx context.Context, ownerID uuid.UUID) ([]*APIKey, error)
    ListAPIKeysByOrganization(ctx context.Context, orgID uuid.UUID) ([]*APIKey, error)
    UpdateAPIKey(ctx context.Context, key *APIKey) error
    DeleteAPIKey(ctx context.Context, id uuid.UUID) error
    UpdateAPIKeyLastUsed(ctx context.Context, id uuid.UUID, ip string) error
}

// EntStore implements Store using Ent.
type EntStore struct {
    config EntStoreConfig
}

// NewEntStore creates a new Ent-backed API key store.
func NewEntStore(config EntStoreConfig) *EntStore {
    return &EntStore{config: config}
}

// ... implement Store interface methods
```

## App Integration Pattern

### Step 1: Add Schema to App

```go
// internal/ent/schema/bff_session.go

package schema

import (
    "entgo.io/ent"
    "github.com/plexusone/systemforge/identity/ent/mixin"
)

// BFFSession holds the schema definition.
type BFFSession struct {
    ent.Schema
}

// Mixin of the BFFSession.
func (BFFSession) Mixin() []ent.Mixin {
    return []ent.Mixin{
        mixin.BFFSession{},
    }
}

// Edges of the BFFSession.
func (BFFSession) Edges() []ent.Edge {
    return []ent.Edge{
        edge.From("user", User.Type).
            Ref("bff_sessions").
            Field("user_id").
            Required().
            Unique(),
    }
}
```

### Step 2: Implement Client Interface

```go
// internal/auth/bff_store.go

package auth

import (
    "context"
    "github.com/plexusone/systemforge/session/bff"
    "myapp/internal/ent"
)

// EntClientWrapper implements bff.EntClientInterface.
type EntClientWrapper struct {
    client *ent.Client
}

func NewEntClientWrapper(client *ent.Client) *EntClientWrapper {
    return &EntClientWrapper{client: client}
}

func (w *EntClientWrapper) CreateBFFSession(ctx context.Context, session *bff.Session) error {
    _, err := w.client.BFFSession.Create().
        SetID(session.ID).
        SetUserID(session.UserID).
        // ... set other fields
        Save(ctx)
    return err
}

// ... implement other methods
```

### Step 3: Wire Up in App

```go
// main.go or wire.go

store, err := bff.NewEntStore(bff.EntStoreConfig{
    Client:           auth.NewEntClientWrapper(entClient),
    EncryptionKey:    []byte(cfg.SessionEncryptionKey),
    CleanupInterval:  5 * time.Minute,
    CleanupBatchSize: 100,
})

bffHandler, err := bff.NewHandler(bff.HandlerConfig{
    Store:          store,
    AllowedOrigins: cfg.AllowedOrigins,
    // ...
})
```

## Security Considerations

### Token Encryption at Rest

- Access and refresh tokens encrypted with AES-256-GCM
- Encryption key managed by app (from env/secrets manager)
- Encrypted values stored as `[]byte` in database

### Key Hash Storage

- API keys never stored in plaintext
- SHA-256 hash used for lookup
- Only prefix visible for identification

### Automatic Cleanup

- Expired sessions deleted automatically
- Configurable cleanup interval and batch size
- Prevents database bloat

## Testing Strategy

### Unit Tests

- Test each store method in isolation
- Mock Ent client interface
- Test encryption/decryption

### Integration Tests

- Use SQLite for fast tests
- Test full CRUD cycle
- Test cleanup functionality

### Benchmark Tests

- Measure read/write latency
- Test with realistic session counts
- Identify bottlenecks
