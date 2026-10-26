# Ent-Backed BFF Session Store

SystemForge provides an Ent-backed session store for production BFF deployments. This stores sessions in your database with encrypted tokens at rest.

## Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        SystemForge (Library)                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│   session/bff/store.go          session/bff/store_ent.go                    │
│                                                                              │
│   type Store interface {         type EntStore struct {                      │
│     Create(...)                    config    EntStoreConfig                  │
│     Get(...)                       sealer    SessionSealer                   │
│     Update(...)                  }                                           │
│     Delete(...)                                                              │
│   }                              func NewEntStore(...) (*EntStore, error)    │
└────────────────────────────────────────────────────────┬────────────────────┘
                                                         │
                                                         │ implements
                                                         ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        App-Level Implementation                              │
├─────────────────────────────────────────────────────────────────────────────┤
│   internal/ent/schema/bff_session.go    internal/auth/bff_store.go          │
│                                                                              │
│   Uses mixin:                           Implements EntClientInterface:       │
│   systemforge/identity/ent/mixin          wraps generated Ent client           │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Features

- **Encrypted tokens** - AES-256-GCM encryption for tokens and DPoP keys at rest, bound to the session and field, with key IDs for rotation
- **Automatic cleanup** - Background goroutine removes expired sessions
- **Database agnostic** - Works with PostgreSQL, MySQL, SQLite
- **Reusable schema** - Ent mixin provides consistent field definitions

## Setup

### Step 1: Add Schema to Your App

Create an Ent schema using the SystemForge mixin:

```go
// internal/ent/schema/bff_session.go

package schema

import (
    "entgo.io/ent"
    "entgo.io/ent/schema/edge"
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

// Edges of the BFFSession (optional, for relations).
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

Then run `go generate ./ent` to generate the Ent code.

### Step 2: Implement Client Interface

Create a wrapper that implements `bff.EntClientInterface`:

```go
// internal/auth/bff_store.go

package auth

import (
    "context"
    "time"

    "github.com/google/uuid"
    "github.com/plexusone/systemforge/session/bff"
    "myapp/internal/ent"
    "myapp/internal/ent/bffsession"
)

// EntClientWrapper implements bff.EntClientInterface.
type EntClientWrapper struct {
    client *ent.Client
}

// NewEntClientWrapper creates a new wrapper.
func NewEntClientWrapper(client *ent.Client) *EntClientWrapper {
    return &EntClientWrapper{client: client}
}

func (w *EntClientWrapper) CreateBFFSession(ctx context.Context, session *bff.Session) error {
    create := w.client.BFFSession.Create().
        SetID(session.ID).
        SetUserID(session.UserID).
        SetAccessTokenEncrypted(session.EncryptedAccessToken()).
        SetRefreshTokenEncrypted(session.EncryptedRefreshToken()).
        SetAccessTokenExpiresAt(session.AccessTokenExpiresAt).
        SetRefreshTokenExpiresAt(session.RefreshTokenExpiresAt).
        SetExpiresAt(session.ExpiresAt).
        SetCreatedAt(session.CreatedAt).
        SetUpdatedAt(session.UpdatedAt).
        SetLastAccessedAt(session.LastAccessedAt)

    if session.OrganizationID != nil {
        create = create.SetOrganizationID(*session.OrganizationID)
    }
    if session.IPAddress != "" {
        create = create.SetIPAddress(session.IPAddress)
    }
    if session.UserAgent != "" {
        create = create.SetUserAgent(session.UserAgent)
    }
    if len(session.EncryptedDPoPKeyPair()) > 0 {
        create = create.SetDpopKeyPairEncrypted(session.EncryptedDPoPKeyPair())
    }
    if session.DPoPThumbprint != "" {
        create = create.SetDpopThumbprint(session.DPoPThumbprint)
    }
    if session.Metadata != nil {
        create = create.SetMetadata(session.Metadata)
    }

    _, err := create.Save(ctx)
    return err
}

func (w *EntClientWrapper) GetBFFSession(ctx context.Context, id string) (*bff.Session, error) {
    s, err := w.client.BFFSession.Query().
        Where(bffsession.IDEQ(id)).
        Only(ctx)
    if err != nil {
        if ent.IsNotFound(err) {
            return nil, bff.ErrSessionNotFound
        }
        return nil, err
    }

    session := &bff.Session{
        ID:                    s.ID,
        UserID:                s.UserID,
        OrganizationID:        s.OrganizationID,
        AccessTokenExpiresAt:  s.AccessTokenExpiresAt,
        RefreshTokenExpiresAt: s.RefreshTokenExpiresAt,
        DPoPThumbprint:        s.DpopThumbprint,
        IPAddress:             s.IPAddress,
        UserAgent:             s.UserAgent,
        Metadata:              s.Metadata,
        CreatedAt:             s.CreatedAt,
        UpdatedAt:             s.UpdatedAt,
        LastAccessedAt:        s.LastAccessedAt,
        ExpiresAt:             s.ExpiresAt,
    }

    // Set encrypted fields for decryption by EntStore
    session.SetEncryptedTokens(
        s.AccessTokenEncrypted,
        s.RefreshTokenEncrypted,
        s.DpopKeyPairEncrypted,
    )

    return session, nil
}

func (w *EntClientWrapper) UpdateBFFSession(ctx context.Context, session *bff.Session) error {
    update := w.client.BFFSession.UpdateOneID(session.ID).
        SetAccessTokenEncrypted(session.EncryptedAccessToken()).
        SetRefreshTokenEncrypted(session.EncryptedRefreshToken()).
        SetAccessTokenExpiresAt(session.AccessTokenExpiresAt).
        SetRefreshTokenExpiresAt(session.RefreshTokenExpiresAt).
        SetExpiresAt(session.ExpiresAt).
        SetUpdatedAt(session.UpdatedAt).
        SetLastAccessedAt(session.LastAccessedAt)

    if len(session.EncryptedDPoPKeyPair()) > 0 {
        update = update.SetDpopKeyPairEncrypted(session.EncryptedDPoPKeyPair())
    }
    if session.DPoPThumbprint != "" {
        update = update.SetDpopThumbprint(session.DPoPThumbprint)
    }
    if session.Metadata != nil {
        update = update.SetMetadata(session.Metadata)
    }

    _, err := update.Save(ctx)
    return err
}

func (w *EntClientWrapper) DeleteBFFSession(ctx context.Context, id string) error {
    return w.client.BFFSession.DeleteOneID(id).Exec(ctx)
}

func (w *EntClientWrapper) DeleteBFFSessionsByUserID(ctx context.Context, userID uuid.UUID) (int, error) {
    return w.client.BFFSession.Delete().
        Where(bffsession.UserIDEQ(userID)).
        Exec(ctx)
}

func (w *EntClientWrapper) TouchBFFSession(ctx context.Context, id string) error {
    _, err := w.client.BFFSession.UpdateOneID(id).
        SetLastAccessedAt(time.Now()).
        Save(ctx)
    return err
}

func (w *EntClientWrapper) CleanupExpiredBFFSessions(ctx context.Context, limit int) (int, error) {
    return w.client.BFFSession.Delete().
        Where(bffsession.ExpiresAtLT(time.Now())).
        Exec(ctx)
}
```

### Step 3: Wire Up the Store

```go
// main.go or wire.go

import (
    "github.com/plexusone/systemforge/session/bff"
    "myapp/internal/auth"
)

// Seal session secrets under named keys, so they can be rotated.
sealer, err := bff.NewKeyringSealer("k1", map[string][]byte{
    "k1": cfg.SessionEncryptionKey, // 32 bytes, from your secret store
})
if err != nil {
    log.Fatal(err)
}

// Create the Ent store
store, err := bff.NewEntStore(bff.EntStoreConfig{
    Client:           auth.NewEntClientWrapper(entClient),
    Sealer:           sealer,
    CleanupInterval:  5 * time.Minute,
    CleanupBatchSize: 100,
})
if err != nil {
    log.Fatal(err)
}
defer store.Close()

// Use with BFF handler
bffHandler, err := bff.NewHandler(bff.HandlerConfig{
    Store:          store,
    AllowedOrigins: cfg.AllowedOrigins,
    // ...
})
```

## Configuration

### EntStoreConfig

```go
type EntStoreConfig struct {
    // Required: Ent client wrapper
    Client EntClientInterface

    // Sealer encrypts tokens and DPoP keys (NewKeyringSealer or
    // NewKeysSealer). Either Sealer or EncryptionKey is required.
    Sealer SessionSealer

    // A single 32-byte AES-256 key. Without a Sealer the store seals with
    // it under the key ID "default" (EntStoreDefaultKeyID). When set, it
    // also opens rows written by earlier versions.
    EncryptionKey []byte

    // Optional: cleanup interval (0 = disabled)
    CleanupInterval time.Duration

    // Optional: max sessions deleted per cleanup (default: 100)
    CleanupBatchSize int
}
```

### Encryption Key

The encryption key must be exactly 32 bytes for AES-256-GCM:

```go
// From environment variable (base64 encoded)
key, _ := base64.StdEncoding.DecodeString(os.Getenv("SESSION_ENCRYPTION_KEY"))

// Or generate one for development
key := make([]byte, 32)
rand.Read(key)
fmt.Println("Key:", base64.StdEncoding.EncodeToString(key))
```

## Mixin Fields

The `mixin.BFFSession` provides these fields:

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Session ID (unique, immutable) |
| `user_id` | UUID | Owner user |
| `organization_id` | UUID | Organization context (optional) |
| `access_token_encrypted` | []byte | Encrypted access token |
| `refresh_token_encrypted` | []byte | Encrypted refresh token |
| `access_token_expires_at` | time | Access token expiry |
| `refresh_token_expires_at` | time | Refresh token expiry |
| `dpop_key_pair_encrypted` | []byte | Encrypted DPoP key pair (optional) |
| `dpop_thumbprint` | string | DPoP JWK thumbprint (optional) |
| `ip_address` | string | Client IP (optional) |
| `user_agent` | string | Client User-Agent (optional) |
| `metadata` | JSON | Additional metadata (optional) |
| `last_accessed_at` | time | Last access timestamp |
| `expires_at` | time | Session expiry |
| `created_at` | time | Creation timestamp |
| `updated_at` | time | Update timestamp |

## Indexes

The mixin creates indexes for common queries:

```go
index.Fields("user_id")        // Find sessions by user
index.Fields("expires_at")     // Cleanup expired sessions
index.Fields("organization_id") // Filter by organization
```

## Encryption

The access token, refresh token and DPoP key pair are sealed with
AES-256-GCM before storage and opened in `Get`. Each value is bound to its
session ID and column, so a ciphertext copied into another row or column
does not open, and names the key that sealed it:

```go
// Sealing happens automatically in Create/Update
store.Create(ctx, session)

// Opening happens automatically in Get
session, err := store.Get(ctx, id)
```

### Key rotation

Rotation keeps the active key N and the previous key N-1 in the keyring and
removes only N-2. Each step is its own deploy, so rolling back any deploy
still opens every session written so far:

1. **Pre-stage `k2`.** Add it while `k1` stays active, and wait until every
   instance runs it:
   `bff.NewKeyringSealer("k1", map[string][]byte{"k1": k1, "k2": k2})`.
2. **Promote `k2`.** Make it active and keep `k1`:
   `bff.NewKeyringSealer("k2", map[string][]byte{"k1": k1, "k2": k2})`.
   Rolling back returns to step 1, which still opens sessions sealed with
   `k2`.
3. **Next rotation.** Pre-stage `k3` with `k1` still present, then promote
   `k3` with `{"k2": k2, "k3": k3}`; only `k1` (N-2) is removed.

Never add a new active key and drop the previous one in the same deploy.

### Moving from `EncryptionKey`

Earlier versions encrypted with `EncryptionKey` alone, without a key ID or
session binding. Such rows still open while `EncryptionKey` is set, and are
sealed in the current form on the session's next update. A store given only
`EncryptionKey` seals under the key ID `"default"`, so the move to a keyring
needs no re-encryption: keep the same key under `bff.EntStoreDefaultKeyID`
and pre-stage the next key beside it.

```go
sealer, err := bff.NewKeyringSealer(bff.EntStoreDefaultKeyID, map[string][]byte{
    bff.EntStoreDefaultKeyID: oldKey,
    "k2":                     newKey, // pre-staged; promote in the next deploy
})
store, err := bff.NewEntStore(bff.EntStoreConfig{
    Client:        client,
    Sealer:        sealer,
    EncryptionKey: oldKey, // still opens rows written by earlier versions
})
```

Remove `EncryptionKey` when `"default"` leaves the keyring as N-2.

Rows sealed by this version do not open with earlier versions of
SystemForge, so rolling the library back signs out the users whose sessions
were written or refreshed since the upgrade.

The `Encryptor` is also available for direct use:

```go
encryptor, err := bff.NewEncryptor(key)

ciphertext, err := encryptor.Encrypt([]byte("secret"))
plaintext, err := encryptor.Decrypt(ciphertext)
```

## Automatic Cleanup

When `CleanupInterval` is set, expired sessions are automatically deleted:

```go
store, _ := bff.NewEntStore(bff.EntStoreConfig{
    // ...
    CleanupInterval:  5 * time.Minute,
    CleanupBatchSize: 100, // Delete at most 100 per run
})

// Cleanup runs in background goroutine
// Stop it on shutdown:
store.Close()
```

Manual cleanup is also available:

```go
deleted, err := store.Cleanup(ctx)
fmt.Printf("Deleted %d expired sessions\n", deleted)
```

## Database Migration

Example SQL migration (PostgreSQL):

```sql
CREATE TABLE bff_sessions (
    id VARCHAR(64) PRIMARY KEY,
    user_id UUID NOT NULL,
    organization_id UUID,
    access_token_encrypted BYTEA NOT NULL,
    refresh_token_encrypted BYTEA NOT NULL,
    access_token_expires_at TIMESTAMP NOT NULL,
    refresh_token_expires_at TIMESTAMP NOT NULL,
    dpop_key_pair_encrypted BYTEA,
    dpop_thumbprint VARCHAR(64),
    ip_address VARCHAR(45),
    user_agent VARCHAR(500),
    metadata JSONB,
    last_accessed_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

CREATE INDEX idx_bff_sessions_user_id ON bff_sessions(user_id);
CREATE INDEX idx_bff_sessions_expires_at ON bff_sessions(expires_at);
CREATE INDEX idx_bff_sessions_organization_id ON bff_sessions(organization_id);
```

## Security Considerations

1. **Protect the encryption key** - Store in secrets manager, not in code
2. **Rotate keys periodically** - Keep N and N-1 in the keyring, pre-stage each new key (see [Key rotation](#key-rotation))
3. **Use HTTPS** - Encrypted storage doesn't help if transport is insecure
4. **Monitor session counts** - Alert on unusual session creation rates
5. **Audit access** - Log session creation/deletion for security review
