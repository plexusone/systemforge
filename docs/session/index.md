# Session Management

SystemForge provides a comprehensive session management system for BFF (Backend for Frontend) architectures. It supports server-side sessions with HTTP-only cookies, OAuth token storage, and distributed storage backends.

## Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Frontend (Browser)                       │
│  - HTTP-only session cookie (not accessible to JS)         │
│  - OAuth tokens stored server-side                          │
└─────────────────────────────────┬───────────────────────────┘
                                  │
┌─────────────────────────────────▼───────────────────────────┐
│                    BFF Server (Go)                          │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Session Middleware                                   │  │
│  │  - Cookie management (create, read, rotate)          │  │
│  │  - Session loading from store                        │  │
│  │  - CSRF protection                                    │  │
│  └───────────────────────────────────────────────────────┘  │
│                          │                                   │
│  ┌───────────────────────▼───────────────────────────────┐  │
│  │  Session Store (bff.Store interface)                  │  │
│  │  - Create, Get, Update, Delete, Touch                │  │
│  │  - Per-user session operations                       │  │
│  │  - Automatic cleanup                                  │  │
│  └───────────────────────────────────────────────────────┘  │
│         │              │              │                      │
│         ▼              ▼              ▼                      │
│  ┌───────────┐  ┌───────────┐  ┌─────────────────────┐      │
│  │  Memory   │  │   Ent     │  │   OmniStorage       │      │
│  │  Store    │  │  Store    │  │   Store             │      │
│  └───────────┘  └───────────┘  └──────────┬──────────┘      │
└────────────────────────────────────────────┼─────────────────┘
                                             │
                                    ┌────────▼────────┐
                                    │ omnistorage-core│
                                    │ (Memory/Redis)  │
                                    └─────────────────┘
```

## Components

### Session Store (`session/bff`)

The BFF session package provides:

- **Session interface** - Create, Get, Update, Delete, Touch
- **Cookie manager** - HTTP-only, Secure, SameSite cookies
- **Session middleware** - Automatic session loading per request
- **Multiple backends** - Memory, Ent (SQL), OmniStorage (Redis)

[BFF Sessions →](bff-sessions.md)

### Session Invalidation (`session/invalidation`)

For managing active sessions across devices:

- Track sessions with device info and metadata
- "Logout all devices" functionality
- Maximum sessions per user enforcement
- Memory and Redis backends

[Session Invalidation →](invalidation.md)

## Quick Start

### Basic BFF Session Setup

```go
import (
    "github.com/plexusone/systemforge/session/bff"
)

// Create session store (using omnistorage for Redis support)
store, err := bff.NewOmniStorageStore(bff.OmniStorageConfig{
    Backend:        "redis",
    SiteID:         "myapp", // required for redis
    Sealer:         sealer,  // required for redis: encrypts tokens at rest
    RedisURL:       "redis://localhost:6379",
    MaxSessionSize: 1024 * 1024, // 1MB
    DefaultTTL:     24 * time.Hour,
})

// Create cookie manager
cookies := bff.NewCookieManager(bff.CookieConfig{
    Name:     "__Host-myapp_session",
    Path:     "/",
    SameSite: http.SameSiteStrictMode,
    MaxAge:   86400,
})

// Apply middleware
router.Use(bff.SessionMiddleware(store, cookies))
```

### Accessing Session in Handlers

```go
func handleRequest(w http.ResponseWriter, r *http.Request) {
    // Get session from context
    session := bff.SessionFromContext(r.Context())
    if session == nil {
        // No session (not logged in)
    }

    // Access session data
    userID := session.UserID
    orgID := session.OrganizationID
    accessToken := session.AccessToken
}
```

## Storage Backends

| Backend | Use Case | Distributed |
|---------|----------|-------------|
| Memory | Development, testing | No |
| Ent (SQL) | Single-server production | No |
| OmniStorage (Memory) | Development, testing | No |
| OmniStorage (Redis) | Multi-server production | Yes |

### OmniStorage Backend (Recommended)

The OmniStorage backend provides:

- **Size limits** - Prevent session bloat attacks
- **JSON validation** - Block non-serializable data
- **Violation callbacks** - Hook into metrics/alerting
- **Structured errors** - Machine-readable error codes

```go
store, err := bff.NewOmniStorageStore(bff.OmniStorageConfig{
    Backend:        "redis",
    SiteID:         "myapp", // required for redis
    Sealer:         sealer,  // required for redis: encrypts tokens at rest
    RedisURL:       os.Getenv("REDIS_URL"),
    MaxSessionSize: 1024 * 1024,
    ControlOptions: []omnisession.ControlOption{
        omnisession.WithLogger(logger),
        omnisession.WithViolationHandler(metricsHandler),
    },
})
```

See [omnistorage-core docs](https://plexusone.github.io/omnistorage-core/session/) for details.

## Session Structure

```go
type Session struct {
    ID                    string
    UserID                uuid.UUID
    OrganizationID        *uuid.UUID

    // OAuth tokens (stored server-side)
    AccessToken           string
    RefreshToken          string
    TokenType             string // "DPoP": sent with the DPoP scheme and a proof; "Bearer": as Bearer
    AccessTokenExpiresAt  time.Time
    RefreshTokenExpiresAt time.Time

    // DPoP key pair the tokens are bound to
    DPoPKeyPairJSON       []byte
    DPoPThumbprint        string

    // Metadata
    Metadata              map[string]string
    IPAddress             string
    UserAgent             string

    // Timestamps
    CreatedAt             time.Time
    UpdatedAt             time.Time
    LastAccessedAt        time.Time
    ExpiresAt             time.Time
}
```

## Security Considerations

1. **HTTP-only cookies** - Session ID not accessible to JavaScript
2. **Server-side tokens** - OAuth tokens never sent to browser
3. **Size limits** - Prevent session bloat attacks
4. **JSON-only data** - Prevent serialization vulnerabilities
5. **CSRF protection** - Origin/Referer checking for mutations
6. **Secure cookies** - HTTPS-only in production
