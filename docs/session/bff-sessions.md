# BFF Sessions

The BFF (Backend for Frontend) session package provides server-side session management with HTTP-only cookies for secure web applications.

## Why BFF Sessions?

Traditional SPA architectures store tokens in browser storage (localStorage/sessionStorage), which exposes them to XSS attacks. BFF sessions keep tokens server-side:

| Approach | Token Location | XSS Risk | CSRF Risk |
|----------|----------------|----------|-----------|
| localStorage | Browser | High | None |
| sessionStorage | Browser | High | None |
| HTTP-only Cookie | Server | None | Mitigated |

## Store Interface

```go
type Store interface {
    // Create stores a new session.
    Create(ctx context.Context, session *Session) error

    // Get retrieves a session by ID.
    Get(ctx context.Context, id string) (*Session, error)

    // Update updates an existing session.
    Update(ctx context.Context, session *Session) error

    // Delete removes a session by ID.
    Delete(ctx context.Context, id string) error

    // DeleteByUserID removes all sessions for a user.
    DeleteByUserID(ctx context.Context, userID string) (int, error)

    // Touch updates the LastAccessedAt timestamp.
    Touch(ctx context.Context, id string) error

    // Cleanup removes expired sessions.
    Cleanup(ctx context.Context) (int, error)

    // Close closes the store.
    Close() error
}
```

## Storage Backends

### Memory Store

For development and single-server deployments:

```go
store := bff.NewMemoryStore()
```

### Ent Store

For SQL databases via Ent ORM:

```go
store := bff.NewEntStore(entClient)
```

### OmniStorage Store (Recommended)

For production with Redis and security controls:

```go
store, err := bff.NewOmniStorageStore(bff.OmniStorageConfig{
    Backend:         "redis",
    SiteID:          "myapp", // required for redis
    RedisURL:        "redis://localhost:6379",
    MaxSessionSize:  1024 * 1024, // 1MB
    DefaultTTL:      24 * time.Hour,
    CleanupInterval: 5 * time.Minute,
    KeyPrefix:       "myapp:session:",
})
```

#### OmniStorage Configuration

| Field | Description | Default |
|-------|-------------|---------|
| `Backend` | `"memory"` or `"redis"` | `"memory"` |
| `RedisURL` | Redis connection URL | Required for redis |
| `SiteID` | Tags every session with this application; a session tagged for another site is not found | Required for redis |
| `MaxSessionSize` | Max session size in bytes | 1MB |
| `DefaultTTL` | Session lifetime | 24 hours |
| `CleanupInterval` | Cleanup frequency | 5 minutes |
| `KeyPrefix` | Redis key prefix | `"session:"` |
| `ControlOptions` | Logger, violation handler | None |

#### With Observability

```go
import omnisession "github.com/plexusone/omnistorage-core/session"

store, err := bff.NewOmniStorageStore(bff.OmniStorageConfig{
    Backend:        "redis",
    SiteID:         "myapp", // required for redis
    RedisURL:       os.Getenv("REDIS_URL"),
    MaxSessionSize: 1024 * 1024,
    ControlOptions: []omnisession.ControlOption{
        omnisession.WithLogger(slog.Default()),
        omnisession.WithViolationHandler(func(ctx context.Context, event omnisession.ViolationEvent) {
            // Record metric
            metrics.SessionViolations.Inc(event.Type)

            // Alert on abuse
            if event.Type == omnisession.ViolationSizeExceeded {
                alerting.Warn("Session size exceeded", event)
            }
        }),
    },
})
```

## Cookie Manager

```go
cookies := bff.NewCookieManager(bff.CookieConfig{
    Name:     "__Host-myapp_session", // Default: bff.DefaultCookieName ("__Host-sf_session")
    Path:     "/",                    // Required for a __Host- cookie
    SameSite: http.SameSiteStrictMode,
    MaxAge:   86400,                  // 24 hours in seconds
})
```

The cookie is always `HttpOnly`, and `Secure` unless `AllowInsecure` is set
for plain-HTTP development (the default name is then `bff.InsecureCookieName`,
`sf_session`, because browsers reject a `__Host-` cookie that is not
`Secure`). Leave `Domain` empty: a `Domain` shares the cookie with every
subdomain, any of which can then overwrite it, and is rejected for a
`__Host-` name by `CookieConfig.Validate` (which `bff.NewHandler` calls).

## Middleware

### Required Session

Requires authentication, returns 401 if no session:

```go
router.Use(bff.SessionMiddleware(store, cookies))

// In handler
session := bff.SessionFromContext(r.Context())
// session is guaranteed non-nil
```

### Optional Session

Loads session if present, but doesn't require it:

```go
router.Use(bff.OptionalSessionMiddleware(store, cookies))

// In handler
session := bff.SessionFromContext(r.Context())
if session == nil {
    // Not logged in
}
```

## Session Operations

### Create Session (Login)

```go
func handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
    // Exchange code for tokens
    tokens, err := oauth.Exchange(ctx, code)

    // Create session
    session := &bff.Session{
        ID:                    bff.GenerateSessionID(),
        UserID:                user.ID,
        OrganizationID:        &user.DefaultOrgID,
        AccessToken:           tokens.AccessToken,
        RefreshToken:          tokens.RefreshToken,
        AccessTokenExpiresAt:  tokens.Expiry,
        IPAddress:             r.RemoteAddr,
        UserAgent:             r.UserAgent(),
        CreatedAt:             time.Now(),
        ExpiresAt:             time.Now().Add(24 * time.Hour),
    }

    if err := store.Create(ctx, session); err != nil {
        // Handle error
    }

    // Set session cookie
    cookies.Set(w, session.ID)

    http.Redirect(w, r, "/dashboard", http.StatusFound)
}
```

### Get Current Session

```go
func handleGetSession(w http.ResponseWriter, r *http.Request) {
    session := bff.SessionFromContext(r.Context())

    json.NewEncoder(w).Encode(map[string]any{
        "user_id":         session.UserID,
        "organization_id": session.OrganizationID,
        "expires_at":      session.ExpiresAt,
    })
}
```

### Update Session (Token Refresh)

```go
func refreshTokens(ctx context.Context, session *bff.Session) error {
    // Refresh OAuth tokens
    newTokens, err := oauth.Refresh(ctx, session.RefreshToken)
    if err != nil {
        return err
    }

    // Update session
    session.AccessToken = newTokens.AccessToken
    session.RefreshToken = newTokens.RefreshToken
    session.AccessTokenExpiresAt = newTokens.Expiry
    session.UpdatedAt = time.Now()

    return store.Update(ctx, session)
}
```

### Delete Session (Logout)

```go
func handleLogout(w http.ResponseWriter, r *http.Request) {
    session := bff.SessionFromContext(r.Context())

    // Delete from store
    store.Delete(ctx, session.ID)

    // Clear cookie
    cookies.Clear(w)

    http.Redirect(w, r, "/", http.StatusFound)
}
```

### Logout All Devices

```go
func handleLogoutAllDevices(w http.ResponseWriter, r *http.Request) {
    session := bff.SessionFromContext(r.Context())

    // Delete all sessions for user
    count, err := store.DeleteByUserID(ctx, session.UserID.String())

    // Clear current cookie
    cookies.Clear(w)

    json.NewEncoder(w).Encode(map[string]any{
        "logged_out_sessions": count,
    })
}
```

## Error Handling

```go
session, err := store.Get(ctx, sessionID)
if err != nil {
    switch {
    case errors.Is(err, bff.ErrSessionNotFound):
        // Session doesn't exist
        http.Error(w, "Session not found", http.StatusUnauthorized)
    case errors.Is(err, bff.ErrSessionExpired):
        // Session expired
        cookies.Clear(w)
        http.Error(w, "Session expired", http.StatusUnauthorized)
    default:
        // Internal error
        http.Error(w, "Internal error", http.StatusInternalServerError)
    }
}
```

## Integration with OAuth

See [OAuth documentation](../oauth/) for integrating BFF sessions with OAuth providers.

```go
// OAuth callback handler
func handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
    // 1. Validate state parameter
    // 2. Exchange code for tokens
    // 3. Get or create user
    // 4. Create BFF session with tokens
    // 5. Set session cookie
    // 6. Redirect to app
}
```
