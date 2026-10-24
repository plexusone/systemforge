# Backend for Frontend (BFF) Package

The `session/bff` package implements the Backend for Frontend pattern for secure session management in web applications. It stores OAuth tokens server-side and uses HTTP-only cookies to identify browser sessions.

## Why BFF?

Traditional SPAs store JWT tokens in localStorage or sessionStorage, which exposes them to XSS attacks. The BFF pattern solves this by:

1. **Server-side token storage** - Access and refresh tokens never reach the browser
2. **HTTP-only cookies** - Session IDs are stored in cookies that JavaScript cannot access
3. **Automatic token injection** - BFF proxies API requests, injecting the Bearer token
4. **Built-in CSRF protection** - Origin validation prevents cross-site request forgery

```
┌─────────────┐     Cookie (session_id)      ┌─────────────────┐
│   Browser   │ ────────────────────────────▶│   BFF Handler   │
│   (React)   │                              │   /bff/*        │
└─────────────┘                              └────────┬────────┘
                                                      │
                                                      │ Inject Bearer token
                                                      ▼
                                             ┌─────────────────┐
                                             │   API Backend   │
                                             │   /api/v1/*     │
                                             └─────────────────┘
```

## Quick Start

```go
import (
    "github.com/plexusone/systemforge/session/bff"
)

// Create handler with required configuration
handler, err := bff.NewHandler(bff.HandlerConfig{
    // Required: session storage
    Store: bff.NewMemoryStore(bff.DefaultStoreConfig()),

    // Required: CSRF protection
    AllowedOrigins: []string{
        "https://myapp.com",
        "https://app.myapp.com",
    },

    // Required for API proxy
    ProxyConfig: bff.ProxyConfig{
        TargetURL:   "https://api.myapp.com",
        StripPrefix: "/bff/api",
    },

    // App-specific hooks
    OnRefresh: myRefreshHandler,
    OnLogout:  myLogoutHandler,
})

// Mount on your router
router.Mount("/bff", handler.Router())
```

## Routes

The BFF handler provides these endpoints:

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/session` | GET | Cookie | Check session status |
| `/logout` | POST | Cookie | Delete the session, clear the cookie, and run `OnLogout` |
| `/refresh` | POST | Cookie | Refresh access token |
| `/api/*` | ANY | Cookie | Proxy to API backend |

## Configuration

### HandlerConfig

```go
type HandlerConfig struct {
    // Required: session storage backend
    Store Store

    // Required: allowed origins for CSRF protection
    AllowedOrigins []string

    // Cookie configuration (optional, has secure defaults)
    CookieConfig CookieConfig

    // Proxy configuration (required if using /api/* proxy)
    ProxyConfig ProxyConfig

    // Client IP extraction (optional, for Cloudflare/proxy support)
    ClientIPConfig ClientIPConfig

    // Application hooks
    OnCreateSession func(ctx context.Context, session *Session) error
    OnRefresh       func(ctx context.Context, session *Session) (*TokenRefreshResult, error)
    OnLogout        func(ctx context.Context, session *Session) error
    OnSessionLoad   func(ctx context.Context, session *Session) error

    // Rate limiting (optional)
    RateLimitConfig *RateLimitConfig

    // Session lifetime (zero = default, negative = disabled)
    IdleTimeout time.Duration // default 24h
    MaxLifetime time.Duration // default 7 days
}
```

### Session Lifetime

A session ends when it has not been used for `IdleTimeout` (default
`bff.DefaultIdleTimeout`, 24 hours) or when `MaxLifetime` (default
`bff.DefaultMaxLifetime`, 7 days) has passed since it was created, whichever
comes first. Refreshing tokens does not extend a session past `MaxLifetime`:
the session and cookie expiry are capped at creation time plus `MaxLifetime`,
and the user must sign in again. `/session` reports an ended session as
unauthenticated, `/refresh` and the API proxy answer `401`, and the session is
deleted. Set a negative value to disable a check. The same limits are fields
of `MiddlewareConfig` for applications that use `bff.SessionMiddleware`
directly.

### CookieConfig

```go
// Secure defaults
cookieConfig := bff.DefaultCookieConfig()
// Name:     "__Host-sf_session"
// Path:     "/"
// Secure:   true        // HTTPS only
// HTTPOnly: true        // No JavaScript access
// SameSite: Strict      // No cross-site requests

// Development over plain HTTP
if isDevelopment {
    cookieConfig = bff.CookieConfig{
        Name:          bff.InsecureCookieName, // "sf_session"
        AllowInsecure: true,
    }
}
```

The default name carries the `__Host-` prefix, so browsers accept the cookie
only when it is `Secure`, has `Path=/` and no `Domain`; a sibling subdomain
cannot set or overwrite it. Give each application on a host its own name.
`NewHandler` rejects a `__Host-` name with a `Domain`, another `Path` or
without `Secure`. Avoid `Domain` with other names too: it shares the cookie
with every subdomain.

### ClientIPConfig (Cloudflare Support)

```go
// For Cloudflare deployments
clientIPConfig := bff.CloudflareClientIPConfig()
// Trusts: CF-Connecting-IP, True-Client-IP, X-Forwarded-For

// For custom proxy setup
clientIPConfig := bff.ClientIPConfig{
    TrustProxy:     true,
    TrustedProxies: []string{"10.0.0.0/8", "172.16.0.0/12"},
}

// Validate Cloudflare IPs (optional, more secure)
clientIPConfig := bff.ClientIPConfig{
    TrustCloudflare:    true,
    CloudflareIPRanges: []string{
        "173.245.48.0/20",
        "103.21.244.0/22",
        // ... see https://www.cloudflare.com/ips/
    },
}
```

## Creating Sessions

After OAuth callback completes, create a BFF session:

```go
func handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
    // ... OAuth flow, get tokens ...

    session, err := bffHandler.CreateSession(ctx, w, r, bff.CreateSessionParams{
        UserID:                userID,
        AccessToken:           tokens.AccessToken,
        RefreshToken:          tokens.RefreshToken,
        AccessTokenExpiresIn:  15 * time.Minute,
        RefreshTokenExpiresIn: 7 * 24 * time.Hour,
        Metadata: map[string]string{
            "provider": "google",
        },
    })

    // Cookie is set automatically
    http.Redirect(w, r, "/dashboard", http.StatusFound)
}
```

## Token Refresh Hook

The `OnRefresh` hook exchanges the session's refresh token for new tokens. With SystemAuth as the authorization server, the refresh token never needs to be stored by your application: SystemAuth keeps token state in its own database, rotates refresh tokens on every use, and revokes the whole token family if a used refresh token is replayed. The hook only calls the token endpoint:

```go
import "golang.org/x/oauth2"

oauthCfg := &oauth2.Config{
    ClientID:     "my-app",
    ClientSecret: clientSecret,
    Endpoint:     oauth2.Endpoint{TokenURL: "https://auth.example.com/oauth/token"},
}

OnRefresh: func(ctx context.Context, session *bff.Session) (*bff.TokenRefreshResult, error) {
    tok, err := oauthCfg.TokenSource(ctx, &oauth2.Token{
        RefreshToken: session.RefreshToken,
    }).Token()
    if err != nil {
        return nil, err
    }
    return &bff.TokenRefreshResult{
        AccessToken:           tok.AccessToken,
        RefreshToken:          tok.RefreshToken, // rotated by SystemAuth
        AccessTokenExpiresIn:  time.Until(tok.Expiry),
        RefreshTokenExpiresIn: 7 * 24 * time.Hour,
    }, nil
}
```

The handler writes the new tokens back to the session store. For refresh in middleware rather than an endpoint, `bff.NewRefresher` performs the same exchange against `RefreshConfig.TokenEndpoint`, including DPoP key rotation.

## Security Features

### Origin Validation (CSRF Protection)

The handler validates `Origin` header on state-changing requests (POST, PUT, DELETE):

```go
AllowedOrigins: []string{
    "https://myapp.com",
    "https://app.myapp.com",
}
```

- GET/HEAD/OPTIONS requests to `/session` skip origin validation (safe methods)
- Missing Origin header on POST/PUT/DELETE returns 403 Forbidden
- Referer header is checked as fallback
- Proxied `/api/*` requests are checked whatever the method, because an
  upstream GET may change state and carries the user's token: a GET, HEAD or
  OPTIONS request with a disallowed `Origin`, a `Sec-Fetch-Site` other than
  `same-origin` (when `Origin` is absent), or a disallowed `Referer` (when
  both are absent) returns 403 Forbidden

### Cookie Security

Default cookie settings:

| Attribute | Value | Purpose |
|-----------|-------|---------|
| Name | `__Host-sf_session` | Host-only; subdomains cannot set or overwrite it |
| HttpOnly | true | Prevents XSS from reading cookie |
| Secure | true | HTTPS only (`AllowInsecure` for localhost) |
| SameSite | Strict | Prevents CSRF via cookie scope |
| Path | / | Available to all paths |

### Rate Limiting

Built-in rate limiting protects against brute force and DoS:

```go
RateLimitConfig: &bff.RateLimitConfig{
    // Per-IP limits
    RequestsPerMinute: 60,
    BurstSize:         10,

    // Endpoint-specific overrides
    EndpointLimits: map[string]bff.EndpointLimit{
        "/refresh": {RequestsPerMinute: 10, BurstSize: 2},
        "/logout":  {RequestsPerMinute: 10, BurstSize: 2},
    },
}
```

## Session Storage

### MemoryStore (Development)

```go
store := bff.NewMemoryStore(bff.DefaultStoreConfig())
// - In-memory, lost on restart
// - Automatic cleanup of expired sessions
// - Not suitable for multi-instance deployments
```

### RedisStore (Production)

```go
store, err := bff.NewRedisStore(bff.RedisStoreConfig{
    Addr:     "localhost:6379",
    Password: "",
    DB:       0,
    Prefix:   "bff:session:",
})
// - Persistent across restarts
// - Shared across multiple instances
// - Recommended for production
```

## Frontend Integration

### Check Session Status

```typescript
const response = await fetch('/bff/session', {
    credentials: 'include', // Important: send cookies
});
const { authenticated, user_id, expires_at } = await response.json();
```

### Make API Requests

```typescript
// Requests go through BFF proxy
const response = await fetch('/bff/api/v1/users/me', {
    credentials: 'include',
});
// BFF injects Bearer token automatically
```

### Logout

```typescript
await fetch('/bff/logout', {
    method: 'POST',
    credentials: 'include',
});
// Session cleared, cookie removed
```

Logout fails closed. If the session store cannot load or delete the session,
`/logout` responds `500` with `{"error": "logout_failed"}` and leaves the
cookie in place so the frontend can retry. The BFF does not revoke tokens on
its own; revoke them at the authorization server in `OnLogout`. If `OnLogout`
returns an error, the session is still deleted and the cookie cleared, but the
response is `500` with `{"error": "revocation_failed"}`.

### Refresh Session

```typescript
// Usually automatic, but can be explicit
await fetch('/bff/refresh', {
    method: 'POST',
    credentials: 'include',
});
```

## Cloudflare Deployment

When deploying behind Cloudflare:

```go
handler, _ := bff.NewHandler(bff.HandlerConfig{
    // ... other config ...

    ClientIPConfig: bff.CloudflareClientIPConfig(),
})
```

This trusts these headers (set by Cloudflare):

| Header | Description |
|--------|-------------|
| CF-Connecting-IP | Original client IP |
| True-Client-IP | Client IP (Enterprise) |
| CF-Ray | Request trace ID |
| CF-IPCountry | Client country code |

Cloudflare metadata is automatically added to session:

```go
session.Metadata["cf_ray"]     // "abc123-SJC"
session.Metadata["cf_country"] // "US"
```

## OpenAPI Specification

While BFF endpoints are typically internal, you can generate OpenAPI specs for:

- Internal documentation
- TypeScript type generation
- API gateway configuration
- Contract testing

### Huma Integration

Register BFF routes with Huma for automatic OpenAPI generation:

```go
import (
    "github.com/danielgtaylor/huma/v2"
    "github.com/plexusone/systemforge/session/bff"
)

// Create BFF handler
bffHandler, _ := bff.NewHandler(config)

// Mount chi routes for actual handling
router.Mount("/bff", bffHandler.Router())

// Register with Huma for OpenAPI spec
bff.RegisterHumaRoutes(humaAPI, bff.HumaConfig{
    Handler:              bffHandler,
    PathPrefix:           "/bff",
    Tags:                 []string{"BFF", "Internal"},
    IncludeRateLimitDocs: true,
})

// Add BFF security scheme
bff.AddBFFSecurityScheme(humaAPI, "aos_session")
```

### Generated OpenAPI Extensions

The Huma integration adds these vendor extensions:

| Extension | Description |
|-----------|-------------|
| `x-internal` | Marks endpoint as internal |
| `x-cookie-auth` | Indicates cookie-based authentication |
| `x-csrf-protected` | Indicates Origin header requirement |
| `x-ratelimit-limit` | Requests per minute |
| `x-ratelimit-burst` | Burst size |
| `x-ratelimit-window` | Rate limit window |

### Example OpenAPI Output

```yaml
paths:
  /bff/session:
    get:
      operationId: bff-get-session
      summary: Get session status
      tags: [BFF]
      x-internal: true
      x-cookie-auth: true
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/SessionStatusResponse'

  /bff/refresh:
    post:
      operationId: bff-refresh-session
      summary: Refresh session
      tags: [BFF]
      x-internal: true
      x-cookie-auth: true
      x-csrf-protected: true
      x-ratelimit-limit: 10
      x-ratelimit-burst: 2
      x-ratelimit-window: 1m
      responses:
        '200':
          headers:
            X-RateLimit-Limit:
              schema: { type: integer }
            X-RateLimit-Remaining:
              schema: { type: integer }
            X-RateLimit-Reset:
              schema: { type: integer }
        '429':
          headers:
            Retry-After:
              schema: { type: integer }

components:
  securitySchemes:
    bff-session:
      type: apiKey
      in: cookie
      name: aos_session
      description: HTTP-only session cookie
```

### TypeScript Types

Generate TypeScript types from the OpenAPI spec:

```bash
npx openapi-typescript ./openapi.yaml -o ./src/types/bff.ts
```

```typescript
// Generated types
interface SessionStatusResponse {
  authenticated: boolean;
  user_id?: string;
  organization_id?: string;
  expires_at?: string;
  access_token_expires_at?: string;
}

interface RefreshResponse {
  message: string;
  expires_at: number;
}
```
