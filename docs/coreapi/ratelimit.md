# Rate Limiting

Enforce rate limits using the `session/ratelimit` package with CoreAPI policies.

## Architecture

```
Request → JWT Middleware → Rate Limit Middleware → Handler
              │                    │
              │                    ├── Extract client_id from JWT
              │                    ├── Look up policy from PolicyStore
              │                    └── Check/update rate limit counters
              │
              └── Set claims in context (including azp/client_id)
```

## Quick Start

```go
import (
    "github.com/plexusone/systemforge/coreapi"
    "github.com/plexusone/systemforge/session/ratelimit"
)

// 1. Create policy store with policies
policyStore := coreapi.NewMemoryPolicyStore()
policyStore.CreatePolicy(ctx, coreapi.StandardPolicy)
policyStore.CreatePolicy(ctx, coreapi.PremiumPolicy)
policyStore.SetDefaultPolicy(ctx, "standard")

// 2. Bind clients to policies
policyStore.BindClientToPolicy(ctx, "mobile-app", "standard")
policyStore.BindClientToPolicy(ctx, "partner-api", "premium")

// 3. Create rate limiter with CoreAPI resolver
limiter := ratelimit.New(
    ratelimit.NewMemoryStorage(),
    ratelimit.WithResolver(ratelimit.NewCoreAPIResolver(policyStore)),
    ratelimit.WithKeyFunc(ratelimit.CompositeKey()),
)

// 4. Apply middleware
router.Use(jwtMiddleware)         // Extract JWT claims
router.Use(limiter.Middleware())  // Enforce rate limits
```

## Storage Options

### Memory Storage

For development and single-instance deployments:

```go
storage := ratelimit.NewMemoryStorage()
```

Uses sliding window algorithm with automatic cleanup of expired entries.

### Redis Storage

For distributed deployments:

```go
storage := ratelimit.NewRedisStorage(
    redisClient,
    ratelimit.WithRedisKeyPrefix("ratelimit:"),
)
```

Uses Lua scripts for atomic operations. Requires `github.com/redis/go-redis/v9`.

## Key Functions

Key functions extract the rate limit key from the request context.

### PrincipalKey

Rate limit per user/principal:

```go
ratelimit.WithKeyFunc(ratelimit.PrincipalKey())
// Key: "pid:user-uuid"
```

### ClientKey

Rate limit per OAuth client/application:

```go
ratelimit.WithKeyFunc(ratelimit.ClientKey())
// Key: "azp:mobile-app"
```

### CompositeKey

Rate limit per user per application (recommended):

```go
ratelimit.WithKeyFunc(ratelimit.CompositeKey())
// Key: "pid:user-uuid:azp:mobile-app"
```

## Limit Resolvers

Resolvers determine the rate limit for each request.

### CoreAPI Resolver

Look up limits from PolicyStore based on client_id:

```go
resolver := ratelimit.NewCoreAPIResolver(policyStore,
    ratelimit.WithResolverCacheDuration(5 * time.Minute),
)

limiter := ratelimit.New(storage,
    ratelimit.WithResolver(resolver),
)
```

### Static Resolver

Apply the same limit to all requests:

```go
limiter := ratelimit.New(storage,
    ratelimit.WithStaticLimit(ratelimit.Limit{
        Requests: 100,
        Window:   time.Minute,
    }),
)
```

## Rate Limit Headers

The middleware adds standard headers to responses:

| Header | Description |
|--------|-------------|
| `RateLimit-Policy` | IETF draft: `"<name>";q=<quota>;w=<window seconds>` per checked limit |
| `RateLimit` | IETF draft: `"<name>";r=<remaining>;t=<seconds to reset>` per checked limit |
| `X-RateLimit-Limit` | Maximum requests allowed |
| `X-RateLimit-Remaining` | Requests remaining in window |
| `X-RateLimit-Reset` | Unix timestamp when limit resets |
| `Retry-After` | Seconds to wait, rounded up and at least 1 (only on 429) |

Name a limiter's policy with `WithName`. For the layered limits (a default
per client address, route policies, signed-in callers) see
[Client Addresses and Rate Limiting](../guides/rate-limiting.md).

## Handling Rate Limit Exceeded

When limits are exceeded, the middleware returns:

- **Status**: `429 Too Many Requests`
- **Body**: JSON error with details
- **Headers**: Rate limit headers including `Retry-After`

```json
{
  "error": "rate_limit_exceeded",
  "message": "Rate limit exceeded. Try again in 30 seconds.",
  "retry_after": 30
}
```

## Options

```go
limiter := ratelimit.New(storage,
    // Use CoreAPI resolver
    ratelimit.WithResolver(resolver),

    // Key extraction from JWT
    ratelimit.WithKeyFunc(ratelimit.CompositeKey()),

    // Custom error handler
    ratelimit.WithErrorHandler(func(w http.ResponseWriter, r *http.Request, err error) {
        // Custom error response
    }),

    // Skip rate limiting for certain requests
    ratelimit.WithSkipper(func(r *http.Request) bool {
        return r.URL.Path == "/health"
    }),
)
```

## Full Example

```go
package main

import (
    "net/http"

    "github.com/go-chi/chi/v5"
    "github.com/plexusone/systemforge/coreapi"
    "github.com/plexusone/systemforge/session/jwt"
    "github.com/plexusone/systemforge/session/ratelimit"
)

func main() {
    // Policy store setup
    policyStore := coreapi.NewMemoryPolicyStore()
    policyStore.CreatePolicy(ctx, coreapi.FreePolicy)
    policyStore.CreatePolicy(ctx, coreapi.StandardPolicy)
    policyStore.CreatePolicy(ctx, coreapi.PremiumPolicy)
    policyStore.SetDefaultPolicy(ctx, "free")

    // Bind OAuth clients to policies
    policyStore.BindClientToPolicy(ctx, "mobile-app", "standard")
    policyStore.BindClientToPolicy(ctx, "enterprise-client", "premium")

    // Rate limiter
    limiter := ratelimit.New(
        ratelimit.NewMemoryStorage(),
        ratelimit.WithResolver(ratelimit.NewCoreAPIResolver(policyStore)),
        ratelimit.WithKeyFunc(ratelimit.CompositeKey()),
    )

    // Router
    r := chi.NewRouter()
    r.Use(jwt.Middleware(jwtConfig))
    r.Use(limiter.Middleware())

    r.Get("/api/resource", handleResource)

    http.ListenAndServe(":8080", r)
}
```

## JWT Claims

The rate limiter extracts claims from JWT tokens set by the JWT middleware:

| Claim | Use |
|-------|-----|
| `pid` (principal ID) | Identifies the user |
| `azp` (authorized party) | Identifies the OAuth client |

Ensure your JWT middleware sets these claims in the request context.

## Next Steps

- [Policies](policies.md) - Define custom rate limit policies
- [Overview](overview.md) - CoreAPI architecture
