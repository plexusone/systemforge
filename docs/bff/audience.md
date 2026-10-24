# JWT Audience Separation

SystemForge supports audience-aware JWT tokens to distinguish between BFF (web browser) and API (programmatic) clients. This enables strict path separation and prevents token misuse.

## Why Audience Separation?

Without audience validation, a token obtained for the web UI could be used against the API directly, bypassing CSRF protection. Audience claims solve this:

| Client Type | Audience | Transport | CSRF Protected |
|-------------|----------|-----------|----------------|
| Web Browser | `bff` | HTTP-only cookie | Yes |
| API Client | `api` | Bearer header | No (uses scopes) |

```
Web App                    API Client
   │                           │
   │ POST /bff/login          │ POST /api/tokens
   │                           │
   ▼                           ▼
┌──────────────┐         ┌──────────────┐
│ JWT          │         │ JWT          │
│ aud: "bff"   │         │ aud: "api"   │
│ no scopes    │         │ scopes: [...]│
└──────────────┘         └──────────────┘
   │                           │
   │ Cookie only accepted      │ Bearer only accepted
   │ on /bff/* routes          │ on /api/* routes
   ▼                           ▼
┌──────────────┐         ┌──────────────┐
│ BFF Handler  │         │ API Handler  │
│ /bff/*       │         │ /api/*       │
└──────────────┘         └──────────────┘
```

## Application Audience

`Config.Audience` names the application a `jwt.Service` issues tokens for and
is required: `NewService` returns `ErrMissingAudience` without it. Every token
the service mints carries it, and `ValidateAccessToken` and
`ValidateRefreshToken` refuse tokens that do not, so applications that share a
signing key do not accept each other's tokens.

```go
cfg := jwt.DefaultConfig()
cfg.Secret = secret
cfg.Audience = []string{"my-app"}
jwtService, err := jwt.NewService(cfg)
```

The client-kind audiences below (`bff`, `api`) are added in front of the
application audience rather than replacing it, so a BFF token for `my-app`
carries `aud: ["bff", "my-app"]`.

## Constants

```go
import "github.com/plexusone/systemforge/session/jwt"

// Audience constants
const (
    jwt.AudienceBFF = "bff" // Web browser clients
    jwt.AudienceAPI = "api" // Programmatic clients
)
```

## Generating Tokens with Audience

### BFF Tokens (Web Clients)

```go
import (
    "github.com/plexusone/systemforge/session/jwt"
)

jwtService, _ := jwt.NewService(cfg)

// Generate BFF token pair (no scopes)
tokenPair, err := jwtService.GenerateBFFTokenPair(
    userID,
    email,
    name,
)
// tokenPair.AccessToken has aud: ["bff", "my-app"]
```

### API Tokens (Programmatic Clients)

```go
// Generate API token (requires scopes)
apiToken, err := jwtService.GenerateAPIToken(
    userID,
    email,
    name,
    []string{"read:users", "write:projects"},
    90 * 24 * time.Hour, // 90 days
)
// apiToken has aud: ["api", "my-app"] and scopes
```

### Custom Audience

```go
// For custom audiences (e.g., mobile apps, service-to-service)
accessToken, err := jwtService.GenerateAccessTokenWithAudience(
    userID,
    email,
    name,
    "mobile",
    []string{"read:*"},
)
```

## Validating Tokens with Audience

### Standard Validation (Application Audience)

```go
// Accepts any kind of token addressed to this application (Config.Audience)
claims, err := jwtService.ValidateAccessToken(tokenString)
```

### Audience-Aware Validation

```go
// Strict - requires matching audience
claims, err := jwtService.ValidateAccessTokenWithAudience(
    tokenString,
    jwt.AudienceBFF, // Expected audience
)

if errors.Is(err, jwt.ErrAudienceMismatch) {
    // Token has wrong audience
    return http.StatusForbidden
}
```

## Claims Helper Methods

The `Claims` struct provides helper methods for audience handling:

```go
// Get first audience value
aud := claims.Audience() // "bff" or "api"

// Check for specific audience
if claims.HasAudience("bff") {
    // Token is for BFF client
}

// Set audience (builder pattern)
claims.WithAudience("bff")
claims.WithAudience("api", "mobile") // Multiple audiences
```

## Middleware Integration

### BFF Middleware

```go
func BFFAuthMiddleware(jwtService *jwt.Service) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Get token from cookie
            cookie, err := r.Cookie("sf_session")
            if err != nil {
                http.Error(w, "unauthorized", http.StatusUnauthorized)
                return
            }

            // Validate with BFF audience
            claims, err := jwtService.ValidateAccessTokenWithAudience(
                cookie.Value,
                jwt.AudienceBFF,
            )
            if err != nil {
                http.Error(w, "invalid token", http.StatusUnauthorized)
                return
            }

            ctx := WithClaims(r.Context(), claims)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}
```

### API Middleware

```go
func APIAuthMiddleware(jwtService *jwt.Service) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Get token from Authorization header
            auth := r.Header.Get("Authorization")
            if !strings.HasPrefix(auth, "Bearer ") {
                http.Error(w, "unauthorized", http.StatusUnauthorized)
                return
            }
            token := strings.TrimPrefix(auth, "Bearer ")

            // Validate with API audience
            claims, err := jwtService.ValidateAccessTokenWithAudience(
                token,
                jwt.AudienceAPI,
            )
            if err != nil {
                http.Error(w, "invalid token", http.StatusUnauthorized)
                return
            }

            ctx := WithClaims(r.Context(), claims)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}
```

## Errors

```go
var (
    // ErrAudienceMismatch is returned when token audience doesn't match expected
    jwt.ErrAudienceMismatch = errors.New("audience mismatch")

    // ErrScopesRequired is returned when API tokens are created without scopes
    jwt.ErrScopesRequired = errors.New("at least one scope is required for API tokens")
)
```

## Migration Guide

### From Non-Audience Tokens

1. **Update token generation** to include audience:
   ```go
   // Before
   token, _ := jwtService.GenerateAccessToken(userID, email, name)

   // After (BFF)
   tokenPair, _ := jwtService.GenerateBFFTokenPair(userID, email, name)

   // After (API)
   token, _ := jwtService.GenerateAPIToken(userID, email, name, scopes, duration)
   ```

2. **Update validation** (optional, for strict enforcement):
   ```go
   // Before
   claims, err := jwtService.ValidateAccessToken(token)

   // After (strict)
   claims, err := jwtService.ValidateAccessTokenWithAudience(token, jwt.AudienceBFF)
   ```

3. **Existing tokens** without audience will:
   - Pass `ValidateAccessToken()` (backward compatible)
   - Fail `ValidateAccessTokenWithAudience()` (strict mode)

### Rollout Strategy

1. Deploy with audience in new tokens, but don't validate audience yet
2. Monitor for any issues with new tokens
3. After token rotation period (refresh token lifetime), enable strict audience validation
4. Remove backward compatibility code

## Security Considerations

1. **Always validate audience** on security-sensitive endpoints
2. **Use short-lived access tokens** with refresh for BFF clients
3. **Require scopes** for all API tokens
4. **Log audience mismatches** for security monitoring
5. **Don't accept BFF tokens via Bearer header** - they should only come from cookies
