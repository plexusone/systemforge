# SystemAuth Overview

SystemAuth provides authentication and OAuth 2.0 functionality through clean, swappable provider interfaces. This design allows you to start with embedded implementations and migrate to external services (like Ory Hydra/Kratos) when needed.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Your Application                            │
├─────────────────────────────────────────────────────────────────┤
│                         SystemAuth                                 │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │IdentityProvider │  │AuthenticationPr │  │  OAuthProvider  │ │
│  │  (User CRUD)    │  │ (Sessions)      │  │ (OAuth 2.0)     │ │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘ │
│           │                    │                    │           │
│  ┌────────▼────────────────────▼────────────────────▼────────┐ │
│  │              Embedded (Fosite) or Ory Adapters             │ │
│  └────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## Provider Interfaces

| Interface | Purpose | Maps to Ory |
|-----------|---------|-------------|
| `IdentityProvider` | User CRUD operations | Kratos Identity API |
| `AuthenticationProvider` | Session management | Kratos Session API |
| `OAuthProvider` | OAuth 2.0/OIDC flows | Hydra Public/Admin API |
| `OAuthClientStore` | OAuth client management | Hydra Client API |

## Quick Start

### Option 1: Full OAuth Server

```go
import "github.com/plexusone/systemforge/identity/systemauth"

// Create embedded OAuth server
server, err := systemauth.NewEmbedded(systemauth.Config{
    Issuer: "https://auth.example.com",
})

// Get all providers
providers := systemauth.NewProviders(server,
    systemauth.WithProviderSessionDuration(24 * time.Hour),
    systemauth.WithProviderPasswordVerifier(myPasswordVerifier),
)

// Use providers
identity, _ := providers.Identity.GetIdentity(ctx, userID)
session, _ := providers.Authentication.ValidateSession(ctx, token)
userInfo, _ := providers.OAuth.UserInfo(ctx, accessToken)
```

### Option 2: Identity/Auth Only (No OAuth)

```go
// Create from storage directly
storage := systemauth.NewMemoryStorage() // or Ent storage
providers := systemauth.NewProvidersFromStorage(storage)

// Identity and Authentication available
// OAuth is nil (no server)
```

## HTTP Endpoints

A `systemauth.Server` (embedded or the standalone `cmd/systemauth` binary)
serves:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/.well-known/openid-configuration` | GET | OIDC discovery |
| `/.well-known/jwks.json` | GET | JSON Web Key Set |
| `/oauth/authorize` | GET/POST | Authorization endpoint |
| `/oauth/token` | POST | Token endpoint (refresh tokens rotate; see [Social Login](social-login.md#refresh-tokens)) |
| `/oauth/introspect` | POST | Token introspection (RFC 7662) |
| `/oauth/revoke` | POST | Token revocation (RFC 7009) |
| `/oauth/userinfo` | GET/POST | OpenID Connect UserInfo |

With `social_login` configured, `/login*`, `/logout` and `/consent` are added
(see [Social Login](social-login.md)).

### UserInfo

`/oauth/userinfo` implements OIDC Core §5.3. Send the access token as
`Authorization: Bearer <token>` (or `access_token` in a form-encoded `POST`
body; query parameters are not accepted). The token must have been granted the
`openid` scope.

```json
{
  "sub": "5f1c0a9e-...",
  "email": "octo@example.com",
  "email_verified": true,
  "name": "Octo Cat",
  "picture": "https://avatars.example.com/u/4242"
}
```

`sub` is the SystemAuth principal ID. Standard claims are released per granted
scope — `email` → `email`, `email_verified`; `profile` → `name`, `picture`, … —
and are read live from the principal (via the `SessionProvider`), so they
reflect the current profile rather than the one at sign-in.

| Condition | Response |
|-----------|----------|
| No token | `401`, `WWW-Authenticate: Bearer realm="systemauth"` |
| Unknown, expired or revoked token | `401`, `WWW-Authenticate: Bearer ..., error="invalid_token"` |
| Token without `openid` scope | `403`, `WWW-Authenticate: Bearer ..., error="insufficient_scope", scope="openid"` |

## Embedded vs Ory

| Aspect | Embedded | Ory Services |
|--------|----------|--------------|
| Deployment | Single binary | Multiple services |
| Database | App's database | Separate databases |
| Scaling | With app | Independent |
| Customization | Full code control | Config + webhooks |
| Production Ready | ✅ (Fosite-based) | ✅ (Battle-tested) |

## Migration Path

Start embedded, migrate to Ory when needed:

```go
// Today: Embedded
providers := systemauth.NewProviders(server)

// Future: Ory adapters (same interface)
providers := &systemauth.Providers{
    Identity:       ory.NewKratosIdentityProvider(kratosClient),
    Authentication: ory.NewKratosAuthProvider(kratosClient),
    OAuth:          ory.NewHydraOAuthProvider(hydraClient),
    OAuthClients:   ory.NewHydraClientStore(hydraAdminClient),
}

// Application code using providers.* doesn't change!
```

## Next Steps

- [Identity Provider](providers.md#identity-provider) - User management
- [Authentication Provider](providers.md#authentication-provider) - Sessions
- [OAuth Provider](providers.md#oauth-provider) - OAuth 2.0 flows
