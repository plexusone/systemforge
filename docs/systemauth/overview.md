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
| `/oauth/token` | POST | Token endpoint; requires a DPoP proof and issues DPoP-bound tokens ([DPoP Enforcement](../session/dpop.md)); refresh tokens rotate (see [Social Login](social-login.md#refresh-tokens)) |
| `/oauth/introspect` | POST | Token introspection (RFC 7662) |
| `/oauth/revoke` | POST | Token revocation (RFC 7009) |
| `/oauth/userinfo` | GET/POST | OpenID Connect UserInfo |
| `/oauth/userinfo/memberships` | GET | Paginated organization memberships of the token's principal (needs an `OrgsSource`) |
| `/oauth/userinfo/memberships/resolve?slug=` | GET | The token principal's membership in the organization a slug names, including a slug given up by renaming within its cooling-off period (`alias: true`); 404 for an unknown slug or an organization the principal is not in |

With `social_login` configured, `/login*`, `/logout` and `/consent` are added
(see [Social Login](social-login.md)). `/oauth/authorize` honours the OIDC
`prompt` parameter (`none`, `login`, `consent`, `select_account`); see
[Silent sign-in and prompt](social-login.md#silent-sign-in-and-prompt).

### Client party

Every client has a party, which says who owns the application; the customer
owns the data in every case. It decides whether users are asked for consent:

| Party | Who owns the app | Consent |
|-------|------------------|---------|
| `first_party` | The service provider running SystemAuth | Skipped |
| `second_party` | The customer | Asked and recorded |
| `third_party` | A partner | Asked and recorded |

```yaml
clients:
  - id: web-app            # the operator's own app: first_party by default
    type: confidential
    name: Web Application
  - id: partner-reports
    type: confidential
    name: Partner Reports
    party: third_party      # users are asked for consent
    logo_url: https://partner.example.com/logo.png   # shown on the login page
```

A client in the configuration file is `first_party` unless it sets `party`.
A client registered at runtime (`Server.RegisterClient`, `Storage`,
`EmbeddedOAuthClientStore`) without one is `third_party`. Unknown values are
refused. The decision is made by the authorization endpoint whatever the
`SessionProvider`: a second- or third-party client always needs the user's
recorded consent, so a deployment that registers such clients needs a
`SessionProvider` that records consent (social login does;
`DefaultSessionProvider` records none). `logo_url`, optional, must be an
absolute https URL. With `EntStorage` the party is the `sf_oauth_apps.party`
column; see the [upgrade notes](deployment.md#client-party-column).

### UserInfo

`/oauth/userinfo` implements OIDC Core §5.3. SystemAuth's tokens are
DPoP-bound ([DPoP Enforcement](../session/dpop.md)): send the access token as
`Authorization: DPoP <token>` with a `DPoP` proof for the request, signed by
the key the token is bound to and carrying the token's hash. Only a bearer
token, issued to a client with the `allow_bearer_tokens` exception, is sent as
`Authorization: Bearer <token>` (or `access_token` in a form-encoded `POST`
body). Query parameters are not accepted. The token must have been granted the
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

With `systemauth.WithOrgsSource` configured, userinfo and the ID token also
carry `orgs` and `orgs_truncated` whatever the scopes, and JWT access tokens
carry the compact form. `GET /oauth/userinfo/memberships?limit=&cursor=`
returns every organization, paginated. See
[The `orgs` claim](../design/architecture/organizations.md#the-orgs-claim).

`sub` is the SystemAuth principal ID. Standard claims are released per granted
scope — `email` → `email`, `email_verified`; `profile` → `name`, `picture`, … —
and are read live from the principal (via the `SessionProvider`), so they
reflect the current profile rather than the one at sign-in.

Token subjects are principals (ADR-004). A custom `SessionProvider` must
return principal IDs from `GetAuthenticatedUser`: every time a token is
used or refreshed, SystemAuth checks that its subject names an active
principal in its storage (`PrincipalStatus`). A subject that is not a
principal ID, or whose principal was deactivated or deleted, is refused and
its token family revoked. Only client-credentials tokens, whose subject is
empty, carry no principal.

| Condition | Response |
|-----------|----------|
| No token | `401`, `WWW-Authenticate: Bearer realm="systemauth"` and `WWW-Authenticate: DPoP algs="ES256 ES384 ES512"` |
| Unknown, expired or revoked token | `401`, `WWW-Authenticate: ..., error="invalid_token"` |
| DPoP-bound token sent as Bearer, or without a valid proof | `401`, `WWW-Authenticate: DPoP ..., error="invalid_token"` or `error="invalid_dpop_proof"` |
| Token without `openid` scope | `403`, `WWW-Authenticate: ..., error="insufficient_scope", scope="openid"` |

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
