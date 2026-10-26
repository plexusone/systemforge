# OAuth 2.0 Overview

SystemForge includes a full OAuth 2.0 server implementation using [Fosite](https://github.com/ory/fosite).

## Supported Grant Types

| Grant Type | Use Case | PKCE Required |
|------------|----------|---------------|
| Authorization Code | Web apps, SPAs, mobile apps | Yes (public clients) |
| Client Credentials | Server-to-server | No |
| Refresh Token | Token renewal | N/A |

The JWT Bearer grant (RFC 7523) is not implemented. See
[Service Principals](service-accounts.md) for what exists today for
non-human identities.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      OAuth Provider                          │
│  ┌──────────────────────────────────────────────────────┐   │
│  │                     Fosite Core                       │   │
│  └──────────────────────────────────────────────────────┘   │
│       │              │              │              │         │
│  ┌────┴────┐   ┌────┴────┐   ┌────┴────┐   ┌────┴────┐    │
│  │ AuthZ   │   │ Token   │   │ Intro-  │   │ Revoke  │    │
│  │ Handler │   │ Handler │   │ spect   │   │ Handler │    │
│  └─────────┘   └─────────┘   └─────────┘   └─────────┘    │
│                        │                                     │
│  ┌─────────────────────┴─────────────────────────────────┐  │
│  │                   Ent Storage Adapter                  │  │
│  └────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      PostgreSQL                              │
│  sf_oauth_apps │ sf_oauth_tokens │ sf_oauth_auth_codes      │
└─────────────────────────────────────────────────────────────┘
```

## Database Schema

| Table | Description |
|-------|-------------|
| `sf_oauth_apps` | OAuth client applications |
| `sf_oauth_app_secrets` | Client secrets (hashed) |
| `sf_oauth_tokens` | Access and refresh tokens |
| `sf_oauth_auth_codes` | Authorization codes |
| `sf_oauth_consents` | User consent records |

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/oauth/authorize` | GET/POST | Authorization endpoint |
| `/oauth/token` | POST | Token endpoint |
| `/oauth/introspect` | POST | Token introspection |
| `/oauth/revoke` | POST | Token revocation |
| `/.well-known/openid-configuration` | GET | OIDC discovery |
| `/.well-known/jwks.json` | GET | JSON Web Key Set |

## Quick Setup

```go
import (
    "github.com/plexusone/systemforge/identity/ent"
    "github.com/plexusone/systemforge/identity/oauth"
)

// Create provider
cfg := oauth.DefaultConfig("https://api.example.com", []byte("secret"))
cfg.PrivateKey = signingKey // required: the same on every instance
cfg.DPoP.ReplayCache = middleware.NewRedisReplayCache(redisClient, "dpop-jti:")
provider, _ := oauth.NewProvider(entClient, cfg)

// Create API (all endpoints auto-registered)
api, _ := oauth.NewAPI(provider)

// Mount router (includes all OAuth and discovery endpoints)
http.Handle("/", api.Router())
```

## Security Features

### DPoP-Bound Tokens

The provider issues DPoP-bound tokens (RFC 9449) by default: every token
request carries a DPoP proof, and the access and refresh tokens are bound to
its key (`token_type: DPoP`). Only a client registered with the legacy
`allow_bearer_tokens` exception may get unbound bearer tokens. See
[DPoP Enforcement](../session/dpop.md#the-identityoauth-provider).

### Signing Key Rotation

`Config.KeyID` names the signing key and `Config.VerificationKeys` holds
keys that verify but never sign. Rotate N / N-1 in two deploys:

1. Pre-stage: add the new key N to `VerificationKeys` while N-1 still signs.
2. Promote: make N `PrivateKey`, move N-1 into `VerificationKeys`, and drop
   N-2. Never drop N-1 in the deploy that promotes N.

The JWKS publishes the signing key and every verification key; a token
whose `kid` names no key is refused.

### PKCE Enforcement

PKCE is required for public clients (SPAs, mobile apps):

```go
fositeConfig := &fosite.Config{
    EnforcePKCE:                 true,
    EnforcePKCEForPublicClients: true,
}
```

### Token Signatures

Tokens are stored as SHA256 signatures, not raw values:

```go
signature := sha256.Sum256([]byte(token))
// Only the signature is stored in the database
```

### Refresh Token Rotation

Each refresh token use generates a new token:

```go
app, _ := client.OAuthApp.Create().
    SetRefreshTokenRotation(true).
    // ...
```

### Secret Hashing

Client secrets use Argon2id:

```go
hash := argon2.IDKey(secret, salt, 3, 64*1024, 4, 32)
```

## Client Types

| Type | Secret | PKCE | Use Case |
|------|--------|------|----------|
| `web` | Required | Optional | Traditional web apps |
| `spa` | None | Required | Single-page apps |
| `native` | None | Required | Mobile/desktop apps |
| `service` | Required | No | Server-to-server |
| `machine` | Required | No | Automated systems |

## Next Steps

- [OAuth Apps](apps.md) - Creating and managing OAuth apps
- [Authorization Code](authorization-code.md) - User authorization flow
- [Client Credentials](client-credentials.md) - Server-to-server auth
- [Service Principals](service-accounts.md) - Non-human identities and keypair credentials
