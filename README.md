# SystemForge

[![Go CI][go-ci-svg]][go-ci-url]
[![Go Lint][go-lint-svg]][go-lint-url]
[![Go SAST][go-sast-svg]][go-sast-url]
[![Docs][docs-godoc-svg]][docs-godoc-url]
[![DevGuide][docs-mkdoc-svg]][docs-mkdoc-url]
[![Visualization][viz-svg]][viz-url]
[![License][license-svg]][license-url]

 [go-ci-svg]: https://github.com/plexusone/systemforge/actions/workflows/go-ci.yaml/badge.svg?branch=main
 [go-ci-url]: https://github.com/plexusone/systemforge/actions/workflows/go-ci.yaml
 [go-lint-svg]: https://github.com/plexusone/systemforge/actions/workflows/go-lint.yaml/badge.svg?branch=main
 [go-lint-url]: https://github.com/plexusone/systemforge/actions/workflows/go-lint.yaml
 [go-sast-svg]: https://github.com/plexusone/systemforge/actions/workflows/go-sast-codeql.yaml/badge.svg?branch=main
 [go-sast-url]: https://github.com/plexusone/systemforge/actions/workflows/go-sast-codeql.yaml
 [docs-godoc-svg]: https://pkg.go.dev/badge/github.com/plexusone/systemforge
 [docs-godoc-url]: https://pkg.go.dev/github.com/plexusone/systemforge
 [docs-mkdoc-svg]: https://img.shields.io/badge/Go-dev%20guide-blue.svg
 [docs-mkdoc-url]: https://plexusone.github.io/systemforge
 [viz-svg]: https://img.shields.io/badge/visualizaton-Go-blue.svg
 [viz-url]: https://mango-dune-07a8b7110.1.azurestaticapps.net/?repo=plexusone%2Fsystemforge
 [loc-svg]: https://tokei.rs/b1/github/plexusone/systemforge
 [repo-url]: https://github.com/plexusone/systemforge
 [license-svg]: https://img.shields.io/badge/license-MIT-blue.svg
 [license-url]: https://github.com/plexusone/systemforge/blob/main/LICENSE

SystemForge is a batteries-included Go platform module providing reusable identity, session, authorization, and feature flags for multi-tenant SaaS applications. Think of it as Django/Laravel-style conveniences for Go.

Within the plexusone org, SystemForge is the shared identity/session/authorization foundation the Forge platform family (ActionForge, AgentForge, DashForge) builds on — one contract instead of each app inventing its own. See [INIT-SYSTEMFORGE-001](docs/specs/initiatives/INIT-SYSTEMFORGE-001/PRD.md) for the unified authorization vocabulary, IAM console, and shell composition work this drives.

> Moved from `github.com/grokify/systemforge` to `github.com/plexusone/systemforge` in v0.10.0 — the old path still resolves via GitHub's repository-transfer redirect for existing pins, but won't receive new tags. See the [v0.10.0 release notes](docs/releases/v0.10.0.md) for the full migration.

## Features

### Identity Module

- 👤 **Users** - Email, password hash (Argon2id), platform admin flag
- 🏢 **Organizations** - Multi-tenant with name, slug, plan, settings
- 🔗 **Memberships** - User-org relationships with flexible roles
- 👑 **Ownership Transfer** - Transaction-safe organization ownership transfers
- 🔐 **OAuth Accounts** - External OAuth provider links (GitHub, Google)
- 🔑 **API Keys** - Machine-to-machine authentication with scopes

### OAuth 2.0 Server (Fosite)

- 📜 **Authorization Code + PKCE** - Secure browser-based auth
- 🤖 **Client Credentials** - Service-to-service auth
- 🔄 **Refresh Token** - With rotation and theft detection
- 📝 **JWT Bearer (RFC 7523)** - Service account authentication
- ⚙️ **Service Accounts** - Non-human identities with RSA/EC key pairs
- 🔍 **Token Introspection & Revocation** - RFC 7662/7009

### Session Module

- 🎫 **JWT Service** - Access/refresh token generation with HS256/RS256/ES256
- 🔒 **DPoP (RFC 9449)** - Proof-of-possession token binding
- 🖥️ **BFF Pattern** - Backend for Frontend with server-side sessions
- 💾 **OmniStorage Backend** - Production session storage with Redis, size limits, and observability
- 🌐 **OAuth Handlers** - GitHub and Google social login
- 🛡️ **Middleware** - JWT Bearer and API key authentication

### Authorization Module

- 👥 **RBAC/ReBAC** - Role and relationship-based access control
- 🔐 **SpiceDB Provider** - Zanzibar-style fine-grained authorization
- ✨ **Simple Provider** - Lightweight permission checking
- 🧩 **Query Policy Bridge** - Use `authz.Authorizer` to feed safe query languages such as GrokifyQL
- 🚧 **HTTP Middleware** - Route protection for Chi and stdlib

### Observability

- 📊 **Vendor-Agnostic** - Integrates with [omniobserve](https://github.com/plexusone/omniobserve)
- 🔌 **Multiple Backends** - OTLP, Datadog, New Relic, Dynatrace
- 📈 **Pre-Built Metrics** - CoreAuth, rate limiting, JWT/API key validation
- 🔍 **Distributed Tracing** - Automatic span creation for OAuth flows
- 📝 **slog Integration** - Trace-correlated structured logging

### Marketplace

- 🛒 **Listings** - Product catalog with tiers and pricing
- 💳 **Stripe Integration** - Subscription billing and webhooks
- 📜 **Licensing** - Per-seat, unlimited, and time-limited licenses
- 👥 **Seat Management** - Assign and revoke user access

### Feature Flags

- 🚩 **Flag Engine** - Boolean, percentage, and user list flags
- 🏢 **Organization Scoping** - Per-org flag evaluation
- 💾 **In-Memory Store** - Development and testing

### Row-Level Security (RLS)

- 🗃️ **PostgreSQL RLS** - Policy generation and session variables
- 🏠 **Tenant Isolation** - Multi-tenant data separation
- 🔗 **Ent Integration** - Transaction helpers with tenant context

### Multi-App Platform

- 🏗️ **Multi-App Server** - Run multiple SaaS apps on shared infrastructure
- 📦 **Schema Isolation** - Each app gets its own PostgreSQL schema
- 🔀 **X-App-ID Routing** - Header-based request routing to app backends
- 🔌 **AppBackend Interface** - Composable app registration with lifecycle hooks
- 💾 **Shared Caching** - Redis or in-memory with app-scoped prefixes

## Installation

```bash
go get github.com/plexusone/systemforge
```

## Quick Start

### Using Identity Schemas

SystemForge provides Ent schemas with `cf_` table prefix for side-by-side migration.

#### Direct Schema Usage

```go
package main

import (
    "context"

    "github.com/plexusone/systemforge/identity/ent"
    _ "github.com/lib/pq"
)

func main() {
    client, err := ent.Open("postgres", "postgres://...")
    if err != nil {
        panic(err)
    }
    defer client.Close()

    // Run migrations
    if err := client.Schema.Create(context.Background()); err != nil {
        panic(err)
    }

    // Create a user
    user, err := client.User.Create().
        SetEmail("user@example.com").
        SetName("Example User").
        Save(context.Background())
}
```

#### Mixin Composition (Recommended)

Compose SystemForge mixins into your own schemas:

```go
// your-app/ent/schema/user.go
package schema

import (
    "entgo.io/ent"
    "entgo.io/ent/schema/field"
    cfmixin "github.com/plexusone/systemforge/identity/ent/mixin"
)

type User struct {
    ent.Schema
}

func (User) Mixin() []ent.Mixin {
    return []ent.Mixin{
        cfmixin.UUIDMixin{},      // UUID primary key
        cfmixin.TimestampMixin{}, // created_at, updated_at
    }
}

func (User) Fields() []ent.Field {
    return []ent.Field{
        field.String("username").Unique(),
        // App-specific fields...
    }
}
```

### JWT Authentication

```go
import (
    "github.com/plexusone/systemforge/session/jwt"
    "github.com/plexusone/systemforge/session/middleware"
)

// Create JWT service
svc, err := jwt.NewService(&jwt.Config{
    Secret:             []byte("your-secret-key"),
    AccessTokenExpiry:  15 * time.Minute,
    RefreshTokenExpiry: 7 * 24 * time.Hour,
    Issuer:             "your-app",
})

// Generate tokens
pair, err := svc.GenerateTokenPair(userID, email, name)

// Middleware for protected routes
r.Use(middleware.JWT(svc))
```

### DPoP Token Binding

DPoP (RFC 9449) lives in the standalone [`github.com/grokify/goauth/dpop`](https://github.com/grokify/goauth) package (moved out of SystemForge in v0.9.0). See the [goauth DPoP guide](https://grokify.github.io/goauth/guides/dpop/).

```go
import "github.com/grokify/goauth/dpop"

// Generate DPoP key pair (BFF side)
keyPair, err := dpop.GenerateKeyPair()

// Create proof for API request
proof, err := dpop.CreateProofWithOptions(keyPair, "POST", "https://api.example.com/data", dpop.ProofOptions{
    AccessToken: accessToken,
})

// Verify proof (API side)
verifier := dpop.NewVerifier(dpop.VerificationConfig{
    MaxAge: 5 * time.Minute,
})
result, err := verifier.Verify(proofJWT, dpop.VerificationRequest{
    Method:      "POST",
    URI:         "https://api.example.com/data",
    AccessToken: accessToken,
})
```

### BFF Pattern

```go
import "github.com/plexusone/systemforge/session/bff"

// Create BFF proxy
proxy := bff.NewProxy(bff.ProxyConfig{
    Backend:        "https://api.internal.example.com",
    AllowedOrigins: []string{"https://app.example.com"},
    SessionStore:   bff.NewMemoryStore(),
})

// Mount proxy handler
r.Handle("/api/*", proxy.Handler())
```

### Authorization

```go
import (
    "github.com/plexusone/systemforge/authz"
    "github.com/plexusone/systemforge/authz/simple"
)

// Create authorization provider
provider := simple.NewProvider(simple.Config{
    AllowOwnerFullAccess:  true,
    AllowPlatformAdminAll: true,
})

// Add role permissions
provider.AddRolePermissions("admin", []string{
    "users:read", "users:write",
    "settings:read", "settings:write",
})
provider.AddRolePermissions("member", []string{
    "users:read",
})

// Use middleware
mw := authz.NewMiddleware(provider)
r.With(mw.RequireAction(authz.ResourceType("users"), authz.ActionRead)).Get("/users", listUsers)
```

## Module Structure

```
github.com/plexusone/systemforge/
├── identity/              # User, Organization, Membership, OAuth
│   ├── ent/schema/        # Ent schemas with cf_ prefix
│   ├── apikey/            # API key service
│   ├── oauth/             # OAuth 2.0 server (Fosite)
│   ├── password.go        # Argon2id hashing
│   └── service.go         # Identity service interfaces
│
├── session/               # Session management
│   ├── jwt/               # JWT service with DPoP claims
│   ├── bff/               # Backend for Frontend pattern (DPoP via goauth/dpop)
│   ├── oauth/             # Social login handlers
│   ├── middleware/        # Auth middleware
│   └── ratelimit/         # Rate limiting with observability
│
├── observability/         # Vendor-agnostic observability
│   ├── observability.go   # Core wrapper for omniobserve
│   ├── middleware.go      # HTTP request tracing
│   └── metrics.go         # Pre-defined metric names
│
├── authz/                 # Authorization
│   ├── simple/            # Simple RBAC provider
│   ├── spicedb/           # SpiceDB ReBAC provider
│   ├── noop/              # No-op syncer for testing
│   ├── providertest/      # Provider test suite
│   └── middleware.go      # HTTP middleware
│
├── marketplace/           # SaaS marketplace
│   ├── listing.go         # Product listings and tiers
│   ├── license.go         # License management
│   ├── subscription.go    # Subscription handling
│   └── stripe/            # Stripe billing integration
│
├── featureflags/          # Feature flag engine
│   └── stores/            # Flag stores
│
├── multiapp/              # Multi-app platform
│   ├── server.go          # Multi-app server with routing
│   ├── app.go             # AppBackend interface
│   ├── database.go        # Schema-per-app isolation
│   ├── cache.go           # Redis and memory cache
│   └── context.go         # App context helpers
│
└── rls/                   # PostgreSQL Row-Level Security
    ├── rls.go             # Policy generation
    └── middleware.go      # HTTP middleware
```

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Table prefix | `cf_` | Avoids conflicts, enables side-by-side migration |
| Role storage | String field | Apps define own vocabularies (owner/admin/member) |
| OAuth pattern | Fosite library | Production-ready, RFC-compliant OAuth 2.0 |
| Refresh tokens | Database-backed | Enables revocation, theft detection |
| Primary keys | UUID | Modern, distributed-friendly |
| Password hashing | Argon2id | OWASP recommended, memory-hard |

## Database Tables

SystemForge creates the following tables (all prefixed with `cf_`):

| Table | Description |
|-------|-------------|
| `cf_users` | User accounts |
| `cf_organizations` | Multi-tenant organizations |
| `cf_memberships` | User-organization relationships |
| `cf_oauth_accounts` | External OAuth provider links |
| `cf_refresh_tokens` | JWT refresh token tracking |
| `cf_api_keys` | Developer API keys |
| `cf_oauth_apps` | OAuth client applications |
| `cf_oauth_app_secrets` | Client secrets (hashed) |
| `cf_oauth_tokens` | Issued OAuth tokens |
| `cf_oauth_auth_codes` | Authorization codes |
| `cf_oauth_consents` | User consent records |
| `cf_service_accounts` | Non-human identities |
| `cf_service_account_key_pairs` | RSA/EC key pairs |

## Migration Strategy

For existing apps, SystemForge supports side-by-side migration:

1. **Side-by-Side**: Create `cf_*` tables alongside existing tables
2. **Dual-Write**: Write to both old and new tables
3. **Cutover**: Switch reads to SystemForge tables
4. **Cleanup**: Remove old tables

## Documentation

Full documentation is available via MkDocs:

```bash
# Install MkDocs
pip install mkdocs mkdocs-material

# Serve locally
mkdocs serve

# Build static site
mkdocs build
```

Relevant authorization guides:

- `docs/authorization/spicedb-setup.md`
- `docs/authorization/spicedb-schema.md`
- `docs/authorization/integration.md`
- `docs/authorization/query-policy-engines.md`

## Contributing

Contributions are welcome! Please read the contributing guidelines before submitting PRs.

## License

MIT License - see [LICENSE](LICENSE) file for details.
