# SystemForge

**Batteries-included Go platform module for multi-tenant SaaS applications.**

SystemForge provides reusable identity, session, RBAC, and OAuth 2.0 functionality that you can integrate into your Go applications. Think of it as Django/Laravel for Go—pre-built components for the things every SaaS needs.

## Features

- **Identity Management**: Users, organizations, memberships with role-based access
- **OAuth 2.0 / OIDC Server (SystemAuth)**: Fosite-based authorization server issuing ID tokens, optional JWT access tokens, and UserInfo
- **Social Login**: GitHub/Google login served centrally by SystemAuth, with refresh-token rotation, logout, and consent
- **Embeddable SystemAuth**: `identity/systemauthsvc` lets a host binary mount SystemAuth alongside its applications in one process
- **Relying Parties**: `identity/relyingparty` lets applications federate to SystemAuth (OIDC client, `/bff/*` cookie sessions, bearer middleware), with durable encrypted PostgreSQL session stores
- **API Key Authentication**: Secure server-to-server access
- **Service Accounts**: JWT Bearer authentication for automation
- **Multi-Tenant Ready**: Organization-scoped resources with RLS support
- **Ent ORM**: Type-safe database schemas with migrations

## Quick Example

```go
package main

import (
    "github.com/plexusone/systemforge/identity/ent"
    "github.com/plexusone/systemforge/identity/oauth"
)

func main() {
    // Connect to database
    client, _ := ent.Open("postgres", "postgres://...")

    // Create OAuth provider
    cfg := oauth.DefaultConfig("https://api.example.com", []byte("secret"))
    provider, _ := oauth.NewProvider(client, cfg)

    // Create OAuth API (Huma/Chi)
    api, _ := oauth.NewAPI(provider)

    // Mount the API router
    http.Handle("/", api.Router())
    http.ListenAndServe(":8080", nil)
}
```

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                      Your Application                    │
├──────────────────────────────────────────────────────────┤
│                        SystemForge                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │ Identity │  │  OAuth   │  │   RBAC   │  │ Feature  │  │
│  │  Module  │  │  Server  │  │  Module  │  │  Flags   │  │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  │
├──────────────────────────────────────────────────────────┤
│                      Ent ORM Layer                       │
├──────────────────────────────────────────────────────────┤
│                      PostgreSQL                          │
└──────────────────────────────────────────────────────────┘
```

## Module Status

| Module | Status | Description |
|--------|--------|-------------|
| Identity | ✅ Ready | User, Org, Membership, OAuthAccount |
| OAuth 2.0 | ✅ Ready | Authorization Code, Client Credentials, Refresh Token |
| API Keys | ✅ Ready | Server-to-server authentication |
| Service Accounts | ✅ Ready | JWT Bearer authentication |
| RBAC | 🚧 Planned | Role-based access control |
| Feature Flags | 🚧 Planned | Feature flag engine |
| RLS Helpers | 🚧 Planned | PostgreSQL Row-Level Security |

## Why SystemForge?

Building a SaaS application means implementing the same foundational features over and over:

- User authentication and registration
- Organization/team management
- OAuth 2.0 for third-party integrations
- API key management for developers
- Role-based permissions

SystemForge provides battle-tested implementations of these features so you can focus on your application's unique value.

## Getting Started

- [Installation](getting-started/installation.md)
- [Quick Start](getting-started/quickstart.md)
- [Configuration](getting-started/configuration.md)

## License

Apache 2.0
