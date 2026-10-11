# PRD: SystemForge Authentication & Authorization

> **Status**: Implemented in v0.1.0
>
> This PRD defined the requirements for SystemForge authentication. The features described below have been implemented in the following modules:
>
> - `session/dpop/` - DPoP proof-of-possession (RFC 9449)
> - `session/bff/` - Backend for Frontend pattern
> - `session/jwt/` - JWT service with DPoP claims
> - `session/middleware/` - Authentication middleware
> - `identity/apikey/` - API key service
> - `authz/` - RBAC with Casbin and simple providers

## Overview

This document defines the product requirements for SystemForge's authentication and authorization system, designed to support multi-tenant SaaS applications with both WebUI (SPA) and Developer API access patterns.

## Goals

1. **Unified Identity Model**: Organizations where users can be members of multiple orgs (replacing tenant-per-user)
2. **Secure SPA Authentication**: Prevent token hijacking for direct API abuse
3. **Developer API Support**: Enable 3rd party integrations via Developer Program
4. **Extensible Architecture**: Pluggable providers for OAuth, token binding, and authorization

## Target Applications

| Application | Current State | Target State |
|-------------|---------------|--------------|
| **App1** | SystemForge integrated | Add DPoP + BFF |
| **Dashforge** | Custom auth, tenant-per-user | Full SystemForge migration |
| **Future Apps** | - | SystemForge from day one |

## User Stories

### WebUI Authentication

**US-1**: As a user, I can sign in via OAuth (GitHub, Google) through the web application.

**US-2**: As a user, my session is secure even if an attacker intercepts network traffic.

**US-3**: As a user, tokens stolen from my browser cannot be used outside the web application context.

**US-4**: As a user, I can belong to multiple organizations and switch between them.

### Developer API Authentication

**US-5**: As a developer, I can create API keys for server-to-server integration.

**US-6**: As a developer, I can use OAuth to access APIs on behalf of users (with their consent).

**US-7**: As an admin, I can revoke developer API keys without affecting WebUI sessions.

### Organization Management

**US-8**: As an org owner, I can invite users to my organization with specific roles.

**US-9**: As a user, I can accept invitations to join organizations.

**US-10**: As a platform admin, I can manage all organizations and users.

## Authentication Flows

### Flow 1: WebUI Login (SPA)

```
┌─────────┐     ┌─────────┐     ┌─────────┐     ┌─────────┐
│  User   │     │  React  │     │   BFF   │     │  Auth   │
│         │     │   SPA   │     │         │     │ Server  │
└────┬────┘     └────┬────┘     └────┬────┘     └────┬────┘
     │               │               │               │
     │  Click Login  │               │               │
     │──────────────▶│               │               │
     │               │  Start OAuth  │               │
     │               │──────────────▶│               │
     │               │               │  Auth URL     │
     │               │               │──────────────▶│
     │               │               │               │
     │◀──────────────────────────────────────────────│
     │           Redirect to OAuth Provider          │
     │               │               │               │
     │  Authenticate │               │               │
     │──────────────▶│               │               │
     │               │               │               │
     │◀──────────────────────────────────────────────│
     │         Redirect with auth code               │
     │               │               │               │
     │               │  Code + PKCE  │               │
     │               │──────────────▶│               │
     │               │               │  Exchange     │
     │               │               │──────────────▶│
     │               │               │  Tokens       │
     │               │               │◀──────────────│
     │               │               │               │
     │               │  Session Cookie (HTTP-only)   │
     │               │◀──────────────│               │
     │               │               │               │
     │  Logged In    │               │               │
     │◀──────────────│               │               │
```

### Flow 2: Developer API Authentication

```
┌─────────┐     ┌─────────┐     ┌─────────┐
│Developer│     │  Their  │     │SystemForge│
│         │     │ Server  │     │   API   │
└────┬────┘     └────┬────┘     └────┬────┘
     │               │               │
     │ Create API Key│               │
     │ (via WebUI)   │               │
     │──────────────▶│               │
     │               │               │
     │  API Key      │               │
     │◀──────────────│               │
     │               │               │
     │  Configure    │               │
     │──────────────▶│               │
     │               │               │
     │               │  Client Creds │
     │               │──────────────▶│
     │               │  Access Token │
     │               │◀──────────────│
     │               │               │
     │               │  API Request  │
     │               │  + Bearer Token│
     │               │──────────────▶│
     │               │  Response     │
     │               │◀──────────────│
```

## Token Types

| Token Type | Purpose | Lifetime | Binding | Audience |
|------------|---------|----------|---------|----------|
| WebUI Access | SPA API calls via BFF | 15 min | DPoP (BFF-held) | `webui` |
| WebUI Refresh | Renew WebUI access | 7 days | HTTP-only cookie | `webui` |
| Developer Access | Server-to-server API | 1 hour | None (server-side) | `api` |
| Developer Refresh | Renew developer access | 30 days | Secure storage | `api` |

## OAuth Grant Types

| Use Case | Grant Type | PKCE Required | Client Type |
|----------|------------|---------------|-------------|
| WebUI (SPA via BFF) | Authorization Code | Yes | Confidential (BFF) |
| Developer (server) | Client Credentials | No | Confidential |
| Developer (user context) | Authorization Code | Yes | Confidential |
| Mobile App (future) | Authorization Code | Yes | Public |

## Security Requirements

### Token Binding Strategy: DPoP + BFF

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              BROWSER                                     │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                         React SPA                                │    │
│  │                                                                  │    │
│  │  • NO access tokens                                              │    │
│  │  • NO refresh tokens                                             │    │
│  │  • NO DPoP keys                                                  │    │
│  │  • Only HTTP-only session cookie                                 │    │
│  └──────────────────────────┬──────────────────────────────────────┘    │
│                             │                                            │
│              Cookie: session=abc123 (HTTP-only, Secure, SameSite=Strict) │
└─────────────────────────────┼───────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         BFF (Backend for Frontend)                       │
│                         same origin as SPA                               │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                                                                  │    │
│  │  • Validates session cookie                                      │    │
│  │  • Validates Origin/Referer header                               │    │
│  │  • Holds access + refresh tokens (server-side session store)     │    │
│  │  • Holds DPoP private key (per-session)                          │    │
│  │  • Signs DPoP proofs for API calls                               │    │
│  │                                                                  │    │
│  └──────────────────────────┬──────────────────────────────────────┘    │
│                             │                                            │
│              Authorization: DPoP <access_token>                          │
│              DPoP: <signed_proof_jwt>                                    │
└─────────────────────────────┼───────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         SystemForge API Backend                            │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                                                                  │    │
│  │  • Validates DPoP proof signature                                │    │
│  │  • Validates token is bound to proof key (cnf.jkt claim)         │    │
│  │  • Validates audience = "api"                                    │    │
│  │  • Processes request                                             │    │
│  │                                                                  │    │
│  └─────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────┘
```

### Defense in Depth Layers

```
┌────────────────────────────────────────────────────────────┐
│                    Defense in Depth                         │
├────────────────────────────────────────────────────────────┤
│  Layer 1: HTTP-only Secure Cookies (SPA ↔ BFF)              │
│           └─ Tokens never exposed to JavaScript             │
│                                                             │
│  Layer 2: Origin Validation                                 │
│           └─ BFF rejects requests without valid Origin      │
│                                                             │
│  Layer 3: DPoP Token Binding (BFF ↔ API)                    │
│           └─ Stolen tokens useless without private key      │
│                                                             │
│  Layer 4: Short Token Lifetime (15 min access)              │
│           └─ Limits attack window                           │
│                                                             │
│  Layer 5: Audience Separation                               │
│           └─ WebUI tokens can't access Developer API        │
│                                                             │
│  Layer 6: Strict CSP + XSS Prevention                       │
│           └─ Prevents attacker code from running            │
└────────────────────────────────────────────────────────────┘
```

### Attack Prevention Matrix

| Attack Vector | Cookie (SPA↔BFF) | Origin Check | DPoP (BFF↔API) |
|---------------|------------------|--------------|----------------|
| XSS steals token from browser | ✅ No token to steal | - | - |
| XSS makes API calls via browser | ✅ Must go through BFF | ✅ BFF validates origin | - |
| CSRF attack | ✅ SameSite cookie | ✅ Origin mismatch | - |
| Token stolen from BFF logs | - | - | ✅ Can't sign proofs |
| Token intercepted BFF↔API | - | - | ✅ Can't sign proofs |
| curl/Postman with stolen cookie | ✅ No Origin header | ✅ Origin validation | - |
| curl/Postman with stolen token | - | - | ✅ No private key |

## Multi-Tenancy Model

### Current: Tenant-per-User (Dashforge)

```
┌─────────┐     ┌─────────┐
│  User   │────▶│ Tenant  │  One user = One tenant
└─────────┘     └─────────┘
```

### Target: Organization-based (SystemForge)

```
┌─────────┐     ┌────────────┐     ┌──────────────┐
│  User   │────▶│ Membership │────▶│ Organization │
└─────────┘     │  (role)    │     └──────────────┘
                └────────────┘
     │                                    ▲
     │          ┌────────────┐            │
     └─────────▶│ Membership │────────────┘
                │  (role)    │
                └────────────┘

One user can belong to multiple organizations with different roles
```

## Success Metrics

1. **Security**: Zero token hijacking incidents
2. **Performance**: < 50ms overhead for DPoP validation
3. **Developer Experience**: < 30 min to integrate Developer API
4. **Migration**: Dashforge migrated with zero data loss

## Out of Scope (v1)

- Mobile app native authentication (future)
- SAML/OIDC enterprise SSO (future)
- Hardware security key (WebAuthn) binding (future)
- Cedar authorization provider (future)

## Dependencies

- SystemForge identity module (existing)
- SystemForge session/JWT module (existing)
- SystemForge authz module (existing)
- PostgreSQL for session storage
- Redis for session caching (optional)

## Timeline

See TRD_TASKS.md for implementation phases and priorities.
