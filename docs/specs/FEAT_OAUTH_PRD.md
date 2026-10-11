# SystemForge OAuth 2.0 Server - Product Requirements Document

> **Status**: Implemented in v0.1.0
>
> This PRD defined the requirements for SystemForge OAuth 2.0 server. The features described below have been implemented in the following modules:
>
> - `identity/oauth/` - OAuth 2.0 server with Fosite
> - `identity/ent/schema/` - OAuth-related Ent schemas (oauth_app, oauth_token, service_account, etc.)
>
> **Implemented Grants:**
> - Authorization Code + PKCE
> - Client Credentials
> - Refresh Token with rotation
> - JWT Bearer (RFC 7523)

## Overview

SystemForge OAuth Server provides a complete OAuth 2.0 and OpenID Connect implementation for multi-tenant SaaS applications. It enables first-party applications (SPAs, mobile apps) and third-party integrations to securely access APIs.

## Goals

1. **Developer Self-Service**: Developers can create OAuth apps and service accounts without admin intervention
2. **Security First**: Implement modern OAuth 2.0 best practices (PKCE, token rotation, short-lived tokens)
3. **Multi-Tenant**: OAuth apps can be scoped to organizations or platform-wide
4. **Batteries Included**: Works out of the box with sensible defaults

## User Personas

### 1. Platform Developer (First-Party)
- Building the React SPA frontend
- Needs secure authentication without exposing tokens to JavaScript
- Uses BFF pattern or Authorization Code + PKCE

### 2. Integration Developer (Third-Party)
- Building integrations with the platform
- Creates OAuth apps to get client credentials
- Uses Authorization Code flow for user-context or Client Credentials for service-context

### 3. DevOps/Automation Engineer
- Running CI/CD pipelines, cron jobs, scripts
- Creates service accounts with key pairs
- Uses JWT Bearer grant for secure, keyless authentication

### 4. Platform Administrator
- Manages OAuth apps and service accounts across the platform
- Reviews API access and usage
- Revokes compromised credentials

## Features

### F1: OAuth App Management

**F1.1: Create OAuth App**
- Developer provides: name, description, redirect URIs, app type
- System generates: client_id, client_secret
- App types: `web` (confidential), `spa` (public), `native` (public), `service` (confidential)

**F1.2: App Settings**
- Allowed grant types (based on app type)
- Allowed scopes
- Token lifetimes (access, refresh)
- Redirect URI validation (exact match or wildcard for subdomains)

**F1.3: Secret Management**
- Rotate client secret (generates new, old valid for grace period)
- View secret only at creation (hashed storage)
- Multiple active secrets during rotation

**F1.4: Organization Scoping**
- Apps can be organization-scoped (only org members can authorize)
- Apps can be platform-wide (any user can authorize)

### F2: Service Accounts

**F2.1: Create Service Account**
- Name, description, scopes
- No human user - represents a service/automation
- Tied to an organization or platform-wide

**F2.2: Key Pair Management**
- Generate RSA or EC key pairs
- Download private key (shown once)
- Public key stored for JWT verification
- Multiple keys for rotation (max 10)
- Key expiration dates

**F2.3: Impersonation (Optional)**
- Service account can impersonate users (with admin grant)
- Useful for admin tools, migrations

### F3: OAuth 2.0 Grants

**F3.1: Authorization Code + PKCE**
- Required for all public clients (SPAs, mobile, CLI)
- Optional for confidential clients
- S256 challenge method required

**F3.2: Client Credentials**
- For confidential clients only
- No user context - service-to-service
- Scopes limited to what app is granted

**F3.3: Refresh Token**
- Rotation on use (new refresh token each time)
- Absolute expiration (max lifetime)
- Revocation on reuse (theft detection)

**F3.4: JWT Bearer (RFC 7523)**
- For service accounts
- Client creates signed JWT assertion
- Server verifies signature with stored public key
- Short-lived assertions (max 1 hour)

### F4: Token Management

**F4.1: Access Tokens**
- JWT format with standard claims
- Short-lived (15 minutes default)
- Contains: sub, aud, scope, org_id, client_id

**F4.2: Refresh Tokens**
- Opaque tokens (database lookup)
- Longer-lived (7 days default, 90 days max)
- Tied to client and user

**F4.3: Token Introspection (RFC 7662)**
- Check if token is active
- Get token metadata
- For resource servers

**F4.4: Token Revocation (RFC 7009)**
- Revoke access or refresh token
- Revoke all tokens for user/client

### F5: OpenID Connect

**F5.1: Discovery**
- `/.well-known/openid-configuration`
- Advertises supported features

**F5.2: JWKS**
- `/.well-known/jwks.json`
- Public keys for token verification

**F5.3: UserInfo**
- `/oauth/userinfo`
- Returns user profile based on scopes

**F5.4: ID Tokens**
- JWT with user identity
- Returned alongside access token
- Standard OIDC claims

### F6: Scopes

**F6.1: Standard Scopes**
```
openid        - Required for OIDC
profile       - User profile (name, picture)
email         - User email
offline_access - Request refresh token
```

**F6.2: API Scopes**
```
read:users         - Read user data
write:users        - Modify user data
read:organizations - Read org data
write:organizations - Modify org data
admin:*            - Full admin access
```

**F6.3: Scope Consent**
- First-party apps: auto-approve configured scopes
- Third-party apps: user consent screen
- Remember consent (don't ask again)

### F7: Security

**F7.1: Rate Limiting**
- Token endpoint: 100 req/min per client
- Authorization endpoint: 20 req/min per IP
- Failed auth lockout: 5 failures = 15 min lockout

**F7.2: Audit Logging**
- All token grants logged
- Failed attempts logged
- Token revocations logged

**F7.3: Threat Detection**
- Refresh token reuse detection
- Unusual grant patterns
- Geographic anomalies (optional)

## User Flows

### Flow 1: Developer Creates OAuth App

1. Developer logs into Developer Portal
2. Navigates to "OAuth Apps" → "Create App"
3. Fills form: name, type (SPA), redirect URIs
4. System generates client_id
5. For confidential apps: shows client_secret once
6. Developer copies credentials to their app config

### Flow 2: SPA User Login (Authorization Code + PKCE)

1. User clicks "Login" in React SPA
2. SPA generates code_verifier and code_challenge
3. SPA redirects to `/oauth/authorize?...&code_challenge=xxx`
4. User sees login page, authenticates
5. User sees consent screen (if third-party)
6. SystemForge redirects to SPA with authorization code
7. SPA exchanges code + code_verifier for tokens
8. SPA stores access token, uses for API calls

### Flow 3: Service Account Access (JWT Bearer)

1. DevOps creates service account in portal
2. Generates key pair, downloads private key
3. CI/CD pipeline creates JWT signed with private key
4. Pipeline calls `/oauth/token` with JWT assertion
5. SystemForge verifies signature, issues access token
6. Pipeline uses access token for API calls

### Flow 4: Third-Party Integration

1. Third-party developer creates OAuth app
2. Their users click "Connect to [Platform]"
3. User authorizes access on consent screen
4. Third-party receives tokens
5. Third-party stores refresh token, uses access token
6. Third-party refreshes tokens as needed

## Success Metrics

1. **Adoption**: Number of OAuth apps created
2. **Security**: Zero token leaks, low failed auth rate
3. **Reliability**: Token endpoint 99.9% uptime
4. **Performance**: Token issuance < 100ms p99
5. **Developer Experience**: < 30 min to first successful API call

## Non-Goals (v1)

- SAML support
- Social login providers (handled separately)
- Fine-grained consent (scope-by-scope)
- Dynamic client registration (RFC 7591)
- Pushed Authorization Requests (RFC 9126)

## Timeline

| Phase | Features | Target |
|-------|----------|--------|
| Phase 1 | OAuth App CRUD, Client Credentials, PKCE | Week 1-2 |
| Phase 2 | Service Accounts, JWT Bearer | Week 3 |
| Phase 3 | OpenID Connect, Discovery | Week 4 |
| Phase 4 | Consent UI, Third-party flows | Week 5 |
| Phase 5 | Audit logging, Rate limiting | Week 6 |

## Open Questions

1. Should we support PAR (Pushed Authorization Requests) for enhanced security?
2. Should service accounts support organization impersonation?
3. What's the maximum number of OAuth apps per organization?
4. Should we implement DPoP for access tokens (beyond BFF)?

## Appendix: Scope Definitions

| Scope | Description | Grants Access To |
|-------|-------------|------------------|
| `openid` | OpenID Connect | ID token |
| `profile` | Basic profile | name, picture, locale |
| `email` | Email address | email, email_verified |
| `offline_access` | Refresh tokens | refresh_token in response |
| `read:users` | Read users | GET /api/v1/users/* |
| `write:users` | Write users | POST/PATCH/DELETE /api/v1/users/* |
| `read:courses` | Read courses | GET /api/v1/courses/* |
| `write:courses` | Write courses | POST/PATCH/DELETE /api/v1/courses/* |
| `admin:*` | Full admin | All endpoints |
