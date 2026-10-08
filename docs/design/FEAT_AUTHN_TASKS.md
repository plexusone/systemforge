# TRD Tasks: Authentication Implementation

> **Status**: Phases 1-5 Completed in v0.1.0
>
> The core authentication infrastructure (DPoP, BFF, API Keys) has been implemented.
> Remaining work includes app-specific integration (Phase 6) and security hardening (Phases 7-8).
>
> | Phase | Status |
> |-------|--------|
> | Phase 1: DPoP Core | ✅ Complete |
> | Phase 2: DPoP-Bound Tokens | ✅ Complete |
> | Phase 3: BFF Session Management | ✅ Complete (Memory store) |
> | Phase 4: BFF Middleware & Proxy | ✅ Complete |
> | Phase 5: Developer API Keys | ✅ Complete |
> | Phase 6: Dashforge Migration | Pending |
> | Phase 7: Audience Separation | Pending |
> | Phase 8: Replay Prevention | Pending |

## Overview

Prioritized task list for implementing DPoP + BFF authentication in SystemForge and migrating Dashforge.

## Priority Levels

- **P0**: Critical path, blocks other work
- **P1**: High priority, core functionality
- **P2**: Important, enhances security/UX
- **P3**: Nice to have, future iteration

---

## Phase 1: DPoP Core (P0)

Foundation for token binding.

### Task 1.1: DPoP Key Management
**Priority**: P0
**Estimate**: 1 day
**Files**:
- `session/dpop/keys.go`
- `session/dpop/keys_test.go`

**Acceptance Criteria**:
- [ ] Generate ES256 key pairs
- [ ] Compute JWK thumbprint (RFC 7638)
- [ ] Serialize/deserialize key pairs for storage
- [ ] Unit tests with 90%+ coverage

### Task 1.2: DPoP Proof Creation
**Priority**: P0
**Estimate**: 1 day
**Files**:
- `session/dpop/proof.go`
- `session/dpop/claims.go`
- `session/dpop/proof_test.go`

**Acceptance Criteria**:
- [ ] Create DPoP proof JWT per RFC 9449
- [ ] Include htm, htu, jti, iat claims
- [ ] Optional ath claim for token binding
- [ ] Embed public key in JWT header
- [ ] Unit tests for proof creation

### Task 1.3: DPoP Proof Verification
**Priority**: P0
**Estimate**: 1 day
**Files**:
- `session/dpop/verifier.go`
- `session/dpop/verifier_test.go`

**Acceptance Criteria**:
- [ ] Verify proof signature using embedded JWK
- [ ] Validate htm (method) matches request
- [ ] Validate htu (URL) matches request
- [ ] Validate iat is within max age
- [ ] Validate ath matches access token hash
- [ ] Unit tests for all validation scenarios

### Task 1.4: DPoP Middleware
**Priority**: P0
**Estimate**: 0.5 day
**Files**:
- `session/dpop/middleware.go`
- `session/dpop/middleware_test.go`

**Acceptance Criteria**:
- [ ] Extract DPoP proof from request header
- [ ] Extract access token from Authorization header
- [ ] Call verifier and reject invalid proofs
- [ ] Add verified claims to request context
- [ ] Integration test with HTTP handler

---

## Phase 2: DPoP-Bound Tokens (P0)

Extend JWT service for DPoP binding.

### Task 2.1: DPoP-Bound Claims
**Priority**: P0
**Estimate**: 0.5 day
**Files**:
- `session/jwt/dpop_claims.go`
- `session/jwt/dpop_claims_test.go`

**Acceptance Criteria**:
- [ ] Add CNF claim struct with jkt field
- [ ] DPoPBoundClaims extends existing claims
- [ ] IsDPoPBound() helper method
- [ ] Unit tests

### Task 2.2: Token Issuance with DPoP Binding
**Priority**: P0
**Estimate**: 0.5 day
**Files**:
- `session/jwt/service.go` (modify)
- `session/jwt/service_test.go` (modify)

**Acceptance Criteria**:
- [ ] Option to bind token to DPoP thumbprint
- [ ] Include cnf.jkt claim in token
- [ ] Backward compatible (non-DPoP tokens still work)
- [ ] Unit tests for bound token creation

### Task 2.3: Token Validation with DPoP
**Priority**: P0
**Estimate**: 0.5 day
**Files**:
- `session/jwt/service.go` (modify)

**Acceptance Criteria**:
- [ ] Extract cnf.jkt from token claims
- [ ] Compare with DPoP proof thumbprint
- [ ] Reject if mismatch
- [ ] Integration test

---

## Phase 3: BFF Session Management (P0)

Server-side session storage.

### Task 3.1: Session Store Interface
**Priority**: P0
**Estimate**: 0.5 day
**Files**:
- `session/bff/store.go`
- `session/bff/session.go`

**Acceptance Criteria**:
- [ ] Session struct with tokens, DPoP key, metadata
- [ ] Store interface (Create, Get, Update, Delete)
- [ ] Session ID generation (secure random)

### Task 3.2: Memory Session Store
**Priority**: P0
**Estimate**: 0.5 day
**Files**:
- `session/bff/store_memory.go`
- `session/bff/store_memory_test.go`

**Acceptance Criteria**:
- [ ] In-memory store for development/testing
- [ ] Automatic expiration cleanup
- [ ] Thread-safe implementation
- [ ] Unit tests

### Task 3.3: PostgreSQL Session Store
**Priority**: P1
**Estimate**: 1 day
**Files**:
- `session/bff/store_postgres.go`
- `session/bff/store_postgres_test.go`
- `identity/ent/schema/session.go`

**Acceptance Criteria**:
- [ ] Ent schema for sessions (cf_sessions)
- [ ] Encrypted token storage
- [ ] Cleanup query for expired sessions
- [ ] Integration tests

### Task 3.4: Redis Session Store
**Priority**: P2
**Estimate**: 1 day
**Files**:
- `session/bff/store_redis.go`
- `session/bff/store_redis_test.go`

**Acceptance Criteria**:
- [ ] Redis store for production caching
- [ ] TTL-based expiration
- [ ] Encrypted token values
- [ ] Integration tests

---

## Phase 4: BFF Middleware & Proxy (P0)

Request handling layer.

### Task 4.1: Secure Cookie Handling
**Priority**: P0
**Estimate**: 0.5 day
**Files**:
- `session/bff/cookie.go`
- `session/bff/cookie_test.go`

**Acceptance Criteria**:
- [ ] Create session cookie (HttpOnly, Secure, SameSite=Strict)
- [ ] Parse session cookie from request
- [ ] Clear session cookie on logout
- [ ] Configurable domain/path

### Task 4.2: Origin Validation Middleware
**Priority**: P0
**Estimate**: 0.5 day
**Files**:
- `session/middleware/origin.go`
- `session/middleware/origin_test.go`

**Acceptance Criteria**:
- [ ] Validate Origin header against allowlist
- [ ] Fall back to Referer header
- [ ] Reject requests without valid origin
- [ ] Unit tests

### Task 4.3: BFF Session Middleware
**Priority**: P0
**Estimate**: 0.5 day
**Files**:
- `session/bff/middleware.go`
- `session/bff/middleware_test.go`

**Acceptance Criteria**:
- [ ] Extract session ID from cookie
- [ ] Load session from store
- [ ] Add session to request context
- [ ] Handle expired/invalid sessions

### Task 4.4: API Proxy Handler
**Priority**: P0
**Estimate**: 1 day
**Files**:
- `session/bff/proxy.go`
- `session/bff/proxy_test.go`

**Acceptance Criteria**:
- [ ] Proxy requests to API backend
- [ ] Inject DPoP proof header
- [ ] Inject Authorization header
- [ ] Forward response to client
- [ ] Handle errors gracefully

### Task 4.5: Token Refresh Handler
**Priority**: P1
**Estimate**: 0.5 day
**Files**:
- `session/bff/refresh.go`
- `session/bff/refresh_test.go`

**Acceptance Criteria**:
- [ ] Detect expired access token
- [ ] Use refresh token to get new tokens
- [ ] Generate new DPoP key pair
- [ ] Update session store

---

## Phase 5: Developer API Keys (P1)

Alternative auth for server-to-server.

### Task 5.1: API Key Schema
**Priority**: P1
**Estimate**: 0.5 day
**Files**:
- `identity/ent/schema/api_key.go`

**Acceptance Criteria**:
- [ ] Ent schema for API keys
- [ ] Key prefix, hash, scopes, expiry
- [ ] Edges to user and organization
- [ ] Run ent generate

### Task 5.2: API Key Service
**Priority**: P1
**Estimate**: 1 day
**Files**:
- `identity/apikey/service.go`
- `identity/apikey/service_test.go`

**Acceptance Criteria**:
- [ ] Create API key (returns full key once)
- [ ] Validate API key
- [ ] List user's API keys (prefix only)
- [ ] Revoke API key
- [ ] Check scopes

### Task 5.3: API Key Middleware
**Priority**: P1
**Estimate**: 0.5 day
**Files**:
- `session/middleware/apikey.go`
- `session/middleware/apikey_test.go`

**Acceptance Criteria**:
- [ ] Extract API key from Authorization header
- [ ] Validate key and check scopes
- [ ] Add principal to context
- [ ] Reject invalid/revoked keys

---

## Phase 6: Dashforge Migration (P1)

Apply SystemForge to Dashforge.

### Task 6.1: Add SystemForge Dependency
**Priority**: P1
**Estimate**: 0.5 day
**Files**:
- `app2/go.mod`

**Acceptance Criteria**:
- [ ] Add github.com/plexusone/systemforge dependency
- [ ] Run go mod tidy
- [ ] Verify build succeeds

### Task 6.2: Add SystemForge Identity Schemas
**Priority**: P1
**Estimate**: 0.5 day
**Files**:
- `app2/ent/schema/` (new files or mixins)

**Acceptance Criteria**:
- [ ] Import SystemForge identity mixins
- [ ] Generate Ent code
- [ ] Run migrations (creates cf_* tables)

### Task 6.3: Data Migration Script
**Priority**: P1
**Estimate**: 1 day
**Files**:
- `app2/migrations/migrate_to_systemforge.sql`
- `app2/cmd/migrate/main.go`

**Acceptance Criteria**:
- [ ] Migrate users to cf_users
- [ ] Convert tenants to cf_organizations
- [ ] Create cf_memberships (tenant owner → org owner)
- [ ] Preserve all IDs for foreign key compatibility
- [ ] Rollback script

### Task 6.4: Update Dashforge Auth
**Priority**: P1
**Estimate**: 2 days
**Files**:
- `app2/internal/server/auth/` (refactor)
- `app2/internal/server/server.go`

**Acceptance Criteria**:
- [ ] Replace JWT service with SystemForge
- [ ] Replace OAuth handlers with SystemForge
- [ ] Add BFF middleware stack
- [ ] Add API proxy
- [ ] Update routes

### Task 6.5: Update Dashforge RBAC
**Priority**: P1
**Estimate**: 1 day
**Files**:
- `app2/internal/rbac/` (new)

**Acceptance Criteria**:
- [ ] Create Dashforge-specific permissions
- [ ] Use SystemForge authz/rbac provider
- [ ] Update API handlers to check permissions

### Task 6.6: Integration Testing
**Priority**: P1
**Estimate**: 1 day
**Files**:
- `app2/tests/auth_test.go`
- `app2/tests/bff_test.go`

**Acceptance Criteria**:
- [ ] Test full OAuth login flow
- [ ] Test session management
- [ ] Test API proxy with DPoP
- [ ] Test organization switching

---

## Phase 7: Audience Separation (P2)

Isolate WebUI and Developer API tokens.

### Task 7.1: Audience Validation Middleware
**Priority**: P2
**Estimate**: 0.5 day
**Files**:
- `session/middleware/audience.go`
- `session/middleware/audience_test.go`

**Acceptance Criteria**:
- [ ] Validate aud claim matches expected value
- [ ] Configurable required audiences
- [ ] Reject mismatched tokens

### Task 7.2: Token Type Claim
**Priority**: P2
**Estimate**: 0.5 day
**Files**:
- `session/jwt/claims.go` (modify)

**Acceptance Criteria**:
- [ ] Add TokenType claim ("webui" or "api")
- [ ] Include in token generation
- [ ] Validate in middleware

---

## Phase 8: Replay Prevention (P2)

Prevent DPoP proof reuse.

### Task 8.1: Nonce Store Interface
**Priority**: P2
**Estimate**: 0.5 day
**Files**:
- `session/dpop/nonce.go`

**Acceptance Criteria**:
- [ ] NonceStore interface
- [ ] Add/check/expire nonces
- [ ] Configurable TTL

### Task 8.2: Redis Nonce Store
**Priority**: P2
**Estimate**: 0.5 day
**Files**:
- `session/dpop/nonce_redis.go`
- `session/dpop/nonce_redis_test.go`

**Acceptance Criteria**:
- [ ] Redis-backed nonce store
- [ ] TTL-based expiration
- [ ] Unit tests

---

## Summary

### Phase Timeline

| Phase | Priority | Tasks | Estimate |
|-------|----------|-------|----------|
| 1. DPoP Core | P0 | 4 | 3.5 days |
| 2. DPoP-Bound Tokens | P0 | 3 | 1.5 days |
| 3. BFF Session | P0/P1/P2 | 4 | 3 days |
| 4. BFF Middleware | P0/P1 | 5 | 3 days |
| 5. Developer API Keys | P1 | 3 | 2 days |
| 6. Dashforge Migration | P1 | 6 | 6 days |
| 7. Audience Separation | P2 | 2 | 1 day |
| 8. Replay Prevention | P2 | 2 | 1 day |

**Total P0 Tasks**: 12 tasks, ~8 days
**Total P1 Tasks**: 10 tasks, ~8 days
**Total P2 Tasks**: 6 tasks, ~4 days

### Implementation Order

```
Week 1: Phase 1 + Phase 2 (DPoP foundation)
Week 2: Phase 3 + Phase 4 (BFF infrastructure)
Week 3: Phase 5 + Phase 6.1-6.3 (API keys + Dashforge prep)
Week 4: Phase 6.4-6.6 (Dashforge integration)
Week 5: Phase 7 + Phase 8 (Security hardening)
```

### Dependencies

```
Phase 1 (DPoP Core)
    │
    ▼
Phase 2 (DPoP-Bound Tokens)
    │
    ├──────────────────┐
    ▼                  ▼
Phase 3 (BFF Session)  Phase 5 (API Keys)
    │                  │
    ▼                  │
Phase 4 (BFF Middleware)
    │                  │
    ▼                  │
Phase 6 (Dashforge) ◀──┘
    │
    ├──────────────────┐
    ▼                  ▼
Phase 7 (Audience)   Phase 8 (Replay)
```

---

## Next Steps

1. Start with Task 1.1: DPoP Key Management
2. Create feature branch: `feat/dpop-bff-auth`
3. Implement in order, with tests
4. PR review at each phase completion
