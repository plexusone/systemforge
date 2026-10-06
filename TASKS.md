# SystemForge Tasks

**Last Updated:** 2026-04-28

See [PLAN.md](PLAN.md) for the overall roadmap and feature priorities.

---

## Implementation Tasks (Pre-App1)

These tasks must be completed before App1 integration.

### P0: Marketplace Module (Critical - Enables Course Sales)

The marketplace module has types and interfaces defined but lacks concrete implementations.

#### Phase 1: Ent Schemas ✅

- [x] Create `identity/ent/schema/listing.go` - Product/course listing entity
- [x] Create `identity/ent/schema/license.go` - License entitlement entity
- [x] Create `identity/ent/schema/subscription.go` - Subscription entity
- [x] Create `identity/ent/schema/seat_assignment.go` - Seat assignment entity
- [x] Run `go generate ./identity/ent/...` to generate Ent code
- [x] Add database migrations for new tables

#### Phase 2: Service Implementations ✅

- [x] Implement `ListingService` in `marketplace/listing_service.go`
  - [x] `Create(ctx, input)` - Create new listing
  - [x] `Get(ctx, id)` - Get listing by ID
  - [x] `List(ctx, opts)` - List with filtering
  - [x] `Update(ctx, id, input)` - Update listing
  - [x] `Delete(ctx, id)` - Delete listing
  - [x] `Publish(ctx, id)` - Publish listing
  - [x] `Archive(ctx, id)` - Archive listing

- [x] Implement `LicenseService` in `marketplace/license_service.go`
  - [x] `Grant(ctx, input)` - Grant license to org
  - [x] `Revoke(ctx, id)` - Revoke license
  - [x] `Get(ctx, id)` - Get license by ID
  - [x] `ListForOrg(ctx, orgID)` - List org's licenses
  - [x] `AssignSeat(ctx, licenseID, principalID)` - Assign seat
  - [x] `UnassignSeat(ctx, assignmentID)` - Remove seat assignment
  - [x] `GetAvailableSeats(ctx, licenseID)` - Check available seats

- [x] Implement `SubscriptionService` in `marketplace/subscription_service.go`
  - [x] `Create(ctx, input)` - Create subscription
  - [x] `Get(ctx, id)` - Get subscription
  - [x] `Cancel(ctx, id)` - Cancel subscription
  - [x] `UpdateStatus(ctx, id, status)` - Update status
  - [x] `ListForOrg(ctx, orgID)` - List org subscriptions

#### Phase 3: Stripe Integration ✅

- [x] Create `marketplace/stripe/` package
- [x] Implement `CheckoutService` in `marketplace/stripe/checkout.go`
  - [x] `CreateCheckoutSession(ctx, input)` - Create Stripe Checkout
  - [ ] `CreatePortalSession(ctx, customerID)` - Customer portal (deferred)
- [x] Implement webhook handlers in `marketplace/stripe/webhooks.go`
  - [x] `HandleCheckoutCompleted` - Grant license on purchase
  - [x] `HandleSubscriptionCreated` - Create subscription record
  - [x] `HandleSubscriptionUpdated` - Update subscription status
  - [x] `HandleSubscriptionDeleted` - Handle cancellation
  - [x] `HandleInvoicePaid` - Record payment
  - [x] `HandleInvoicePaymentFailed` - Handle failed payment
- [x] Implement Stripe Connect in `marketplace/stripe/connect.go`
  - [x] `CreateConnectAccount(ctx, orgID)` - Create seller account
  - [x] `CreateAccountLink(ctx, accountID)` - Onboarding link
  - [x] `CreatePayout(ctx, accountID, amount)` - Trigger payout

#### Phase 4: API Handlers ✅

- [x] Create `marketplace/handlers.go` with Huma handlers
  - [x] `POST /api/v1/listings` - Create listing
  - [x] `GET /api/v1/listings` - List listings
  - [x] `GET /api/v1/listings/{id}` - Get listing
  - [x] `PATCH /api/v1/listings/{id}` - Update listing
  - [x] `DELETE /api/v1/listings/{id}` - Delete listing
  - [x] `POST /api/v1/listings/{id}/publish` - Publish
  - [x] `POST /api/v1/listings/{id}/archive` - Archive
  - [x] `POST /api/v1/checkout` - Create checkout session
  - [x] `GET /api/v1/licenses` - List licenses
  - [x] `GET /api/v1/licenses/{id}` - Get license
  - [x] `POST /api/v1/licenses/{license_id}/seats` - Assign seat
  - [x] `DELETE /api/v1/licenses/{license_id}/seats/{principal_id}` - Unassign seat
  - [x] `GET /api/v1/licenses/{license_id}/seats` - List seats
  - [ ] `POST /api/v1/webhooks/stripe` - Stripe webhook endpoint (requires raw body handling)

#### Phase 5: Tests

- [x] Add `marketplace/listing_service_test.go`
- [x] Add `marketplace/license_service_test.go`
- [x] Add `marketplace/subscription_service_test.go`
- [ ] Add `marketplace/stripe/checkout_test.go`
- [ ] Add `marketplace/stripe/webhooks_test.go`
- [ ] Add `marketplace/handlers_test.go`

### P2: Rate Limiting Redis Backend

- [ ] Implement Redis storage in `session/ratelimit/redis.go`
  - [ ] `NewRedisStorage(client)` - Create Redis storage
  - [ ] `Allow(ctx, key, limit, window)` - Check and increment
  - [ ] `Reset(ctx, key)` - Reset counter
  - [ ] `GetUsage(ctx, key)` - Get current usage
- [ ] Add `session/ratelimit/redis_test.go` with integration tests
- [ ] Add Redis connection configuration

### P2: Observability Integration

- [ ] Add marketplace metrics to `observability/`
  - [ ] `marketplace.checkouts_total` - Checkout attempts
  - [ ] `marketplace.purchases_total` - Successful purchases
  - [ ] `marketplace.licenses_granted_total` - Licenses granted
  - [ ] `marketplace.seats_assigned_total` - Seats assigned
- [ ] Add Stripe webhook metrics
  - [ ] `marketplace.webhook_received_total` - Webhooks received
  - [ ] `marketplace.webhook_processed_total` - Webhooks processed
  - [ ] `marketplace.webhook_errors_total` - Webhook errors

---

## GoDoc Documentation

### Overview

GoDoc coverage analysis identified ~600+ exported items missing documentation comments. This excludes auto-generated ent code (~100+ items) which should not be manually documented.

### Priority 1: Public API Types (High Impact)

These are used directly by consumers of the library.

#### Configuration Types (`identity/systemauth/config.go`)

- [ ] `Config` - Main configuration struct
- [ ] `ClientConfig` - OAuth client configuration
- [ ] `Duration` - Custom duration type for config parsing
- [ ] `FederationConfig` - Federation settings
- [ ] `TokenConfig` - Token generation settings

#### Session Middleware (`session/middleware/`)

- [ ] `ClaimsFromContext` - Extract JWT claims from context
- [ ] `UserIDFromContext` - Extract user ID from context
- [ ] `OrganizationIDFromContext` - Extract org ID from context
- [ ] `PrincipalIDFromContext` - Extract principal ID from context
- [ ] `RoleFromContext` - Extract role from context
- [ ] `PermissionsFromContext` - Extract permissions from context
- [ ] `HTTPAuth` - HTTP authentication middleware
- [ ] `HTTPAuthOptional` - Optional HTTP auth middleware
- [ ] `RequireRole` - Role requirement middleware
- [ ] `RequirePermission` - Permission requirement middleware
- [ ] `RequireAnyRole` - Any role requirement middleware
- [ ] `RequireAnyPermission` - Any permission requirement middleware
- [ ] `RequirePlatformAdmin` - Platform admin requirement
- [ ] `RequireOrganization` - Organization requirement middleware
- [ ] `ChiAuth` - Chi router auth middleware
- [ ] `ChiAuthOptional` - Chi router optional auth
- [ ] `ChiRequireRole` - Chi router role requirement
- [ ] `RequireAPIKey` - API key requirement middleware
- [ ] `RequireScope` - OAuth scope requirement middleware

#### JWT Service (`session/jwt/`)

- [ ] `Claims` - JWT claims structure
- [ ] `TokenPair` - Access/refresh token pair
- [ ] `CNFClaim` - Confirmation claim for DPoP
- [ ] `DefaultConfig` - Default JWT configuration
- [ ] `AccessTokenTTL` - Access token TTL method
- [ ] `RefreshTokenTTL` - Refresh token TTL method
- [ ] `GenerateRefreshToken` - Refresh token generation
- [ ] `GenerateTokenPairLegacy` - Legacy token pair generation
- [ ] `WithDPoPBinding` - DPoP binding option
- [ ] `DPoPThumbprint` - DPoP thumbprint extraction
- [ ] `ComputeTokenHash` - Token hash computation

### Priority 2: Authorization Module (Security Critical)

#### Core Types (`authz/`)

- [ ] `Authorizer` - Main authorizer interface
- [ ] `OrgAuthorizer` - Organization-scoped authorizer
- [ ] `RelationshipSyncer` - Relationship synchronization interface
- [ ] `ResourceExtractor` - Resource ID extraction function type

#### Middleware (`authz/middleware.go`)

- [ ] `RequireAction` - Action requirement middleware
- [ ] `RequireAllActions` - All actions requirement
- [ ] `RequireAnyAction` - Any action requirement
- [ ] `RequireMembership` - Membership requirement
- [ ] `RequireResourceAction` - Resource action requirement
- [ ] `RequireRole` - Role requirement
- [ ] `WithResourceID` - Resource ID injection
- [ ] `Error` - Error handling method

#### SpiceDB Provider (`authz/spicedb/`)

- [ ] `BaseSchema` - Base SpiceDB schema constant
- [ ] `ResourceSchema` - Resource schema generation
- [ ] `RegisterPrincipal` - Principal registration
- [ ] `UpdateOrgMembership` - Org membership update

### Priority 3: Identity & Authentication

#### SystemAuth Server (`identity/systemauth/`)

- [ ] `NewEmbedded` - Create embedded auth server
- [ ] `AuthenticationProvider` - Authentication provider interface
- [ ] `IdentityProvider` - Identity provider interface
- [ ] `OAuthProvider` - OAuth provider interface
- [ ] `OAuthClientStore` - OAuth client storage interface
- [ ] `Identity` - Identity type
- [ ] `Providers` - Provider collection
- [ ] `NewProviders` - Create provider collection
- [ ] `Storage` - Storage interface
- [ ] `MemoryStorage` - In-memory storage
- [ ] `CleanupExpired` - Expired token cleanup

#### Session Management (`identity/systemauth/session.go`)

- [ ] `SessionProvider` - Session provider interface
- [ ] `DefaultSessionProvider` - Default session implementation
- [ ] `AuthorizationSession` - Authorization session type
- [ ] `GetUserClaims` - Get user claims from session
- [ ] `HasConsent` - Check consent status
- [ ] `SaveConsent` - Save user consent
- [ ] `WithUserIDHeader` - User ID header option

#### OAuth Types (`identity/systemauth/types_oauth.go`, `identity/oauth/types_oauth.go`)

- [ ] `TokenInput` - Token request input
- [ ] `TokenResponse` - Token response structure

#### SCIM (`identity/scim/`)

- [ ] `Provider` - SCIM provider interface
- [ ] `Store` - SCIM store interface
- [ ] `ListUsers` - List users method
- [ ] `ListGroups` - List groups method
- [ ] `ToSCIMError` - Error conversion
- [ ] `CompositeAuthorizationHook` - Composite auth hook
- [ ] `RoleBasedAuthorizationHook` - Role-based auth hook
- [ ] `ScopedAuthorizationHook` - Scoped auth hook
- [ ] `PrincipalUserMapper` - Principal to user mapping
- [ ] `EnterpriseExtension` - Enterprise SCIM extension
- [ ] `ServiceProviderConfig` - SCIM service provider config
- [ ] `MultiValue` - Multi-value SCIM type

#### Password Utilities (`identity/password.go`)

- [ ] `HashPassword` - Password hashing
- [ ] `VerifyPassword` - Password verification
- [ ] `NeedsRehash` - Check if rehash needed
- [ ] `DefaultArgon2idParams` - Default Argon2id parameters

### Priority 4: Row-Level Security (`rls/`)

- [ ] `Middleware` - RLS middleware type
- [ ] `DBWithRLS` - Database wrapper with RLS
- [ ] `EntDriver` - Ent driver with RLS
- [ ] `EntHook` - Ent hook for RLS
- [ ] `ContextInjector` - Context injection type
- [ ] `Executor` - SQL executor with RLS
- [ ] `TenantIDFromContext` - Get tenant from context
- [ ] `UserIDFromContext` - Get user from context
- [ ] `BypassRLS` - Bypass RLS for admin operations
- [ ] `SetTenant` - Set tenant in context
- [ ] `WithTenant` - Transaction with tenant
- [ ] `WithTenantFromContext` - Transaction with context tenant
- [ ] `RequireTenant` - Require tenant middleware
- [ ] `InjectContext` - Inject RLS context
- [ ] `SetContextFromContext` - Set context from existing
- [ ] `GenerateMigrationSQL` - Generate RLS migration SQL
- [ ] `SystemForgeTables` - Tables requiring RLS

#### Testing Helpers (`rls/testing.go`)

- [ ] `AsUser` - Run as specific user
- [ ] `WithoutRLS` - Run without RLS
- [ ] `AssertTenantIsolation` - Assert tenant isolation

### Priority 5: Session Components

#### BFF (Backend for Frontend) (`session/bff/`)

- [ ] `Session` - BFF session type
- [ ] `Store` - Session store interface
- [ ] `MemoryStore` - In-memory session store
- [ ] `NeedsRefresh` - Check if refresh needed
- [ ] `GetSessionID` - Get session ID from cookie
- [ ] `OptionalSessionMiddleware` - Optional session middleware
- [ ] `RequireSessionMiddleware` - Required session middleware
- [ ] `OriginMiddleware` - Origin validation middleware
- [ ] `APIProxyMiddleware` - API proxy middleware
- [ ] `RefreshHandler` - Token refresh handler
- [ ] `TokenResponse` - BFF token response

#### DPoP (`session/dpop/`)

- [ ] `ProofHeader` - DPoP proof header type
- [ ] `SerializedKeyPair` - Serialized key pair
- [ ] `NewProofClaims` - Create proof claims
- [ ] `ComputeAccessTokenHash` - Compute access token hash
- [ ] `ComputeThumbprint` - Compute key thumbprint
- [ ] `GenerateKeyPair` - Generate DPoP key pair
- [ ] `CreateProof` - Create DPoP proof
- [ ] `ParseProof` - Parse DPoP proof
- [ ] `VerifyTokenBinding` - Verify token binding

#### Rate Limiting (`session/ratelimit/`)

- [ ] `KeyFunc` - Rate limit key function type
- [ ] `LimitResolver` - Limit resolver interface
- [ ] `MemoryStorage` - In-memory rate limit storage
- [ ] `RedisStorage` - Redis rate limit storage
- [ ] `NewRedisStorage` - Create Redis storage
- [ ] `CoreAPIResolver` - CoreAPI rate limit resolver
- [ ] `GetPolicyForRequest` - Get policy for request
- [ ] `ClientKey` - Client-based key function
- [ ] `PrincipalKey` - Principal-based key function
- [ ] `EndpointKey` - Endpoint-based key function
- [ ] `CompositeKey` - Composite key function

#### OAuth Client (`identity/oauthclient/`)

- [x] `MemoryStateStore` - In-memory OAuth state store
- [x] `Connector` - GitHub/Google login connector (exchange + profile fetch)

### Priority 6: Other Components

#### CoreAPI (`coreapi/`)

- [ ] `RateLimits` - Rate limits configuration
- [ ] `MostGranularLimit` - Get most granular limit
- [ ] `MemoryPolicyStore` - In-memory policy store
- [ ] `NewMemoryPolicyStore` - Create memory policy store

#### Contract (`contract/`)

- [ ] `WithLogger` - Logger option
- [ ] `ToContractError` - Error conversion
- [ ] `RequireAuth` - Auth requirement middleware
- [ ] `Middleware` - Contract middleware
- [ ] `RecordAuditEvent` - Record audit event
- [ ] `StartSync` - Start provider sync
- [ ] `SyncLagSeconds` - Get sync lag
- [ ] `MemoryStore` - In-memory audit store

#### Marketplace (`marketplace/`)

- [ ] `MarketplaceSchema` - Marketplace SpiceDB schema
- [ ] `MergeSchema` - Merge schemas
- [ ] `SeatsRemaining` - Get remaining seats
- [ ] `SyncLicense` - Sync license to SpiceDB
- [ ] `SyncLicenseRevocation` - Sync license revocation
- [ ] `SyncListing` - Sync listing
- [ ] `SyncSubscription` - Sync subscription
- [ ] `SyncSeatAssignment` - Sync seat assignment
- [ ] `SyncSeatUnassignment` - Sync seat unassignment

#### Observability (`observability/`)

- [ ] `New` - Create observability provider
- [ ] `ConfigFromEnv` - Load config from environment
- [ ] `Middleware` - Observability middleware
- [ ] `SlogHandler` - Get slog handler

#### Feature Flags (`featureflags/`)

- [ ] `MemoryStore` - In-memory feature flag store

#### Ent Mixins (`identity/ent/mixin/`)

- [ ] `BaseMixin` - Base entity mixin
- [ ] `UUIDMixin` - UUID field mixin
- [ ] `TimestampMixin` - Timestamp fields mixin
- [ ] `UserBase` - User base mixin
- [ ] `OrganizationBase` - Organization base mixin
- [ ] `MembershipBase` - Membership base mixin
- [ ] `PrincipalMixin` - Principal mixin
- [ ] `HumanMixin` - Human entity mixin
- [ ] `AgentMixin` - Agent entity mixin
- [ ] `ApplicationMixin` - Application mixin
- [ ] `ServicePrincipalMixin` - Service principal mixin
- [ ] `PrincipalMembershipMixin` - Principal membership mixin
- [ ] `OAuthAccountMixin` - OAuth account mixin
- [ ] `RefreshTokenMixin` - Refresh token mixin

### Excluded from Documentation

The following are auto-generated and should NOT be manually documented:

- `identity/ent/*.go` (except `mixin/` and `schema/`)
- `identity/ent/hook/hook.go` - Generated hook types
- `identity/ent/privacy/privacy.go` - Generated privacy rules
- `identity/ent/migrate/` - Generated migrations
- `identity/ent/internal/` - Internal generated code

### Documentation Guidelines

1. **Start comment with item name**: `// Config holds the main configuration...`
2. **Describe purpose, not implementation**: Focus on what it does, not how
3. **Document parameters for functions**: Explain each parameter's purpose
4. **Document return values**: Explain what is returned and when errors occur
5. **Add examples for complex APIs**: Use `// Example:` blocks where helpful
6. **Cross-reference related items**: Use `// See also: OtherType` when relevant

### Example Documentation

```go
// Config holds the main configuration for the SystemAuth server.
// It includes settings for OAuth clients, token generation, and federation.
type Config struct {
    // Clients defines the OAuth 2.0 clients that can authenticate.
    Clients []ClientConfig `json:"clients" yaml:"clients"`

    // Token configures access and refresh token generation.
    Token TokenConfig `json:"token" yaml:"token"`

    // Federation configures cross-application identity federation.
    Federation FederationConfig `json:"federation" yaml:"federation"`
}

// HTTPAuth returns middleware that requires a valid JWT in the Authorization header.
// It extracts claims and adds them to the request context.
// Returns 401 Unauthorized if the token is missing or invalid.
// Returns 403 Forbidden if the token is expired.
//
// See also: HTTPAuthOptional, ClaimsFromContext
func HTTPAuth(jwtService *jwt.Service) func(http.Handler) http.Handler
```

---

## Security Hardening

### P1: Multi-Factor Authentication (MFA)

#### Phase 1: TOTP Support

- [ ] Create `identity/mfa/` package
- [ ] Create `identity/mfa/totp.go`
  - [ ] `GenerateSecret()` - Generate TOTP secret
  - [ ] `GenerateQRCode(secret, issuer, account)` - QR code for authenticator apps
  - [ ] `ValidateCode(secret, code)` - Validate 6-digit code
  - [ ] `ValidateCodeWithWindow(secret, code, window)` - Allow time drift
- [ ] Create `identity/mfa/recovery.go`
  - [ ] `GenerateRecoveryCodes(count)` - Generate backup codes
  - [ ] `HashRecoveryCode(code)` - Hash for storage
  - [ ] `ValidateRecoveryCode(hash, code)` - Validate and mark used
- [ ] Create `identity/ent/schema/mfa_enrollment.go`
  - [ ] User relationship
  - [ ] Secret (encrypted)
  - [ ] Verified timestamp
  - [ ] Recovery codes (hashed)

#### Phase 2: Enrollment Flow

- [ ] Create `identity/mfa/enrollment.go`
  - [ ] `StartEnrollment(userID)` - Begin MFA setup
  - [ ] `VerifyEnrollment(userID, code)` - Complete setup
  - [ ] `Unenroll(userID)` - Remove MFA
  - [ ] `GetEnrollmentStatus(userID)` - Check MFA status
- [ ] Create `identity/mfa/handlers.go`
  - [ ] `POST /api/v1/mfa/enroll` - Start enrollment
  - [ ] `POST /api/v1/mfa/verify` - Verify enrollment
  - [ ] `POST /api/v1/mfa/challenge` - Request MFA challenge
  - [ ] `POST /api/v1/mfa/validate` - Validate MFA code
  - [ ] `DELETE /api/v1/mfa` - Unenroll

#### Phase 3: MFA Middleware

- [ ] Create `session/middleware/mfa.go`
  - [ ] `RequireMFA()` - Require MFA for route
  - [ ] `MFAVerifiedFromContext(ctx)` - Check MFA status in context
  - [ ] `SetMFAVerified(ctx)` - Mark session as MFA verified
- [ ] Update JWT claims to include MFA verification status
- [ ] Add MFA requirement to sensitive operations

#### Phase 4: Tests

- [ ] Create `identity/mfa/totp_test.go`
- [ ] Create `identity/mfa/recovery_test.go`
- [ ] Create `identity/mfa/enrollment_test.go`
- [ ] Create `session/middleware/mfa_test.go`

### P1: Account Lockout ✅

- [x] Create `identity/security/lockout.go`
  - [x] `RecordFailure(identifier)` - Track failed login
  - [x] `IsLocked(identifier)` - Check lockout status
  - [x] `RecordSuccess(identifier)` - Clear on success
  - [x] `GetStatus(identifier)` - Get remaining lockout time
  - [x] `CheckAndRecord(identifier, success)` - Combined check and record
- [x] Create `identity/security/lockout_redis.go`
  - [x] Redis-backed storage for distributed deployments
- [x] Create `identity/security/lockout_test.go` (9 tests passing)
- [x] Configuration options:
  - [x] MaxAttempts - Max attempts before lockout
  - [x] LockoutDuration - How long account stays locked
  - [x] AttemptWindow - Time window for counting attempts
- [ ] Create `identity/ent/schema/login_attempt.go` (optional, for persistence)
- [ ] Add lockout check to authentication flow (integration)

### P1: Session Invalidation ✅

- [x] Create `session/invalidation/invalidation.go`
  - [x] `InvalidateAllSessions(userID)` - Logout all devices
  - [x] `InvalidateSession(sessionID)` - Logout specific session
  - [x] `ListSessions(userID)` - List user's sessions
  - [x] `InvalidateDeviceSessions(userID, deviceID)` - Logout specific device
  - [x] `InvalidateOtherSessions(userID, currentSessionID)` - Logout other devices
  - [x] `CreateSession(userID, opts...)` - Create tracked session
  - [x] `ValidateSession(sessionID)` - Validate and update LastActiveAt
  - [x] `RefreshSession(sessionID)` - Extend session expiration
- [x] Create `session/invalidation/store_memory.go`
  - [x] In-memory session storage
- [x] Create `session/invalidation/store_redis.go`
  - [x] Redis-backed session storage for distributed deployments
- [x] Session struct with:
  - [x] Session ID
  - [x] UserID
  - [x] DeviceID, DeviceInfo
  - [x] IPAddress
  - [x] LastActiveAt, CreatedAt, ExpiresAt
  - [x] Metadata map
- [x] Create `session/invalidation/invalidation_test.go` (15 tests passing)
- [x] MaxSessionsPerUser enforcement
- [ ] Create `identity/ent/schema/user_session.go` (optional, for persistence)
- [ ] Add session tracking to JWT issuance (integration)
- [ ] Add session validation to JWT middleware (integration)

### P2: Suspicious Activity Detection

- [ ] Create `identity/security/anomaly.go`
  - [ ] `DetectAnomalousLogin(userID, ip, userAgent)` - Check for anomalies
  - [ ] `RecordLogin(userID, ip, userAgent, location)` - Track login patterns
  - [ ] `GetLoginHistory(userID)` - Get recent logins
- [ ] Detection rules:
  - [ ] New device/browser
  - [ ] New location
  - [ ] Impossible travel
  - [ ] Unusual time of day
- [ ] Alert actions:
  - [ ] Email notification
  - [ ] Require MFA
  - [ ] Block login

---

## Infrastructure

### P2: Redis Rate Limiting Backend ✅

- [x] Create `session/ratelimit/redis.go`
  - [x] `NewRedisStorage(client, opts)` - Create Redis storage
  - [x] `Allow(ctx, key, limit)` - Check and increment (sliding window)
  - [x] `Reset(ctx, key)` - Reset counter
  - [x] Lua script for atomic sliding window operations
- [x] Create `session/ratelimit/memory.go`
  - [x] In-memory storage for single-instance deployments
- [x] Create `session/ratelimit/ratelimit.go`
  - [x] Storage interface
  - [x] Limiter with middleware
  - [x] StaticResolver and TieredResolver
  - [x] Observability integration
- [x] Create `session/ratelimit/ratelimit_test.go`
- [x] Add Redis connection configuration (RedisConfig)
- [x] Support cluster mode (UniversalClient)
- [x] Add connection pooling options

### P2: Redis Feature Flags

- [ ] Create `featureflags/stores/redis.go`
  - [ ] `NewRedisStore(client, opts)` - Create Redis store
  - [ ] `Get(ctx, key)` - Get flag value
  - [ ] `Set(ctx, key, value)` - Set flag value
  - [ ] `Delete(ctx, key)` - Delete flag
  - [ ] `List(ctx, prefix)` - List flags
  - [ ] `Watch(ctx, key)` - Watch for changes
- [ ] Create `featureflags/stores/redis_test.go`
- [ ] Add pub/sub for real-time updates
- [ ] Add TTL support for temporary flags

### P2: Webhook System

#### Phase 1: Core Infrastructure

- [ ] Create `webhook/` package
- [ ] Create `webhook/config.go`
  - [ ] Webhook configuration struct
  - [ ] Retry policy options
  - [ ] Signature algorithm options
- [ ] Create `identity/ent/schema/webhook.go`
  - [ ] URL
  - [ ] Secret (encrypted)
  - [ ] Events subscribed
  - [ ] Active flag
  - [ ] Organization relationship
- [ ] Create `identity/ent/schema/webhook_delivery.go`
  - [ ] Webhook relationship
  - [ ] Event type
  - [ ] Payload
  - [ ] Status code
  - [ ] Attempts
  - [ ] Delivered timestamp

#### Phase 2: Dispatcher

- [ ] Create `webhook/dispatcher.go`
  - [ ] `Dispatch(ctx, event)` - Queue event for delivery
  - [ ] `DispatchSync(ctx, event)` - Synchronous delivery
  - [ ] `GetDeliveryStatus(deliveryID)` - Check delivery status
  - [ ] `RetryDelivery(deliveryID)` - Manual retry
- [ ] Create `webhook/worker.go`
  - [ ] Background worker for async delivery
  - [ ] Exponential backoff retry
  - [ ] Dead letter queue handling
- [ ] Create `webhook/signature.go`
  - [ ] `Sign(payload, secret)` - Generate HMAC signature
  - [ ] `Verify(payload, signature, secret)` - Verify signature
  - [ ] Support SHA-256 and SHA-512

#### Phase 3: API Handlers

- [ ] Create `webhook/handlers.go`
  - [ ] `POST /api/v1/webhooks` - Create webhook
  - [ ] `GET /api/v1/webhooks` - List webhooks
  - [ ] `GET /api/v1/webhooks/{id}` - Get webhook
  - [ ] `PATCH /api/v1/webhooks/{id}` - Update webhook
  - [ ] `DELETE /api/v1/webhooks/{id}` - Delete webhook
  - [ ] `POST /api/v1/webhooks/{id}/test` - Send test event
  - [ ] `GET /api/v1/webhooks/{id}/deliveries` - List deliveries
  - [ ] `POST /api/v1/webhooks/{id}/deliveries/{delivery_id}/retry` - Retry delivery

#### Phase 4: Tests

- [ ] Create `webhook/dispatcher_test.go`
- [ ] Create `webhook/signature_test.go`
- [ ] Create `webhook/handlers_test.go`
- [ ] Integration tests with mock server

---

## ProductGraph Integration

### P1: Correlation Middleware ✅

- [x] Create `productgraph/correlation.go`
- [x] Implement `CorrelationMiddleware`
- [x] Implement `SessionIDFromContext`
- [x] Implement `RequestIDFromContext`
- [x] Implement `UserIDFromContext`
- [x] Create `productgraph/correlation_test.go`

### P1: ProductGraph Client ✅

- [x] Create `productgraph/config.go`
- [x] Create `productgraph/event.go`
- [x] Create `productgraph/client.go`
- [x] Implement async batching
- [x] Create `productgraph/client_test.go`

### P1: Request Tracking ✅

- [x] Create `productgraph/middleware.go`
- [x] Implement `RequestTrackerMiddleware`
- [x] Implement `ChainMiddleware`
- [x] Create `productgraph/middleware_test.go`

### P1: Observability Integration ✅

- [x] Create `observability/productgraph.go`
- [x] Add `SetProductGraph` method
- [x] Add `SetProductGraphFromEnv` method
- [x] Update `Shutdown` to close ProductGraph

### P2: Journey Tracking

- [ ] Create `productgraph/journey.go`
  - [ ] `StartJourney(ctx, journeyID, name)` - Start journey
  - [ ] `CompleteJourney(ctx, journeyID)` - Complete journey
  - [ ] `AbandonJourney(ctx, journeyID, reason)` - Abandon journey
- [ ] Add journey context propagation

---

## Compliance & Privacy

### P2: GDPR Data Export

- [ ] Create `identity/gdpr/export.go`
  - [ ] `ExportUserData(ctx, userID)` - Export all user data
  - [ ] `ExportToJSON(data)` - JSON format
  - [ ] `ExportToCSV(data)` - CSV format
- [ ] Define exportable data types:
  - [ ] User profile
  - [ ] Organization memberships
  - [ ] OAuth accounts
  - [ ] API keys (metadata only)
  - [ ] Audit logs
  - [ ] Sessions
- [ ] Create `identity/gdpr/export_test.go`

### P2: GDPR Data Deletion

- [ ] Create `identity/gdpr/deletion.go`
  - [ ] `DeleteUserData(ctx, userID)` - Delete all user data
  - [ ] `ScheduleDeletion(ctx, userID, when)` - Schedule deletion
  - [ ] `CancelDeletion(ctx, userID)` - Cancel scheduled deletion
  - [ ] `AnonymizeUser(ctx, userID)` - Anonymize instead of delete
- [ ] Cascade delete:
  - [ ] User record
  - [ ] Memberships
  - [ ] OAuth accounts
  - [ ] API keys
  - [ ] Sessions
  - [ ] MFA enrollments
- [ ] Create `identity/gdpr/deletion_test.go`

### P2: Audit Log Search

- [ ] Create `contract/audit/search.go`
  - [ ] `Search(ctx, query)` - Search audit logs
  - [ ] `Export(ctx, query, format)` - Export search results
- [ ] Query options:
  - [ ] Date range
  - [ ] Actor (user/service)
  - [ ] Action type
  - [ ] Resource type
  - [ ] Organization
- [ ] Create `contract/audit/search_test.go`

---

## Operations & Admin

### P2: Admin Impersonation

- [ ] Create `identity/admin/impersonation.go`
  - [ ] `StartImpersonation(ctx, adminID, targetUserID)` - Start impersonation
  - [ ] `EndImpersonation(ctx)` - End impersonation
  - [ ] `IsImpersonating(ctx)` - Check impersonation status
  - [ ] `GetRealUser(ctx)` - Get actual admin user
- [ ] Create impersonation token type
- [ ] Add impersonation claims to JWT
- [ ] Audit log all impersonation actions
- [ ] Create `identity/admin/impersonation_test.go`

### P2: Bulk Operations

- [ ] Create `identity/admin/bulk.go`
  - [ ] `BulkImportUsers(ctx, users)` - Import users from CSV/JSON
  - [ ] `BulkExportUsers(ctx, query)` - Export users
  - [ ] `BulkUpdateUsers(ctx, query, updates)` - Bulk update
  - [ ] `BulkDeleteUsers(ctx, userIDs)` - Bulk delete
- [ ] Create `identity/admin/bulk_test.go`
- [ ] Add progress tracking for large operations
- [ ] Add dry-run mode

### P3: Email/Notification Service

- [ ] Create `notification/` package
- [ ] Create `notification/email.go`
  - [ ] `Send(ctx, to, template, data)` - Send email
  - [ ] `SendBulk(ctx, recipients, template, data)` - Bulk send
- [ ] Create `notification/templates/`
  - [ ] Welcome email
  - [ ] Password reset
  - [ ] Email verification
  - [ ] MFA enrollment
  - [ ] Suspicious login alert
  - [ ] Subscription confirmation
- [ ] Provider support:
  - [ ] SMTP
  - [ ] SendGrid
  - [ ] AWS SES
  - [ ] Mailgun

### P3: API Key Management

- [ ] Create `identity/apikey/rotation.go`
  - [ ] `ScheduleRotation(ctx, keyID, interval)` - Schedule rotation
  - [ ] `Rotate(ctx, keyID)` - Rotate key immediately
  - [ ] `GetRotationSchedule(ctx, keyID)` - Get schedule
- [ ] Create `identity/apikey/quota.go`
  - [ ] `SetQuota(ctx, keyID, quota)` - Set rate limit
  - [ ] `GetUsage(ctx, keyID)` - Get current usage
  - [ ] `ResetUsage(ctx, keyID)` - Reset usage counter
- [ ] Create `identity/apikey/metering.go`
  - [ ] `RecordCall(ctx, keyID)` - Record API call
  - [ ] `GetUsageReport(ctx, keyID, period)` - Usage report

---

## Enterprise SSO (Future)

### P3: SAML 2.0 Federation

- [ ] Create `identity/saml/` package
- [ ] Create `identity/saml/provider.go`
  - [ ] `NewSAMLProvider(config)` - Create provider
  - [ ] `GenerateMetadata()` - SP metadata
  - [ ] `HandleAssertion(ctx, assertion)` - Process SAML response
- [ ] Create `identity/saml/handlers.go`
  - [ ] `GET /saml/metadata` - Service provider metadata
  - [ ] `POST /saml/acs` - Assertion consumer service
  - [ ] `GET /saml/login` - Initiate SSO

### P3: OIDC Federation

- [ ] Create `identity/oidc/provider.go`
  - [ ] `NewOIDCProvider(config)` - Create provider
  - [ ] `HandleCallback(ctx, code)` - Handle callback
  - [ ] `RefreshToken(ctx, token)` - Refresh token
- [ ] Support multiple IdPs per organization

### P3: WebAuthn/Passkeys

- [ ] Create `identity/webauthn/` package
- [ ] Create `identity/webauthn/registration.go`
  - [ ] `BeginRegistration(ctx, userID)` - Start registration
  - [ ] `FinishRegistration(ctx, userID, response)` - Complete registration
- [ ] Create `identity/webauthn/authentication.go`
  - [ ] `BeginAuthentication(ctx, userID)` - Start authentication
  - [ ] `FinishAuthentication(ctx, userID, response)` - Verify

---

## Summary

### Priority Legend

- P0: Critical path, blocks release
- P1: High priority, should have for production
- P2: Medium priority, important for enterprise
- P3: Future consideration

### Current Focus

1. MFA/2FA support
2. Webhook system
3. GDPR compliance helpers
4. Admin impersonation

### Completed Milestones

- [x] Marketplace module (Phase 1-4)
- [x] ProductGraph correlation and client
- [x] Request tracking middleware
- [x] Observability integration
- [x] Redis rate limiting backend
- [x] Account lockout (brute-force protection)
- [x] Session invalidation (logout all devices)
