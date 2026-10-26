# Ent Schema Reference

Reference for the SystemForge Ent schemas in `identity/ent/schema`. Table names come from each schema's `entsql` annotation; every table uses the `sf_` prefix. Columns marked "FK" are foreign keys created from the schema's edges.

## Identity Schemas

Every actor is a `Principal`. Its `type` selects a one-to-one extension: `Human` for people, `ServicePrincipal` for backend services, `Application` for OAuth client applications, and `Agent` for AI agents. Credentials, upstream login identities, and organization memberships all belong to the principal.

### Principal

**Table**: `sf_principals`

Principal is the unified identity root representing any type of actor: human, application, agent, or service.

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| `id` | UUID | PK, immutable | Primary key |
| `created_at` | time | immutable | Creation time |
| `updated_at` | time | — | Last modification time |
| `type` | enum | immutable | Type of principal: human, application, agent, service |
| `identifier` | string | unique, not empty | Unique identifier (email, client_id, service@org) |
| `display_name` | string | not empty | Human-readable display name |
| `active` | bool | default: true | Whether the principal is active |
| `capabilities` | JSON | — | Principal capabilities (can_access_ui, can_delegate, etc.) |
| `allowed_scopes` | JSON | — | Scopes this principal can request |
| `metadata` | JSON | nullable | Custom metadata |
| `organization_id` | UUID | FK → Organization, nullable | Organization this principal belongs to |

**`type` values**: `human`, `application`, `agent`, `service`

**Edges**:

- `organization` → Organization (M2O)
- `human` → Human (O2O)
- `application` → Application (O2O)
- `agent` → Agent (O2O)
- `service_principal` → ServicePrincipal (O2O)
- `credentials` → Credential (O2M)
- `external_identities` → ExternalIdentity (O2M)
- `principal_tokens` → PrincipalToken (O2M)
- `principal_memberships` → PrincipalMembership (O2M)
- `owned_organizations` → Organization (O2M)
- `owned_oauth_apps` → OAuthApp (O2M)
- `oauth_consents` → OAuthConsent (O2M)
- `sent_invites` → Invite (O2M)
- `owned_listings` → Listing (O2M)
- `purchased_licenses` → License (O2M)
- `seat_assignments` → SeatAssignment (O2M)
- `assigned_seats` → SeatAssignment (O2M)

---

### Human

**Table**: `sf_humans`

Human-specific principal data. This is a one-to-one extension of Principal where type="human".

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| `id` | UUID | PK, immutable | Primary key |
| `created_at` | time | immutable | Creation time |
| `updated_at` | time | — | Last modification time |
| `email` | string | unique, not empty | Primary email address |
| `given_name` | string | nullable | First/given name |
| `family_name` | string | nullable | Last/family name |
| `avatar_url` | string | nullable | Profile picture URL |
| `locale` | string | nullable, default: en | Preferred locale (e.g., en-US) |
| `timezone` | string | nullable, default: UTC | Preferred timezone (e.g., America/Los_Angeles) |
| `is_platform_admin` | bool | default: false | Cross-organization admin access |
| `last_login_at` | time | nullable | Last successful login timestamp |
| `email_verified_at` | time | nullable | When email was verified |
| `principal_id` | UUID | FK → Principal, unique, immutable | Reference to parent Principal |

**Edges**:

- `principal` → Principal (O2O)

---

### ServicePrincipal

**Table**: `sf_service_principals`

Backend service-specific principal data. This is a one-to-one extension of Principal where type="service".

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| `id` | UUID | PK, immutable | Primary key |
| `created_at` | time | immutable | Creation time |
| `updated_at` | time | — | Last modification time |
| `service_type` | string | not empty | Type of service (e.g., backend, worker, gateway) |
| `description` | string | nullable | Service description |
| `last_used_at` | time | nullable | Last time this service account was used |
| `allowed_ips` | JSON | — | IP addresses/CIDRs allowed to use this service account |
| `principal_id` | UUID | FK → Principal, unique, immutable | Reference to parent Principal |
| `created_by` | UUID | FK → Principal, nullable | Principal who created this service account |

**Edges**:

- `principal` → Principal (O2O)
- `creator` → Principal (O2O)

---

### Application

**Table**: `sf_applications`

OAuth application-specific principal data. This is a one-to-one extension of Principal where type="application".

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| `id` | UUID | PK, immutable | Primary key |
| `created_at` | time | immutable | Creation time |
| `updated_at` | time | — | Last modification time |
| `client_id` | string | unique, not empty, immutable | Public OAuth client identifier |
| `description` | string | nullable | Application description |
| `logo_url` | string | nullable | Application logo URL |
| `app_type` | enum | default: web | web=confidential, spa/native=public+PKCE, machine=client_credentials |
| `redirect_uris` | JSON | — | Allowed redirect URIs |
| `allowed_grants` | JSON | — | Allowed grant types |
| `allowed_response_types` | JSON | — | Allowed response types |
| `access_token_ttl` | int | default: 900 | Access token TTL in seconds (default 15 min) |
| `refresh_token_ttl` | int | default: 604800 | Refresh token TTL in seconds (default 7 days) |
| `refresh_token_rotation` | bool | default: true | Rotate refresh tokens on use |
| `first_party` | bool | default: false | First-party apps skip consent screen |
| `public` | bool | default: false | Public clients cannot keep secrets |
| `principal_id` | UUID | FK → Principal, unique, immutable | Reference to parent Principal |

**`app_type` values**: `web`, `spa`, `native`, `machine`

**Edges**:

- `principal` → Principal (O2O)
- `issued_tokens` → PrincipalToken (O2M)

---

### Agent

**Table**: `sf_agents`

AI agent-specific principal data. This is a one-to-one extension of Principal where type="agent".

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| `id` | UUID | PK, immutable | Primary key |
| `created_at` | time | immutable | Creation time |
| `updated_at` | time | — | Last modification time |
| `model_id` | string | not empty | AI model identifier (e.g., claude-3-opus) |
| `version` | string | nullable | Agent version |
| `capability_constraints` | JSON | — | Capabilities this agent is constrained to |
| `resource_constraints` | JSON | — | Resources this agent can access |
| `max_token_lifetime` | int | default: 3600 | Maximum token lifetime in seconds (default 1 hour) |
| `session_id` | string | nullable | Current session identifier |
| `requires_confirmation` | bool | default: true | Whether actions require human confirmation |
| `delegating_principal_id` | UUID | FK → Principal, nullable | Principal who delegated authority to this agent |
| `principal_id` | UUID | FK → Principal, unique, immutable | Reference to parent Principal |

**Edges**:

- `principal` → Principal (O2O)
- `delegating_principal` → Principal (O2O)

---

### Credential

**Table**: `sf_credentials`

Unified credentials. Credentials can be passwords, API keys, keypairs, WebAuthn credentials, or TOTP secrets.

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| `id` | UUID | PK, immutable | Primary key |
| `type` | enum | — | Type of credential |
| `identifier` | string | nullable | Unique identifier for this credential (e.g., key prefix) |
| `secret_hash` | string | nullable, sensitive | Hashed secret (Argon2id for passwords/secrets, SHA256 for tokens) |
| `public_key` | string | nullable | Public key (PEM format) for keypair credentials |
| `key_algorithm` | string | nullable | Key algorithm (RS256, ES256, etc.) |
| `key_id` | string | unique, nullable | Key ID for keypair credentials (used in JWT kid header) |
| `webauthn_credential_id` | bytes | nullable | WebAuthn credential ID |
| `webauthn_public_key` | bytes | nullable | WebAuthn public key (COSE format) |
| `webauthn_aaguid` | string | nullable | WebAuthn authenticator AAGUID |
| `webauthn_sign_count` | uint32 | nullable, default: 0 | WebAuthn signature counter |
| `scopes` | JSON | — | Scopes this credential grants |
| `active` | bool | default: true | Whether this credential is active |
| `expires_at` | time | nullable | When this credential expires (nil = never) |
| `revoked` | bool | default: false | Whether this credential has been revoked |
| `revoked_at` | time | nullable | When this credential was revoked |
| `revoked_reason` | string | nullable | Reason for revocation |
| `last_used_at` | time | nullable | Last time this credential was used |
| `last_used_ip` | string | nullable | IP address of last use |
| `name` | string | nullable | Human-readable name for this credential |
| `metadata` | JSON | nullable | Custom metadata |
| `created_at` | time | immutable | Creation time |
| `updated_at` | time | — | Last modification time |
| `principal_id` | UUID | FK → Principal | Principal that owns this credential |

**`type` values**: `password`, `api_key`, `keypair`, `webauthn`, `totp`, `client_secret`

**Unique constraint**: `(type, identifier)`

**Edges**:

- `principal` → Principal (M2O)

---

### ExternalIdentity

**Table**: `sf_external_identities`

Links a Principal to an upstream login identity (e.g. a GitHub or Google account). The (provider, subject) pair is the stable key used to find the principal on every social login; email is recorded for information and verified-email linking only.

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| `id` | UUID | PK, immutable | Primary key |
| `created_at` | time | immutable | Creation time |
| `updated_at` | time | — | Last modification time |
| `provider` | string | not empty, immutable | Upstream provider name (e.g., github, google) |
| `subject` | string | not empty, immutable | Stable user ID at the provider (GitHub numeric id, Google sub) |
| `email` | string | nullable | Email last reported by the provider |
| `email_verified` | bool | default: false | Whether the provider asserted the email is verified |
| `last_login_at` | time | nullable | Last successful login through this identity |
| `principal_id` | UUID | FK → Principal | Principal this upstream identity is linked to |

**Unique constraint**: `(provider, subject)`

**Edges**:

- `principal` → Principal (M2O)

---

### Organization

**Table**: `sf_organizations`

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| `id` | UUID | PK, immutable | Primary key |
| `created_at` | time | immutable | Creation time |
| `updated_at` | time | — | Last modification time |
| `name` | string | not empty |  |
| `slug` | string | unique, not empty | URL-safe identifier |
| `org_type` | enum | default: team | personal=user namespace, team=shared org, enterprise=large org |
| `logo_url` | string | nullable |  |
| `description` | string | nullable | Organization description |
| `website_url` | string | nullable | Organization website |
| `settings` | JSON | nullable | App-specific configuration |
| `active` | bool | default: true |  |
| `owner_principal_id` | UUID | FK → Principal, nullable | For personal orgs, the principal who owns this namespace |

**`org_type` values**: `personal`, `team`, `enterprise`

**Edges**:

- `oauth_apps` → OAuthApp (O2M)
- `principals` → Principal (O2M)
- `principal_memberships` → PrincipalMembership (O2M)
- `owner` → Principal (M2O)
- `invites` → Invite (O2M)
- `listings` → Listing (O2M)
- `licenses` → License (O2M)
- `subscription` → Subscription (O2O)

---

### PrincipalMembership

**Table**: `sf_principal_memberships`

Principal-organization memberships for every principal type, with an app-defined role and an `active` flag for soft deactivation.

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| `id` | UUID | PK, immutable | Primary key |
| `created_at` | time | immutable | Creation time |
| `updated_at` | time | — | Last modification time |
| `role` | string | not empty | App-defined role (e.g., owner, admin, member) |
| `permissions` | JSON | nullable | Optional fine-grained permissions |
| `active` | bool | default: true | Whether this membership is active |
| `organization_id` | UUID | FK → Organization |  |
| `principal_id` | UUID | FK → Principal |  |

**Unique constraint**: `(principal_id, organization_id)`

**Edges**:

- `principal` → Principal (M2O)
- `organization` → Organization (M2O)

---

### Invite

**Table**: `sf_invites`

Organization invitations. Invites allow existing members to invite new users to join an organization.

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| `id` | UUID | PK, immutable | Primary key |
| `created_at` | time | immutable | Creation time |
| `updated_at` | time | — | Last modification time |
| `email` | string | not empty | Email address of the invitee |
| `role` | string | not empty, default: member | Role to assign when invite is accepted |
| `token` | string | unique, not empty, sensitive | Secure token for invite URL |
| `status` | enum | default: pending | Current status of the invite |
| `message` | string | nullable | Personal message from inviter |
| `expires_at` | time | — | When this invite expires |
| `accepted_at` | time | nullable | When the invite was accepted |
| `accepted_by_principal_id` | UUID | nullable | Principal who accepted the invite |
| `resend_count` | int | default: 0 | Number of times invite was resent |
| `last_sent_at` | time | — | When invite was last sent/resent |
| `organization_id` | UUID | FK → Organization | Organization the invite is for |
| `inviter_principal_id` | UUID | FK → Principal | Principal who created the invite |

**`status` values**: `pending`, `accepted`, `declined`, `expired`, `revoked`

**Edges**:

- `organization` → Organization (M2O)
- `inviter` → Principal (M2O)

## Session and Token Schemas

### PrincipalToken

**Table**: `sf_principal_tokens`

Holds OAuth 2.0 access and refresh tokens for principals. This replaces OAuthToken with principal-centric token management.

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| `id` | UUID | PK, immutable | Primary key |
| `principal_type` | enum | — | Type of the principal (denormalized for fast lookup) |
| `access_token_signature` | string | unique | SHA256 signature of access token |
| `refresh_token_signature` | string | unique, nullable | SHA256 signature of refresh token |
| `family_id` | UUID | — | Token family for refresh rotation |
| `scopes` | JSON | — | Granted scopes |
| `audience` | JSON | — | Token audience |
| `capabilities` | JSON | — | Capabilities granted to this token |
| `delegation_chain` | JSON | — | Chain of principal IDs in delegation (root to current) |
| `dpop_jkt` | string | nullable | DPoP JWK thumbprint for proof-of-possession |
| `session_id` | string | nullable | BFF session ID if applicable |
| `request_data` | string | nullable | Serialized Fosite request for introspection |
| `access_expires_at` | time | — | When access token expires |
| `refresh_expires_at` | time | nullable | When refresh token expires |
| `revoked` | bool | default: false |  |
| `revoked_at` | time | nullable |  |
| `revoked_reason` | string | nullable |  |
| `client_ip` | string | nullable |  |
| `user_agent` | string | nullable |  |
| `last_used_at` | time | nullable |  |
| `created_at` | time | immutable | Creation time |
| `issued_by_app_id` | UUID | FK → Application, nullable | Application principal that issued this token |
| `principal_id` | UUID | FK → Principal | Principal this token represents |
| `parent_token_id` | UUID | FK → PrincipalToken, nullable | Parent token ID (for delegated tokens) |

**`principal_type` values**: `human`, `application`, `agent`, `service`

**Edges**:

- `principal` → Principal (M2O)
- `issued_by_app` → Application (M2O)
- `child_tokens` → PrincipalToken (O2O)

---

### LoginSession

**Table**: `sf_login_sessions`

Holds SystemAuth browser login sessions (the __Host-sf_login cookie). Only a SHA-256 hash of the opaque session token is stored.

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| `id` | UUID | PK, immutable | Primary key |
| `token_hash` | string | unique, immutable | Hex SHA-256 of the session token; the token itself is never stored |
| `principal_id` | UUID | immutable | Authenticated principal |
| `provider` | string | nullable, immutable | Upstream provider used to sign in |
| `created_at` | time | immutable | When the session was established |
| `expires_at` | time | immutable | Absolute session expiry |

---

### LoginState

**Table**: `sf_login_states`

Holds in-flight upstream OAuth logins started by SystemAuth social login. Rows are single-use and short-lived; only a SHA-256 hash of the OAuth state value is stored.

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| `id` | UUID | PK, immutable | Primary key |
| `state_hash` | string | unique, immutable | Hex SHA-256 of the OAuth state value |
| `provider` | string | immutable | Upstream provider the flow was started for |
| `redirect_url` | string | nullable, immutable | Validated post-login destination |
| `nonce` | string | nullable, immutable, sensitive | OpenID Connect nonce |
| `pkce_verifier` | string | nullable, immutable, sensitive | PKCE code verifier for the upstream token exchange |
| `expires_at` | time | immutable | When the in-flight login expires |

---

### ConsentGrant

**Table**: `sf_consent_grants`

Records one scope a principal granted to an OAuth client on the SystemAuth consent page. One row per (principal, client, scope) keeps concurrent grants race-free without read-modify-write.

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| `id` | UUID | PK, immutable | Primary key |
| `principal_id` | string | immutable | Principal that granted consent |
| `client_id` | string | immutable | OAuth client ID that received consent |
| `scope` | string | immutable | Granted scope |
| `granted_at` | time | immutable |  |

**Unique constraint**: `(principal_id, client_id, scope)`

## OAuth Schemas

Tables used by the embedded OAuth 2.0 / OpenID Connect server. Tokens and authorization codes record the authenticated principal in `subject`; it is empty for `client_credentials` tokens.

### OAuthApp

**Table**: `sf_oauth_apps`

OAuth 2.0 applications/clients.

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| `id` | UUID | PK, immutable | Primary key |
| `client_id` | string | unique, not empty, immutable | Public client identifier |
| `name` | string | not empty | Human-readable app name |
| `description` | string | nullable |  |
| `logo_url` | string | nullable |  |
| `app_type` | enum | default: web | web=confidential, spa/native=public+PKCE, service/machine=client_credentials |
| `redirect_uris` | JSON | — | Allowed redirect URIs |
| `allowed_scopes` | JSON | — | Scopes this app can request |
| `allowed_grants` | JSON | — | Allowed grant types |
| `allowed_response_types` | JSON | — | Allowed response types |
| `access_token_ttl` | int | default: 900 | Access token TTL in seconds (default 15 min) |
| `refresh_token_ttl` | int | default: 604800 | Refresh token TTL in seconds (default 7 days) |
| `refresh_token_rotation` | bool | default: true | Rotate refresh tokens on use |
| `first_party` | bool | default: false | First-party apps skip consent screen |
| `public` | bool | default: false | Public clients cannot keep secrets |
| `active` | bool | default: true |  |
| `revoked_at` | time | nullable |  |
| `metadata` | JSON | nullable | Custom metadata |
| `created_at` | time | immutable | Creation time |
| `updated_at` | time | — | Last modification time |
| `organization_id` | UUID | FK → Organization, nullable | Organization scope (optional) |
| `owner_id` | UUID | FK → Principal | Principal that owns this app |

**`app_type` values**: `web`, `spa`, `native`, `service`, `machine`

**Edges**:

- `owner` → Principal (M2O)
- `organization` → Organization (M2O)
- `secrets` → OAuthAppSecret (O2M)
- `tokens` → OAuthToken (O2M)
- `auth_codes` → OAuthAuthCode (O2M)
- `consents` → OAuthConsent (O2M)

---

### OAuthAppSecret

**Table**: `sf_oauth_app_secrets`

Holds client secrets for OAuth apps. Multiple secrets can exist for rotation purposes.

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| `id` | UUID | PK, immutable | Primary key |
| `secret_hash` | string | not empty, sensitive | bcrypt or Argon2id (PHC string) hash of the secret |
| `secret_prefix` | string | — | First few chars for identification |
| `expires_at` | time | nullable | When this secret expires |
| `last_used_at` | time | nullable |  |
| `revoked` | bool | default: false |  |
| `revoked_at` | time | nullable |  |
| `created_at` | time | immutable | Creation time |
| `app_id` | UUID | FK → OAuthApp | OAuth app this secret belongs to |

**Edges**:

- `app` → OAuthApp (M2O)

---

### OAuthToken

**Table**: `sf_oauth_tokens`

Holds OAuth 2.0 access and refresh tokens.

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| `id` | UUID | PK, immutable | Primary key |
| `subject` | string | nullable | Authenticated subject (principal ID); empty for client_credentials |
| `access_token_signature` | string | unique | SHA256 signature of access token |
| `refresh_token_signature` | string | unique, nullable | SHA256 signature of refresh token |
| `family_id` | UUID | — | Token family for refresh rotation |
| `scopes` | JSON | — | Granted scopes |
| `audience` | JSON | — | Token audience |
| `session_id` | string | nullable | BFF session ID if applicable |
| `request_data` | string | nullable | Serialized Fosite request for introspection |
| `access_expires_at` | time | — | When access token expires |
| `refresh_expires_at` | time | nullable | When refresh token expires |
| `revoked` | bool | default: false |  |
| `revoked_at` | time | nullable |  |
| `revoked_reason` | string | nullable |  |
| `client_ip` | string | nullable |  |
| `user_agent` | string | nullable |  |
| `last_used_at` | time | nullable |  |
| `created_at` | time | immutable | Creation time |
| `app_id` | UUID | FK → OAuthApp | OAuth app that issued this token |

**Edges**:

- `app` → OAuthApp (M2O)

---

### OAuthAuthCode

**Table**: `sf_oauth_auth_codes`

Holds OAuth 2.0 authorization codes.

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| `id` | UUID | PK, immutable | Primary key |
| `code_signature` | string | unique | SHA256 signature of the authorization code |
| `subject` | string | nullable | Authenticated subject (principal ID) the code was issued for |
| `code_challenge` | string | nullable | PKCE code challenge |
| `code_challenge_method` | string | nullable, default: S256 | PKCE challenge method (S256) |
| `redirect_uri` | string | — | Redirect URI from authorization request |
| `scopes` | JSON | — | Requested scopes |
| `state` | string | nullable | State parameter from request |
| `nonce` | string | nullable | OIDC nonce |
| `request_data` | string | nullable | Serialized Fosite request |
| `expires_at` | time | — | When this code expires (short-lived, ~10 min) |
| `used` | bool | default: false | Whether code has been exchanged |
| `used_at` | time | nullable |  |
| `client_ip` | string | nullable |  |
| `user_agent` | string | nullable |  |
| `created_at` | time | immutable | Creation time |
| `app_id` | UUID | FK → OAuthApp | OAuth app this code was issued to |

**Edges**:

- `app` → OAuthApp (M2O)

---

### OAuthConsent

**Table**: `sf_oauth_consents`

Tracks user consent for OAuth apps. First-party apps skip consent; third-party apps require explicit approval.

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| `id` | UUID | PK, immutable | Primary key |
| `scopes` | JSON | — | Scopes the user consented to |
| `granted` | bool | default: true | Whether consent is currently active |
| `granted_at` | time | — | When consent was first granted |
| `last_used_at` | time | nullable | Last time this consent was used for authorization |
| `revoked` | bool | default: false |  |
| `revoked_at` | time | nullable |  |
| `revoked_reason` | string | nullable | user_initiated, admin_revoked, app_deleted, etc. |
| `created_at` | time | immutable | Creation time |
| `updated_at` | time | — | Last modification time |
| `app_id` | UUID | FK → OAuthApp | OAuth app that received consent |
| `principal_id` | UUID | FK → Principal | Principal who granted consent |

**Unique constraint**: `(principal_id, app_id)`

**Edges**:

- `principal` → Principal (M2O)
- `app` → OAuthApp (M2O)

## Marketplace Schemas

### Listing

**Table**: `sf_listings`

A marketplace product listing.

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| `id` | UUID | PK, immutable | Primary key |
| `product_type` | string | not empty | Type of product: course, dashboard_template, etc. |
| `product_id` | UUID | nullable | Reference to the actual product (optional for drafts) |
| `title` | string | not empty |  |
| `description` | string | nullable |  |
| `pricing_model` | enum | default: free |  |
| `price_cents` | int64 | default: 0 | Price in cents (0 for free) |
| `currency` | string | default: USD | ISO 4217 currency code |
| `status` | enum | default: draft |  |
| `metadata` | JSON | nullable | App-specific metadata |
| `created_at` | time | immutable | Creation time |
| `updated_at` | time | — | Last modification time |
| `published_at` | time | nullable | When the listing was published |
| `creator_org_id` | UUID | FK → Organization | Organization that created this listing |
| `owner_id` | UUID | FK → Principal | Principal who owns this listing |

**`pricing_model` values**: `free`, `one_time`, `subscription`, `per_seat`

**`status` values**: `draft`, `pending_review`, `published`, `archived`

**Edges**:

- `creator_org` → Organization (M2O)
- `owner` → Principal (M2O)
- `licenses` → License (O2M)

---

### License

**Table**: `sf_licenses`

A marketplace license entitlement.

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| `id` | UUID | PK, immutable | Primary key |
| `license_type` | enum | default: unlimited |  |
| `seats` | int | nullable | Number of seats (nil for unlimited) |
| `used_seats` | int | default: 0 | Currently assigned seats |
| `valid_from` | time | — | When the license becomes active |
| `valid_until` | time | nullable | When the license expires (nil for perpetual) |
| `stripe_subscription_id` | string | nullable | Stripe subscription ID for recurring licenses |
| `created_at` | time | immutable | Creation time |
| `updated_at` | time | — | Last modification time |
| `listing_id` | UUID | FK → Listing | The marketplace listing this license grants access to |
| `organization_id` | UUID | FK → Organization | The organization that holds this license |
| `purchased_by` | UUID | FK → Principal | Principal who purchased this license |

**`license_type` values**: `seat_based`, `team`, `unlimited`

**Unique constraint**: `(listing_id, organization_id)`

**Edges**:

- `listing` → Listing (M2O)
- `organization` → Organization (M2O)
- `purchaser` → Principal (M2O)
- `seat_assignments` → SeatAssignment (O2M)

---

### Subscription

**Table**: `sf_subscriptions`

A platform subscription.

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| `id` | UUID | PK, immutable | Primary key |
| `plan_tier` | string | not empty, default: free | Plan name: free, starter, pro, enterprise |
| `status` | enum | default: active |  |
| `current_period_start` | time | — |  |
| `current_period_end` | time | — |  |
| `stripe_subscription_id` | string | unique, nullable |  |
| `stripe_customer_id` | string | nullable |  |
| `cancel_at_period_end` | bool | default: false |  |
| `created_at` | time | immutable | Creation time |
| `updated_at` | time | — | Last modification time |
| `organization_id` | UUID | FK → Organization, unique | The subscribing organization |

**`status` values**: `active`, `trialing`, `past_due`, `canceled`, `unpaid`

**Edges**:

- `organization` → Organization (O2O)

---

### SeatAssignment

**Table**: `sf_seat_assignments`

A license seat assignment.

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| `id` | UUID | PK, immutable | Primary key |
| `assigned_at` | time | immutable |  |
| `license_id` | UUID | FK → License | The license this seat belongs to |
| `principal_id` | UUID | FK → Principal | The principal assigned to this seat |
| `assigned_by` | UUID | FK → Principal | Principal who made this assignment |

**Unique constraint**: `(license_id, principal_id)`

**Edges**:

- `license` → License (M2O)
- `principal` → Principal (M2O)
- `assigner` → Principal (M2O)

