# TRD — SystemForge Learner Accounts — Optional Email, QR Login, Guardian and Educator Relationships

**Initiative:** `INIT-SYSTEMFORGE-007`
**Design of record:** [ADR-005](../../adrs/ADR-005-managed-principals-and-manager-relationships.md)

## Current State

After INIT-SYSTEMFORGE-008, a human is `Principal(type=human)` + `Human`,
with `Human.email` declared `NotEmpty().Unique()` and `Principal.identifier`
set to the email. Credentials live in `sf_credentials` with the type enum
`password | api_key | keypair | webauthn | totp | client_secret`.
`principal.Capabilities` already carries `CanManageProfile` and
`CanDelegate`. SystemAuth authenticates clients as `OAuthApp` rows
(`client_id`, grants, TTLs, `first_party`, `public`) and static
`ClientConfig` entries, with no feature flags. (The `Application`
principal extension also has a `client_id` but is not what SystemAuth
authenticates.) The base SpiceDB schema defines `principal {}` with no relations.

Paths that assume an email exists (non-test code): `systemauth` social
login (`FindByVerifiedEmail`, account creation requires a verified email),
`GetHumanByEmail` for password login, `userinfo` and ID-token `email`
claims; `invite` (email is required on the invite request); `signup`;
`scim/mapper` (`userName` and `emails`); `relyingparty` principal views;
`session/jwt` claims; `marketplace/stripe` customer email.

## Design

### 1. Schema

**`Human`**

- `email`: `Optional().Nillable().Unique()`. Confirm on the target database
  that the unique index admits multiple nulls (MySQL-compatible engines do;
  verify on the deployment target).
- `email_verified_at` unchanged.

**`Principal`**

- `identifier`: email when present, else `human:<principal-id>`, set by the
  service layer; documented as a lookup key.

**`OAuthApp`** (and `ClientConfig.managed_principals` for static clients)

- `managed_principals_enabled` `Bool`, default `false`.
- `login_token_ttl` `Int` (seconds), `Optional().Nillable()`; null means
  use the platform default. Ignored unless `managed_principals_enabled`.

**`Credential.type`**

- Add `login_token`.

**New `ManagerRelationship`** (`sf_manager_relationships`)

| Field | Notes |
|---|---|
| `managed_principal_id` | → `Principal`, must be `type=human` |
| `manager_principal_id` | → `Principal`, must be `type=human`, active, with email |
| `role` | `String`, validated against the manager-role vocabulary; built-ins `guardian`, `educator` |
| `active` | `Bool` |
| `created_by` | → `Principal` (the acting manager or admin) |
| timestamps | via `BaseMixin` |

Unique on `(managed_principal_id, manager_principal_id, role)`.

### 2. `identity/managedprincipal` service

A new package owning the invariants:

- `Create(ctx, CreateInput{ClientID, DisplayName, Managers: []ManagerInput{PrincipalID, Role}, ActorID})`
  checks the deployment setting and the client's flag through
  `Server.ManagedPrincipalsAllowed`, validates every
  manager (human, active, has email), then creates `Principal` (identifier
  `human:<id>`, capabilities with `CanManageProfile=false`,
  `CanDelegate=false`), `Human` (no email), and the relationships in one
  transaction. Refused with a typed error if `Managers` is empty.
- `AddManager`, `RemoveManager`: `RemoveManager` refuses to remove the last
  active relationship while `Human.email` is null (`ErrLastManager`).
  `AddManager` is idempotent and reactivates an inactive relationship;
  `RemoveManager` deactivates rather than deletes. Both update the managed
  principal's row first, so concurrent changes to one principal serialize
  on its row lock and cannot together remove the last manager.
- `IssueClaim(ctx, managedID, byManager) (claimCode, expiry)` and
  `RedeemClaim(ctx, code, claimantID)`: an `educator` or `guardian` issues a
  short-lived, single-use claim; a human with an email redeems it and becomes
  `guardian`. Stored hashed in `sf_credentials` as a `login_token` flagged
  `metadata.purpose = "claim"`, or as its own small table if mixing purposes
  proves confusing; decide during implementation, documenting the choice.
- `AttachEmail(ctx, managedID, email)`: initiates INIT-SYSTEMFORGE-006
  verification; on success sets `Human.email`, updates `identifier`,
  restores default human capabilities. Relationships are untouched.
- `IsManaged(ctx, principalID) bool` for callers that need the distinction.

Deployment setting: `identity.managed_principals.enabled` in the SystemAuth
config, default `false`, surfaced through `systemauthsvc`.

### 3. `login_token` credential

In `identity/credential`:

- `IssueLoginToken(ctx, principalID, IssueInput{IssuedBy, ExpiresAt, SingleUse bool}) (plain, *Credential)`:
  32 bytes of randomness, base32-encoded for QR friendliness, stored as a
  hash; `identifier` holds a short prefix for display; `metadata` records
  `issued_by` and `single_use`. The plain value is returned once.
- `VerifyLoginToken(ctx, plain) (*Credential, error)`: constant-time
  comparison against the hash; rejects expired, revoked, or inactive rows;
  updates `last_used_at`/`last_used_ip`; revokes the row when `single_use`.
- Existing `Revoke` applies.

As implemented: tokens are `SFLT` followed by the base32 encoding of the
random bytes without padding, so they use only uppercase letters and digits
and a QR code can encode them in alphanumeric mode; verification also
accepts lowercase and grouping spaces or hyphens for typed entry. The
stored `identifier` is the first 12 characters and is the lookup key; the
SHA-256 hash is then compared in constant time. Every unusable token yields
the same `ErrInvalidLoginToken`. Recording a use re-checks `active` and
`revoked` in the `UPDATE`, and a single-use token is revoked in that same
statement, so it succeeds at most once under concurrent presentation.
`LoginTokenPolicy.ExpiresAt` resolves the lifetime; `systemauth.Server`
supplies the policy for a client through `LoginTokenPolicy`, and
`managedprincipal.IssueLoginToken` requires the issuer to be an active
manager until the authorization relations of RMI-SYSTEMFORGE-107 land.

Lifetime policy, resolved at issue time:

1. An explicit `ExpiresAt` on the request, if present.
2. Else the client's `login_token_ttl` (new nullable field on `OAuthApp`;
   a learning application sets a school year).
3. Else the platform default `identity.managed_principals.login_token_ttl`,
   default **30 days**.
4. Never beyond the platform ceiling
   `identity.managed_principals.login_token_max_ttl`, default 400 days
   (one school year plus slack); a request above it is clamped and the
   clamp is logged.
5. Single-use tokens ignore 2–3 and use
   `identity.managed_principals.single_use_token_ttl`, default 20 minutes.

The 30-day default reflects SystemForge's posture as a general SaaS identity
platform; the override exists because classroom products conventionally
issue codes that last a term or a school year.

### 4. SystemAuth exchange and claims

- New endpoint on SystemAuth: `POST /login-token` (name finalized in
  implementation) accepting the plain token and the requesting client. It
  verifies the token, confirms the principal is managed and active, confirms
  `Server.ManagedPrincipalsAllowed` for the client, and creates a
  SystemAuth session. Responses for unknown, expired, revoked, and
  disabled-application cases are identical, and the endpoint is rate-limited
  per client and per source address using the existing `session/ratelimit`.
- Session and ID-token claims: `email` and `email_verified` are omitted when
  absent; a `managed: true` claim is added for managed principals. `userinfo`
  follows the same rule.
- Capabilities already flow into `PrincipalToken.capabilities`; managed
  principals' tokens therefore carry `can_manage_profile=false`.

### 5. Manager visibility

In `identity/managedprincipal` with handlers mounted on SystemAuth:

- `ListLoginTokens(ctx, managedID)` and `ListSessions(ctx, managedID)`
  (joining `sf_credentials` type `login_token`, `sf_login_sessions`, and
  active `sf_principal_tokens`).
- `RevokeLoginToken`, `RevokeSession`, `RevokeAll`.
- Every call authorizes the caller through `authz` with `manage_credentials`
  on the managed principal (§7).

### 6. Email-assuming paths

Each becomes conditional on `Human.email != nil`:

| Path | Change |
|---|---|
| Social login | `FindByVerifiedEmail` already filters verified emails; nulls are excluded. No linking to managed principals. |
| Password login | `GetHumanByEmail` cannot match a null; managed principals have no password until an email is attached. |
| `invite` | Unchanged: invites target an email and never create managed principals; documented. |
| `signup` | Unchanged: requires an email. |
| SCIM mapper and store | `userName` = `Principal.identifier`; `emails` omitted when null; filters on `emails` exclude nulls. |
| `userinfo`, ID token, `session/jwt` | `email`/`email_verified` omitted when null; `managed` claim added. |
| `relyingparty` principal view | `Email` becomes optional; `Managed bool` added. |
| `marketplace` | Purchase and subscription creation reject managed purchasers with a typed error; Stripe customer email is the purchaser's. |
| `contract` identity types | `Email` optional. |

### 7. Authorization

Extend `authz.BaseSpiceDBSchema`:

```zed
definition principal {
    relation guardian: principal
    relation educator: principal

    permission manage_account     = guardian
    permission manage_credentials = guardian + educator
    permission view_profile       = guardian + educator
    permission manage_managers    = guardian
}
```

`identity/managedprincipal` writes and deletes these relationships through
the existing `authz.Sync` path when a `ManagerRelationship` row changes, so
the simple provider and the SpiceDB provider agree. Applications add domain
permissions in their facets, for example `learning_org` granting
`view_progress = org->view + principal->view_profile`.

### 8. Documentation

- New `docs/identity/managed-principals.md`: the primitive, invariants,
  roles, `login_token`, claim flow, attach-email flow, and the two
  configuration switches, with a learning application as the worked example.
- Update `docs/identity/users.md` (email optionality, identifier rule),
  `docs/identity/security.md` (token handling), and the authorization
  conventions doc (new base relations).

## Sequencing Constraints

- §1 and §2 depend on INIT-SYSTEMFORGE-008 having removed the legacy model
  (`RMI-SYSTEMFORGE-099`), so there is one `Human` to change.
- §3 and §4 depend on §1 (credential type enum) and §2 (managed check).
- §5 depends on §3 and §7.
- §6 can proceed in parallel with §3–§5 once §1 lands.
- The claim flow in §2 depends on INIT-SYSTEMFORGE-006 only for the
  attach-email step; the claim itself does not.

## Risks

- **Null uniqueness.** Verify on the deployment database before the schema
  change; if it does not admit multiple nulls, use a generated-column or
  partial-index approach and document it.
- **Token reuse.** Reusable tokens are the product requirement; the
  mitigations in ADR-005 are structural and must all land before release,
  so the exchange endpoint, rate limiting, reduced capabilities, and manager
  revocation are in the same phase.
- **Vocabulary drift.** Applications may be tempted to add `parent`/`child`
  roles; the manager-role vocabulary validator and docs steer them to the
  built-ins plus facet permissions.

## Testing Strategy

- `storetest` conformance suites gain managed-principal cases: create with
  and without managers, remove last manager, attach email, identifier
  updates.
- `credential` tests for issue/verify/revoke of `login_token`, single-use
  behavior, expiry, and constant-time verification.
- SystemAuth handler tests for the exchange endpoint: success, each failure
  class returning an identical response, rate limiting, claim shape.
- `authz/providertest` cases for the new base relations in both providers.
- A no-opt-in regression run: both flags off, full suite green.
