# Managed Principals and Manager Relationships

This page describes managed principals as implemented in
`identity/managedprincipal`, `identity/credential` and SystemAuth
(`identity/systemauth`): what makes a principal managed, the invariants the
service enforces, the built-in manager roles, the `login_token` credential
and its exchange, the claims a managed session carries, what managers can
see and revoke, and how an email is attached. The last section lists what
ADR-009 changes that is not yet built. The user-facing guide is
[Managed Principals](../../identity/managed-principals.md).

**Decisions:**
[ADR-005](../adrs/ADR-005-managed-principals-and-manager-relationships.md)
(managed principals and manager relationships),
[ADR-009](../adrs/ADR-009-management-is-a-relationship.md)
(management is a relationship, not the absence of an email; amends
ADR-005).

## Definition as implemented

A managed principal is a `Principal(type=human)` whose `sf_humans.email` is
`NULL`. That is the test everywhere in the code today:

| Check | Where |
|---|---|
| `Service.IsManaged(principalID)` | `human.EmailIsNil()` |
| Manager authority checks (`authorizeCredentials`, `authorizeAccount`, `checkIssuer`) | Require the target to be a human with `email IS NULL` (and active) before consulting the authorizer |
| Login-token exchange (`verifyLoginToken`) | Rejects a principal whose `Email != ""` |
| `managed` claim | Emitted when the session's principal has no email |

A managed principal is created with `principal.ManagedHumanCapabilities()`
(`CanAccessUI` only: `CanManageProfile` and `CanDelegate` are false) and
`sf_principals.identifier = "human:<principal-id>"`, a lookup key rather
than an address. `signup.validateEmail` requires a plain address, so a
managed identifier can never be looked up as an email.

### Enabling

Managed principals exist only when both gates are open:

| Gate | Setting |
|---|---|
| Deployment | `systemauth` config `managed_principals.enabled` (`ManagedPrincipalsConfig.Enabled`), default off |
| Client | `sf_oauth_apps.managed_principals_enabled` or config `clients[].managed_principals`, default off |

`systemauth.Server.ManagedPrincipalsAllowed(ctx, clientID)` evaluates both
and is the `managedprincipal.Gate` the service consults; `Server.LoginTokenPolicy(ctx, clientID)` supplies lifetimes (below).

## Tables

### `sf_manager_relationships` (`identity/ent/schema/manager_relationship.go`)

| Column | Notes |
|---|---|
| `managed_principal_id` | The principal being managed; immutable |
| `manager_principal_id` | The manager; immutable |
| `role` | `guardian`, `educator`, or a role registered with `managedprincipal.WithRoles`; immutable |
| `active` | Removal deactivates rather than deletes; re-adding reactivates |
| `created_by` | The actor that established the relationship |

Unique on `(managed_principal_id, manager_principal_id, role)`.

### `sf_manager_claims` (`identity/ent/schema/manager_claim.go`)

A single-use code with which a human with an email becomes guardian of a
managed principal. Kept apart from `sf_credentials` so a claim code can
never sign anyone in.

| Column | Notes |
|---|---|
| `managed_principal_id` | The principal the claim grants guardianship of |
| `code_prefix` | `SFMC` plus 8 characters, unique, used to look the claim up |
| `code_hash` | SHA-256 of the full code (`SFMC` + 160 random bits, base32) |
| `issued_by`, `expires_at` | Issuer and expiry (`DefaultClaimTTL` 7 days, `WithClaimTTL`) |
| `redeemed_at`, `redeemed_by` | Set once; a redeemed or expired claim is refused |

### `sf_credentials` type `login_token` (`identity/ent/schema/credential.go`)

The manager-issued sign-in secret is a credential like any other:
`identifier` holds the displayable prefix (`SFLT` plus 8 characters),
`secret_hash` the SHA-256 of the token (`SFLT` + 32 random bytes, base32),
`metadata` records `issued_by` and `single_use`, and `expires_at`,
`active`, `revoked`, `revoked_at`, `revoked_reason`, `last_used_at` and
`last_used_ip` give it the standard lifecycle.

## Invariants enforced by `managedprincipal.Service`

| # | Invariant | Enforcement |
|---|---|---|
| 1 | At least one active manager at all times | `Create` refuses `len(Managers) == 0` (`ErrNoManagers`); `RemoveManager` refuses to deactivate the last active relationship of a principal without an email (`ErrLastManager`). `lockHuman` takes a row lock on the principal for the transaction so concurrent removals serialize |
| 2 | A manager is an active human with an email | `validateManager` requires `type = human`, `active`, `email IS NOT NULL`; a managed principal, having no email, cannot manage. A principal cannot manage itself |
| 3 | Both the deployment and the client allow managed principals | `Create` and `IssueLoginToken` call `Gate.ManagedPrincipalsAllowed(clientID)` and return `ErrNotAllowed` otherwise |
| 4 | A managed principal may later attach an email and become an ordinary human | `AttachVerifiedEmail` (below); afterwards `RemoveManager` may remove the last manager, and login tokens no longer sign it in |

Roles are checked against the registered set (`ErrInvalidRole`); the
built-ins are `managedprincipal.RoleGuardian` and `RoleEducator`.

## Manager roles and permissions

The platform permissions a manager holds over a principal are defined in
`authz` (`authz/manager.go`) and in the base SpiceDB schema
(`definition principal`):

| Permission | `guardian` | `educator` | Covers |
|---|---|---|---|
| `manage_account` | yes | no | Consent, deletion, billing; attaching an email |
| `manage_credentials` | yes | yes | Issuing claims; listing and revoking login tokens and sessions |
| `view_profile` | yes | yes | Reading the profile |
| `manage_managers` | yes | no | Adding and removing other managers |

`authz.ManagerRolePermissions` and `ManagerRoleAllows` mirror the schema;
the parity test keeps them equal. The role-based provider evaluates a check
on `authz.NewPrincipalResource(managedID)` through
`rbac.WithManagerRoleGetter`, for which `Service.ManagerRoles(managerID,
managedID)` is the getter; the service's default authorizer is exactly
`rbac.New(rbac.WithManagerRoleGetter(svc.ManagerRoles))`, replaceable with
`WithAuthorizer`. The relationship-based provider reads the `guardian` and
`educator` relations that `Syncer.AddPrincipalManager` writes.

Which service operations consult the authorizer:

| Operation | Permission checked |
|---|---|
| `IssueClaim`, `ListLoginTokens`, `RevokeLoginToken`, `ListSessions`, `RevokeSession`, `RevokeAll` | `manage_credentials` |
| `AttachVerifiedEmail` | `manage_account` |
| `IssueLoginToken` | None through the authorizer: `checkIssuer` requires the issuer to be an active manager of the principal, in any role |
| `Create`, `AddManager`, `RemoveManager`, `RedeemClaim` | None: the caller supplies `ActorID` for the audit trail and is expected to have checked `manage_managers` (or to be the manager creating the principal). The repository mounts no HTTP surface for these; the only handler is the visibility API below |

The service accepts `WithRoles` for application-defined manager roles, but
`authz.ManagerRolePermissions` grants nothing to them in the role-based
provider; an application maps them in its own vocabulary.

## Creating and maintaining managers

| Method | Behavior |
|---|---|
| `Create(in CreateInput)` | Requires `DisplayName`, at least one `ManagerInput{PrincipalID, Role}`, a client that allows managed principals. In one transaction validates each manager, creates `sf_principals` (identifier `human:<id>`, managed capabilities), `sf_humans` without an email, and the relationships. Emits `managed_principal.created`, then syncs `RegisterPrincipal` and `AddPrincipalManager` for each manager |
| `AddManager(managedID, m, actorID)` | Idempotent: no-op when active, reactivates when inactive; emits `managed_principal.manager_added`; syncs |
| `RemoveManager(managedID, m, actorID)` | Deactivates; refuses the last manager of a principal without an email; emits `managed_principal.manager_removed`; syncs |
| `ListManagers(managedID)` | Active relationships, oldest first |
| `IssueClaim(actorID, managedID)` | Returns the plain code once; `managed_principal.claim_issued` |
| `RedeemClaim(code, claimantID)` | Normalizes the code (case, spaces, hyphens), compares the hash in constant time, spends the claim with a conditional update so two redemptions cannot both succeed, validates the claimant as a manager, and makes them `guardian`; `managed_principal.claim_redeemed`; syncs |

Audit events go through `contract/audit.Emitter` when
`WithAuditEmitter` is set; authorization sync follows `authz.SyncMode`
(`WithAuthzSyncer`): a sync failure after the commit is returned in
`strict` mode and logged in `eventual` mode.

## Sign-in: the `login_token` credential

| Policy | Default | Source |
|---|---|---|
| Reusable token lifetime | 30 days (`credential.DefaultLoginTokenTTL`) | `managed_principals.login_token_ttl`; a client's `login_token_ttl` (`sf_oauth_apps.login_token_ttl`) overrides it |
| Ceiling | 400 days (`DefaultLoginTokenMaxTTL`) | `managed_principals.login_token_max_ttl`; longer requests are clamped and logged |
| Single-use lifetime | 20 minutes (`DefaultSingleUseLoginTokenTTL`) | `managed_principals.single_use_token_ttl` |

`Service.IssueLoginToken(in)` checks the client gate, requires the issuer to
be an active manager with an email and the subject to be an active managed
principal, resolves the expiry with `credential.LoginTokenPolicy.ExpiresAt`,
and calls `credential.Service.IssueLoginToken`, which stores the hashed
credential and returns the plain token once
(`credential.GeneratedLoginToken`). The event
`managed_principal.login_token_issued` records the prefix, expiry and
whether the lifetime was clamped. Tokens use uppercase letters and digits
so a QR code can encode them in alphanumeric mode; how an application
renders them is its own choice.

`credential.Service.VerifyLoginToken(plain, ip)` looks the token up by
prefix, compares the hash in constant time, requires it active, unrevoked
and unexpired, records `last_used_at` and `last_used_ip`, and revokes a
single-use token in the same conditional update (`revoked_reason = "used"`).
Every failure is `credential.ErrInvalidLoginToken`.

### Exchange endpoint

SystemAuth mounts `POST /login-token` (`systemauth.LoginTokenPath`) when
managed principals are enabled and a `credential.Service` is available
(`WithCredentialService`, or the Ent storage's database). It takes form
fields `token`, `client_id` and optional `return_to`, and:

1. rate-limits per source address (`DefaultLoginTokenAddressLimit`, 60 per
   minute) and per registered client (`DefaultLoginTokenClientLimit`, 600
   per minute; unregistered client IDs share one bucket), with
   `WithLoginTokenRateLimit` and `WithLoginTokenClientIP` for shared
   storage and proxy-aware addressing;
2. resolves `return_to` against the redirect allowlist;
3. requires the client to allow managed principals, verifies the token, and
   requires the principal to be active and to have no email;
4. establishes a browser login session (`sf_login_sessions` with
   `provider = login_token`) and redirects.

Every rejection is the same 401 `invalid login token`; the response never
says which condition failed.

## Claims

`GetUserClaims` adds `"managed": true` for a session whose principal has no
email, whatever scopes were granted, and omits `email` and
`email_verified`. The claim appears in the ID token and at
`/oauth/userinfo` (`systemauth.ManagedClaim`). The relying-party layer reads
it into `relyingparty.VerifiedIdentity.Managed` from either source
(`IdentityFromClaims`), and `ResolvePrincipal` creates a managed principal
locally without an email and never links one by email; the BFF reports
`managed` on the current user.

## Sessions and manager visibility

`Service.ListSessions(actorID, managedID)` returns every way the principal
is signed in now, as `managedprincipal.Session{ID, Kind, Provider,
ClientID, CreatedAt, ExpiresAt, LastUsedAt, ClientIP}`:

| Kind | Source | Revocation |
|---|---|---|
| `login` | `sf_login_sessions` (browser sessions, `provider` such as `login_token`) | Row deleted |
| `oauth` | `sf_oauth_tokens`, one entry per token family | Family marked revoked (`revoked_reason = "revoked by manager"`), so its refresh token cannot renew it |
| `principal_token` | `sf_principal_tokens`, one entry per family | Family marked revoked |

`ListLoginTokens` returns live login tokens without their values;
`RevokeLoginToken` revokes one; `RevokeSession(kind, id)` ends one session;
`RevokeAll` revokes every login token and ends every session in one
transaction. Each emits an audit event (`login_token_revoked`,
`session_revoked`, `all_revoked`). `managedprincipal.NewHandler(svc)`
exposes these as a chi router to mount behind
`requestprincipal.Middleware`, which identifies the calling manager:

```
GET    /{principalID}/login-tokens
DELETE /{principalID}/login-tokens/{credentialID}
GET    /{principalID}/sessions
DELETE /{principalID}/sessions/{kind}/{sessionID}
POST   /{principalID}/revoke-all
```

## Attaching an email

`Service.AttachVerifiedEmail(actorID, managedID, email, verifiedAt)`
requires `manage_account`, and in one transaction sets `sf_humans.email` and
`email_verified_at`, makes the email the `sf_principals.identifier`, and
restores `principal.DefaultCapabilitiesForType(human)`. A taken address is
`ErrEmailInUse`. Manager relationships are kept, and from then on all of
them may be removed; login tokens stop signing the principal in. Proving
control of the address is the caller's job (ADR-003 verification is not
wired into this step).

## Other surfaces today

| Surface | Behavior |
|---|---|
| Invites | Accepting or listing invites requires a caller with an email; a managed principal gets 403 |
| Signup and social login | Look principals up by email; a managed identifier never matches |
| Marketplace | `marketplace.PurchaserChecker` (`Service.IsManaged`) refuses checkout for managed principals |
| Deletion | No `Delete` operation exists in the service; deleting or deactivating a managed principal is done through the principal service by the application, which ADR-005 restricts to guardians and platform administrators |

## Planned changes

Accepted decisions not yet implemented. Each item names the ADR that
decides it.

### Management is a relationship (ADR-009)

- A managed principal is a human with at least one active manager
  relationship. `IsManaged`, the authority checks that today require
  `email IS NULL`, and the `managed` session claim answer from
  `sf_manager_relationships` instead of the email column. `ErrNotManaged`
  comes to mean "has no active manager".
- Email is independent of management: `Create` accepts an optional email,
  verified like any other (ADR-003) before it counts; attaching an email
  changes nothing about management; a managed principal with an email
  keeps its managers.
- Email still decides whether management may end: the last manager can be
  removed only when the principal has a verified email. `ErrLastManager`
  keeps its meaning and its wording changes to say so.
- A `release` operation removes the last manager of a principal with a
  verified email and clears the managed state in one transaction, as an
  explicit, audited event. Whether the person being released must confirm
  is the application's choice; the platform records the release.
- A managed principal may hold its own credentials when a manager allows
  it: a password, a social login linked to its email, or login tokens. The
  login-token exchange stops rejecting principals that have an email, and
  manager authority (consent, deletion, credential and session revocation)
  is unchanged by the principal signing in itself.
- Consent invitations: a new invite kind carrying a manager role, which a
  signed-in self-managed principal accepts to enter management. Creation
  by a manager remains the path for principals the manager creates.
- Managers are unchanged: an active human with a verified email that is
  not itself managed.
- Slugs for managed principals (ADR-006) keep the manager-entered or
  generated form whether or not an email exists; an email's local part is
  never used, so a handle never reveals a child's address.
- What a managed principal may do for itself is the application's
  decision, expressed in its authorization vocabulary.
