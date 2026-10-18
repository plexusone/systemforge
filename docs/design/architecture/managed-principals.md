# Managed Principals and Manager Relationships

This page describes managed principals as implemented in
`identity/managedprincipal`, `identity/credential` and SystemAuth
(`identity/systemauth`): what makes a principal managed, the invariants the
service enforces, the built-in manager roles, the `login_token` credential
and its exchange, the claims a managed session carries, what managers can
see and revoke, how an email is attached, how management ends (release),
how a self-managed human consents to be managed (manager invitations), and
how a managed principal's slug is chosen. The user-facing guide is
[Managed Principals](../../identity/managed-principals.md).

**Decisions:**
[ADR-005](../adrs/ADR-005-managed-principals-and-manager-relationships.md)
(managed principals and manager relationships),
[ADR-009](../adrs/ADR-009-management-is-a-relationship.md)
(management is a relationship, not the absence of an email; amends
ADR-005),
[ADR-006](../adrs/ADR-006-organization-lifecycle-personal-team-slugs.md)
(how a managed principal's slug is chosen),
[ADR-010](../adrs/ADR-010-real-time-access-invalidation.md)
(access changes recorded when management starts or ends).

## Definition as implemented

A managed principal is a `Principal(type=human)` with at least one active
row in `sf_manager_relationships` as the managed side (ADR-009). The email
plays no part: a managed principal may have none, an unverified one, or a
verified one. That is the test everywhere in the code:

| Check | Where |
|---|---|
| `Service.IsManaged(principalID)` | An active manager relationship exists (`hasActiveManager`) |
| Manager authority checks (`authorizeCredentials`, `authorizeAccount`, `checkIssuer`) | Require the target to be an active human with an active manager relationship before consulting the authorizer; otherwise `ErrNotManaged` |
| Login-token exchange (`verifyLoginToken`) | Requires the principal to be active and `HumanPrincipal.Managed`; an email does not matter |
| `managed` claim | Emitted when the session's principal has an active manager relationship (`HumanPrincipal.Managed`, loaded with the principal) |

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

### `sf_manager_invites` (`identity/ent/schema/manager_invite.go`)

A single-use invitation with which a human with a verified email offers to
manage a self-managed human. Kept apart from organization invites
(`sf_invites`), which grant membership rather than authority over a person.

| Column | Notes |
|---|---|
| `manager_principal_id` | The inviter, who becomes a manager on acceptance |
| `email` | Verified address of the invited human; only a principal whose verified email matches (case-insensitive) can accept |
| `role` | The manager role the inviter will hold |
| `token_prefix`, `token_hash` | `SFMI` plus 8 characters, unique, used to look it up; SHA-256 of the full token (`SFMI` + 160 random bits, base32) |
| `expires_at` | `DefaultInviteTTL` 7 days, `WithInviteTTL` |
| `accepted_at`, `accepted_by`, `revoked_at`, `declined_at`, `declined_by` | Set once; an accepted, revoked, declined or expired invitation is refused |

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
| 1 | At least one active manager unless the principal has a verified email | `Create` refuses `len(Managers) == 0` (`ErrNoManagers`); `RemoveManager` refuses to deactivate the last active relationship of a principal whose email is missing or unverified (`ErrLastManager`). `lockHuman` takes a row lock on the principal for the transaction so concurrent removals serialize |
| 2 | A manager is an active human with an email | `validateManager` requires `type = human`, `active`, `email IS NOT NULL`; a managed principal, having no email, cannot manage. A principal cannot manage itself |
| 3 | Both the deployment and the client allow managed principals | `Create` and `IssueLoginToken` call `Gate.ManagedPrincipalsAllowed(clientID)` and return `ErrNotAllowed` otherwise |
| 4 | Email is independent of management, but decides whether management may end | A managed principal may have an email from `Create` or `AttachVerifiedEmail` and keeps its managers and managed capabilities. Once the email is verified (`VerifyEmail`, or attached verified), `RemoveManager` may remove the last manager; with no active manager the principal is no longer managed and login tokens stop signing it in |
| 5 | A principal with no manager cannot be given one by a manager | `AddManager` and `RedeemClaim` return `ErrNotManaged` for a principal with no active manager: entering management takes the principal's own consent (`AcceptManagerInvite`, below) |
| 6 | A managed principal is never a manager | `validateManager` also requires the candidate to have no active manager of its own, whether or not it has an email; accepting an invitation is refused with `ErrManagesOthers` for a principal that manages others |

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
| `AttachVerifiedEmail`, `Delete` | `manage_account` |
| `AddManager`, `RemoveManager`, `Release` | `manage_managers` |
| `ListManagersFor` | `view_profile` |
| `IssueLoginToken` | None through the authorizer: `checkIssuer` requires the issuer to be an active manager of the principal, in any role |
| `Create` | No principal exists to check a permission against, so the actor must be one of the managers being named (the manager creating the principal) or a platform administrator (`authz.PlatformAuthorizer.IsPlatformAdmin`); otherwise `ErrForbidden`. A missing actor is refused |
| `RedeemClaim` | The claim carries its issuer's authority: redemption is refused (`ErrInvalidClaim`) unless the issuer still holds `manage_credentials` on the principal, so removing a manager withdraws the claims they issued. The claimant must be a valid manager |
| `InviteManager` | The inviter must be a valid manager and the client must allow managed principals; consent is given by the invitee in `AcceptManagerInvite`, which checks the principal's own verified email, not a permission |

The service accepts `WithRoles` for application-defined manager roles, but
`authz.ManagerRolePermissions` grants nothing to them in the role-based
provider; an application maps them in its own vocabulary.

## Creating and maintaining managers

| Method | Behavior |
|---|---|
| `Create(in CreateInput)` | Requires `DisplayName`, at least one `ManagerInput{PrincipalID, Role}`, a client that allows managed principals. In one transaction validates each manager, creates `sf_principals` (identifier `human:<id>`, managed capabilities), `sf_humans`, and the relationships. `CreateInput.Email` is optional: when set it is stored unverified, becomes the identifier, and `ErrEmailInUse` refuses a taken address. Emits `managed_principal.created`, then syncs `RegisterPrincipal` and `AddPrincipalManager` for each manager |
| `AddManager(managedID, m, actorID)` | Needs `manage_managers`, checked under the principal's row lock in the writing transaction. Idempotent: no-op when active, reactivates when inactive; emits `managed_principal.manager_added`; syncs |
| `RemoveManager(managedID, m, actorID)` | Needs `manage_managers`, checked under the principal's row lock in the writing transaction. Deactivates; refuses the last manager of a principal without a verified email (`ErrLastManager`); emits `managed_principal.manager_removed`; syncs |
| `ListManagers(managedID)` | Active relationships, oldest first; unchecked, for callers that already hold authority. `ListManagersFor(actorID, managedID)` checks `view_profile` |
| `Delete(actorID, managedID)` | Needs `manage_account`. Soft delete with erasure in one transaction: the principal is deactivated, its identifier becomes `deleted:<id>` and its display name "Deleted account"; email, verification, names and avatar are cleared (freeing the address); credentials, external identities, login sessions, OAuth consents and claims are deleted; OAuth and principal token families are revoked; memberships and manager relationships are deactivated; pending manager invitations to its address are withdrawn; an access change `deactivated` is recorded and announced (ADR-010); the authorization backend loses its relations and the principal. `managed_principal.deleted`. The row stays so identifiers elsewhere keep resolving; application data and any personal organization are the application's to remove |
| `Release(actorID, managedID)` | Ends management of a principal with a verified email: deactivates every remaining relationship, restores `DefaultCapabilitiesForType(human)` and records an access change (`management_ended`), in one transaction. Needs `manage_managers`, checked under the principal's row lock; `ErrEmailNotVerified` without a verified email; `managed_principal.released`; syncs each removal. `RemoveManager` of the last manager of a verified principal does the same |
| `InviteManager(in)` | A manager-to-be offers to manage the human with a verified `Email`. Needs a client that allows managed principals and a valid manager; returns the token once; `managed_principal.manager_invited` |
| `AcceptManagerInvite(token, principalID)` | The signed-in principal's consent. Spends the invitation conditionally, creates the relationship, sets `ManagedHumanCapabilities`, records an access change (`management_granted`), `managed_principal.manager_invite_accepted`, syncs. `ErrInvalidInvite` for any mismatch, `ErrAlreadyManaged`, `ErrManagesOthers` |
| `DeclineManagerInvite(token, principalID)` | The invitee's refusal, with the same identity match as acceptance (an active principal whose verified email is the invited address; `ErrInvalidInvite` for any mismatch, unknown, expired, revoked, accepted or already declined token). Single use: it marks the invitation declined (`declined_at`, `declined_by`) conditionally, so a concurrent acceptance or decline wins exactly once, and a declined invitation can be neither accepted nor revoked. Touches no relationship, capability or access change. `managed_principal.manager_invite_declined`, whose details carry the inviter and the invitation, is the inviter's notification: the service sends none itself, so the application delivers it |
| `RevokeManagerInvite(actorID, inviteID)` | The inviter withdraws a pending invitation; `ErrNotFound` otherwise, including after the invitee accepted or declined |
| `VerifyEmail(managedID, verifiedAt)` | Records that the principal controls the email it was created with; called by the verification flow, not by a manager. `managed_principal.email_verified` |
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
   requires the principal to be active and managed (an email does not
   matter);
4. establishes a browser login session (`sf_login_sessions` with
   `provider = login_token`) and redirects.

Every rejection is the same 401 `invalid login token`; the response never
says which condition failed.

## Claims

`GetUserClaims` adds `"managed": true` for a session whose principal has an
active manager, whatever scopes were granted; `email` and `email_verified`
appear only when the principal has an email and the `email` scope is
granted. The claim appears in the ID token and at
`/oauth/userinfo` (`systemauth.ManagedClaim`). The relying-party layer reads
it into `relyingparty.VerifiedIdentity.Managed` from either source
(`IdentityFromClaims`), and `ResolvePrincipal` creates a managed principal
locally, with the email when the claims carry one but never linking by
email; the BFF reports
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
exposes these and the managing operations as a chi router to mount behind
`requestprincipal.Middleware`, which identifies the calling principal. The
caller is always the actor; every route runs the service operation and so
its authorizer check:

```
GET    /                                          ListManagedBy (?after=&limit=, at most 200)
POST   /                                          Create (JSON: client_id, display_name, email?, managers[] or role)
GET    /{principalID}/managers                    ListManagersFor
POST   /{principalID}/managers                    AddManager (JSON: principal_id, role)
DELETE /{principalID}/managers/{managerID}/{role} RemoveManager
POST   /{principalID}/release                     Release
DELETE /{principalID}                             Delete
POST   /{principalID}/claims                      IssueClaim
POST   /claims/redeem                             RedeemClaim (JSON: code)
POST   /manager-invites                           InviteManager (JSON: client_id, email, role)
POST   /manager-invites/accept                    AcceptManagerInvite (JSON: token)
POST   /manager-invites/decline                   DeclineManagerInvite (JSON: token); 204, 400 for any mismatch
DELETE /manager-invites/{inviteID}                RevokeManagerInvite
GET    /{principalID}/login-tokens
POST   /{principalID}/login-tokens                IssueLoginToken (JSON: client_id, name?, single_use?, expires_at?)
DELETE /{principalID}/login-tokens/{credentialID}
GET    /{principalID}/sessions
DELETE /{principalID}/sessions/{kind}/{sessionID}
POST   /{principalID}/revoke-all
```

Responses: 401 without a principal, 403 for a missing permission (or a
client that does not allow managed principals), 404 for an unknown or
unmanaged principal, 400 for malformed input or any unusable code, 409 for
conflicts (`ErrLastManager`, `ErrEmailInUse`, `ErrEmailNotVerified`,
`ErrAlreadyManaged`). Bodies are bounded and refuse unknown fields.
`client_id` in a create, invite or login-token body is the caller's
assertion; the deployment and that client's opt-in still gate it
(`ManagedPrincipalsAllowed`).

In relying-party mode (`WithRequestClient`), which `systemauthsvc` uses to
serve the API on SystemAuth, the client is the authenticated access token's
and a different body `client_id` is a 400; create names only the caller as
manager; `POST /{principalID}/managers` is refused (managers join through
invitations and claims); and an unknown or unmanaged principal answers 403,
like a principal the caller does not manage. `WithCodeRateLimit` adds a
per-caller 429 on the routes that present a code.

## Attaching an email

`Service.AttachVerifiedEmail(actorID, managedID, email, verifiedAt)`
requires `manage_account`, and in one transaction sets `sf_humans.email` and
`email_verified_at` on a managed principal that has no email, and makes the
email the `sf_principals.identifier`. Management is unchanged (ADR-009):
the relationships and the managed capabilities stay, and the verified email
is what allows the last manager to be removed. A taken address is
`ErrEmailInUse`; a principal that already has an email is `ErrHasEmail`.
Proving control of the address is the caller's job (ADR-003 verification is
not wired into this step). A principal created with an unverified email is
verified with `Service.VerifyEmail` instead.

## Other surfaces today

| Surface | Behavior |
|---|---|
| Invites | Accepting or listing invites requires a caller with an email; a managed principal gets 403 |
| Signup and social login | Look principals up by email; a managed identifier never matches |
| Marketplace | `marketplace.PurchaserChecker` (`Service.IsManaged`) refuses checkout for managed principals |
| Deletion | `Service.Delete` (above), restricted by `manage_account` to guardians, which ADR-005 requires |

## Releasing a principal

Management ends only for a principal that can be reached and has proven it
controls its address (ADR-009). `Release` and the removal of the last
manager of such a principal are the same event: the relationships are
deactivated and the human capabilities that management withheld
(`CanManageProfile`, `CanDelegate`) are restored in the transaction, and
`managed_principal.released` is emitted. The platform records the release;
whether the person must confirm first is the application's decision. Once
released the principal is self-managed: managers lose their authority, the
`managed` claim is no longer emitted, login tokens stop signing it in, and
re-entering management takes a new invitation.

## Manager invitations

A manager relationship with an existing principal gives up control of its
own profile, so it is created only by that principal accepting an
invitation while signed in (`AcceptManagerInvite`). The caller passes its
own authenticated principal ID, and the invitation matches only when the
principal's verified email is the invited address, so a leaked token alone
does not enter anyone into management. The invitee may instead decline
(`DeclineManagerInvite`), with the same identity match: the invitation is
then spent, the inviter cannot withdraw it and nothing about the invitee
changes. Creation by a manager (`Create`,
`RedeemClaim`) remains the path for principals the manager creates or
whose guardian claims them. How the token is delivered (email, link, QR)
is the application's choice.

## Slugs

A managed principal's personal organization (ADR-006) is never slugged from
an email. `signup.SlugForManaged` produces the manager-entered value or a
generated `adjective-noun-NN`; SystemAuth uses it, with the managers'
display name and no provider avatar, when a managed principal signs in with
an email of its own (`personalOrgParamsFor`). A handle therefore never
reveals a child's address.

## What a managed principal may do for itself

That is the application's decision, expressed in its authorization
vocabulary (ADR-009 decision 7): the platform supplies the relationship,
the roles and the `managed` claim. A managed principal may hold its own
credentials (a password, a social login linked to its email, login
tokens); manager authority (consent, deletion, credential and session
revocation) is unchanged by the principal signing in itself.
