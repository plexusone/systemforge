# Organizations and Membership

This page describes how SystemForge models organizations, who belongs to
them, how people get in, what an organization is entitled to, and how a
relying party learns a principal's memberships. The first part describes the
system as implemented in `identity/organization`, `identity/invite`,
`identity/signup`, `identity/systemauth`, `identity/relyingparty` and
`marketplace`; the last section lists what the accepted decisions change
that is not yet built.

**Decisions:**
[ADR-006](../adrs/ADR-006-organization-lifecycle-personal-team-slugs.md)
(lifecycle, personal and team organizations, slugs, removal of `plan`),
[ADR-007](../adrs/ADR-007-memberships-and-entitlements-as-claims.md)
(memberships and entitlements as claims),
[ADR-010](../adrs/ADR-010-real-time-access-invalidation.md)
(real-time invalidation of access),
[ADR-002](../adrs/ADR-002-centralized-social-login-systemauth.md)
(account linking at login).

## Organization

An organization is a tenant. Every principal-scoped record in a SystemForge
application hangs off one, and a person's own namespace is itself an
organization of type `personal`.

### Table `sf_organizations` (`identity/ent/schema/organization.go`)

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | Primary key |
| `name` | string | Display name; required (`NotEmpty`) |
| `slug` | string | Unique URL-safe identifier; `^[a-z][a-z0-9-]*[a-z0-9]$`, 3–63 characters (`organization.isValidSlug`) |
| `org_type` | enum `personal`, `team`, `enterprise` | Default `team` |
| `owner_principal_id` | UUID, nullable | The owning principal; required for `personal`, set by the API for every organization it creates |
| `logo_url`, `description`, `website_url` | string, nullable | Cosmetic |
| `settings` | JSON object | Application-specific configuration |
| `plan` | enum `free`, `starter`, `pro`, `enterprise` | Default `free`; see [The `plan` column](#the-plan-column) |
| `active` | bool | `Delete` sets it to `false` (soft delete) |

Edges: `principal_memberships`, `invites`, `oauth_apps`, marketplace
`listings`, `licenses` and a single `subscription`.

### Types

| Kind | Go constant | Meaning today |
|---|---|---|
| `personal` | `organization.OrgTypePersonal` | A person's own namespace, created by `signup`; `Organization.IsPersonal()` |
| `team` | `organization.OrgTypeTeam` | A shared organization; the default |
| `enterprise` | `organization.OrgTypeEnterprise` | A large organization; no behavioral difference from `team` in code |

Nothing in the service distinguishes the types beyond creation: a personal
organization requires an owner (`Create` refuses one without
`OwnerPrincipalID`), and `GetPersonalOrg(principalID)` finds it by
`org_type = personal AND owner_principal_id = principalID`.

### Slug is the identity

The slug is how an organization is addressed: every organization and
membership endpoint is keyed by it (`/organizations/{slug}`,
`/organizations/{slug}/members/...`, `/organizations/{slug}/invites/...`),
and `GetBySlug` is the lookup the API uses. The display name is cosmetic and
carries no identity. The slug is unique across every organization type, so
personal and team organizations share one namespace.

Today the slug is set once at creation and cannot be changed:
`UpdateOrganizationInput` has no slug field and `PATCH /organizations/{slug}`
accepts only `name`, `logo_url`, `description`, `website_url`, `plan` and
`settings`. `SlugAvailable(slug)` is an existence check on
`sf_organizations.slug`; `GenerateSlug(name)` slugifies the name
(lowercase, spaces and underscores to hyphens, other characters dropped,
`-org` appended below three characters) and appends `-1` to `-100`, then an
eight-character UUID fragment, until one is free.

### Service (`identity/organization`)

`organization.Service` is implemented by `DefaultService` over Ent, with an
`authz.RelationshipSyncer` (default `noop`) and an `authz.SyncMode`
(`strict` fails the call on a sync error after the database commit;
`eventual`, the default, logs it).

| Method | Behavior |
|---|---|
| `Create(input)` | Validates and reserves the slug; creates the organization and, when an owner is given, an `owner` membership in one transaction; then `syncer.RegisterOrganization(orgID, ownerID)` |
| `CreatePersonalOrg(input)` | `Create` with `org_type = personal`, the owner, and `plan = free` |
| `GetByID`, `GetBySlug`, `GetPersonalOrg` | Lookups |
| `Update(id, input)` | Name, logo, description, website, settings, plan; never the slug or type |
| `Delete(id)` | Sets `active = false`; `syncer.UnregisterOrganization` |
| `List(input)` | Filters: `OrgType`, `Plan`, `Active`, `MemberPrincipalID` (active memberships only), limit and offset |
| `TransferOwnership(input)` | See [Ownership transfer](#ownership-transfer) |
| `SlugAvailable`, `GenerateSlug` | See above |

### HTTP API (`identity/organization` handlers, huma over chi)

The organization API requires an `authz.Authorizer`; until one is
configured every endpoint except `createOrganization` and
`checkSlugAvailability` answers 501. The caller is resolved by
`requestprincipal.PrincipalUUID` (configurable through `APIConfig.Caller`).
`orgFor` loads the organization by slug and checks the operation's
permission; a caller who cannot even `view` the organization gets 404, so
its existence is not confirmed to outsiders.

| Operation | Route | Permission (`authz`) |
|---|---|---|
| `createOrganization` | `POST /organizations` | Any authenticated principal; the caller becomes the owner. Default `org_type = team`, default `plan = free` |
| `getOrganization` | `GET /organizations/{slug}` | `view` |
| `updateOrganization` | `PATCH /organizations/{slug}` | `settings` |
| `deleteOrganization` | `DELETE /organizations/{slug}` | `delete` (owner only) |
| `listOrganizations` | `GET /organizations` | The caller's own memberships, or every organization for a platform admin |
| `checkSlugAvailability` | `GET /organizations/check-slug/{slug}` | None |

## Memberships

### Table `sf_principal_memberships` (`identity/ent/schema/principal_membership.go`)

| Column | Type | Notes |
|---|---|---|
| `principal_id`, `organization_id` | UUID | Unique together: one membership per principal per organization |
| `role` | string | Free-form; the package defines `RoleOwner`, `RoleAdmin`, `RoleMember` (`owner`, `admin`, `member`); the API's role enums are `owner,admin,member` |
| `permissions` | JSON string array | Optional per-membership permissions; stored and returned, not evaluated by the providers |
| `active` | bool | Deactivated memberships are kept and excluded from listings unless `organization.IncludeInactive()` is passed |

Any principal type can hold a membership. The owner's membership is created
with the organization; there is no separate "owner" flag on the membership,
only `role = owner` plus `sf_organizations.owner_principal_id`.

### Service methods

| Method | Behavior |
|---|---|
| `AddMember(input)` | Refuses when a membership (active or not) exists; creates it active; `syncer.AddOrgMembership(principal, org, role)` |
| `UpdateMember(membershipID, input)` | Role, permissions, active; a role change calls `syncer.UpdateOrgMembership(old, new)` |
| `RemoveMember(orgID, principalID)` | Deletes the row; `syncer.RemoveOrgMembership` |
| `GetMembership(orgID, principalID)` | Returns the row whatever its `active` value, or `ErrMembershipNotFound` |
| `ListMembers(orgID)`, `ListMemberships(principalID)` | Active rows by default |

`organization.MembershipRoleGetter(svc)` adapts `GetMembership` to
`rbac.WithRoleGetter`: an inactive or missing membership has no role.

### Member endpoints

| Operation | Route | Rule |
|---|---|---|
| `listMembers`, `getMember` | `GET /organizations/{slug}/members[/{principal_id}]` | `view` |
| `addMember` | `POST /organizations/{slug}/members` | `invite_member`; granting `owner` additionally needs the owner-only permission (`delete`) |
| `updateMember` | `PATCH /organizations/{slug}/members/{principal_id}` | `change_role`; touching an owner's role, or granting `owner`, needs the owner-only permission; deactivating needs `remove_member` |
| `removeMember` | `DELETE /organizations/{slug}/members/{principal_id}` | A member may remove themself with `view`; removing someone else needs `remove_member`, and removing the owner needs the owner-only permission |
| `transferOwnership` | `POST /organizations/{slug}/transfer-ownership` | `delete`, and the caller must be `owner_principal_id` |

### Ownership transfer

`TransferOwnership` requires the current owner's membership to have
`role = owner` and the new owner to already be a member. In one transaction
it sets the old owner's role to `NewRoleForOld` (`admin` by default; only
`admin` or `member` are accepted), sets the new owner's role to `owner`, and
updates `owner_principal_id`. Both role changes are then synced. There is no
type check: a personal organization can be transferred today.

## Invites

### Table `sf_invites` (`identity/ent/schema/invite.go`)

| Column | Notes |
|---|---|
| `organization_id`, `inviter_principal_id` | Who invited, to where |
| `email` | The invitee; the invite is bound to this address |
| `role` | Role granted on acceptance; default `member`; the API accepts `owner`, `admin`, `member` |
| `token` | Hex SHA-256 of the URL token (32 random bytes, base64url); the token itself is never stored |
| `status` | `pending`, `accepted`, `declined`, `expired`, `revoked` |
| `message`, `expires_at`, `accepted_at`, `accepted_by_principal_id`, `resend_count`, `last_sent_at` | Lifecycle |

### Service (`identity/invite`)

| Method | Behavior |
|---|---|
| `Create(input)` | Refuses when a pending, unexpired invite exists for the same organization and email; default expiry `invite.DefaultInviteExpiry` (7 days); returns the one-time `InviteURL` (`{baseURL}/invites/{token}`) |
| `GetByToken`, `GetByID`, `List`, `ListPendingForEmail`, `HasPendingInvite` | Lookups; email matching is case-insensitive |
| `Accept(input)` | Requires `pending` and unexpired (an expired one is marked `expired`); in one transaction refuses an existing membership, creates the membership with the invite's role, and marks the invite accepted. It writes the membership directly and does not call the organization service, so no `RelationshipSyncer` call is made for memberships created by acceptance |
| `Decline(token)`, `Revoke(id)` | Status changes |
| `Resend(id)` | New token, `resend_count + 1`, expiry reset to 7 days |
| `ExpireOld()` | Batch status update |

### Invite endpoints

Organization-side routes (`POST`/`GET /organizations/{slug}/invites`,
`DELETE .../{invite_id}`, `POST .../{invite_id}/resend`) need
`invite_member`; inviting an `owner` needs the owner-only permission, and
`inviter_principal_id` must be the caller. Invitee-side routes
(`GET /invites/{token}`, `POST /invites/{token}/accept`, `POST
/invites/{token}/decline`, `GET /invites`) require the caller to have an
email that matches the invite's address; a principal without an email (a
managed principal) gets 403, and a mismatched invite answers 404. Signing up
through an invite (`signup.SignupWithInvite`) applies the same match
(`signup.ErrInviteEmailMismatch`).

## Signup (`identity/signup`)

`signup.Service` creates a person and their personal organization:

| Method | Behavior |
|---|---|
| `Signup(input)` | Requires a plain email, a display name and `PersonalOrgSlug`; refuses a taken email (`ErrEmailTaken`) or slug; creates the human principal with `AllowedScopes` `openid profile email`, then the personal organization (name defaults to the display name, logo to the avatar). The two writes are separate transactions; a failure after the principal exists deletes it again |
| `SignupWithInvite(input)` | `Signup`, then `invite.Accept` for the invite (email must match) |
| `SignupOrGetExisting(input)` | Returns the existing principal and personal organization for an email only when `EmailVerified` is set (`ErrEmailNotVerified` otherwise); creates them otherwise |

### Signup on first social login

GitHub and Google login (`systemauth.ResolveExternalLogin`, ADR-002,
ADR-006 decision 1) resolve a principal by `(provider, subject)` first, then
link by a verified email to an existing principal whose own email is
verified, and otherwise create one. An unverified email never links to or
creates an account (`ErrEmailNotVerified`, nothing written).

The create step does not call `signup.Service`, whose principal and
organization services each commit their own transaction. Instead
`EntPrincipalDirectory.CreateFromExternal` opens one Ent transaction and
writes the principal, its `sf_humans` row, the `sf_external_identities` link,
and, through `signup.CreatePersonalOrgInTx`, a personal organization (type
`personal`, owner set, name = display name, else provider username, else
email local part, logo = avatar) with an active `owner` membership. A failure
at any step rolls all of it back. The organization is not registered with an
authorization syncer: the directory has none, as it had none for the
principal.

- **Slug.** `signup.SlugForLogin(provider, username, email)` returns the
  GitHub username for `github`, the email local part for `google`, and the
  username (else the local part) for any other provider, normalized to a valid
  slug. If that slug is taken, `-1` to `-100` and then an eight-character
  random suffix are tried inside the transaction. Managed principals and
  reserved slugs are not handled yet (see Planned changes).
- **Races.** Two first logins of the same identity race on the unique
  `(provider, subject)` constraint; the loser's transaction rolls back and
  `ResolveExternalLogin` re-reads the winner. A lost race for the slug alone
  retries the transaction (up to three times).
- **Backfill.** After every successful login `ResolveExternalLogin` calls
  `EnsurePersonalOrg` (the optional `systemauth.PersonalOrgEnsurer`, which
  `EntPrincipalDirectory` implements). A principal that has no personal
  organization, such as one created before this behavior or linked by verified
  email, gets one in its own transaction; a principal that has one is left
  untouched, so repeat logins create nothing. `MemoryPrincipalDirectory` keeps
  no organizations.
- `signup.SignupOrGetExisting` is unchanged and still resolves by email only;
  social login does not use it.

## The `plan` column

`sf_organizations.plan` is set at creation (`free` by default from the API,
`CreatePersonalOrg` and SCIM group provisioning), changed by
`PATCH /organizations/{slug}`, used as a `List` filter, and returned as
`plan` in `OrgResponse`. No code reads it to decide what an organization may
use. ADR-006 removes it, together with the `organization.Plan*` constants
and the `plan` field in the API; see
[Planned changes](#planned-changes).

## Entitlements via the marketplace

What an organization may use is recorded by `marketplace`, not by the
organization:

| Table | Purpose | Key columns |
|---|---|---|
| `sf_listings` | A product offered by a creator organization | `creator_org_id`, `owner_id`, `product_type`, `product_id`, `pricing_model` (`free`, `one_time`, `subscription`, `per_seat`), `price_cents`, `currency`, `status` (`draft`, `pending_review`, `published`, `archived`) |
| `sf_licenses` | An organization's right to a listing | `listing_id`, `organization_id`, `license_type` (`seat_based`, `team`, `unlimited`), `seats`, `used_seats`, `valid_from`, `valid_until`, `stripe_subscription_id`, `purchased_by` |
| `sf_seat_assignments` | A seat of a license given to a principal | `license_id`, `principal_id`, `assigned_by`, `assigned_at` |
| `sf_subscriptions` | One platform subscription per organization (unique edge) | `organization_id`, `plan_tier` (`free`, `starter`, `pro`, `enterprise`), `status` (`active`, `trialing`, `past_due`, `canceled`, `unpaid`), `current_period_start/end`, `cancel_at_period_end`, Stripe IDs |

Services: `marketplace.ListingService` (create, publish, archive, list),
`LicenseService` (`Grant`, `Revoke`, `Check(listingID, orgID)` for a valid
license, `CheckPrincipal(listingID, principalID)` which passes any valid
`unlimited` license outright and otherwise requires a seat assignment,
`AssignSeat`/`UnassignSeat`), `SubscriptionService` (`GetByOrg`,
`IsActive`, `GetPlanTier`, `ChangePlan`, `Cancel`, `CancelImmediately`,
`Reactivate`) and `CheckoutService` (Stripe). Tiers are a property of the
organization's subscription, not of a listing. The
`marketplace.PurchaserChecker` (implemented by
`managedprincipal.Service.IsManaged`) refuses checkout for managed
principals. `marketplace.SpiceDBSyncer` writes listing, license, seat and
subscription relationships for the relationship-based provider
(`creator_org`, `owner`, `licensed_org`, `listing`, `purchased_by`,
`seat_holder`, `subscriber`).

Nothing today turns subscriptions and licenses into a per-application
entitlement list, and `authz.FeatureAuthorizer` is an interface with no
implementation in the repository.

## How relying parties get memberships today

A relying party (`identity/relyingparty`) authenticates a SystemAuth session,
access token or API key and attaches memberships to the request through a
`MembershipSource`:

```go
type MembershipSource interface {
    Memberships(ctx context.Context, q MembershipQuery) ([]Membership, error)
}
```

`MembershipQuery` carries the app-local `Principal`, the SystemAuth
`Subject` and, for sessions and JWT access tokens, the verified `Claims`.
The default (`defaultMembershipSource`) is `LocalMemberships` over the
application's `PrincipalStore` when it also implements `MembershipLister`,
otherwise `NoMemberships`. `relyingparty.Membership` is `{ID,
OrganizationID, OrganizationName, OrganizationSlug, Role, JoinedAt}`;
`BearerMiddleware`, `RequestAuthenticator` and the BFF's `CurrentSession`
all go through the source, and the BFF's `GET /bff/api/v1/users/me`
returns the result as `memberships`. In short: memberships are an app-local table per relying
party, keyed by the application's own organization IDs.

## The claims model

SystemAuth's claims come from `SessionProvider.GetUserClaims`, which feeds
both the ID token (`OIDCSession` puts them in `Extra`) and `/oauth/userinfo`
(filtered by `UserInfoClaims` to the granted scopes). For a principal
signed in through social login or a login token they are:

| Claim | When |
|---|---|
| `sub` | Always; the SystemAuth principal ID, which relying parties store as `sf_principal_id` |
| `managed: true` | The human has no email (a managed principal); emitted whatever the scopes |
| `email`, `email_verified` | `email` scope, and only when the principal has an email |
| `name`, `picture` | `profile` scope |

No organization, role or entitlement claim is emitted. Access tokens are
JWTs (`relyingparty.AccessTokenVerifier` yields `Subject`, `ClientID`,
`Scopes` and the raw claims); they carry no memberships either.

## Token freshness and revocation

| Setting | Default | Where |
|---|---|---|
| Access token lifetime | 15 minutes | `systemauth` config `tokens.access_token_lifetime`; per client `access_token_lifetime`; `sf_oauth_apps.access_token_ttl` (900 s) |
| Refresh token lifetime | 7 days (absolute lifetime 30 days) | `tokens.refresh_token_lifetime`, `refresh_token_absolute_lifetime` |
| ID token lifetime | 1 hour | `tokens.id_token_lifetime` |

Revocation today is by principal status, not by membership: every
introspection, userinfo call and refresh runs `Server.requireActiveSubject`,
which asks `PrincipalStatus.PrincipalActive(subject)` (implemented by the
Ent and memory stores); a deactivated principal's token family is revoked
and the token reported inactive. Removing a principal from an organization
or changing their role does nothing to their tokens, and no relying-party
revocation cache exists. The relying-party `SessionStore` can delete BFF
sessions by SystemAuth session ID or subject, which is the hook back-channel
logout would use.

## Planned changes

Accepted decisions not yet implemented. Each item names the ADR that
decides it.

### Lifecycle and slugs (ADR-006)

- Slug derivation for a managed principal (a manager-entered slug, or a
  generated one such as two words and a number, ADR-006 decision 2). The
  GitHub and Google rules and the numeric suffix on collision are implemented
  (see [Signup on first social login](#signup-on-first-social-login)).
- Personal organizations have exactly one member: `AddMember` and invites
  to a personal organization are refused (except collaborators, ADR-008),
  and `TransferOwnership` of a personal organization is refused. Today none
  of these checks exist.
- `organization.Service.Rename(ctx, orgID, slug)`,
  `ConvertToTeam(ctx, orgID, teamSlug)` and `ResolveSlug(ctx, slug)`, backed
  by a new `sf_slug_reservations` table (slug, `released_by_principal_id`,
  `released_from_organization_id`, `released_at`, `expires_at`): a freed
  slug is reserved for 7 days for the principal that gave it up (or an
  organization it owns), resolves to its previous organization as an alias
  meanwhile, and then becomes free. `SlugAvailable` and `GetBySlug` consult
  the table.
- `ConvertToTeam` keeps the organization's ID, data and memberships, sets
  the type to `team`, gives it the chosen free slug, and creates a new
  personal organization for the owner under their handle.
- The `plan` column, `organization.Plan*`, and the `plan` field in create,
  update, list filter and responses (and SCIM's default) are removed;
  entitlements are derived from the marketplace and exposed as an
  `entitlements` summary. Note that ADR-006 speaks of listings with tiers,
  while today tiers (`plan_tier`) live on the single per-organization
  subscription and listings have none; the mapping from subscriptions and
  licenses to per-application entitlements is part of this change.

### Planned, not yet decided by an ADR

- The display name becomes optional and defaults to the slug (today
  `name` is required).
- Reserved slugs: names the shell needs as path segments (`admin`, `api`,
  `o`, `login`, product names) are refused for organizations.

### Memberships and entitlements as claims (ADR-007)

- SystemAuth emits an `orgs` claim in the ID token and at userinfo: a list of
  `{id, slug, name, type, role, apps}` where `apps` maps application
  identifier to the principal's application role; the JWT access token
  carries the compact `{id, role, apps}` form; at most 50 organizations,
  personal first, with `orgs_truncated: true` when any were omitted.
- `GET /userinfo/memberships` returns the full, paginated list.
- `relyingparty` gains `ClaimsMemberships` (default) and
  `RemoteMemberships`; `LocalMemberships` remains for development and tests
  and is documented as not for production.
- Organization roles are `owner`, `admin`, `member` and `collaborator`
  (ADR-008); application roles are recorded per (principal, organization,
  application) in a new `sf_app_roles` table, which replaces seat
  assignments as the record of who may use what. Owners hold `admin` in
  every entitled application implicitly; admins and members hold only the
  roles assigned to them, none by default; no custom roles.
- Entitlements are derived from active subscriptions and licenses mapped to
  application identifiers registered through `authz.AppVocabulary`, with
  deployment-level default entitlements.
- Invites carry the application roles to grant; removal from the
  organization removes every application role and grant.

### Real-time invalidation (ADR-010)

- The default access-token lifetime becomes 10 minutes, configurable up to
  15; today the default is 15 minutes and no maximum is enforced.
- SystemAuth records every access change (membership removal or role
  change, application-role or grant change, deactivation, session
  revocation, a manager revoking a managed principal's sessions) in a new
  `sf_access_changes` table as `(principal_id, organization_id or null,
  changed_at, reason)` and announces it.
- Relying parties keep a revocation cache keyed by principal (and
  organization) and reject tokens issued before the change, after a
  clock-skew margin (30 s default, 15 s floor); the cache is shared memory
  in a modular monolith, polled from `sf_access_changes` across replicas,
  and delivered as an OIDC back-channel `access_change` event across
  deployments, all in `relyingparty`.
- A membership or role change no longer revokes refresh tokens (ADR-007
  decision 9 is amended): the next refresh issues reduced claims. Only
  deactivation and explicit session revocation revoke refresh tokens.
- `GET /access-changes?since=` lets a restarted relying party rebuild its
  cache.
