# Organizations and Membership

This page describes how SystemForge models organizations, who belongs to
them, how people get in, what an organization is entitled to, and how a
relying party learns a principal's memberships. The first part describes the
system as implemented in `identity/organization`, `identity/invite`,
`identity/signup`, `identity/systemauth`, `identity/relyingparty` and
`marketplace`; the last section records where the implementation differs
from the wording of the decisions.

**Decisions:**
[ADR-006](../adrs/ADR-006-organization-lifecycle-personal-team-slugs.md)
(lifecycle, personal and team organizations, slugs, removal of `plan`),
[ADR-007](../adrs/ADR-007-memberships-and-entitlements-as-claims.md)
(memberships and entitlements as claims),
[ADR-008](../adrs/ADR-008-resource-scoped-collaborators.md)
(collaborators, resource grants, resource-targeted invites),
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
| `active` | bool | `Delete` sets it to `false` (soft delete) |

Edges: `principal_memberships`, `invites`, `oauth_apps`, marketplace
`listings`, `licenses` and `subscriptions`.

### Types

| Kind | Go constant | Meaning today |
|---|---|---|
| `personal` | `organization.OrgTypePersonal` | A person's own namespace, created by `signup`; `Organization.IsPersonal()` |
| `team` | `organization.OrgTypeTeam` | A shared organization; the default |
| `enterprise` | `organization.OrgTypeEnterprise` | A large organization; no behavioral difference from `team` in code |

A personal organization requires an owner (`Create` refuses one without
`OwnerPrincipalID`), and `GetPersonalOrg(principalID)` finds it by
`org_type = personal AND owner_principal_id = principalID`.

A personal organization has exactly one member, its owner (ADR-006 decision
3). `organization.RequireMembersAllowed` is the check every path that creates
or changes a membership applies: `AddMember`, `UpdateMember` (including
deactivating the owner), `invite.Create` and `invite.Accept`, and SCIM group
membership refuse a personal organization with `ErrPersonalOrganization`
unless the role is `organization.RoleCollaborator` (ADR-008), and
`TransferOwnership` refuses it outright. The members API answers `409` for
`ErrPersonalOrganization`, and `POST /organizations` accepts only `team` and
`enterprise` for `org_type`: personal organizations come from signup. The
`collaborator` role is one of the organization roles and is in the members
API's role enum.

### Slug is the identity

The slug is how an organization is addressed: every organization and
membership endpoint is keyed by it (`/organizations/{slug}`,
`/organizations/{slug}/members/...`, `/organizations/{slug}/invites/...`),
and `GetBySlug` is the lookup the API uses. The display name is cosmetic and
carries no identity. The slug is unique across every organization type, so
personal and team organizations share one namespace.

The slug changes only through `Rename` (see
[Renaming and the cooling-off period](#renaming-and-the-cooling-off-period)):
`UpdateOrganizationInput` has no slug field and `PATCH /organizations/{slug}`
accepts only `name`, `logo_url`, `description`, `website_url` and
`settings`. `SlugAvailable(slug)` checks `sf_organizations.slug`, the reserved
list and live cooling-off reservations; `GenerateSlug(name)` slugifies the name
(lowercase, spaces and underscores to hyphens, other characters dropped,
`-org` appended below three characters) and appends `-1` to `-100`, then an
eight-character UUID fragment, until one is free.

**Reserved slugs.** `organization.ReservedSlugs` lists names no organization
may take because they would collide with a route or a protocol path
(`admin`, `api`, `login`, `logout`, `oauth`, `scim`, `invites`,
`organizations`, `well-known`, `www`, `support`, `help`, `about`, `settings`,
`new`, `o`). A deployment adds its own product names with
`WithReservedSlugs(...)`. `SlugAvailable` answers `false` with
`ErrSlugReserved` for a reserved slug, `Create` and `CreatePersonalOrg`
fail with it, `GenerateSlug` steps past a reserved base to its numeric
suffix, and SCIM group creation refuses a reserved slug. Personal slugs
derived at signup go through `uniqueSlugInTx`, which skips reserved names
the same way (`PersonalOrgParams.ReservedSlugs` carries the deployment's
additions). `signup.SlugForLogin` derives a login's base slug and
`signup.SlugForManaged` returns a manager-entered slug or a generated one
(two words and a number, never derived from an email address).

#### Renaming and the cooling-off period

`Rename(ctx, orgID, slug, actor)` changes an organization's slug in one
transaction. `actor` must be an active owner of the organization
(`ErrNotOwner`); the new slug must be well formed (`ErrInvalidSlug`), not
reserved (`ErrSlugReserved`), not used by an organization (`ErrSlugTaken`)
and not held by someone else's reservation (`ErrSlugCoolingOff`). The old
slug is written to `sf_slug_reservations` (`slug` unique,
`released_by_principal_id`, `released_from_organization_id`, `released_at`,
`expires_at`) and held for `organization.SlugCoolingOff` (7 days;
`WithSlugCoolingOff` overrides it). The rule is the same for personal and
team organizations in every direction.

- **Who may take a held slug.** The principal who released it, or an owner
  of the organization that released it. `Create` passes its owner as the
  acting principal, so that owner may create an organization under the held
  slug, which spends the reservation; `Rename` does the same for its actor.
  `SlugAvailable` has no actor and answers `false` with `ErrSlugCoolingOff`.
- **Aliases.** `ResolveSlug(ctx, slug)` returns the organization using the
  slug, else, while a reservation is live, the organization that released it
  with `alias = true`. The organization and invite handlers resolve `{slug}`
  through it, so old links keep working and responses carry the current slug.
  `GetBySlug` stays an exact match.
- **Expiry.** An expired reservation is ignored everywhere and deleted when
  next read. Signup's `uniqueSlugInTx` skips a slug under a live reservation
  and takes the next numeric suffix.
- There is no HTTP endpoint for renaming yet; `Rename` is a service method.

#### Converting a personal organization to a team

`ConvertToTeam(ctx, orgID, teamSlug, actor)` returns a `ConvertResult{Team,
Personal}`. In one transaction it checks that the organization is personal
(`ErrNotPersonal`) and that `actor` is its owner (`ErrNotOwner`), renames it
to `teamSlug` with the rules above (which reserves the person's handle for
`actor`), sets its type to `team`, and creates a new personal organization
for `actor` under the handle, spending that reservation. The converted
organization keeps its ID, data, settings and every membership, so its owner
membership is the team's first owner and collaborators stay; it now accepts
members like any team. The new personal organization is named after the
owner's display name, has the owner as its only member, and is registered
with the authorization syncer after commit. Any failure rolls everything
back. There is no HTTP endpoint for the conversion yet.

### Service (`identity/organization`)

`organization.Service` is implemented by `DefaultService` over Ent, with an
`authz.RelationshipSyncer` (default `noop`) and an `authz.SyncMode`.
Changes that end access (`RemoveMember`, a deactivation or role change in
`UpdateMember`, `TransferOwnership`, `Delete`) remove the relationships
from the graph inside their transaction, before the commit, and roll back
with the error when the graph refuses, whatever the mode; the call can then
be retried as is. Granted relationships are written after the commit,
holding the graph locks of the organization and the principal and only if
the rows still call for them, so a revocation that committed in between is
not undone: `strict` fails the call on a sync error, `eventual`, the
default, logs it.
See [Keeping providers in step with identity](authorization.md#keeping-providers-in-step-with-identity).

| Method | Behavior |
|---|---|
| `Create(input)` | Validates and reserves the slug; creates the organization and, when an owner is given, an `owner` membership in one transaction; then `syncer.RegisterOrganization(orgID, ownerID)` |
| `CreatePersonalOrg(input)` | `Create` with `org_type = personal`, and the owner |
| `GetByID`, `GetBySlug`, `GetPersonalOrg` | Lookups |
| `Update(id, input)` | Name, logo, description, website, settings; never the slug or type |
| `Delete(id)` | Sets `active = false`; `syncer.UnregisterOrganization`. A deleted organization no longer resolves by slug (`ResolveSlug`), takes no membership changes (`RequireMembersAllowed` returns `ErrOrganizationDeleted`, so `AddMember`, `UpdateMember`, invites and SCIM refuse it), and `MembershipRoleGetter` gives its members no role, so the RBAC authorizer denies them as SpiceDB does after `UnregisterOrganization` |
| `List(input)` | Filters: `OrgType`, `Active`, `MemberPrincipalID` (active memberships only), limit and offset |
| `TransferOwnership(input)` | See [Ownership transfer](#ownership-transfer) |
| `Rename(orgID, slug, actor)`, `ResolveSlug(slug)` | See [Renaming and the cooling-off period](#renaming-and-the-cooling-off-period) |
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
| `createOrganization` | `POST /organizations` | Any authenticated principal; the caller becomes the owner. Default `org_type = team` |
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
| `role` | string | One of the organization roles `owner`, `admin`, `member`, `collaborator` (`RoleOwner`, `RoleAdmin`, `RoleMember`, `RoleCollaborator`); every service path that writes a membership refuses any other value with `ErrInvalidRole`, and the API's role enums are `owner,admin,member,collaborator`. `editor` and `viewer` were retired as organization roles; migration `0008_drop_editor_viewer_roles.sql` maps stored `editor` to `member` and `viewer` to `collaborator`, recording an access change for each active membership it changes |
| `permissions` | JSON string array | Optional per-membership permissions; stored and returned, not evaluated by the providers |
| `active` | bool | Deactivated memberships are kept and excluded from listings unless `organization.IncludeInactive()` is passed |

Any principal type can hold a membership. The owner's membership is created
with the organization; there is no separate "owner" flag on the membership,
only `role = owner` plus `sf_organizations.owner_principal_id`.

### Service methods

| Method | Behavior |
|---|---|
| `AddMember(input)` | Refuses when a membership (active or not) exists; creates it active; `syncer.AddOrgMembership(principal, org, role)` |
| `UpdateMember(membershipID, input)` | Role, permissions, active. A role change removes the old role from the graph before the commit and writes the new one after; a change to `collaborator` also deletes the member's application roles in the organization, removing them from the graph first, and records `app_role_changed` |
| `RemoveMember(orgID, principalID)` | Deletes the row; `syncer.RemoveOrgMembership` |
| `GetMembership(orgID, principalID)` | Returns the row whatever its `active` value, or `ErrMembershipNotFound` |
| `ListMembers(orgID)`, `ListMemberships(principalID)` | Active rows by default |

`organization.MembershipRoleGetter(svc)` adapts `GetMembership` to
`rbac.WithRoleGetter`: an inactive or missing membership has no role.

### Member endpoints

| Operation | Route | Rule |
|---|---|---|
| `listMembers`, `getMember` | `GET /organizations/{slug}/members[/{principal_id}]` | `view` |
| `addMember` | `POST /organizations/{slug}/members` | `invite_member`, and the caller must be allowed to enroll the principal without its consent: by default only a platform administrator; `APIConfig.DirectAdd` can allow principals the organization governs (for example managed principals the caller manages). Everyone else joins by invitation. Granting `owner` additionally needs the owner-only permission (`delete`) |
| `updateMember` | `PATCH /organizations/{slug}/members/{principal_id}` | `change_role`; touching an owner's role, or granting `owner`, needs the owner-only permission; deactivating needs `remove_member` |
| `removeMember` | `DELETE /organizations/{slug}/members/{principal_id}` | A member may remove themself with `view`; removing someone else needs `remove_member`, and removing the owner needs the owner-only permission |
| `transferOwnership` | `POST /organizations/{slug}/transfer-ownership` | `delete`, and the caller must be `owner_principal_id` |

### Ownership transfer

`TransferOwnership` requires the current owner's membership to have
`role = owner` and the new owner to already be a member. In one transaction
it sets the old owner's role to `NewRoleForOld` (`admin` by default; only
`admin` or `member` are accepted), sets the new owner's role to `owner`, and
updates `owner_principal_id`. Both role changes are then synced. A personal
organization is refused with `ErrPersonalOrganization`.

## Invites

### Table `sf_invites` (`identity/ent/schema/invite.go`)

| Column | Notes |
|---|---|
| `organization_id`, `inviter_principal_id` | Who invited, to where |
| `email` | The invitee; the invite is bound to this address |
| `role` | Role granted on acceptance; default `member`; the API accepts `owner`, `admin`, `member`, `collaborator` |
| `token` | Hex SHA-256 of the URL token (32 random bytes, base64url); the token itself is never stored |
| `app_roles` | Optional JSON object, application identifier to role, granted on acceptance (ADR-007); migration `migrations/0006_invite_app_roles.sql` adds the column to an existing database |
| `resource_type`, `resource_id`, `resource_role` | Optional, all or none: the resource and the resource role to grant on acceptance (ADR-008); migration `migrations/0009_invite_resource_target.sql` adds the columns to an existing database |
| `status` | `pending`, `accepted`, `declined`, `expired`, `revoked` |
| `message`, `expires_at`, `accepted_at`, `accepted_by_principal_id`, `resend_count`, `last_sent_at` | Lifecycle |

### Service (`identity/invite`)

| Method | Behavior |
|---|---|
| `Create(input)` | Refuses when a pending, unexpired invite exists for the same organization and email; default expiry `invite.DefaultInviteExpiry` (7 days); returns the one-time `InviteURL` (`{baseURL}/invites/{token}`). With `invite.WithAppRoles(approleService)`, `AppRoles` (none preselected) are validated against the registered vocabularies and the organization's entitlements, collaborators may carry none, and an admin or member invitation to an organization entitled to any application must choose at least one (`ErrAppRoleRequired`); owners hold every role implicitly. Without that option, `AppRoles` are refused and nothing is required. A resource target (`ResourceType`, `ResourceID`, `ResourceRole`, all three) requires `Role` to be `collaborator` and `invite.WithResourceGrants(svc)`, and is validated with `resourcegrant.Service.Validate` (a registered application, a collaborator-able type, a valid identifier and role); a collaborator invitation with no target is refused for a personal organization, which accepts only resource-targeted invites. A person may hold several pending invites to one organization if each targets a different resource |
| `GetByToken`, `GetByID`, `List`, `ListPendingForEmail`, `HasPendingInvite` | Lookups; email matching is case-insensitive |
| `Accept(input)` | Requires `pending` and unexpired (an expired one is marked `expired`); in one transaction refuses an existing membership, creates the membership with the invite's role, grants the invite's application roles (`approle.Service.AssignInTx`, seat limits enforced under the same lock as `Assign`; an invitation that cannot grant a role, for example because no seat is left, is refused and stays pending), and marks the invite accepted. A resource-targeted invite instead calls `resourcegrant.Service.GrantInTx` in the same transaction, which creates the collaborator membership when the principal has none (an existing member keeps their role and gains the grant); a grant the store refuses leaves no membership and a pending invite. It writes the membership directly rather than through the organization service, so after commit it calls `syncer.AddOrgMembership` itself (options `invite.WithAuthzSyncer`, `WithSyncMode`, `WithLogger`; default `noop` and eventual, like the organization service) |
| `Decline(token)`, `Revoke(id)` | Status changes |
| `Resend(id)` | New token, `resend_count + 1`, expiry reset to 7 days |
| `ExpireOld()` | Batch status update |

### Invite endpoints

Organization-side routes (`POST`/`GET /organizations/{slug}/invites`,
`DELETE .../{invite_id}`, `POST .../{invite_id}/resend`) need
`invite_member`; inviting an `owner` needs the owner-only permission, and
`inviter_principal_id` must be the caller. The create body takes `app_roles`
and invites in responses carry them. A member's roles are changed later, per
application and without touching the membership, through the application role
endpoints (`PUT`/`DELETE /organizations/{slug}/members/{principal_id}/app-roles/{application}`). Invitee-side routes
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
| `Signup(input)` | Requires a plain email, a display name and `PersonalOrgSlug`; refuses a taken email (`ErrEmailTaken`) or slug; creates the human principal with `AllowedScopes` `openid profile email`, then the personal organization (name defaults to the display name, logo to the avatar). With the default services the principal, organization and owner membership are written in one transaction (`principal.HumanTxCreator.CreateHumanInTx` and `organization.PersonalOrgTxCreator.CreatePersonalOrgInTx`), so a failure leaves nothing behind; the syncer registrations (`RegisterPrincipal`, then `RegisterOrganization`) run after the commit and, in strict sync mode, a failed one is returned with the rows kept. Services that do not implement those interfaces fall back to separate commits, and a failure after the principal exists deletes it again. With `EmailVerified` set, the email is recorded as verified (`email_verified_at`) |
| `SignupWithInvite(input)` | `Signup`, then `invite.Accept` for the invite (email must match) |
| `SignupOrGetExisting(input)` | Returns the existing principal and personal organization for an email only when `EmailVerified` is set (`ErrEmailNotVerified` otherwise) and the existing account's own email is verified (`ErrAccountEmailUnverified` otherwise, so a verified login never takes over an account registered without proof of the address); creates them otherwise, recording the email as verified when `EmailVerified` is set |

### Signup on first social login

GitHub and Google login (`systemauth.ResolveExternalLogin`, ADR-002,
ADR-006 decision 1) resolve a principal by `(provider, subject)` first, then
link by a verified email to an existing principal whose own email is
verified, and otherwise create one. An unverified email never links to or
creates an account (`ErrEmailNotVerified`, nothing written).

The create step does not call `signup.Service` (neither `Signup` nor
`SignupOrGetExisting`); it writes with the same in-transaction helpers
rather than the services' syncer-aware `*InTx` variants, because it also
creates the external identity row in that transaction. Instead
`EntPrincipalDirectory.CreateFromExternal` opens one Ent transaction and
writes the principal, its `sf_humans` row, the `sf_external_identities` link,
and, through `signup.CreatePersonalOrgInTx`, a personal organization (type
`personal`, owner set, name = display name, else provider username, else
email local part, logo = avatar) with an active `owner` membership. A failure
at any step rolls all of it back. After the commit, the directory registers
the principal (`syncer.RegisterPrincipal`) and the organization with its owner
(`syncer.RegisterOrganization`) with an `authz.RelationshipSyncer`, so both
exist in rebac mode; the backfill path registers only the organization it
creates. Configure it with `systemauth.WithSocialAuthzSyncer(syncer, mode)`
on the server, or `WithDirectoryAuthzSyncer`, `WithDirectorySyncMode` and
`WithDirectoryLogger` on `NewEntPrincipalDirectory`. The default is `noop`
and eventual mode: a failed registration is logged. In strict mode it is
returned, with the rows already committed.

- **Slug.** `signup.SlugForLogin(provider, username, email)` returns the
  GitHub username for `github`, the email local part for `google`, and the
  username (else the local part) for any other provider, normalized to a valid
  slug. If that slug is taken or reserved (the built-in list, or the
  deployment's through `PersonalOrgParams.ReservedSlugs`), `-1` to `-100` and
  then an eight-character random suffix are tried inside the transaction. A
  managed principal's organization is never slugged from an email:
  `signup.SlugForManaged` returns a manager-entered value or a generated
  `adjective-noun-NN` (see [Slugs](managed-principals.md#slugs)).
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
  social login does not use it. Note on ADR-006 decision 1: that ADR says
  social login calls `SignupOrGetExisting`; in practice it uses the
  in-transaction helpers described above, which is the behavior of record.

## No plan on the organization

An organization has no `plan`. The column was a placeholder from before the
marketplace: set at creation and never consulted, and one value cannot
describe an organization holding several subscriptions or licenses
(ADR-006). It is gone from `sf_organizations`, from `organization` service
inputs and the list filter, from the API, and from SCIM group provisioning;
the `organization.Plan*` constants are removed. Existing PostgreSQL
databases run `migrations/0004_drop_organization_plan.sql`; fresh databases
need nothing.

What an organization may use is its `entitlements`, a list returned in
every `OrgResponse` and derived from the marketplace (next section).
`APIConfig.Entitlements` supplies the source;
`marketplace.EntitlementSource(subscriptions, licenses, listings, opts...)`
builds one from each active subscription (source `subscription`, tier =
`plan_tier`, valid until the period end), each valid license (source
`license`, the listing ID, tier = license type, valid until, and `seats`
for a seat-based license) and the deployment's default entitlements (source
`default`). An entitlement that comes from a listing naming an application
carries that `application`. Without a source the list is empty.

## Entitlements via the marketplace

What an organization may use is recorded by `marketplace`, not by the
organization:

| Table | Purpose | Key columns |
|---|---|---|
| `sf_listings` | A product offered by a creator organization | `creator_org_id`, `owner_id`, `product_type`, `product_id`, `application` (optional), `pricing_model` (`free`, `one_time`, `subscription`, `per_seat`), `price_cents`, `currency`, `status` (`draft`, `pending_review`, `published`, `archived`) |
| `sf_licenses` | An organization's right to a listing | `listing_id`, `organization_id`, `license_type` (`seat_based`, `team`, `unlimited`), `seats`, `used_seats`, `valid_from`, `valid_until`, `stripe_subscription_id`, `purchased_by` |
| `sf_seat_assignments` | A seat of a license given to a principal | `license_id`, `principal_id`, `assigned_by`, `assigned_at` |
| `sf_subscriptions` | A subscription of an organization: at most one platform-wide (no `listing_id`) plus one per listing | `organization_id`, `listing_id` (optional), `plan_tier` (`free`, `starter`, `pro`, `enterprise`), `status` (`active`, `trialing`, `past_due`, `canceled`, `unpaid`), `current_period_start/end`, `cancel_at_period_end`, Stripe IDs |

Services: `marketplace.ListingService` (create, publish, archive, list),
`LicenseService` (`Grant`, `Revoke`, `Check(listingID, orgID)` for a valid
license, `CheckPrincipal(listingID, principalID)` which passes any valid
`unlimited` license outright and otherwise requires a seat assignment,
`AssignSeat`/`UnassignSeat`), `SubscriptionService` (`GetByOrg`, which returns the platform
subscription, `IsActive`, `GetPlanTier`, `ChangePlan`, `Cancel`, `CancelImmediately`,
`Reactivate`); payments are taken by package `billing`. A `SubscriptionService` that
also implements the optional `SubscriptionLister` (`ListByOrg`) contributes
every subscription of an organization to entitlements. Tiers are a property
of a subscription, not of a listing. The
`marketplace.PurchaserChecker` (implemented by
`managedprincipal.Service.IsManaged`) refuses `billing` checkout for managed
principals. `marketplace.SpiceDBSyncer` writes listing, license, seat and
subscription relationships for the relationship-based provider
(`creator_org`, `owner`, `licensed_org`, `listing`, `purchased_by`,
`seat_holder`, `subscriber`).

A listing's optional `application` is the registered application identifier
(an `authz.AppVocabulary` application) that an active subscription or a
valid license on it entitles the organization to. It is not settable through
the listing HTTP API, only through the service, so that a listing creator
cannot entitle buyers to an application they do not control. An
organization's entitled applications are therefore:

- the `application` of each listing it holds an active (`active` or
  `trialing`) subscription or a currently valid license for, and
- the deployment's default entitlements,
  `marketplace.WithDefaultEntitlements(apps...)` (configuration
  `marketplace.default_entitlements`), for applications free to everyone.

Seat accounting: the seat limit of an application is the sum of the seats of
its valid `seat_based` licenses, and there is none when any entitlement for
the application is not seat-limited (a subscription, an unlimited license, a
default). `approle` counts `sf_app_roles` rows for (organization,
application) against it and refuses with `ErrNoSeats`; the count and the
insert run in one transaction under a PostgreSQL advisory lock keyed by
(organization, application), so concurrent assignments cannot exceed the
limit (SQLite is serialized in process); owners' implicit
roles hold no seat. `marketplace.WarnIfNoEntitlements` logs a warning at
startup when applications are registered but there is no default entitlement
and no listing names an application, in which case every organization is
refused every application role. `authz.FeatureAuthorizer` remains an
interface with no implementation in the repository.

Existing PostgreSQL databases run
`migrations/0005_subscriptions_per_listing.sql`, which adds the two nullable
columns and relaxes the one-subscription-per-organization constraint;
existing subscriptions become platform subscriptions.

## Application roles (`identity/approle`)

A principal's access inside an application is an application role, stored
per (principal, organization, application) in `sf_app_roles` (Ent schema
`AppRole`):

| Column | Notes |
|---|---|
| `principal_id`, `organization_id` | Foreign keys, cascade on delete |
| `application` | Identifier registered in `authz.VocabularyRegistry` |
| `role` | One of the application's `AppVocabulary.Roles()`; free text in the column, validated by the service |
| `assigned_by` | Principal who made the change; null if that principal is deleted |
| `id`, `created_at`, `updated_at` | `BaseMixin` |

Unique on `(principal_id, organization_id, application)`, indexed on
`(organization_id, application)`. Fresh databases get the table from the Ent
migration; no SQL migration is needed.

`approle.Service` (built with `NewService(client, registry, opts...)`):

| Method | Behavior |
|---|---|
| `Assign(in)` | Creates the role; `ErrAlreadyAssigned` if the principal already has one in that application |
| `Change(in)` | Sets a different role; `ErrNotAssigned` if there is none |
| `Remove(org, principal, app, by)` | Deletes the role; `ErrNotAssigned` if there is none |
| `RemoveForMember(org, principal)` | Deletes every role of a member in the organization |
| `ListForPrincipal`, `ListForOrganization` | Stored roles only |
| `EffectiveRoles(principal, org)` | Map of application to role: stored roles plus the implicit owner role, only while the membership is active |
| `Roles(app)` | The application's roles, lowest first, for pickers |

Rules enforced by `Assign` and `Change`: the application is registered, the
role is one the application declares, the organization is entitled to the
application and has a free seat if the application is seat-limited
(`WithEntitlementGrants`, built from the marketplace by
`marketplace.ApproleOptions(marketplace.EntitlementSource(...))`; without an
entitlement option no organization is entitled to anything, and
`approle.EntitleAll` is for development and tests), and the principal has an active `owner`,
`admin` or `member` membership. Collaborators, non-members and deactivated
members cannot hold roles. Each assignment is logged with who made it and
whether it was to themself.

`EffectiveRoles` gives owners the top role of every entitled registered
application, `admin` where the vocabulary declares it, else the highest role
in its hierarchy; when an owner also has a stored role the higher wins.
Admins and members hold only stored roles, and nobody holds any by default.
Deactivating a membership leaves the rows but they are not effective;
removing the member deletes them, in the same transaction
(`organization.Service.RemoveMember`, and SCIM's group member removal), and
so does demoting the member to `collaborator` (`UpdateMember`); promoting
them again does not restore the roles.

HTTP endpoints, on the organization API when `APIConfig.AppRoles` is set
(501 otherwise):

| Route | Permission |
|---|---|
| `GET /organizations/{slug}/app-roles[?application=]` | `change_role` |
| `GET /organizations/{slug}/members/{principal_id}/app-roles` | `change_role`, or `view` for one's own roles; returns stored and effective roles |
| `PUT /organizations/{slug}/members/{principal_id}/app-roles/{application}` | `change_role`; body `{"role": "..."}`; assigns or changes |
| `DELETE /organizations/{slug}/members/{principal_id}/app-roles/{application}` | `change_role` |

With `approle.WithAuthzSyncer`, assign, change and remove also write to the
authorization graph through the optional `authz.AppRoleSyncer` (see
[Keeping providers in step with identity](authorization.md#keeping-providers-in-step-with-identity)).

Invites carry application roles (see [Invites](#invites)).

## Resource grants (`identity/resourcegrant`)

A collaborator reaches individual resources, not the organization (ADR-008).
A grant is a principal's role (`viewer`, `contributor` or `maintainer`) on
one resource of an organization, stored in `sf_resource_grants` (Ent schema
`ResourceGrant`):

| Column | Notes |
|---|---|
| `principal_id`, `organization_id` | The grantee and the resource's organization; deleting either deletes the grant |
| `resource_type` | `{app}_{type}`, as declared in the application's vocabulary |
| `resource_id` | The application's identifier, 1 to 1024 characters of `a-zA-Z0-9/_\|-=+` (the characters SpiceDB object identifiers allow, so both modes accept the same resources) |
| `role` | A resource role; free text in the column, validated by the service |
| `granted_by` | The granting principal, when known; cleared if that principal is deleted |

Unique on `(principal_id, resource_type, resource_id)`; indexed on
`(organization_id, principal_id)`, `(resource_type, principal_id)` and
`(resource_type, resource_id)`. The table is created by the schema
migration; no SQL script is needed.

`resourcegrant.Service` (built with `NewService(client, opts...)`)
implements `authz.ResourceGranter` and `authz.ResourceGrantReader`:

| Method | Behavior |
|---|---|
| `GrantResourceRole(principal, ref, role, by)` | Validates the role, the reference and, with `WithVocabularies`, that the type belongs to a registered application. In one transaction: gives the principal a `collaborator` membership when it has none in the organization (reactivating a deactivated collaborator; a deactivated member of another role is refused with `ErrInactiveMembership`), and creates the grant or replaces its role. Lowering a role records `grant_reduced`. A resource belongs to one organization: a grant naming another one for a resource that already has grants is refused with `ErrResourceOrganizationMismatch` |
| `GrantInTx(tx, ...)` | The same inside the caller's transaction, returning the function to call after commit (publishes the access changes and syncs); for flows that create membership and grant together, such as accepting an invitation. A grant lowered to a lesser role is replaced in the graph before the caller commits, and its failure is returned so the caller rolls back |
| `RevokeResourceRole(principal, ref)` | Deletes the grant and records `grant_reduced`; when it was the principal's last grant in the organization and the membership is a `collaborator`'s, deletes the membership and records `membership_removed`. Both leave the graph before the commit; a graph failure rolls the revocation back and is returned. `ErrGrantNotFound` when there is none |
| `ListResourceGrants(ref)` | The grants on a resource, highest role first |
| `ListResources(principal, type, permission)` | Resource identifiers on which a grant gives the principal `view`, `edit` or `manage`, in organizations where its membership is active |
| `ResourceRole(principal, ref)` | The principal's role through a grant, or empty when it has none or its membership is inactive |

Grants and revocations of one principal in one organization are serialized
by a PostgreSQL advisory lock, so concurrent first grants create one
membership and concurrent revokes cannot both miss the last grant.
`organization.Service.RemoveMember` deletes the member's grants with the
membership and, with a syncer that implements `authz.ResourceGrantSyncer`,
removes them from the graph. With `WithAuthzSyncer` the service writes the
collaborator membership through `AddOrgMembership` and the grant through
`ResourceGrantSyncer`; `noop` implements it, so any existing syncer keeps
working.

The role-based provider consults the table: `rbac.WithResourceGrants(svc)`
makes `Can` and `Decide` allow `view`, `edit` and `manage` on a resource the
principal holds a role on when the organization role has not (see
[Authorization](authorization.md#resource-grants)).

## How relying parties get memberships

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
The default is `ClaimsMemberships`, which decodes the `orgs` claim (see
[The `orgs` claim](#the-orgs-claim)); `RemoteMemberships` reads
`GET /oauth/userinfo/memberships`, `ClaimsOrRemoteMemberships` combines them
(endpoint used when `orgs_truncated` is set or the claim is absent, claims
served if it fails), `ProvisioningMemberships` runs an idempotent per-organization
hook on first use by a principal holding a role in the application, and
`LocalMemberships` over a `MembershipLister` remains for development and
tests only. `relyingparty.Membership` is `{ID,
OrganizationID, OrganizationName, OrganizationSlug, OrganizationType, Role,
JoinedAt, Applications}`; `MembershipQuery.AccessToken` lazily supplies the
request's access token (the presented JWT, or a session's, refreshed when
needed) for remote sources. `BearerMiddleware`, `RequestAuthenticator` and the BFF's `CurrentSession`
all go through the source, and the BFF's `GET /bff/api/v1/users/me`
returns the result as `memberships`. Requests without claims (API keys) get no
memberships from the default source. A BFF session's claims are those of the
sign-in; a source that must be fresher uses `RemoteMemberships`.

## The claims model

SystemAuth's claims come from `SessionProvider.GetUserClaims`, which feeds
both the ID token (`OIDCSession` puts them in `Extra`) and `/oauth/userinfo`
(filtered by `UserInfoClaims` to the granted scopes). For a principal
signed in through social login or a login token they are:

| Claim | When |
|---|---|
| `sub` | Always; the SystemAuth principal ID, which relying parties store as `sf_principal_id` |
| `managed: true` | The human has an active manager relationship (a managed principal), with or without an email; emitted whatever the scopes |
| `email`, `email_verified` | `email` scope, and only when the principal has an email (a managed principal may have one) |
| `name`, `picture` | `profile` scope |
| `orgs`, `orgs_truncated` | When the server has an `OrgsSource` (`systemauth.WithOrgsSource(systemauth.NewEntOrgsSource(client, approleService))`); emitted whatever the scopes, like `managed` |

Without an `OrgsSource` no organization claim is emitted. Access tokens are
JWTs (`relyingparty.AccessTokenVerifier` yields `Subject`, `ClientID`,
`Scopes` and the raw claims).

### The `orgs` claim

`orgs` lists the organizations the principal belongs to through an active
membership in an active organization, personal organization first and then
newest membership first, at most `MaxOrgsInToken` (50); `orgs_truncated` is
`true` when any were left out. Each entry has the organization `id`, the
principal's organization `role` (`owner`, `admin`, `member` or
`collaborator`) and `apps`, a map from application identifier to the
principal's role there, from `approle.EffectiveRoles`: owners hold `admin` in
every entitled application, everyone else holds what was assigned, and a
collaborator's `apps` is empty. An application absent from `apps` is one the
principal may not open.

| Where | Form | Entry fields |
|---|---|---|
| ID token, `/oauth/userinfo` | Full | `id`, `slug`, `name`, `type` (`personal`, `team`, `enterprise`), `role`, `apps` |
| JWT access token | Compact | `id`, `role`, `apps` |
| `GET /oauth/userinfo/memberships?limit=&cursor=` | Full, every organization | as above, in `{"orgs": [...], "next_cursor": "..."}`; `limit` defaults to 50 and is at most 100; `cursor` is the last organization ID of the previous page; needs a token granted `openid` |

`systemauth.OrgsClaim` (`Server.OrgsClaim(ctx, principalID, compact)`) builds
the claim. The token endpoint recomputes it on every grant, so a refresh
carries current roles in the access token and in the refreshed ID token; a
refresh token is not revoked by a role or membership change (ADR-010
decision 5). Subjects that are not principals (a client under
`client_credentials`) get no claim. If the claim cannot be read, issuance
fails with `server_error` rather than issuing a token without it.

## Token freshness and revocation

| Setting | Default | Where |
|---|---|---|
| Access token lifetime | 10 minutes, at most 15 (`accesschange.DefaultAccessTokenLifetime`, `MaxAccessTokenLifetime`) | `systemauth` config `tokens.access_token_lifetime` (a larger value is refused at load); per client `access_token_lifetime` and `sf_oauth_apps.access_token_ttl` (600 s), both lowered to the maximum |
| Refresh token lifetime | 7 days (absolute lifetime 30 days) | `tokens.refresh_token_lifetime`, `refresh_token_absolute_lifetime` |
| ID token lifetime | 1 hour | `tokens.id_token_lifetime` |

Revocation by principal status: every introspection, userinfo call and
refresh runs `Server.requireActiveSubject`, which asks
`PrincipalStatus.PrincipalActive(subject)` (part of every `Storage`); a
deactivated principal's token family is revoked and the token reported
inactive. A subject that is not a principal ID, or names no principal (one
that was hard-deleted), is inactive in the same way; only a
client-credentials token, with an empty subject, has no principal to check. A role or membership change does not revoke refresh
tokens: the next refresh re-evaluates the `orgs` claim (ADR-010 decision 5).
The relying-party `SessionStore` can delete BFF sessions by SystemAuth
session ID or subject, which is the hook back-channel logout would use.

### Access-change records (`identity/accesschange`)

Access tokens are self-contained, so a change that reduces what an existing
token may claim is recorded and announced (ADR-010). `accesschange.Record`
writes a row of `sf_access_changes` (`principal_id`, `organization_id` or
null for every organization, `changed_at` on the server clock, `reason`) in
the transaction that makes the change, and `accesschange.Publish` hands it
to the service's `accesschange.Sink` after commit. The principal and
organization are plain identifiers rather than foreign keys, so a row
outlives the deletion it describes. Each recording service takes a sink
option (`WithAccessChangeSink`; `systemauth.WithEntAccessChangeSink` for
`EntStorage`); the rows are written with or without one.

The reasons form an open registry, documented with what records each in the
[access-change reasons](authorization.md#access-change-reasons) table of the
authorization page. The column is a plain string, so a new reason needs no
migration; `accesschange.Record` rejects any reason that is not registered.

`accesschange.Since` reads the rows after a timestamp for pollers and the
replay endpoint, and `accesschange.PruneExpired` deletes rows older than
`accesschange.Retention` (the maximum token lifetime, a minute of clock-skew
margin and an hour of slack); no scheduled job calls it yet, so a deployment
runs it from its own maintenance loop. The embedded in-memory
`EmbeddedAuthProvider` keeps no database and records nothing.

### Relying-party revocation cache (`relyingparty.RevocationCache`)

`relyingparty.RevocationCache` consumes the records. `accesschange.ToSink`
adapts it to a `Sink`, so in a modular monolith one instance is passed to
every service's `WithAccessChangeSink` and read by every relying party; it is
written after the recording transaction commits. It keeps the latest change per
principal and per principal and organization, and accepts a token only if
`iat >= changed_at + margin` (default 30 s, floor 15 s); entries expire at
`changed_at + max lifetime + margin`, swept on `Record`. `BearerMiddleware`
(`BearerConfig.Revocation`, with an optional `Organization` function) answers a
refused token `401 invalid_token`, `error_description="token expired"`, and
`NewBFF` (`BFFConfig.Revocation`) refreshes a session's tokens and claims
instead of ending it. See [Access changes](../../systemauth/relying-party.md#access-changes).

Replicas that share the database poll it:
`relyingparty.NewAccessChangePoller(pgstore.NewAccessChangeSource(db), cache)`
(or `accesschange.NewSource` over Ent) reads the rows newer than its last read
every 1 to 2 seconds, re-reading one margin behind the newest so late-committing
rows are not missed. After a restart, `relyingparty.Replay` rebuilds the
cache from `GET /access-changes?since=` (`systemauth.WithAccessChanges`; a
token with the `access_changes:read` scope; paged by `next_since`) or from the
database. A cache created with `WithSuspectStart` refuses tokens issued
before it started listening until the replay or the first poll succeeds.

Across separate deployments SystemAuth delivers each change as an OpenID
Connect Back-Channel Logout token. A client registers `backchannel_logout_uri`
(column `sf_oauth_apps.backchannel_logout_uri`, migration
`migrations/0007_oauth_app_backchannel_logout_uri.sql`);
`systemauth.Server.NewBackchannel()` is an `accesschange.Sink` that queues the
change after commit, signs one `logout+jwt` per client carrying the
`urn:systemforge:event:access_change` event (plus the standard logout event for
deactivation and session revocation), POSTs it, retries with backoff up to one
access-token lifetime and logs failures against the client ID.
`relyingparty.BackchannelHandler` verifies it and feeds the cache and the
session store; the BFF serves it at `<BasePath>/auth/backchannel-logout`. See
[Back-channel events](../../systemauth/relying-party.md#back-channel-events).

## Where the implementation differs from the decisions

Every item of the accepted decisions this page covers is implemented. These
are the places where the code is narrower than, or words things differently
from, the ADR text; the ADRs are append-only and are not rewritten.

- **Listings have no tier.** ADR-006 speaks of listings with tiers. Tiers
  (`plan_tier`) live on subscriptions, a listing maps to an application,
  and a subscription may be per listing (see
  [Entitlements via the marketplace](#entitlements-via-the-marketplace)).
- **The display name is required.** `name` is `NotEmpty` on
  `sf_organizations`; it does not default to the slug.
- **Social login does not call `SignupOrGetExisting`.** See
  [Signup on first social login](#signup-on-first-social-login).
- **Application roles do not replace seat assignments.** ADR-007 decision 8
  says the `sf_app_roles` table replaces seat assignments as the record of
  who may use what. The marketplace seat assignments
  (`LicenseService.AssignSeat`, `CheckPrincipal`) remain a separate record,
  and a seat-licensed application counts its `sf_app_roles` rows against the
  license (see [Application roles](#application-roles-identityapprole)).
- **`addMember` takes no application roles.** Roles are granted by an invite
  or afterwards through the application role endpoints. The administration
  pages for choosing them are the application's to build; this repository
  ships no UI.
- **Rename and conversion are service methods.** `Rename` and
  `ConvertToTeam` have no HTTP endpoint.
- **Refresh tokens survive a role change.** ADR-010 decision 5 amends
  ADR-007 decision 9: only deactivation and explicit session revocation
  revoke refresh tokens.
