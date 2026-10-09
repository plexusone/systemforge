# TRD — Suite Organizations: Lifecycle, Claims, Collaborators, Real-Time Invalidation

**Initiative:** `INIT-SYSTEMFORGE-011`
**Design of record:**
[ADR-006](../../../design/adrs/ADR-006-organization-lifecycle-personal-team-slugs.md),
[ADR-007](../../../design/adrs/ADR-007-memberships-and-entitlements-as-claims.md),
[ADR-008](../../../design/adrs/ADR-008-resource-scoped-collaborators.md),
[ADR-009](../../../design/adrs/ADR-009-management-is-a-relationship.md),
[ADR-010](../../../design/adrs/ADR-010-real-time-access-invalidation.md)

## Current State

**Organizations.** `identity/organization` models `Organization{ID, Name,
Slug, OrgType, OwnerPrincipalID, ..., Plan, Active}` with `OrgType` in
`personal | team | enterprise` and `Plan` in `free | starter | pro |
enterprise` (`Plan*` constants, Ent enum defaulting to `free`). The
`Service` has `Create`, `CreatePersonalOrg`, `GetByID`, `GetBySlug`,
`GetPersonalOrg`, `Update`, `Delete`, `List`, `AddMember`, `UpdateMember`,
`RemoveMember` (a hard delete), `GetMembership`, `ListMembers`,
`ListMemberships`, `SlugAvailable`, `GenerateSlug` and `TransferOwnership`,
built with `WithAuthzSyncer`, `WithSyncMode` and `WithLogger`. Slugs match
`^[a-z][a-z0-9-]*[a-z0-9]$` at 3 to 63 characters, are unique by the Ent
constraint plus an exact-match `SlugAvailable` pre-check, and are not
updatable through `UpdateOrganizationInput`. There are no reserved slugs,
no slug history, and no `Rename`, `ConvertToTeam` or `ResolveSlug`.
Membership roles are `owner`, `admin` and `member` (constants; the column
is a free string); nothing checks `OrgType` in `AddMember`, the members API
or invite acceptance, so personal organizations accept members, and the
API lets clients create personal organizations and set `plan` on create
and update. SCIM group provisioning sets `plan` to `free` in both the
mapper and the Ent store.

**Signup and social login.** `identity/signup.Service` has `Signup`,
`SignupWithInvite` and `SignupOrGetExisting`; `SignupInput` requires
`PersonalOrgSlug` from the caller and no slug derivation exists.
`SignupOrGetExisting` looks up by email and returns the existing account
only when `EmailVerified` is set. No non-test code calls `signup`.
SystemAuth's social login (`identity/systemauth/social_login.go`) resolves
an account through `ResolveExternalLogin`: the `(provider, subject)` link,
then a verified-email match which it links, then
`PrincipalDirectory.CreateFromExternal`, which writes the human, principal
and `ExternalIdentity` rows and no organization or membership.

**Claims and tokens.** `socialSessionProvider.GetUserClaims` returns `sub`,
`managed` (when the login has no email), and the scope-gated `email`,
`email_verified`, `name` and `picture`. `UserInfoClaims` filters standard
claims by scope and passes others through; `prepareAccessClaims` adds only
`sub` and `client_id` to JWT access tokens. There is no `orgs` claim, no
`/userinfo/memberships` (userinfo is `/oauth/userinfo`), and no
back-channel logout: no code, and no logout URI on `OAuthApp`. Token
lifetimes live under `tokens` in `systemauth.Config`
(`access_token_lifetime` 15m, `refresh_token_lifetime` 168h,
`refresh_token_absolute_lifetime` 720h, `id_token_lifetime` 1h) with
per-client overrides in `ClientConfig` and the `OAuthApp` columns
`access_token_ttl`, `refresh_token_ttl`, `login_token_ttl`.
`RevokeSubjectTokens` is called only from `/logout`; `RemoveMember`,
`UpdateMember` and `TransferOwnership` call the authz syncer and nothing
else, so **membership changes have never revoked refresh tokens**. ADR-007
decision 9 described an intended behavior, not an implemented one; ADR-010
decision 5 therefore removes nothing and only fixes the rule.

**Invites.** `identity/invite.Invite` carries `OrganizationID,
InviterPrincipalID, Email, Role, Status, Message, ExpiresAt, ...` with a
hashed token; `Accept` checks status and expiry, refuses an existing
member, creates the membership with `inv.Role` in a transaction and marks
the invite accepted. It does not call `RelationshipSyncer.AddOrgMembership`
(`DefaultService` holds only the client and base URL), so a relationship
engine never learns of members who joined by invite. There are no resource
fields, no invite kind and no application-role selection.

**Relying parties.** `identity/relyingparty` has `MembershipSource`,
`MembershipQuery{Principal, Subject, Claims}`, `MembershipLister`,
`LocalMemberships` and `NoMemberships`; `defaultMembershipSource` picks
the explicit source, else `LocalMemberships` when the `PrincipalStore`
implements `MembershipLister`, else `NoMemberships`. `Membership{ID,
OrganizationID, OrganizationName, OrganizationSlug, Role, JoinedAt}`.
`ResolvePrincipal(ctx, store, VerifiedIdentity, now)` is the existing
first-sign-in hook and `VerifiedIdentity.Managed` comes from the `managed`
claim. `pgstore` creates `sf_rp_sessions` and `sf_rp_login_states` only.
There is no revocation cache and no access-change handling;
`SessionStore.DeleteBySubject` and `DeleteBySID` exist with comments
written for back-channel logout.

**Managed principals.** `identity/managedprincipal.Service.IsManaged`
answers `human.EmailIsNil()`, and the `managed` claim is `lp.Email == ""`.
`CreateInput{ClientID, DisplayName, Managers, ActorID}` has no email;
`RemoveManager` refuses the last manager only when `Email == nil`;
`AttachVerifiedEmail` sets the email and default capabilities and keeps
the relationships. There is no `Release`. The only manager-invitation
path is the claim code (`IssueClaim`/`RedeemClaim`, `sf_manager_claims`).
The deployment switch is `managed_principals.enabled` with
`login_token_ttl`, `login_token_max_ttl` and `single_use_token_ttl`
beside it.

**Authorization.** The real packages are `authz/rbac` and
`authz/rebac/spicedb`; `authz/simple` and `authz/spicedb` are deprecated
type-alias forwarders (the package doc in `authz/authorizer.go` and the
opening comment of `authz/rbac/provider.go` still say "simple" and
"spicedb"). `Authorizer{Can, CanAll, CanAny, Filter}`,
`OrgAuthorizer{CanForOrg, GetRole, IsMember}`, `PlatformAuthorizer`,
`DecisionAuthorizer` and `FeatureAuthorizer{CanWithFeature}` are defined;
**`FeatureAuthorizer` has no implementation**. `RelationshipSyncer` has
organization membership, principal, organization, platform-admin and
manager operations. `BaseSpiceDBSchema` defines `organization` with
relations `owner, admin, editor, member, viewer` and permissions `manage =
owner + admin`, `edit = manage + editor`, `contribute = edit + member`,
`view = contribute + viewer`, the four management permissions equal to
`manage`, and `delete = owner`; `principal` with `guardian`/`educator`;
`platform`. There is no `collaborator` relation and no `list` permission,
no `GrantResourceRole`, `RevokeResourceRole`, `ListResourceGrants` or
`ListResources` on the contract (only `rebac/spicedb.Client.LookupResources`
and the provider's raw relationship writes), and no `authz.mode`
configuration (the only `Mode` is SpiceDB's `embedded | remote`).
`docs/authz-conventions.md` documents the `owner/admin/editor/member/viewer`
ladder. `authz/schema_parity_test.go` holds `OrgRolePermissions` and
`ManagerRolePermissions` equal to the schema; `authz/providertest` runs
interface, behavior, organization-permission and manager-relation suites
against `rbac`. `marketplace/schema/marketplace.zed` carries its own
`organization` definition (`owner/admin/member/viewer`, `edit = manage +
member`, `use/billing/purchase`) that conflicts with the base schema.

**Marketplace.** `Listing{CreatorOrgID, ProductType, ProductID, ...}`,
`License{ListingID, OrganizationID, LicenseType, Seats, UsedSeats,
ValidFrom, ValidUntil, ...}`, `SeatAssignment{LicenseID, PrincipalID,
...}`, `Subscription{OrganizationID, PlanTier, Status, ...}` with
`PricingModel` in `free | one_time | subscription | per_seat`,
`LicenseType` in `seat_based | team | unlimited` and `SubscriptionStatus`
in `active | trialing | past_due | canceled | unpaid`. Nothing maps a
listing to a registered application identifier, and `Subscription.PlanTier`
is never written to `Organization.plan`. `PurchaserChecker{IsManaged}` is
implemented by `managedprincipal.Service`.

**Schema.** Tables are `sf_*` under `identity/ent/schema`; relevant ones
are `sf_organizations`, `sf_principal_memberships` (unique on
`(principal_id, organization_id)`), `sf_invites`,
`sf_manager_relationships`, `sf_manager_claims`, `sf_oauth_apps`,
`sf_oauth_tokens`, `sf_principal_tokens`, `sf_login_sessions`,
`sf_listings`, `sf_licenses`, `sf_seat_assignments`, `sf_subscriptions`.
`sf_slug_reservations`, `sf_app_roles`, `sf_access_changes` and
`sf_resource_grants` do not exist. Migrations so far:
`0001_rename_cf_to_sf.sql`, `0002_drop_legacy_user_tables.sql`,
`0003_hash_invite_tokens.sql`.

## Design

### 1. Organization lifecycle (Phase 1, ADR-006)

#### 1.1 Signup on first social login (RMI-124)

`ResolveExternalLogin` keeps its order: provider identity, then verified
email, then create. The create step changes: `EntPrincipalDirectory.
CreateFromExternal` calls `signup.SignupOrGetExisting` with
`PersonalOrgSlug` from `SlugForLogin` (§1.2) and links the external
identity in the same transaction, so a first login produces the human,
principal, external identity, personal organization (type `personal`,
owner set) and owner membership together, or nothing. `SignupOrGetExisting`
gains a `ProviderIdentity` lookup before the email lookup so the two paths
agree, and keeps refusing an unverified email. The directory is built with
the `signup.Service` (`NewEntPrincipalDirectory(client, signupSvc)`);
`MemoryPrincipalDirectory` creates an in-memory personal organization so
handler tests observe the same shape.

#### 1.2 Slug derivation and reserved slugs (RMI-125)

```go
// signup
func SlugForLogin(provider, providerLogin, email string) string
func SlugForManaged(entered string) string   // entered or generated
```

`SlugForLogin` returns the GitHub username for `github`, the local part of
the email for `google`, and otherwise the local part; the result passes
through `slugify` (lowercase, invalid runes to `-`, `-org` padding under
three characters) and the collision rule in `organization.GenerateSlug`
(`-1` … `-100`, then an 8-character random suffix). `SlugForManaged`
returns the manager-entered value when present, else two words and a
number from a fixed word list (`quiet-otter-42`), never anything derived
from an email (ADR-009). `organization.ReservedSlugs` is the built-in list
(`admin`, `api`, `o`, `login`, `logout`, `oauth`, `scim`, `invites`,
`organizations`, `well-known`, `www`, `support`, `help`, `about`,
`settings`, `new`) plus `WithReservedSlugs(...)` for deployment-configured
product names; `SlugAvailable` refuses them with `ErrSlugReserved`, and
`Create`, `CreatePersonalOrg`, `Rename` and SCIM group creation go through
`SlugAvailable`.

#### 1.3 Slug changes with cooling-off and aliases (RMI-126)

New Ent schema `SlugReservation` → `sf_slug_reservations`:

| Field | Notes |
|---|---|
| `slug` | unique |
| `released_by_principal_id` | → `Principal`; the acting principal |
| `released_from_organization_id` | → `Organization`, nullable (the organization may be deleted) |
| `released_at` | |
| `expires_at` | `released_at + 7 * 24h` (`organization.SlugCoolingOff`, configurable) |

Indexed on `expires_at`. Rows are deleted when the slug is reassigned or
on first read after expiry.

```go
Rename(ctx, orgID uuid.UUID, slug string, actor uuid.UUID) error
ResolveSlug(ctx, slug string) (*Organization, bool /*alias*/, error)
```

`Rename` in one transaction: validates the new slug; `SlugAvailable`
(exact match, reserved list, and a live reservation held by someone other
than `actor` or an organization `actor` owns → `ErrSlugCoolingOff`); writes
the organization; deletes any reservation for the new slug; inserts a
reservation for the old slug with `actor`. `ResolveSlug` tries the exact
match, then a live reservation's `released_from_organization_id`.
`GetBySlug` keeps exact-match semantics; HTTP handlers that resolve
`{slug}` use `ResolveSlug` and answer with the current slug in the body.
The rule is symmetric: it does not care whether either organization is
personal or team, so person → organization, organization → person,
organization → organization and reclaiming one's own handle are the same
code path.

#### 1.4 Personal organization rules (RMI-127)

`AddMember`, `UpdateMember`, `invite.Create`, the members API and SCIM
group membership refuse a personal organization with
`ErrPersonalOrganization` unless the role is `collaborator` (§4).
`TransferOwnership` refuses with the same error. The organization API
stops accepting `org_type: personal` on create (`enum:"team,enterprise"`);
personal organizations are created only by signup and by `ConvertToTeam`.
Existing tests that add members to a personal organization move to team
organizations.

#### 1.5 `ConvertToTeam` (RMI-128)

```go
ConvertToTeam(ctx, orgID uuid.UUID, teamSlug string, actor uuid.UUID) (*ConvertResult, error)
// ConvertResult{Team *Organization, Personal *Organization}
```

One transaction, in order: assert `orgID` is personal and `actor` is its
owner; `handle := org.Slug`; `Rename(orgID, teamSlug)` (which reserves
`handle` for `actor`); set `org_type = team`; `CreatePersonalOrg{Owner:
actor, Slug: handle}` (allowed by the reservation, which it consumes).
Memberships, settings and the ID are untouched; the owner membership
becomes the team's first owner. Audit records both organization IDs.

#### 1.6 Remove the `plan` column (RMI-129)

Drop `plan` from the `Organization` Ent schema (migration
`0004_drop_organization_plan.sql`), `Organization`, `UpdateOrganizationInput`,
`ListOrganizationsInput`, the create/update/list API, the SCIM mapper and
store, and the `Plan` type with its constants. The organization API gains:

```json
"entitlements": {
  "apps": {"<application>": {"source": "subscription|license|default", "listing_id": "...", "seats": 10, "seats_used": 3}}
}
```

derived by `marketplace.Entitlements(ctx, orgID)` (§2.2); until Phase 2
lands, the summary contains only default entitlements. `marketplace.
PlanTier*` stays: it describes a subscription, not an organization.

### 2. Memberships and entitlements as claims (Phase 2, ADR-007)

#### 2.1 Application roles (RMI-130)

New Ent schema `AppRole` → `sf_app_roles`:

| Field | Notes |
|---|---|
| `principal_id` | → `Principal` |
| `organization_id` | → `Organization` |
| `application` | application identifier as registered in `authz.VocabularyRegistry` |
| `role` | validated against `AppVocabulary.Roles()` |
| `assigned_by` | → `Principal` |
| timestamps | `BaseMixin` |

Unique on `(principal_id, organization_id, application)`; indexed on
`(organization_id, application)` for seat counting. A new package
`identity/approle` owns `Assign`, `Change`, `Remove`, `ListForPrincipal`,
`ListForOrganization` and `EffectiveRoles(ctx, principalID, orgID)
map[string]string`, which overlays the implicit `admin` for the
organization owner on every entitled application. Rules: the application
must be entitled for the organization (§2.2); the principal must hold an
active membership with role `owner`, `admin` or `member` (collaborators
hold none); `organization.RemoveMember` deletes the principal's rows in
its transaction and records an access change (§3.1). Assigning to oneself
is allowed and audited. The `authz` syncer gains `AddAppRole` /
`RemoveAppRole` so `rebac` writes `{app}_org#<role>` relationships.

#### 2.2 Entitlements from the marketplace (RMI-131)

`Listing` gains an optional `application` field mapping the listing to a
registered application identifier. `marketplace.Entitlements(ctx, orgID)`
returns the set of applications with an active subscription (`active` or
`trialing`) or a license valid now on such a listing, merged with
`marketplace.WithDefaultEntitlements(apps ...string)` (deployment
configuration, `marketplace.default_entitlements`). A deployment whose
registry has applications but no default entitlements and no listings
with `application` set logs a warning at startup. For seat-licensed
listings (`LicenseType` `seat_based`), `approle.Assign` counts
`sf_app_roles` rows for `(organization, application)` against `Seats` and
refuses with `ErrNoSeats`; `SeatAssignment` becomes derived from
`sf_app_roles` and its API is kept as a view for one release, then removed.

#### 2.3 The `orgs` claim (RMI-132)

ID token and userinfo (`/oauth/userinfo`):

```json
"orgs": [
  {"id": "…", "slug": "jane", "name": "Jane", "type": "personal", "role": "owner",
   "apps": {"notes": "admin", "boards": "admin"}},
  {"id": "…", "slug": "acme", "name": "Acme", "type": "team", "role": "member",
   "apps": {"notes": "contributor"}}
],
"orgs_truncated": false
```

JWT access tokens: `"orgs": [{"id": "…", "role": "owner", "apps": {...}}]`
and `orgs_truncated`. Both are built by one function,
`systemauth.OrgsClaim(ctx, principalID, compact bool)`, ordered personal
first, then by membership `created_at` descending, capped at
`MaxOrgsInToken = 50`; `apps` comes from `approle.EffectiveRoles`
filtered to entitled applications, so an application absent from `apps` is
one the principal may not open. Collaborators appear with role
`collaborator` and empty `apps`. The claim is emitted regardless of scope
(it is authorization data, like `managed`). `GET /oauth/userinfo/memberships?
limit=&cursor=` returns the full list for the presenting token's principal,
in the ID-token shape, paginated by membership ID.

#### 2.4 Relying-party membership sources (RMI-133)

```go
func ClaimsMemberships() MembershipSource      // orgs claim from ID token or userinfo
func RemoteMemberships(c *Client) MembershipSource // GET /oauth/userinfo/memberships
```

`Membership` gains `OrganizationType`, `Apps map[string]string` and
`Truncated` on the result. `defaultMembershipSource` becomes
`ClaimsMemberships` chained to `RemoteMemberships` when `orgs_truncated`
is set or the claims hold only the compact form (no `slug`);
`LocalMemberships` must be chosen explicitly and its doc comment says
development and tests only. `BFFConfig` gains `OnFirstUse func(ctx,
OrganizationRef) error`, called once per organization ID per process
(memoized with single-flight) when a principal holding a role in it first
makes a request, so an application provisions its own rows keyed by the
SystemAuth organization ID. The stale role comment on `Membership.Role`
is corrected to the ADR-007 roles.

#### 2.5 Invites and member management carry application roles (RMI-134)

`Invite` gains `AppRoles map[string]string` (JSON column `app_roles`),
validated at `Create` against the organization's entitlements and each
application's ladder, with no application preselected on the SystemAuth
invite page. `Accept` creates the membership, the `sf_app_roles` rows and
(fixing the existing gap) calls the authz syncer, in one transaction.
`PATCH /organizations/{slug}/members/{principal_id}/apps/{application}`
assigns or changes one application role; `DELETE` removes it; neither
touches the membership row. The SystemAuth member page lists entitled
applications with a role picker per application.

### 3. Real-time invalidation of access (Phase 3, ADR-010)

#### 3.1 Access-change records and refresh semantics (RMI-135)

New Ent schema `AccessChange` → `sf_access_changes`:

| Field | Notes |
|---|---|
| `principal_id` | → `Principal` |
| `organization_id` | → `Organization`, nullable (null = every organization) |
| `changed_at` | server clock at commit |
| `reason` | enum: `membership_removed`, `org_role_changed`, `app_role_changed`, `grant_reduced`, `deactivated`, `sessions_revoked` |

Indexed on `changed_at`. `accesschange.Record(ctx, tx, Change)` is called
inside the transactions of: `organization.RemoveMember`, `UpdateMember`
(role change), `TransferOwnership` (both principals); `approle.Change`
and `Remove`; `authz` `RevokeResourceRole` and a grant change to a lower
role (§4.2); `principal.Deactivate`; `RevokeSubjectTokens`,
`managedprincipal.RevokeSession` and `RevokeAll`. Every record is also
pushed to the configured `AccessChangeSink` (§3.2) after commit. Refresh
tokens are revoked by deactivation and explicit revocation only; a role or
membership change leaves the refresh token valid and the next refresh
re-evaluates `OrgsClaim`. `tokens.access_token_lifetime` defaults to 10m
and is validated at load to be at most `MaxAccessTokenLifetime = 15m`;
per-client and `OAuthApp` overrides are clamped to the same ceiling.
Rows older than `MaxAccessTokenLifetime + margin + 1h` are pruned by the
existing maintenance job.

#### 3.2 Relying-party revocation cache (RMI-136)

```go
// relyingparty
type AccessChange struct {
    PrincipalID    string
    OrganizationID string // "" for every organization
    ChangedAt      time.Time
    Reason         string
}

type AccessChangeSink interface { Record(AccessChange) }

type RevocationCache struct { /* mutex, map[string]time.Time keyed by principal and principal+"/"+org */ }
func NewRevocationCache(opts ...CacheOption) *RevocationCache // WithSkewMargin, WithMaxTokenLifetime, WithClock
func (c *RevocationCache) Record(ch AccessChange)
func (c *RevocationCache) Accept(principalID, orgID string, iat time.Time) bool
```

Algorithm. On `Record`, store `max(existing, changed_at)` under the
principal key when `OrganizationID` is empty, else under the
principal/organization key. On every request, after signature
verification, `Accept` is evaluated for the token's `sub` and for the
organization the request addresses (when the middleware knows it):

```
margin   = max(configured, 15s); default 30s
changed  = latest of cache[principal], cache[principal/org]
accept   = no entry || iat >= changed + margin
```

A token stamped inside the margin is treated as issued before the change
and refused. A refusal is answered as `401` with
`error=invalid_token, error_description="token expired"` so the OIDC
client refreshes; the refresh yields the reduced claims. Entries are
dropped when `now > changed_at + maxTokenLifetime + margin`, sweeping on
`Record` and on a ticker; after that moment no token issued before the
change can still be valid at any verifier, however its clock drifted
within the margin. Cache size is therefore bounded by the number of
changes within one lifetime plus margin. In one process, SystemAuth's
`accesschange.Record` writes to the same `RevocationCache` instance passed
as the sink, in the recording transaction's post-commit hook; both
timestamps come from one clock so the margin is moot there, but it is
applied uniformly.

#### 3.3 Replica poller and replay (RMI-137)

`relyingparty.NewAccessChangePoller(db, cache, interval)` runs an indexed
query `WHERE changed_at > $last ORDER BY changed_at` every `interval`
(default 1s, allowed 1–2s), records each row and advances `last` to the
newest `changed_at` seen minus the margin (so a late-committing row with
an earlier timestamp is re-read, deduplicated by `max`). SystemAuth adds
`GET /access-changes?since=<RFC 3339>` (bearer-authenticated with a client
credential holding scope `access_changes:read`) returning rows newer than
`since` in the sink shape. `relyingparty.Replay(ctx, client, cache)` is
called before the server starts serving with `since = now −
maxTokenLifetime − margin`; until it returns, the middleware is in
**suspect mode**: every token is accepted only after a `RemoteMemberships`
call for its principal (memoized per `jti`), which is slower but never
wider than the pre-change state. Replay failure is retried with backoff
and logged; the server stays in suspect mode.

#### 3.4 Back-channel delivery (RMI-138)

`OAuthApp` gains `backchannel_logout_uri` (and `ClientConfig` the same).
`systemauth.Backchannel` sends, for each registered client, an OpenID Connect Back-Channel
Logout 1.0 logout token (`typ: logout+jwt`) with `sub`, `sid` when known, and
`events: {"http://schemas.openid.net/event/backchannel-logout": {},
"urn:systemforge:event:access_change": {organization_id, changed_at,
reason}}`, signed with the issuer key, `POST`ed as
`logout_token=<jwt>`. Delivery is queued after commit, retried with
exponential backoff for up to the token lifetime, and failures are logged
against the client ID. `relyingparty.BackchannelHandler(cache, verifier)`
verifies the token against the issuer's JWKS, records the
`access_change` event into the cache, and on a plain logout event
deletes sessions by `sid` or subject through the existing `SessionStore`
methods. An application configures one of `WithSharedCache(cache)`,
`WithPoller(db)` or `WithBackchannel(path)` depending on the boundary it
sits on.

### 4. Resource-scoped collaborators (Phase 4, ADR-008)

#### 4.1 Base schema and conventions (RMI-139)

`BaseSpiceDBSchema.organization` gains `relation collaborator: principal`
and `permission list = view + collaborator`. Because the base schema
already has `editor` (which ADR-008's example omits), `list` is defined
through `view` so every existing role keeps `list` and collaborators gain
only it; `view`, `edit`, `manage` and the management permissions are
unchanged and exclude collaborators. `organization.RoleCollaborator =
"collaborator"` joins the role constants and the API enums;
`OrgRolePermissions[collaborator] = {PermOrgList}` with the new
`PermOrgList = "list"`, and `schema_parity_test.go` checks both.
`docs/authz-conventions.md` reserves the resource-role ladder
`viewer < contributor < maintainer` with the fragment shape from ADR-008
and states that `admin` on a resource is not a resource role (it is an
application role). `marketplace/schema/marketplace.zed` drops its own
`organization` definition and attaches `use`, `billing` and `purchase`
through a `marketplace_org` facet on the base `organization`, as the
vocabulary rules require. Personal organizations accept memberships of
role `collaborator` only (§1.4).

#### 4.2 Resource grants in `rbac` (RMI-140)

New Ent schema `ResourceGrant` → `sf_resource_grants`:

| Field | Notes |
|---|---|
| `principal_id` | → `Principal` |
| `organization_id` | → `Organization` (the resource's organization) |
| `resource_type` | `{app}_{type}` as declared in the vocabulary |
| `resource_id` | string |
| `role` | `viewer | contributor | maintainer` |
| `granted_by` | → `Principal` |

Unique on `(principal_id, resource_type, resource_id)`; indexed on
`(organization_id, principal_id)` and `(resource_type, principal_id)`.
The `authz` contract gains:

```go
type ResourceGranter interface {
    GrantResourceRole(ctx, principal, resource Resource, role string, granter uuid.UUID) error
    RevokeResourceRole(ctx, principal, resource Resource) error
    ListResourceGrants(ctx, resource Resource) ([]Grant, error)
    ListResources(ctx, principal uuid.UUID, resourceType, permission string) ([]string, error)
}
```

`rbac` stores rows and, in the same transaction, creates the
`collaborator` membership when the principal has no membership in the
resource's organization; `RevokeResourceRole` deletes the row and removes
the membership when it was the principal's last grant and its role is
`collaborator`. A grant to a lower role or a revoke records an access
change with reason `grant_reduced`. `Can` consults the grant table after
the organization role: `view` ⇐ any of the three, `edit` ⇐ contributor or
maintainer, `manage` ⇐ maintainer, mapped through the vocabulary's
resource permissions. `ListResources` in `rbac` is an indexed query over
`sf_resource_grants` unioned with every resource of the organizations where
the principal's organization role already grants the permission (returned
as the organization IDs with a wildcard marker, so the application can
apply it as `org_id IN (...) OR id IN (...)`).

#### 4.3 Resource grants in `rebac/spicedb` (RMI-141)

The same contract: grants are `{resource}#<role>@principal:<id>`
relationships; `ListResources` is `LookupResources` for the permission;
the collaborator membership is written as `organization#collaborator`.
`ValidateAppSchema` additionally checks that any definition with
`viewer`/`contributor`/`maintainer` relations declares all three, binds
them to `principal`, and has an `org: organization` relation.
`providertest` gains `RunResourceGrantTests` (grant, revoke, last-revoke
removes membership, lower-role reduction, `ListResources` for each
permission, collaborator sees `list` and nothing else on the organization)
and runs it against both providers; the suite is written before the
`rebac` implementation so it is the specification for both.

#### 4.4 Resource-targeted invites (RMI-142)

`Invite` gains nullable `resource_type`, `resource_id`, `resource_role`;
`Create` validates them against the vocabulary and requires `Role =
collaborator` when set. `Accept` creates the collaborator membership, the
grant and the authz relationships in one transaction. Personal
organizations accept only resource-targeted invites (§1.4).

#### 4.5 `authz.mode` configuration (RMI-143)

`authz.Config{Mode: "rbac" | "rebac", Engine: "spicedb", SpiceDB:
spicedb.Config}` with `authz.New(ctx, cfg, deps)` returning the provider;
`systemauth.Config` gains the `authz` key. `authz/simple` and
`authz/spicedb` carry `// Deprecated:` notices naming the next major
release as their removal; the stale package comments are fixed. The
authorization architecture page gets the mode-choice tables from ADR-008.

### 5. Management is a relationship (Phase 5, ADR-009)

#### 5.1 Management derived from relationships (RMI-144)

`IsManaged` becomes `ManagerRelationship.Query().Where(managed ==
principalID, active).Exist`. The `managed` claim in
`socialSessionProvider.GetUserClaims` and the login-token exchange is
built from the same query (through a `ManagedChecker` on the session
provider), not from the email. `ErrNotManaged` reads "principal has no
active manager"; `ErrLastManager` reads "the last manager of a principal
without a verified email cannot be removed" and `RemoveManager` tests
`Email == nil || EmailVerifiedAt == nil`. `CreateInput` gains `Email
*string`; when set, the human is created with the email unverified and the
existing verification flow verifies it, so it counts for release only
afterward. `ManagedHumanCapabilities` apply while managed, whatever the
email; `AttachVerifiedEmail` stops restoring default capabilities, which
`Release` now does.

#### 5.2 Release and manager invitations (RMI-145)

```go
Release(ctx, actorID, managedID uuid.UUID) error
```

requires `manage_managers`, a verified email, and in one transaction
deactivates every manager relationship, restores default capabilities,
removes the authz manager relationships and audits the release.
`Invite` gains `kind` (`organization | manager`, default `organization`)
and `manager_role`; a manager invite names no organization, is created by
the prospective manager (an active, verified, unmanaged human) for an
existing self-managed principal's email, and is accepted only by the
signed-in principal whose email matches, which creates the relationship,
sets managed capabilities and audits the consent. `IssueClaim`/`RedeemClaim`
remain the path from `educator` to `guardian`. Slug derivation for managed
principals uses `SlugForManaged` only (§1.2).

## Migration Notes

- `0004_drop_organization_plan.sql` drops the column; no data is carried
  over because the column was never consulted. Release notes state that
  API clients sending `plan` receive a validation error.
- New tables are added by the Ent migration in the order the phases land:
  `sf_slug_reservations`, `sf_app_roles`, `sf_access_changes`,
  `sf_resource_grants`; new columns on `sf_invites` (`app_roles`,
  `resource_*`, `kind`, `manager_role`), `sf_oauth_apps`
  (`backchannel_logout_uri`), `sf_listings` (`application`) and
  `sf_humans` (none; email already optional).
- Existing principals without a personal organization get one on their
  next login through the same `SignupOrGetExisting` path; a one-off
  `sf-admin backfill personal-orgs` command does it for principals that
  never return.
- Existing `sf_seat_assignments` rows are converted to `sf_app_roles` rows
  with the listing's application and the ladder's lowest role, after which
  the seat-assignment API serves from `sf_app_roles`.
- Relationship engines are rebuilt from the membership, app-role and grant
  tables by the existing sync on startup when switching modes.
- Applications on `LocalMemberships` keep working until they choose a
  source; the default change is called out in the release notes.

## Sequencing Constraints

- §1.6 precedes §2.2: entitlements replace `plan`, so the summary exists
  before the derivation fills it.
- §2.1 precedes §2.3 and §2.5; §2.2 precedes §2.3.
- §3.1 precedes §3.2; §3.2 precedes §3.3 and §3.4. §3.1's grant-reduction
  site is wired when §4.2 lands.
- §4.1 precedes §4.2 and §4.3; §4.2 and §4.3 precede §4.4 and §4.5. §4.1
  needs only the `collaborator` role from §1.4.
- §5.2's manager invite reuses the invite kinds introduced with §2.5.
- Phase 6 follows everything.

## Security Considerations

- **Slug squatting and handle theft.** The reservation is bound to the
  releasing principal; reserved names are refused before any lookup;
  `ResolveSlug` never follows an expired reservation. Aliases are read-only
  redirects and never grant access to the previous organization.
- **Token freshness.** The access token is the only thing a relying party
  trusts per request; the cache check runs after signature verification and
  before any application code; the margin floor prevents a misconfigured
  zero margin from accepting a token stamped by a slow clock after the
  change. The replay endpoint requires a client credential and returns no
  personal data beyond principal and organization IDs.
- **Back-channel tokens** are signed by the issuer, verified against the
  JWKS, and carry `iat`/`exp` and a `jti` the receiver remembers for the
  token lifetime to reject replays.
- **Claims size.** The 50-organization cap bounds the ID token and access
  token; the compact form omits names and slugs.
- **Collaborators** never gain `view`, `edit` or `manage` on the
  organization; aggregates and cross-resource references are the
  application's to filter using `ListResources`, and the scope gate still
  applies to their credential.
- **Seats** are enforced in the assignment transaction, so concurrent
  assignments cannot exceed the license.
- **Management consent.** A self-managed human becomes managed only by
  accepting an invite while signed in; `Release` requires a verified email
  so a managed principal is never left unreachable.
- **Audit.** Rename, conversion, role assignment, grant, revoke, release
  and every access change record the acting principal.

## Testing Strategy

- **Ent-backed service tests** (`enttest` SQLite in-memory) for signup on
  first login (first creates, second does not), slug derivation per
  provider, reserved slugs, rename with reclaim/stranger/expiry cases in
  every direction, `ConvertToTeam`, personal-organization refusals,
  `plan` absence, app roles with the owner overlay and seat limits,
  entitlement derivation, `Release`, manager invites.
- **SystemAuth handler tests** for the `orgs` claim in ID token, userinfo
  and access token (shape, ordering, truncation), `/oauth/userinfo/
  memberships` pagination, `/access-changes`, back-channel delivery with
  retry.
- **`relyingparty` tests** for `ClaimsMemberships`, `RemoteMemberships`
  fallback on truncation, the provisioning hook's once-per-organization
  guarantee, and a table-driven `RevocationCache` test covering the margin
  boundary (`iat == changed_at + margin − 1s` refused, `+ margin`
  accepted), per-organization scoping, expiry, floor enforcement, poller
  re-read of late rows, replay and suspect mode, back-channel receipt and
  replay rejection.
- **Access-change site tests**: one test per recording site asserting a row
  in `sf_access_changes` and a sink call in the same transaction, and no
  refresh-token revocation on role change.
- **`providertest`** resource-grant suite run against `rbac` and
  `rebac/spicedb`; `schema_parity_test.go` extended for `collaborator` and
  `list`; a test that `marketplace.zed` composes with the base schema.
- **Regression**: the INIT-007 managed-principal suite runs unchanged for
  a child created without an email; existing conformance suites pass with
  personal-organization tests moved to team organizations.
- **Documentation**: mkdocs strict build; `golangci-lint`
  clean.

## Discrepancies Found While Surveying

- ADR-007 decision 9 and ADR-010 decision 5 describe refresh-token
  revocation on membership change as current behavior; it never existed.
  RMI-135 adds the recording and leaves refresh tokens alone rather than
  removing a revocation.
- ADR-007's context says `authz.FeatureAuthorizer` can answer feature
  questions; the interface has no implementation. Entitlements are
  derived by `marketplace.Entitlements` and the interface is left for a
  later initiative.
- ADR-008's `list` example omits the base schema's `editor` relation;
  defining `list = view + collaborator` keeps editors.
- `marketplace.zed` defines its own `organization`, which the vocabulary
  rules forbid; §4.1 folds it into a facet.
- `invite.Accept` does not sync memberships to the relationship engine;
  §2.5 fixes it as part of carrying application roles.
- `SignupOrGetExisting` resolves by email only; §1.1 adds the provider
  identity lookup so it matches ADR-006's order.
- The managed-principal switch is `managed_principals.enabled`, not
  `identity.managed_principals.enabled` as the INIT-007 TRD wrote; this
  initiative's new keys (`authz`, `marketplace.default_entitlements`,
  `tokens.access_token_lifetime`) follow the actual top-level layout.
