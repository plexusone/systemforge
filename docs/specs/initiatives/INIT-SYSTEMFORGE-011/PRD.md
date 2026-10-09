# PRD — Suite Organizations: Lifecycle, Claims, Collaborators, Real-Time Invalidation

**Initiative:** `INIT-SYSTEMFORGE-011`
**Status:** Draft
**Home repo:** `github.com/plexusone/systemforge`
**Design of record:**
[ADR-006](../../../design/adrs/ADR-006-organization-lifecycle-personal-team-slugs.md),
[ADR-007](../../../design/adrs/ADR-007-memberships-and-entitlements-as-claims.md),
[ADR-008](../../../design/adrs/ADR-008-resource-scoped-collaborators.md),
[ADR-009](../../../design/adrs/ADR-009-management-is-a-relationship.md),
[ADR-010](../../../design/adrs/ADR-010-real-time-access-invalidation.md)
**Depends on:** INIT-SYSTEMFORGE-007 (managed principals and manager
relationships), INIT-SYSTEMFORGE-008 (single `Principal` root)

## Problem

SystemForge models organizations, memberships, invites, managed principals,
a marketplace and two authorization providers, but the lifecycle that ties
them into something an application can build on is missing. Five accepted
ADRs describe the gaps; this initiative implements them together because
they share tables, claims and transactions.

**Organizations have no lifecycle (ADR-006).** SystemAuth's social login
creates a bare principal and never calls `signup`, so a person's first
sign-in leaves them in no organization and every application needs an
operator step before the person can do anything. Slugs can be changed
freely: nothing remembers a freed slug, so a rename can be followed at once
by someone else taking the old name, and links to the old slug break. A
personal organization cannot become a team without creating a new
organization and moving everything, and nothing enforces what makes a
personal organization personal. The `plan` column on organizations is a
placeholder from before the marketplace: set at creation, never consulted,
and unable to describe an organization that holds several subscriptions.

**Applications keep their own membership tables (ADR-007).** SystemAuth is
meant to be the source of truth for memberships, roles and entitlements,
but it emits none of them, so every application keeps its own table fed by
operators or its own invite flow. In a deployment of several applications
behind one SystemAuth, the same organization has to be created in each, a
person has to be added to each separately, and removal from one does not
remove from another. The marketplace records what an organization is
entitled to, but applications cannot learn that from a login either.

**Access changes wait for token expiry (ADR-010).** Claims make requests
cheap because a relying party asks SystemAuth nothing per request; the cost
is that removing someone from an organization is not seen until their
token expires. For routine offboarding that is tolerable; for a contractor
cut off during a dispute, a compromised account or an agent whose mission
was revoked, it is not. Introspection on every request would reintroduce
the network hop the claims model removed; shorter lifetimes shrink the
window but never close it.

**Every grant is organization-wide (ADR-008).** There is no way to give
someone access to one resource — a project, a document, a site — without
making them a member of the organization. Solo users need that for
contractors, teams need it for outside reviewers, and personal
organizations have no members at all. The substrate already has the pieces
(relationships, vocabularies, lookups); the pattern should be defined once
rather than rebuilt per application.

**Management is inferred from a missing email (ADR-009).** A managed
principal is currently a human whose email is null. That excludes children
with a school-issued address, who still need a guardian in control, and
adults managed by arrangement, whose manager's authority comes from a
relationship they both accept. The email answers whether a person can be
contacted and verified; the relationship answers who may act for them.

## Goals

1. **A working organization after one login.** A first social login creates
   the principal and its personal organization in one transaction, with a
   slug derived from how the person arrived.
2. **Safe, reversible renames.** A freed slug is held for seven days for its
   previous holder, resolves to its previous organization as an alias for
   that time, and the same rule applies to every kind of rename.
3. **Solo to team without moving data.** A personal organization converts
   to a team keeping its ID, data and memberships; the person keeps their
   handle on a fresh personal organization.
4. **Entitlement per listing, not per organization.** The `plan` column is
   removed and an `entitlements` summary derived from marketplace
   subscriptions and licenses takes its place.
5. **Memberships, application roles and entitlements as claims.** The ID
   token, userinfo and access token carry an `orgs` claim; applications
   read it through `relyingparty` and keep no membership tables of their
   own.
6. **Access changes take effect within one request** in the same process,
   within the polling interval on replicas, within back-channel delivery
   time across deployments, and within one token lifetime if every signal
   is lost.
7. **Collaborators on both authorization modes.** Resource grants,
   `ListResources` and resource-targeted invites behave the same under
   `rbac` and `rebac`, verified by a shared conformance suite.
8. **Management is a relationship.** `IsManaged` and the `managed` claim
   derive from active manager relationships; email decides only whether
   management may end.

## Non-Goals

- Pricing and packaging policy: which tiers exist, whether there is a free
  tier, trial lengths. The marketplace expresses them; applications choose
  them.
- Custom or organization-defined application roles, and teams as carriers
  of roles. The roles are the ones an application's vocabulary declares;
  teams are the first addition if per-person assignment becomes the
  problem.
- Resource grants as claims. The `orgs` claim lists a collaborator's
  organizations; the resources they may access are the application's to
  look up.
- Revocation of agent tokens. AAuth tokens carry their own cascading
  revocation keyed by `jti`; this initiative covers SystemAuth-issued
  tokens.
- Moving a resource between organizations. An application that supports it
  must move the grants and the collaborator memberships they imply.
- Deciding what a managed principal may do for itself. The platform
  supplies the relationship, the roles and the `managed` claim; the split
  is the application's vocabulary.
- Any product-specific signup page, organization switcher or invite screen.
  SystemAuth's own pages and API are in scope; an application's user
  interface is not.

## Users and Stakeholders

| Who | Needs |
|---|---|
| A person signing in for the first time | An organization that works at once, with a handle they recognize, no operator involved |
| A solo user | Contractors with access to one resource, not the organization; a path to a team that keeps their data and ID |
| An organization administrator | Invites and member screens that choose application roles per application; role changes that take effect now; a rename that does not break links |
| An application on SystemForge | Organizations, roles and entitlements from the login, keyed by a stable organization ID; a first-use provisioning hook; a one-line revocation cache; `ListResources` to filter queries for collaborators |
| A suite of applications behind one SystemAuth | One membership, one invite, one removal across every application; no per-application organization tables |
| A manager of a managed principal | Management that survives the principal gaining an email; an explicit, audited release |
| A deployment operator | A configured access-token lifetime, clock-skew margin, default entitlements and `authz.mode`, each documented with its default |

## Requirements

### Organization lifecycle (ADR-006)

- **F1.** SystemAuth's GitHub and Google login call
  `signup.SignupOrGetExisting` for a principal they have not seen; the
  principal and its personal organization are created in one transaction
  with the principal as owner. A later login resolves by provider identity
  first, then by verified email, and creates nothing.
- **F2.** The personal slug is derived in one place, `signup.SlugForLogin`:
  the GitHub username; the local part of a Google email; for a managed
  principal, a manager-entered name or a generated slug that reveals
  nothing about the person; a numeric suffix on collision.
- **F3.** A reserved-slug list (`admin`, `api`, `o`, `login`, `oauth`,
  well-known names and deployment-configured product names) is refused by
  `SlugAvailable`.
- **F4.** Every slug change frees the old slug into a seven-day cooling-off
  period during which only the releasing principal, or an organization that
  principal owns, may take it. The freed slug resolves to its previous
  organization as an alias until reassigned or expired; lookups consult
  aliases after exact matches. The rule applies to personal and team
  organizations and in every direction.
- **F5.** A personal organization has exactly one member, its owner.
  `AddMember` and invites are refused for personal organizations except for
  role `collaborator`; `TransferOwnership` is refused.
- **F6.** `ConvertToTeam` keeps the organization's ID, data and memberships,
  sets its type to `team`, takes a free team slug chosen at conversion, and
  creates a new personal organization with the person's handle for the
  owner, in one transaction.
- **F7.** The `plan` column is removed from `sf_organizations`, the
  `organization` service inputs and list filter, API responses, the SCIM
  default and the `Plan*` constants. The organization API gains an
  `entitlements` summary derived from the marketplace.

### Memberships and entitlements as claims (ADR-007)

- **F8.** Application roles are stored per (principal, organization,
  application) in `sf_app_roles`, validated against the application's
  `AppVocabulary` ladder. Owners hold `admin` in every entitled application
  implicitly; admins and members hold only what is assigned, none by
  default; collaborators hold none. Removal from the organization removes
  every application role.
- **F9.** The applications an organization may assign roles in derive from
  its active subscriptions and licenses per listing, mapped to registered
  application identifiers, plus deployment-configured default
  entitlements. A deployment with no entitlements at all logs a warning at
  startup. A seat-licensed application counts its `sf_app_roles` rows
  against the license.
- **F10.** The ID token and userinfo carry `orgs`: a list of `{id, slug,
  name, type, role, apps}` with `apps` a map of application identifier to
  application role. JWT access tokens carry the compact `{id, role, apps}`.
  A token carries at most 50 organizations, personal first then by most
  recent membership, with `orgs_truncated: true` when any were omitted;
  `GET /userinfo/memberships` returns the full paginated list.
- **F11.** `relyingparty` reads memberships from claims by default
  (`ClaimsMemberships`), from the memberships endpoint when truncated or
  when only the compact form is present (`RemoteMemberships`), and keeps
  `LocalMemberships` for development only. Applications get a first-use
  provisioning hook keyed by organization ID.
- **F12.** Invite creation and acceptance, and member management, carry
  per-application role selection with none preselected; roles change per
  application without touching the membership. SystemAuth's pages and API
  expose both.

### Real-time invalidation of access (ADR-010)

- **F13.** Every access change — membership removal, organization or
  application role change, a grant reduction, deactivation, session
  revocation — is recorded in `sf_access_changes` as `(principal_id,
  organization_id or null, changed_at, reason)` inside the transaction that
  makes the change.
- **F14.** A role or membership change no longer revokes refresh tokens;
  the next refresh carries the reduced claims. Deactivation and explicit
  session revocation still revoke.
- **F15.** The access-token lifetime defaults to 10 minutes, is
  configurable, and may not exceed 15 minutes.
- **F16.** `relyingparty` keeps a revocation cache keyed by principal (and
  organization when scoped) and accepts a token only if `iat >= changed_at
  + margin`, with a configurable clock-skew margin defaulting to 30 seconds
  and floored at 15. A rejected token is answered as expired so the client
  refreshes. Entries expire at `changed_at + maximum lifetime + margin`.
- **F17.** In one process the cache is shared memory, written in the
  recording transaction. Replicas poll `sf_access_changes` every one to two
  seconds. Separate deployments receive an OIDC Back-Channel Logout token
  carrying an `access_change` event, with retry and logging.
- **F18.** After a restart a relying party replays `GET
  /access-changes?since=` before serving and treats every token as suspect
  until replay succeeds.

### Resource-scoped collaborators (ADR-008)

- **F19.** The base schema gains a `collaborator` relation and a `list`
  permission on `organization`; collaborators have no `view`, `edit` or
  `manage`. `collaborator` is a membership role. The
  viewer/contributor/maintainer resource-role ladder is reserved in
  `docs/authz-conventions.md`.
- **F20.** `authz` gains `GrantResourceRole`, `RevokeResourceRole`,
  `ListResourceGrants` and `ListResources`, implemented by `rbac` through
  `sf_resource_grants` and by `rebac/spicedb` through relationships and
  `LookupResources`. The first grant to a non-member creates a
  `collaborator` membership; revoking the last grant removes it.
- **F21.** Invites may target a resource (type, ID, role); acceptance
  creates the collaborator membership and the grant in one transaction.
- **F22.** Applications configure `authz.mode: rbac | rebac` and, for
  `rebac`, an engine. The deprecated `authz/simple` and `authz/spicedb`
  forwarders are scheduled for removal in the next major release.

### Management is a relationship (ADR-009)

- **F23.** `IsManaged` and the `managed` claim derive from active manager
  relationships. `ErrNotManaged` means "has no active manager";
  `ErrLastManager` keeps its meaning and is reworded to say the last manager
  of a principal without a verified email cannot be removed.
- **F24.** Creating a managed principal accepts an optional email, verified
  like any other before it counts for release.
- **F25.** `Release` removes the last manager of a principal with a verified
  email and clears the managed state in one transaction.
- **F26.** A self-managed human enters management only by accepting a
  manager invitation, a new invite kind carrying the manager role.
- **F27.** Slugs for managed principals keep the manager-entered or
  generated form whether or not an email exists; an email's local part is
  never used.

### Non-Functional

- **N1.** Every operation that spans tables — signup, rename, conversion,
  invite acceptance, grant plus membership, release, access-change
  recording — is one database transaction.
- **N2.** The per-request cost of the revocation check is a map lookup; the
  cache holds only changes within one token lifetime plus the margin.
- **N3.** Both authorization modes pass the same `providertest` suite for
  organization roles, application roles, resource grants and lookups.
- **N4.** Existing conformance suites pass; tests that added members to
  personal organizations use team organizations.
- **N5.** `golangci-lint` reports no findings; the mkdocs
  strict build passes.
- **N6.** Every manager action, role assignment, grant and release is
  audited with the acting principal.

## Success Criteria

- A new person signs in with GitHub and lands in a personal organization
  whose slug is their GitHub username; signing in again creates nothing.
- Renaming a personal organization, giving the old slug to a team, and
  reclaiming it within seven days each succeed; a stranger taking it within
  seven days is refused; links to the old slug resolve throughout.
- An application that keeps no membership table provisions itself for an
  organization on first use from the `orgs` claim, shows the person only
  the applications they hold a role in, and sees an owner as `admin`
  everywhere.
- Removing a person from an organization is rejected by the application's
  next request in the same process, with a token-expired error that leads
  to a refresh carrying the reduced claims, and the person stays signed in
  to their other organizations.
- A collaborator granted `viewer` on one resource sees that resource and no
  other, under `rbac` and under `rebac`, and the organization appears in
  their switcher with role `collaborator`.
- A managed principal with a school-issued email keeps its guardian;
  releasing it is an explicit, audited call that succeeds only when the
  email is verified.

## Risks

| Risk | Mitigation |
|---|---|
| Dropping `plan` breaks consumers that read it | The column is unconsulted today; the `entitlements` summary ships in the same item, and the change is called out in the release notes |
| A missed access-change site leaves a stale claim honored | The recording call is in the service transaction, not the handler; the list of change sites is enumerated in the TRD and tested one by one; the token lifetime remains the bound |
| Clock skew between SystemAuth and a separate relying party | The margin, its floor and the expiry rule are specified in the TRD; in-process both timestamps come from one clock |
| The two authorization modes drift | `providertest` grows cases for every grant and lookup operation and runs against both |
| Slug cooling-off is gamed or locks a handle forever | Reservations expire; only the releasing principal or their organizations may reclaim; reserved names are refused up front |
| Deployment with no entitlements refuses every organization | Startup warning; default entitlements are a documented configuration |
