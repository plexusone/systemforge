# ROADMAP — Suite Organizations: Lifecycle, Claims, Collaborators, Real-Time Invalidation

**Initiative:** `INIT-SYSTEMFORGE-011`
**Repository:** `github.com/plexusone/systemforge`

Design of record:
[ADR-006](../../../design/adrs/ADR-006-organization-lifecycle-personal-team-slugs.md),
[ADR-007](../../../design/adrs/ADR-007-memberships-and-entitlements-as-claims.md),
[ADR-008](../../../design/adrs/ADR-008-resource-scoped-collaborators.md),
[ADR-009](../../../design/adrs/ADR-009-management-is-a-relationship.md),
[ADR-010](../../../design/adrs/ADR-010-real-time-access-invalidation.md).
A first login yields a personal organization; memberships, application roles
and entitlements reach applications as claims; an access change takes effect
within one request; access to one resource needs no membership; management
is a relationship, not a missing email. Builds on INIT-SYSTEMFORGE-007 and
INIT-SYSTEMFORGE-008.

## Phase 1 — Organization lifecycle (ADR-006)

**Theme:** A first login yields a personal organization; slugs are safe to change; a solo org becomes a team without moving data.

- [ ] `RMI-SYSTEMFORGE-124` Signup on first social login: SystemAuth's GitHub/Google login calls `signup.SignupOrGetExisting` for an unseen principal, creating principal and personal organization in one transaction; later logins resolve by provider identity, then verified email
- [ ] `RMI-SYSTEMFORGE-125` Slug derivation and reserved slugs: `signup.SlugForLogin(provider, login, email)` — GitHub username; Gmail local part; managed principal: manager-entered or generated (two words and a number); numeric suffix on collision; reserved-slug list (admin, api, o, login, oauth, well-known names, deployment-configured product names) refused by `SlugAvailable`
  - Depends on: `RMI-SYSTEMFORGE-124`
- [ ] `RMI-SYSTEMFORGE-126` Slug changes with cooling-off and aliases: `sf_slug_reservations`; `organization.Rename`; freed slug held 7 days, reclaimable only by the releasing principal or an organization they own; `ResolveSlug` resolves aliases to the previous organization for the period; applies to personal and team organizations and in every direction
  - Depends on: `RMI-SYSTEMFORGE-125`
- [ ] `RMI-SYSTEMFORGE-127` Personal organization rules: exactly one member (the owner); `AddMember` and invites refused for personal organizations except role collaborator; `TransferOwnership` refused for personal organizations
  - Depends on: `RMI-SYSTEMFORGE-124`
- [ ] `RMI-SYSTEMFORGE-128` `ConvertToTeam`: organization keeps ID, data and memberships, type becomes team, takes a free team slug chosen at conversion; a new personal organization with the person's handle is created for the owner; one transaction
  - Depends on: `RMI-SYSTEMFORGE-126`
  - Depends on: `RMI-SYSTEMFORGE-127`
- [ ] `RMI-SYSTEMFORGE-129` Remove the organization `plan` column: drop from schema, `organization` service inputs and list filter, API responses, SCIM default and `Plan*` constants; organization API gains an `entitlements` summary derived from marketplace subscriptions and licenses

## Phase 2 — Memberships and entitlements as claims (ADR-007)

**Theme:** Relying parties learn organizations, roles and entitlements from SystemAuth, not from their own tables.

- [ ] `RMI-SYSTEMFORGE-130` Application roles: `sf_app_roles` (principal, organization, application, role) validated against the application's `AppVocabulary` ladder; owners hold admin implicitly, admins and members only what is assigned, none by default; assign/change/remove API; cascade on membership removal
- [ ] `RMI-SYSTEMFORGE-131` Entitlements from the marketplace: per-organization entitled applications derived from active subscriptions and licenses per listing, mapped to registered application identifiers; deployment-configured default entitlements; startup warning when a deployment has none; seat accounting for seat-licensed applications
  - Depends on: `RMI-SYSTEMFORGE-129`
- [ ] `RMI-SYSTEMFORGE-132` The `orgs` claim: ID token and userinfo carry id, slug, name, type, role, apps (app → role); JWT access tokens carry the compact `{id, role, apps}`; at most 50 organizations with `orgs_truncated`; `GET /userinfo/memberships` paginated
  - Depends on: `RMI-SYSTEMFORGE-130`
  - Depends on: `RMI-SYSTEMFORGE-131`
- [ ] `RMI-SYSTEMFORGE-133` Relying-party membership sources: `relyingparty.ClaimsMemberships` (default) and `RemoteMemberships`; `LocalMemberships` documented as development-only; a first-use provisioning hook keyed by organization ID for applications
  - Depends on: `RMI-SYSTEMFORGE-132`
- [ ] `RMI-SYSTEMFORGE-134` Invites and member management carry application roles: invite create/accept with per-application role selection (none preselected); role changes per application without touching membership; SystemAuth pages and API
  - Depends on: `RMI-SYSTEMFORGE-130`

## Phase 3 — Real-time invalidation of access (ADR-010)

**Theme:** An access change takes effect within one request in the monolith and within one token lifetime at worst.

- [ ] `RMI-SYSTEMFORGE-135` Access-change records and refresh semantics: `sf_access_changes` written in the transactions for membership removal, organization or application role change, grant reduction, deactivation and session revocation; role or membership changes no longer revoke refresh tokens (deactivation and explicit revocation still do); access-token lifetime default 10 minutes, configurable, maximum 15
- [ ] `RMI-SYSTEMFORGE-136` Relying-party revocation cache: in-process shared cache (`AccessChangeSink`) written in the recording transaction; acceptance rule `iat >= changed_at + margin` with a configurable clock-skew margin (default 30 s, floor 15 s); entries expire at `changed_at + max lifetime + margin`; rejection answered as token-expired so clients refresh
  - Depends on: `RMI-SYSTEMFORGE-135`
- [ ] `RMI-SYSTEMFORGE-137` Replica poller and replay: instances poll `sf_access_changes` newer than their last read every 1–2 s; `GET /access-changes?since=` for rebuilding the cache after a restart; suspect mode until replay succeeds
  - Depends on: `RMI-SYSTEMFORGE-136`
- [ ] `RMI-SYSTEMFORGE-138` Back-channel delivery: OIDC Back-Channel Logout token carrying an `access_change` event to registered relying-party endpoints, with retry and logging; receiver in `relyingparty`
  - Depends on: `RMI-SYSTEMFORGE-136`

## Phase 4 — Resource-scoped collaborators (ADR-008)

**Theme:** Access to one resource without organization membership, on both authorization modes.

- [ ] `RMI-SYSTEMFORGE-139` Base schema and conventions: `collaborator` relation and `list` permission on `organization` (no view/edit/manage); membership role `collaborator`; personal organizations accept collaborator memberships; the viewer/contributor/maintainer resource-role ladder reserved in `docs/authz-conventions.md`; schema parity test updated
- [ ] `RMI-SYSTEMFORGE-140` Resource grants in `rbac`: `sf_resource_grants`; `GrantResourceRole`, `RevokeResourceRole`, `ListResourceGrants`, `ListResources`; first grant creates the collaborator membership, last revoke removes it
  - Depends on: `RMI-SYSTEMFORGE-139`
- [ ] `RMI-SYSTEMFORGE-141` Resource grants in `rebac/spicedb`: grants as relationships, `ListResources` via LookupResources, vocabulary-fragment validation for collaborator-able resources; `providertest` parity suite for grants and lookups across both modes
  - Depends on: `RMI-SYSTEMFORGE-139`
- [ ] `RMI-SYSTEMFORGE-142` Resource-targeted invites: invite fields for resource type, ID and role; acceptance creates collaborator membership and grant in one transaction
  - Depends on: `RMI-SYSTEMFORGE-140`
  - Depends on: `RMI-SYSTEMFORGE-141`
- [ ] `RMI-SYSTEMFORGE-143` `authz.mode` configuration: `rbac | rebac` with engine selection for rebac; the deprecated `authz/simple` and `authz/spicedb` forwarders scheduled for removal next major release; guidance in the authorization architecture page
  - Depends on: `RMI-SYSTEMFORGE-140`
  - Depends on: `RMI-SYSTEMFORGE-141`

## Phase 5 — Management is a relationship (ADR-009)

**Theme:** A managed principal is one with a manager, whether or not it has an email.

- [ ] `RMI-SYSTEMFORGE-144` Management derived from relationships: `IsManaged` and the `managed` claim from active manager relationships; `ErrNotManaged`/`ErrLastManager` semantics and wording; optional email at creation, verified before it counts for release
- [ ] `RMI-SYSTEMFORGE-145` Release and manager invitations: `Release` removes the last manager of a principal with a verified email; a manager-invitation kind accepted by the signed-in principal for self-managed humans entering management; slugs for managed principals never derived from an email
  - Depends on: `RMI-SYSTEMFORGE-144`
  - Depends on: `RMI-SYSTEMFORGE-134`

## Phase 6 — Documentation and release

**Theme:** Architecture pages describe what shipped; release.

- [ ] `RMI-SYSTEMFORGE-146` Documentation and release: update `docs/design/architecture/{organizations,managed-principals,authorization}.md` to the implemented behavior (planned sections emptied), guides for invites, roles, collaborators and slugs, changelog, release notes, tag v0.15.0 after CI
  - Depends on: `RMI-SYSTEMFORGE-128`
  - Depends on: `RMI-SYSTEMFORGE-133`
  - Depends on: `RMI-SYSTEMFORGE-134`
  - Depends on: `RMI-SYSTEMFORGE-137`
  - Depends on: `RMI-SYSTEMFORGE-138`
  - Depends on: `RMI-SYSTEMFORGE-142`
  - Depends on: `RMI-SYSTEMFORGE-143`
  - Depends on: `RMI-SYSTEMFORGE-145`
