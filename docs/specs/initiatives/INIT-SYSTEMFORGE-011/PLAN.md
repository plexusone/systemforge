# PLAN — Suite Organizations: Lifecycle, Claims, Collaborators, Real-Time Invalidation

**Initiative:** `INIT-SYSTEMFORGE-011`

## Entry Gate

- ADR-006, ADR-007, ADR-008, ADR-009 and ADR-010 accepted.
- INIT-SYSTEMFORGE-008 complete: one `Principal` root, one `Human` model,
  legacy tables gone.
- INIT-SYSTEMFORGE-007 complete: `ManagerRelationship`,
  `identity/managedprincipal`, `login_token`, the `managed` claim and the
  manager authorization relations exist, so Phase 5 amends them rather than
  creating them.
- The `authz/rbac` and `authz/rebac/spicedb` packages exist under their
  mode names with `authz/simple` and `authz/spicedb` forwarding to them.
- v0.14.0 tagged (the INIT-007/INIT-008 release), so this initiative ships
  as v0.15.0 on its own.

## Build Order

Phases 1, 2 and 3 are sequential on the tables and claims they share.
Phase 4 depends only on the `collaborator` membership role from Phase 1 and
can proceed alongside Phases 2 and 3. Phase 5 depends on the invite work in
Phase 2. Phase 6 closes.

### Phase 1 — Organization lifecycle (ADR-006)

Wire SystemAuth's social login to `signup.SignupOrGetExisting`; centralize
slug derivation and reserved names in `signup`; add `sf_slug_reservations`
with `Rename`, `ResolveSlug` and the seven-day rule; enforce the personal
organization invariants; add `ConvertToTeam`; drop the `plan` column and
replace it with the `entitlements` summary. The `plan` removal is first in
the phase because Phase 2's entitlement derivation builds on its absence.
Exit: a first GitHub login yields a personal organization with the GitHub
username as slug and a second login creates nothing; a rename followed by a
reclaim within seven days succeeds and a stranger's attempt is refused;
`ConvertToTeam` keeps the ID and memberships and gives the owner a fresh
personal organization; no `Plan` symbol remains in the organization API.

### Phase 2 — Memberships and entitlements as claims (ADR-007)

Add `sf_app_roles` and its service; derive entitled applications from the
marketplace with default entitlements and seat accounting; emit the `orgs`
claim in the ID token, userinfo and access token with truncation and the
memberships endpoint; add `ClaimsMemberships` and `RemoteMemberships` to
`relyingparty` with the provisioning hook; make invites and member
management carry application roles. Exit: an application configured with
`ClaimsMemberships` and no membership table shows a member only the
applications they were assigned, shows an owner `admin` everywhere, and
provisions itself for an organization on the organization's first use.

### Phase 3 — Real-time invalidation of access (ADR-010)

Add `sf_access_changes` and record a row in every change transaction;
stop revoking refresh tokens on role and membership change; set the
access-token lifetime default and ceiling; implement the in-process
revocation cache with the skew margin and expiry; add the replica poller,
the replay endpoint and suspect mode; add back-channel delivery with retry
and its receiver. The recording and the cache land together because a
recorded change nobody reads is a false promise. Exit: in one process, a
removal at request N is refused at request N+1 with a token-expired error;
on a second replica it is refused within the polling interval; after a
restart the cache is rebuilt from `/access-changes` before serving.

### Phase 4 — Resource-scoped collaborators (ADR-008)

Extend the base schema with `collaborator` and `list`, reserve the
resource-role ladder in the conventions, and update the parity test; add
`sf_resource_grants` and the grant operations to `rbac`; add relationship
grants and `LookupResources` to `rebac/spicedb`; extend `providertest` to
cover grants and lookups on both; add resource-targeted invites; add the
`authz.mode` configuration and the removal schedule for the forwarders.
Exit: `providertest` passes for both modes on every grant and lookup case;
a collaborator sees exactly the resources granted and the organization only
through `list`; a resource-targeted invite creates membership and grant in
one transaction.

### Phase 5 — Management is a relationship (ADR-009)

Derive `IsManaged` and the `managed` claim from active relationships;
accept an optional email at creation; add `Release` and the manager
invitation kind; keep managed slugs free of email. Exit: a managed
principal with a verified email keeps its managers until `Release`;
removing the last manager of a principal without a verified email is still
refused; a self-managed human becomes managed only by accepting an
invitation.

### Phase 6 — Documentation and release

Rewrite the organizations, managed-principals and authorization
architecture pages to describe what shipped and empty their planned
sections; add guides for invites, application roles, collaborators and
slugs; update the changelog and release notes; tag v0.15.0 after CI passes
and record the release. Exit: the PRD success criteria hold and the mkdocs
strict build is clean.

## Risks and Mitigations

| Risk | Mitigation |
|---|---|
| The `plan` drop lands before entitlements can replace it | RMI-129 ships the `entitlements` summary in the same change; Phase 2 derives the full set from it |
| Access-change recording misses a site | The TRD enumerates every change site; each has a test asserting a row in `sf_access_changes` inside the same transaction |
| Phase 3 ships the table without the cache | Phase 3 is tagged only whole; no partial release |
| Mode parity drifts between `rbac` and `rebac` | Every grant and lookup case is added to `providertest` before the second implementation, so the suite is the specification |
| Claims grow past token limits | The 50-organization cap and `orgs_truncated` are in RMI-132; `RemoteMemberships` handles the rest |
| Cooling-off and aliases interact badly with conversion | `ConvertToTeam` is specified in terms of `Rename` and the reservation table and tested for every direction of handle hand-over |
| Phase 5 changes behavior for the original managed-principal consumer | A child created without an email behaves exactly as before; the regression suite from INIT-007 runs unchanged |

## Release

v0.15.0, after all phases are complete and CI passes on the pushed
commits; tag only after CI is green. The release notes call out the
`plan` removal, the changed refresh-token semantics, the new token
lifetime default and ceiling, the `collaborator` role, and the forwarder
removal schedule as behavior changes.

## Follow-On

- Teams as carriers of application roles, if assigning roles one person at
  a time becomes the problem (ADR-007 defers them).
- A second `rebac` engine beside SpiceDB under the same mode name.
- Moving a resource between organizations, with its grants and implied
  collaborator memberships, for applications that need it.
