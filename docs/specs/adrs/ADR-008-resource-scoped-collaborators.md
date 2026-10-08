# ADR-008: Resource-Scoped Collaborators on the Authorization Substrate

**Status:** Proposed
**Deciders:** @grokify
**Relates to:** ADR-006 (personal organizations have collaborators, not
members), ADR-007 (memberships as claims), INIT-SYSTEMFORGE-001 (base
authorization schema), `docs/authz-conventions.md` (the cross-application
authorization contract).

## Context

SystemForge authorization is a two-gate model (`docs/authz-conventions.md`):
the principal's organization role must grant an operation's permission, and
the presenting credential's scopes must include it. Applications register an
`authz.AppVocabulary` with their roles, permissions, scopes and a SpiceDB
schema fragment whose `{app}_`-prefixed definitions attach to the shared
`organization` through an `{app}_org` facet. Two providers exist: `simple`
(role hierarchy) and `spicedb` (ReBAC), with Ent hooks syncing
organizations, members and licenses into relationships.

Every grant is organization-wide: a member sees the whole organization. There
is no way to give someone access to one resource — a project, a document, a
site — without making them a member of the organization. That is what solo
users need for contractors (ADR-006 gives personal organizations no
members), and what teams need for outside reviewers. GitHub's outside
collaborators are the model: access to a repository, not to the
organization.

Applications could each build this themselves, as they built their own
membership tables. The substrate already has the pieces (relationships,
vocabularies, lookups), so the pattern should be defined once.

## Decision

1. **The base schema gains a `collaborator` relation on `organization`.**
   A collaborator is a principal with a membership of role `collaborator`.
   They have no permission on the organization itself: `view`, `edit` and
   `manage` exclude them. They gain only `list`, a new permission
   (`list = manage + member + viewer + collaborator`) that lets an
   application show the organization in the person's organization switcher.
   Personal organizations accept collaborator memberships (the one
   exception in ADR-006).
2. **Applications declare which resource types accept collaborators** in
   their SpiceDB fragment, using a standard ladder of resource roles:
   - `viewer`: read the resource;
   - `contributor`: also change it and create items within it;
   - `maintainer`: also manage its settings and its collaborators.

   A fragment looks like:

   ```zed
   definition myapp_project {
       relation org: organization
       relation viewer: principal
       relation contributor: principal
       relation maintainer: principal

       permission view   = viewer + contributor + maintainer + org->view
       permission edit   = contributor + maintainer + org->edit
       permission manage = maintainer + org->manage
   }
   ```

   Organization members keep their organization-wide access through the
   `org` facet; collaborators have only their direct relations. The ladder's
   names are reserved in `authz-conventions.md` so every application means
   the same thing by them.
3. **Grants are a substrate operation, supported by both providers.**
   `authz` gains `GrantResourceRole(ctx, principal, resource, role)`,
   `RevokeResourceRole` and `ListResourceGrants`. The `spicedb` provider
   writes relationships; the `simple` provider stores grants in a new
   `sf_resource_grants` table (principal, organization, resource type,
   resource ID, role) and consults it in its checks. Granting to a principal
   who is not a member of the resource's organization adds a `collaborator`
   membership; revoking the last grant removes it.
4. **Applications filter by lookup, not by trust.** `Authorizer` gains
   `ListResources(ctx, principal, resourceType, permission)` (SpiceDB
   `LookupResources`; a table scan in `simple`). An application uses the
   result to constrain queries and row-level security to the resources a
   collaborator may see, in addition to checking each request. The scope
   gate still applies: a collaborator's credential must carry the
   operation's scope.
5. **Invites can target a resource.** `sf_invites` gains optional resource
   type, resource ID and resource role. Accepting such an invite creates
   the collaborator membership and the grant in one transaction.
6. **Collaborators appear in claims.** The `orgs` claim (ADR-007) lists a
   collaborator's organizations with role `collaborator`; the resources
   they may access are the application's to look up, not a claim.
7. **Agents and managed principals are granted the same way.** A grant to an
   agent principal confines it to those resources; an application's
   agent-facing scopes (for example per-resource AAuth scopes) are checked
   against the same relationships.

## Consequences

- **One collaborator model for every application**, administrable in the
  IAM console from the registered vocabularies, instead of a per-application
  sharing feature.
- **Applications must filter aggregates and cross-resource references** for
  collaborators (counts, dependency views), since a collaborator may hold
  grants on some resources of an organization and not others. The
  substrate supplies the permitted set; the filtering is the application's.
- **The schema parity test and `authz-conventions.md` change**: the base
  schema gains `collaborator` and `list`, and the resource-role ladder is
  added to the conventions.
- **The `simple` provider grows a table and a scan**, which is acceptable for
  the deployments it serves; large deployments use `spicedb`.
- **Moving a resource between organizations**, if an application supports
  it, must move its grants and the collaborator memberships they imply.
