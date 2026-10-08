# ADR-008: Resource-Scoped Collaborators on the Authorization Substrate

**Status:** Accepted
**Deciders:** @grokify
**Relates to:** ADR-006 (personal organizations have collaborators, not
members), ADR-007 (memberships as claims), INIT-SYSTEMFORGE-001 (base
authorization schema), `docs/authz-conventions.md` (the cross-application
authorization contract).
**Updates:** `docs/design/architecture/authorization.md` (modes, collaborators, resource roles).

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
   `RevokeResourceRole` and `ListResourceGrants`. The `rebac` engine
   writes relationships; the `rbac` provider stores grants in a new
   `sf_resource_grants` table (principal, organization, resource type,
   resource ID, role) and consults it in its checks. Granting to a principal
   who is not a member of the resource's organization adds a `collaborator`
   membership; revoking the last grant removes it.
4. **Applications filter by lookup, not by trust.** `Authorizer` gains
   `ListResources(ctx, principal, resourceType, permission)` (SpiceDB
   `LookupResources`; an indexed query in `rbac`). An application uses the
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

### Naming the providers by what they do

The modes are named for the model they evaluate, not the technology:

- **role-based** (`rbac`): roles, plus direct grants on resources. The
  package is `authz/rbac` (formerly `authz/simple`).
- **relationship-based** (`rebac`): permissions derived through
  relationships, evaluated by an engine. SpiceDB is the engine today, as
  `authz/rebac/spicedb` (formerly `authz/spicedb`); another engine, for
  example OpenFGA, would sit beside it under the same mode without changing
  an application's configuration vocabulary.

An application configures `authz.mode: rbac | rebac`, and for `rebac` an
engine. The same names are used in configuration, documentation, the
architecture pages and the vocabulary registry. The packages were renamed
before this ADR is implemented, so the grants, lookups and tests it adds
land under the mode names once; the old paths forward to the new ones as
deprecated packages for one release. "Coarse-grained" and "fine-grained" are not used: after this ADR
both modes grant per resource, and the relationship engines market
themselves as fine-grained, so the pair would mislead in both directions.

### Choosing a mode

Both modes implement the same platform contract — organization roles,
application roles (ADR-007), resource grants, `ListResources` — with the
same semantics, verified by the shared `providertest` suite. An application
written to the contract switches from `rbac` to `rebac` by
configuration; its relationships are rebuilt from the membership, role and
grant tables. The cost of `rebac` is operational (a service with its own
datastore, schema management, relationship sync), not a function of whether
the application is paid.

| Use `rbac` while | Switch to `rebac` when |
|---|---|
| Access is organization roles, application roles and direct grants on resources | Permissions flow through relationships: nested groups or teams, folder-style hierarchies, "shared with me" graphs |
| One level of inheritance (organization → resource) is enough | Resources inherit from parents more than one level deep |
| `ListResources` over an organization's resources is a SQL query | Lookups span very large organizations or need SpiceDB's consistency tokens |
| One deployment, one process | Several services or regions share one authorization graph |

In terms of what each provider can answer:

| Question | `rbac` today | `rbac` with this ADR | `rebac` |
|---|---|---|---|
| Does the principal's organization or application role grant this action? | yes | yes | yes |
| Does the principal own this resource? | yes | yes | yes |
| Does the principal hold a direct grant on this specific resource? | no | yes, from the grants table | yes |
| Does a permission reach the principal through relationships (team membership, a parent resource, a share with a group)? | no | no | yes, through the schema fragment |

The grants this ADR adds to `rbac` are one hop: principal, role,
resource. That is enough for collaborators. What `rebac` adds beyond the
contract is the application's schema fragment: relations and inheritance
`rbac` cannot express.
An application that needs them declares its fragment and switches; until
then it declares none and the contract is all it uses.

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
- **The `rbac` provider grows a table and indexed queries over it**;
  `providertest` keeps it in step with `rebac` on the contract, so
  choosing it is not a dead end.
- **Moving a resource between organizations**, if an application supports
  it, must move its grants and the collaborator memberships they imply.
