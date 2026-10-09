# Authorization

This page describes the authorization substrate as implemented in `authz`
and its providers: the two-gate model, the application vocabulary, the base
schema shared by every application, the role-based and relationship-based
providers and what each can answer, the conformance suite that keeps them
in step, and how identity changes reach them. The last section lists what
the accepted decisions add that is not yet built. The normative
cross-application contract is
[Cross-Forge Authorization Conventions](../../authz-conventions.md).

**Decisions:**
[ADR-007](../adrs/ADR-007-memberships-and-entitlements-as-claims.md)
(application roles),
[ADR-008](../adrs/ADR-008-resource-scoped-collaborators.md)
(resource-scoped collaborators, provider naming),
[ADR-010](../adrs/ADR-010-real-time-access-invalidation.md)
(revocation cache as part of request authorization).

## The two-gate model

Every API operation is guarded by two independent checks, and both must
pass:

| Gate | Question | Evaluated against |
|---|---|---|
| Role gate | May this person ever do this? | The principal's role in the organization, through `authz.Authorizer.Can` |
| Scope gate | May this credential do it right now? | The OAuth scopes of the presenting credential (`requestprincipal.RequestPrincipal.Scopes`, from the access token, API key or session) |

Effective access is the intersection: an organization admin presenting a
token scoped to one read operation is read-only on that token. Scopes are
namespaced per application (`{app}:{resource}:{verb}`, blanket
`{app}:admin`) and never cross applications.

## Application vocabulary (`authz.AppVocabulary`)

An application registers its vocabulary at startup; registration validates
it, and the IAM console and the composed SpiceDB schema are rendered from
the registry.

```go
type AppVocabulary interface {
    App() string                 // short lowercase identifier, ^[a-z][a-z0-9]{1,31}$
    Roles() RolePermissions      // role -> dotted permissions
    Hierarchy() RoleHierarchy    // every role in Roles() must appear
    Scopes() []string            // {app}:{resource}:{verb} or {app}:admin
    SpiceDBSchema() string       // "" when only the role-based provider is supported
}
```

| Function | Rule |
|---|---|
| `ValidateScope(app, scope)` | Scope matches the convention and its prefix is `app` |
| `ValidateAppSchema(app, schema)` | Every `definition` in the fragment is prefixed `{app}_`, so a fragment can never redefine a base or another application's definition |
| `ValidateVocabulary(v)` | App name, non-empty roles, hierarchy covering every role, scopes valid and unique, schema prefixed |
| `VocabularyRegistry.Register(v)` | Validates; refuses a duplicate app |
| `VocabularyRegistry.AllScopes()` | Every registered scope, sorted, for consent screens and `AllowedScopes` |
| `VocabularyRegistry.ComposeSpiceDBSchema()` | Base schema followed by each registered fragment in registration order; fails on any duplicate definition |

The platform ladder is `owner(100) / admin(80) / editor(60) / member(40) /
viewer(20) / guest(10)` (`authz.DefaultRoleHierarchy`), with
`authz.DefaultRolePermissions` mapping the first five to dotted
`org.*`, `member.*` and `resource.*` permissions. Applications reuse the
ladder where it fits and add domain roles (for separation of duties) that
appear in both `Roles()` and `Hierarchy()`.

### The `{app}_org` facet

An application's SpiceDB fragment attaches to the shared `organization`
through a facet definition that references it and adds the application's
own relations; generic membership flows through arrows (`org->view`):

```zed
definition myapp_org {
    relation org: organization
    relation approver: principal

    permission read    = org->view
    permission write   = org->edit
    permission approve = org->manage + approver
}

definition myapp_document {
    relation app_org: myapp_org
    permission read  = app_org->read
    permission write = app_org->write
}
```

## Base schema (`authz.BaseSpiceDBSchema`)

Owned by the platform; applications never redefine these definitions.

| Definition | Relations | Permissions |
|---|---|---|
| `principal` | `guardian`, `educator` (ADR-005 manager roles) | `manage_account = guardian`; `manage_credentials = guardian + educator`; `view_profile = guardian + educator`; `manage_managers = guardian` |
| `organization` | `owner`, `admin`, `editor`, `member`, `viewer` | `manage = owner + admin`; `edit = manage + editor`; `contribute = edit + member`; `view = contribute + viewer`; `invite_member`, `remove_member`, `change_role`, `settings = manage`; `delete = owner` |
| `platform` | `admin` | `super_admin = admin` |

The same grants exist as Go tables so the role-based provider evaluates
them identically: `authz.OrgRolePermissions` / `OrgRoleAllows` (the
`PermOrg*` constants in `authz/org.go`) and `authz.ManagerRolePermissions` /
`ManagerRoleAllows` (`authz/manager.go`). `authz/schema_parity_test.go`
parses the schema and fails if either table drifts from it.

## Providers

ADR-008 names the modes for what they evaluate. The packages were renamed
ahead of the ADR; the old paths forward to the new ones as deprecated
packages for one release.

| Mode | Package | Formerly | Evaluates |
|---|---|---|---|
| Role-based (`rbac`) | `authz/rbac` | `authz/simple` (deprecated forwarder: `simple.Provider = rbac.Provider`, `simple.New = rbac.New`, options likewise) | Roles, resource ownership, organization role, manager role |
| Relationship-based (`rebac`) | `authz/rebac/spicedb` | `authz/spicedb` (deprecated forwarder) | Permissions derived through relationships by a SpiceDB engine |

Both implement `authz.Authorizer` (`Can`, `CanAll`, `CanAny`, `Filter`),
`authz.OrgAuthorizer` (`CanForOrg`, `GetRole`, `IsMember`) and
`authz.PlatformAuthorizer` (`IsPlatformAdmin`); `rbac` also implements
`authz.DecisionAuthorizer` (`Decide`, returning a reason and policy ID).
`authz.FeatureAuthorizer` is declared and has no implementation.

### Role-based provider (`rbac.Provider`)

Configured with options: `WithRoleHierarchy`, `WithPermissions`,
`WithRoleGetter` (principal's role in an organization; wire
`organization.MembershipRoleGetter(svc)`), `WithPlatformAdminChecker` and
`WithPlatformAdminBypass`, `WithManagerRoleGetter` (wire
`managedprincipal.Service.ManagerRoles`), `WithOwnerFullAccess`.
`Decide` evaluates in this order:

1. Platform admin bypass, when enabled and the checker says so.
2. Resource owner, when `WithOwnerFullAccess` and `Resource.OwnerID` is the
   principal.
3. Resource type `principal` with an ID: a manager role that grants the
   action (`ManagerRoleAllows`), through the manager role getter.
4. A base organization permission (`IsOrgPermission(action)`) on an
   `organization` resource: the principal's organization role through the
   role getter, judged by `OrgRoleAllows`.
5. No `Resource.OrgID`: owner only.
6. Otherwise the organization role's permissions, keyed as
   `{resource type}.{action}` in `RolePermissions`.

`Filter` runs `Can` per resource.

### Relationship-based provider (`spicedb.Provider`)

A thin provider over `spicedb.Client`: `Can` is a `Check` with subject
`principal:<id>`, resource `<type>:<id>` and the action as the permission;
`GetRole` and `IsMember` read the organization's membership relations;
`Filter` checks per resource. The client wraps schema writes and reads,
relationship writes and deletes, `LookupSubjects` and `LookupResources`;
`LookupResources` is available on the client, not on the `Authorizer`
interface. `spicedb.Syncer` implements `authz.RelationshipSyncer` by
writing and deleting base-schema relationships.

### Conformance (`authz/providertest`)

`providertest.RunAll(t, Config{Provider: p})` runs the interface, behavior
and integration tiers against any provider; `RunOrgPermissionTests` (with
`Config.GrantOrgRole`) asserts the organization grants of the base schema,
and `RunManagerRelationTests` (with `Config.GrantManager`) the manager
grants. Both providers run the suite
(`authz/rbac/provider_conformance_test.go`,
`authz/rebac/spicedb/integration_test.go`), which is what makes the two
modes interchangeable on the platform contract.

### Capability table

What each provider can answer today, and after ADR-008:

| Question | `rbac` today | `rbac` after ADR-008 | `rebac` |
|---|---|---|---|
| Does the principal's organization or application role grant this action? | yes | yes | yes |
| Does the principal own this resource? | yes (`WithOwnerFullAccess`, `Resource.OwnerID` supplied by the caller) | yes | yes |
| Does the principal hold a direct grant on this specific resource? | no | yes, from `sf_resource_grants` | yes |
| Does a permission reach the principal through relationships (team membership, a parent resource, a share with a group)? | no | no | yes, through the schema fragment |

### Choosing a mode

| Use `rbac` while | Switch to `rebac` when |
|---|---|
| Access is organization roles, application roles and direct grants on resources | Permissions flow through relationships: nested groups or teams, folder-style hierarchies, "shared with me" graphs |
| One level of inheritance (organization to resource) is enough | Resources inherit from parents more than one level deep |
| Listing a principal's resources is a SQL query | Lookups span very large organizations or need SpiceDB's consistency tokens |
| One deployment, one process | Several services or regions share one authorization graph |

An application written to the contract switches by configuration; the cost
of `rebac` is operational (a service with its own datastore, schema
management, relationship sync).

## Keeping providers in step with identity

Identity changes reach the authorization backend through
`authz.RelationshipSyncer`, called explicitly by the services after their
database transaction commits; there are no Ent hooks.

| Caller | Syncer calls |
|---|---|
| `organization.Service` | `RegisterOrganization` (create), `AddOrgMembership`, `UpdateOrgMembership` (role change, both sides of an ownership transfer), `RemoveOrgMembership`, `UnregisterOrganization` (delete) |
| `managedprincipal.Service` | `RegisterPrincipal`, `AddPrincipalManager`, `RemovePrincipalManager` |
| `marketplace` (`marketplace.AuthzSyncer`, `SpiceDBSyncer`) | Listing, license, license revocation, seat assignment and unassignment, subscription relationships |

`invite.Service.Accept` writes the membership directly and makes no syncer
call. `authz.SyncMode` decides what a sync failure does: `strict` returns
it, `eventual` (the default) logs it. `noop.NewSyncer()` is the default
syncer and what a role-based deployment uses, since `rbac` reads the
membership and relationship tables through its getters at check time.

`authz.Middleware` (`RequireAction`, `RequireAnyAction`,
`RequireAllActions`) adapts an `Authorizer` to HTTP, building the principal
and organization from `session/middleware` claims. The organization,
invite, marketplace and managed-principal APIs call the authorizer directly
with the `PermOrg*` and manager permissions.

## Request authorization today

A request is authorized by the authenticator (`requestprincipal.Middleware`
with `relyingparty.RequestAuthenticator`, or SystemAuth's own token
middleware) establishing the principal and its scopes, and then by the
handler's `Authorizer.Can` call. SystemAuth checks that a token's principal
is still active on every token issue, refresh, introspection and userinfo
call (`PrincipalStatus`), and nothing else: a token issued before a
membership or role change is honored until it expires (15 minutes by
default).

## Planned changes

Accepted decisions not yet implemented. Each item names the ADR that
decides it.

### Resource-scoped collaborators (ADR-008)

- The base `organization` definition gains a `collaborator` relation and a
  `list` permission (`list = manage + member + viewer + collaborator`);
  collaborators have no `view`, `edit` or `manage` on the organization.
  `authz.OrgRolePermissions`, the parity test and the conventions change
  with it. A collaborator is a principal with a membership of role
  `collaborator`; personal organizations accept such memberships.
- A standard resource-role ladder, reserved in the conventions:
  `viewer` (read), `contributor` (also change and create within),
  `maintainer` (also manage settings and collaborators). Applications
  declare which resource types accept collaborators in their fragment,
  with `permission view = viewer + contributor + maintainer + org->view`
  and so on.
- Substrate operations on both providers: `GrantResourceRole(ctx,
  principal, resource, role)`, `RevokeResourceRole`, `ListResourceGrants`.
  `rebac` writes relationships; `rbac` stores grants in a new
  `sf_resource_grants` table (principal, organization, resource type,
  resource ID, role) and consults it in `Decide`. Granting to a non-member
  adds a `collaborator` membership; revoking the last grant removes it.
- `Authorizer.ListResources(ctx, principal, resourceType, permission)`:
  SpiceDB `LookupResources` in `rebac`, an indexed query in `rbac`.
  Applications filter queries by the result rather than trusting the
  caller; the scope gate still applies.
- `sf_invites` gains optional resource type, resource ID and resource role;
  accepting such an invite creates the collaborator membership and the
  grant in one transaction.
- The `orgs` claim (ADR-007) lists a collaborator's organizations with role
  `collaborator`; the resources are the application's to look up.
- Agents and managed principals are granted the same way.
- `providertest` grows cases for grants and `ListResources` so both modes
  stay equivalent on the contract.

### Application roles (ADR-007)

- The `sf_app_roles` table records the application role per (principal,
  organization, application) (built; see
  [Organizations](organizations.md#application-roles-identityapprole)).
  Still to do: it replaces seat assignments as the record of who may use
  what, and a seat-licensed application counts its rows against the
  license.
- Owners hold `admin` in every entitled application implicitly. Admins
  manage the organization but hold only the application roles assigned to
  them, like members; an admin may assign roles to themself, explicitly and
  audited. Members and admins have no application access by default.
- The roles available in an application are the ones its vocabulary
  declares (standard ladder `viewer`, `contributor`, `maintainer`,
  `admin`); no custom roles. Organization-defined roles and teams are
  deferred.
- Removal from the organization removes every application role (built) and grant.

### Revocation cache in request authorization (ADR-010)

- Request authorization gains a step between token verification and the
  permission check: the relying party looks up its revocation cache by
  principal (and organization) and accepts the token only if its `iat` is
  at or after the recorded `changed_at` plus the clock-skew margin;
  otherwise it answers 401 with the standard expired-token error so the
  client refreshes.
- The cache is filled from SystemAuth's `sf_access_changes` (shared memory
  in a modular monolith, polling across replicas, back-channel
  `access_change` events across deployments) and rebuilt after a restart
  from `GET /access-changes?since=`; the `relyingparty` package implements
  all three. Applications that bypass `relyingparty` must implement the
  same check.
- Changes to resource grants that reduce access (ADR-008) are access
  changes and invalidate the same way.
- Agent tokens are out of scope: AAuth tokens carry their own cascading
  revocation keyed by `jti`.
