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
| `ValidateAppSchema(app, schema)` | Every `definition` in the fragment is prefixed `{app}_`, so a fragment can never redefine a base or another application's definition; a definition that declares any of the reserved resource-role relations `viewer`, `contributor`, `maintainer` declares all three, binds each to `principal`, and has `relation org: organization` |
| `CollaboratorDefinitions(schema)` | The definitions of a fragment that declare the whole ladder, that is, the resource types that accept collaborators |
| `VocabularyRegistry.ValidateResourceType(type)` | `{app}_{type}` whose application is registered and, when the vocabulary carries a fragment, whose definition is collaborator-able; a vocabulary with no fragment accepts any type of its application |
| `VocabularyRegistry.CollaboratorResourceTypes(app)` | The sorted collaborator-able types of an application's fragment |
| `ValidateVocabulary(v)` | App name, non-empty roles, hierarchy covering every role, scopes valid and unique, schema prefixed |
| `VocabularyRegistry.Register(v)` | Validates; refuses a duplicate app |
| `VocabularyRegistry.AllScopes()` | Every registered scope, sorted, for consent screens and `AllowedScopes` |
| `VocabularyRegistry.ComposeSpiceDBSchema()` | Base schema followed by each registered fragment in registration order; fails on any duplicate definition |

The organization roles are `owner(100) / admin(80) / member(40) /
collaborator(20)`, with `guest(10)` for applications that model one
(`authz.DefaultRoleHierarchy`), and `authz.DefaultRolePermissions` maps
the first three to dotted `org.*`, `member.*` and `resource.*`
permissions; a collaborator has none, since a collaborator's access is
per resource (below). `editor` and `viewer` are not organization roles.
An application's own roles are its vocabulary's: they appear in both
`Roles()` and `Hierarchy()` and are separate from the organization roles
and from the resource roles.

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
| `organization` | `owner`, `admin`, `member`, `collaborator` | `manage = owner + admin`; `edit = manage`; `contribute = edit + member`; `view = contribute`; `list = view + collaborator`; `invite_member`, `remove_member`, `change_role`, `settings = manage`; `delete = owner` |
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
`GetRole` reads the organization's membership relations (owner, admin,
member, collaborator), and `IsMember` checks `list`, which every
membership grants, collaborators included; `Filter` checks per resource.
The client wraps schema writes and reads, relationship writes and deletes
(`ReplaceRelationships` applies deletes and writes in one request),
`LookupSubjects` and `LookupResources`; a lookup stream that fails returns
the error rather than a partial list. `spicedb.Syncer` implements
`authz.RelationshipSyncer` by writing and deleting base-schema
relationships, `authz.AppRoleSyncer` for application roles and
`authz.ResourceGrantSyncer` for resource grants.

With `spicedb.WithResourceGrants(store)` the provider implements
`authz.ResourceGranter`. The store is the same `resourcegrant.Service` the
role-based provider uses, built with `WithAuthzSyncer(spicedb.NewSyncer(c),
mode)`: it keeps the rows the graph cannot (the collaborator membership
behind the `orgs` claim, the last-grant test, access changes) and mirrors
each change into the graph, so a deployment that switches modes rebuilds its
relationships from the membership, role and grant tables. A grant is the
relationship `{type}:{id}#{role}@principal:{principal}`; changing a role
deletes the other two ladder relations in the same request; the collaborator
membership is `organization:{org}#collaborator@principal:{principal}`. The
application writes a resource's `org` relation when it creates the resource,
which is what lets organization members reach it through `org->view`.
`ListResources` is `LookupResources` for the permission; it follows every
relationship the schema expresses, so its answer is `IDs` and
`OrganizationIDs` is empty.

### Resource grants

ADR-008 gives a collaborator access to individual resources through a
standard ladder of resource roles, reserved in the conventions:

| Resource role | Permissions on the resource | `authz` |
|---|---|---|
| `viewer` | `view` | `ResourceRoleViewer` |
| `contributor` | `view`, `edit` | `ResourceRoleContributor` |
| `maintainer` | `view`, `edit`, `manage` | `ResourceRoleMaintainer` |

`authz.ResourceRolePermissions` holds the table, and
`authz.ResourceRoleFragment(type)` generates the standard definition it
mirrors; `schema_parity_test.go` keeps the two equal. The contract is
`authz.ResourceGranter`:

```go
GrantResourceRole(ctx, principalID, ref ResourceRef, role string, grantedBy uuid.UUID) error
RevokeResourceRole(ctx, principalID, ref ResourceRef) error
ListResourceGrants(ctx, ref ResourceRef) ([]Grant, error)
ListResources(ctx, principalID, resourceType string, permission Action) (ResourceSet, error)
```

`ResourceRef{Type, ID, OrganizationID}` names a resource by its definition
name (`{app}_{type}`), the application's own string identifier and the
organization that owns it. A first grant gives a non-member a `collaborator`
membership; revoking their last grant removes it; a lower role or a revoke
records a `grant_reduced` access change.

**Role-based provider.** `rbac.WithResourceGrants(store)` takes a store that
is both a `ResourceGranter` and an `authz.ResourceGrantReader`;
`identity/resourcegrant.Service` over the Ent client is the store (see
[Resource grants](organizations.md#resource-grants-identityresourcegrant)).
The provider delegates `GrantResourceRole`, `RevokeResourceRole` and
`ListResourceGrants`, and extends the evaluation order of `Decide` and `Can`
with one step after the organization role:

7. A resource with an ID whose action is `view`, `edit` or `manage`: the
   principal's grant on it, when its membership in the organization is
   active, judged by `ResourceRoleAllows`.

`ListResources` returns an `authz.ResourceSet` with two parts, which an
application applies as `organization_id IN (OrganizationIDs) OR id IN
(IDs)`: `IDs` are the resources the principal holds a grant on whose role
grants the permission; `OrganizationIDs` are the organizations in which the
principal's organization role grants `{resourceType}.{permission}` in the
provider's permission map, which makes the permission hold on every
resource of the type there. Platform-admin bypass and resource ownership,
which `Can` honors, are not enumerated. A provider built without a store
answers as before and returns `rbac.ErrNoResourceGrants` from the grant
operations.

### Conformance (`authz/providertest`)

`providertest.RunAll(t, Config{Provider: p})` runs the interface, behavior
and integration tiers against any provider; `RunOrgPermissionTests` (with
`Config.GrantOrgRole`) asserts the organization grants of the base schema,
and `RunManagerRelationTests` (with `Config.GrantManager`) the manager
grants. `RunResourceGrantTests` (with `Config.ResourceGranter`,
`GrantOrgRole` and, for a database-backed provider, `NewPrincipal` and
`NewOrganization`) covers the grant contract: the collaborator lifecycle,
the ladder, reductions, revocation, what a collaborator may do on the
organization, and `ListResources` for each permission. The role-based
provider runs it in `authz/rbac/resource_grants_test.go`, on SQLite and on
PostgreSQL; the relationship-based provider runs it in
`authz/rebac/spicedb/integration_grants_test.go` (build tag `integration`)
against an embedded in-memory SpiceDB, with the deployment schema composed
from a registered vocabulary. The suites are what makes the modes interchangeable on the
platform contract.

### Capability table

What each provider can answer:

| Question | `rbac` | `rebac` |
|---|---|---|
| Does the principal's organization or application role grant this action? | yes | yes |
| Does the principal own this resource? | yes (`WithOwnerFullAccess`, `Resource.OwnerID` supplied by the caller) | yes |
| Does the principal hold a direct grant on this specific resource? | yes, from `sf_resource_grants` | yes, as a relationship |
| Which resources of a type may the principal view, edit or manage? | yes: grants plus the organizations whose role grants it | yes: `LookupResources` |
| Does a permission reach the principal through relationships (team membership, a parent resource, a share with a group)? | no | yes, through the schema fragment |

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
| `approle.Service` (with `WithAuthzSyncer`) | `AddAppRole` (assign, and the new role of a change), `RemoveAppRole` (remove, the old role of a change, `RemoveForMember`) |
| `managedprincipal.Service` | `RegisterPrincipal`, `AddPrincipalManager`, `RemovePrincipalManager` |
| `marketplace` (`marketplace.AuthzSyncer`, `SpiceDBSyncer`) | Listing, license, license revocation, seat assignment and unassignment, subscription relationships |

`AddAppRole` and `RemoveAppRole` belong to the optional interface
`authz.AppRoleSyncer`, which `noop`, `spicedb.Syncer` and the test recorder
implement. A syncer that implements only `RelationshipSyncer` keeps
compiling and working: callers type-assert and skip application roles when it
is not an `AppRoleSyncer`. `spicedb.Syncer` writes
`{application}_org:{org}#{role}@principal:{principal}`, the facet an
application's schema fragment attaches to the base organization; an
application identifier that is not a valid app name is refused. An owner's
implicit `admin` is not a stored role and is not written; an application's
schema fragment must derive it from the owner relation. `organization.Service.RemoveMember` removes the member's
application roles from the graph after its transaction commits; SCIM group
member removal deletes the rows but, like its membership changes, makes no
syncer call.

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
membership or role change is honored until it expires (10 minutes by
default, 15 at most). SystemAuth records those changes in
`sf_access_changes` so a relying party can refuse such tokens sooner (ADR-010;
see the [organizations page](organizations.md#access-change-records-identityaccesschange)).

### Access-change reasons

Every row of `sf_access_changes` carries a reason. The reasons are an open,
validated registry, not a database enum:

- The column is a string, so adding a reason needs no migration.
- The constants live in one package, `identity/accesschange`, and are listed in
  `accesschange.Reasons()`. `accesschange.Record` rejects a value that is not
  registered with an error naming it, and `Reason.Valid()` reports membership.
- Every registered reason has a row in the table below. `TestRegistry`,
  `TestReasonsAreDocumented` and `TestCallSitesUseRegisteredReasons` fail when a
  constant is not registered, a reason has no row (or a row names no reason),
  or a call site builds an `accesschange.Change` with anything other than a
  registered constant.
- Reasons are wire values. They are carried unchanged in the back-channel
  `access_change` event and in `GET /access-changes`, so a reason is never
  renamed or reused for a different meaning. Relying parties treat the
  reason as opaque and tolerate one they do not know, so adding a reason does
  not break an older relying party.

To add a reason: declare the constant and list it in `Reasons()`, add a row
here, and use it at the call site that records the change. Record the
reason that says what happened to the principal; do not reuse a near
match, which is how an invitation that put a principal under management came
to be recorded as a reduced grant.

| Reason | Meaning | Recorded by |
|---|---|---|
| `membership_removed` | The principal was removed from, or deactivated in, an organization | `organization.RemoveMember`; `UpdateMember` setting a membership inactive (scoped to the organization) |
| `org_role_changed` | The principal's organization role changed | `UpdateMember` changing the role; `TransferOwnership`, for both principals (scoped) |
| `app_role_changed` | An application role was changed or removed | `approle.Change` to a different role, `Remove`, `RemoveForMember` (scoped); assignment only adds access and records nothing |
| `deactivated` | The principal was deactivated | `principal.Deactivate`; `managedprincipal.Delete` (every organization) |
| `sessions_revoked` | The principal's sessions or tokens were revoked | `token.RevokeAllForPrincipal`, `EntStorage.RevokeSubjectTokens` for a principal subject, `managedprincipal.RevokeSession` and `RevokeAll` (every organization) |
| `management_granted` | The principal came under management and gave up the capabilities managed principals do not hold | `managedprincipal.AcceptManagerInvite` (every organization) |
| `management_ended` | The principal's management ended and its own capabilities were restored | `managedprincipal.Release`; `RemoveManager` removing the last manager of a principal with a verified email (every organization) |
| `grant_reduced` | A resource grant was reduced or removed | `resourcegrant.Service.GrantResourceRole` giving a lower role, `RevokeResourceRole` (scoped to the resource's organization); granting or raising a role records nothing. Revoking a collaborator's last grant also records `membership_removed` |

## Planned changes

Accepted decisions not yet implemented. Each item names the ADR that
decides it.

### Resource-scoped collaborators (ADR-008)

- The base `organization` definition, `authz.OrgRolePermissions`, the
  parity test and the conventions carry the `collaborator` relation and the
  `list` permission (built). A collaborator is a principal with a membership
  of role `collaborator`, who has no `view`, `edit` or `manage` on the
  organization; personal organizations accept such memberships.
- Built: the standard resource-role ladder, the grant contract, both
  providers' implementations, the vocabulary validation of collaborator-able
  definitions and the shared suite across both modes (see [Resource
  grants](#resource-grants)).
- Built: `sf_invites` carries an optional resource type, resource ID and
  resource role; accepting such an invite creates the collaborator
  membership and the grant in one transaction (see
  [Invites](organizations.md#invites)).
- The `orgs` claim (ADR-007) lists a collaborator's organizations with role
  `collaborator`; the resources are the application's to look up.
- Agents and managed principals are granted the same way.

### Application roles (ADR-007)

- The `sf_app_roles` table records the application role per (principal,
  organization, application) (built; see
  [Organizations](organizations.md#application-roles-identityapprole)).
  Still to do: it replaces seat assignments as the record of who may use
  what. A seat-licensed application already counts its rows against the
  license, and role changes reach the authorization graph through
  `AppRoleSyncer`.
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
