# Collaborators and resource grants

A collaborator is a principal who belongs to an organization with role
`collaborator` and reaches individual resources, not the organization. A
resource grant gives a principal one of three roles on one resource. The
design is in [Organizations and Membership](../design/architecture/organizations.md#resource-grants-identityresourcegrant)
and [Authorization](../design/architecture/authorization.md#resource-grants).

## The model

| Piece | Rule |
|---|---|
| Collaborator membership | Role `collaborator`: no `view`, `edit` or `manage` on the organization, only `list` so an application can show the organization in a switcher. No application roles |
| Resource roles | `viewer` (view), `contributor` (view, edit), `maintainer` (view, edit, manage); each includes the ones below. The names are reserved for every application |
| Resource | `{app}_{type}` (a collaborator-able definition of a registered application) plus the application's own identifier, 1 to 1024 characters of letters, digits and `/_\|-=+` |
| Ownership | A resource belongs to one organization; grants naming another organization for an already-granted resource are refused |

An application declares which of its resource types accept collaborators by
giving the definition the three relations `viewer`, `contributor` and
`maintainer` in its vocabulary's schema fragment
(`authz.ResourceRoleFragment` renders it); a vocabulary with no fragment
accepts any type of its application.

## Granting and revoking

There is no HTTP API for grants: the application checks that its caller may
`manage` the resource, then calls the service.

```go
res, err := mode.New(ctx, cfg.Authz, mode.Deps{DB: db, Registry: registry})
ref := authz.ResourceRef{Type: "myapp_project", ID: projectID, OrganizationID: orgID}

err = res.Provider.GrantResourceRole(ctx, principalID, ref, authz.ResourceRoleContributor, callerID)
err = res.Provider.RevokeResourceRole(ctx, principalID, ref)
grants, err := res.Provider.ListResourceGrants(ctx, ref)
set, err := res.Provider.ListResources(ctx, principalID, "myapp_project", authz.PermResourceView)
// where org_id IN set.OrganizationIDs OR id IN set.IDs
```

Granting to a principal with no membership creates a collaborator
membership in the same transaction; granting again replaces the role.
Revoking the last grant of a collaborator removes the membership. An
existing member keeps their role and gains the grant. The same grant can be
made by accepting a [resource-targeted invite](invites.md).

Removing a member from the organization deletes their grants with the
membership. Demoting a member to collaborator keeps their grants but
deletes their application roles, since collaborators hold none. Agents and
managed principals are granted through the same operations, which confines
them to the granted resources.

Under authorization mode `rebac`, lowering or revoking a grant removes the
relationship from the graph inside the transaction, before the commit. If
the graph refuses, nothing changes and the call returns the error, in both
sync modes; retry the same call. A new or raised grant is written to the
graph after its commit, under the graph locks, so it never undoes a
revocation that committed meanwhile. See
[Authorization mode](authorization-mode.md#keeping-the-graph-consistent-under-rebac).

## Checking access

Both modes answer `Can(principal, view|edit|manage, resource)` with the same
result. The role-based provider needs `rbac.WithResourceGrants(svc)`, which
`mode.New` sets. Access that comes from an organization role (an admin's
`manage` through the organization) is unaffected by grants.

## Permissions

The grant service does no authorization of its own. The application should
require `manage` on the resource for resource grants, and `invite_member` for
invites.

## Errors

| Error | Meaning |
|---|---|
| `authz.ErrInvalidResourceRole` | The role is not `viewer`, `contributor` or `maintainer` |
| `authz.ErrInvalidResource` | The reference is malformed, or the type is not a collaborator-able type of a registered application |
| `authz.ErrGrantNotFound` | Revoking a grant the principal does not hold |
| `authz.ErrResourceOrganizationMismatch` | The resource already has grants in another organization |
| `resourcegrant.ErrInactiveMembership` | The principal has a deactivated membership that is not a collaborator's; reactivate or remove it first |
| `organization.ErrPersonalOrganization` | Collaborator invites without a target are refused for a personal organization |

Lowering or removing a grant records an access change (`grant_reduced`, plus
`membership_removed` when it was the last), so relying parties with a
revocation cache refuse earlier tokens; see
[Access-change invalidation](access-change-invalidation.md).
