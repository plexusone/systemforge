# Application roles and entitlements

An application role is a principal's role inside one application of an
organization, stored in `sf_app_roles` per (principal, organization,
application). An organization may hold roles only in the applications it is
entitled to, which the marketplace decides. The design is in
[Organizations and Membership](../design/architecture/organizations.md#application-roles-identityapprole).

## Wiring

```go
registry := authz.NewVocabularyRegistry()
_ = registry.Register(myAppVocabulary{}) // handle the error

src := marketplace.EntitlementSource(subscriptions, licenses, listings,
    marketplace.WithDefaultEntitlements("myapp")) // free to everyone, if any
roles := approle.NewService(db, registry,
    append(marketplace.ApproleOptions(src), approle.WithAuthzSyncer(res.Syncer, authz.SyncModeEventual))...)

cfg := organization.DefaultAPIConfig()
cfg.AppRoles = roles
cfg.Entitlements = src
```

Entitlement checks fail closed: with no entitlement option, no organization
is entitled to anything and every assignment is refused. `approle.EntitleAll`
exists for development and tests only. `marketplace.WarnIfNoEntitlements`
logs a warning at startup when applications are registered but nothing
entitles anyone.

## Where entitlements come from

An organization is entitled to an application through:

- an active (`active` or `trialing`) subscription to a listing that names the
  application, or a currently valid license for such a listing;
- the deployment's default entitlements.

A listing's `application` is settable only through the service, not the
listing HTTP API, so a listing creator cannot entitle buyers to an
application they do not control. Each `OrgResponse` carries the resulting
`entitlements` list.

A seat-licensed application has a seat limit, the sum of the seats of its
valid seat-based licenses; there is none when any entitlement is not
seat-limited. Roles are counted against it under an advisory lock, and
owners' implicit roles hold no seat.

### Entitlements in tokens

Entitlements reach relying parties through the `apps` map of each
organization in the `orgs` claim, in the ID token, the JWT access token,
`/oauth/userinfo` and `/oauth/userinfo/memberships`. `apps` lists only the
applications the organization is entitled to now, each with the principal's
role there (an owner's implicit top role included); an application absent
from it is one the principal may not open, whether because the
organization is not entitled or because the principal holds no role. A
stored role in an application the organization has lost drops out of the
claim at the next token or userinfo call, without being deleted. The claim
does not carry subscription tiers, seat counts or validity dates; read
those from the organization API's `entitlements`.

## Rules

- Roles come from the application's vocabulary (`AppVocabulary.Roles()`);
  there are no custom roles.
- Only an active `owner`, `admin` or `member` may hold a role. Collaborators,
  non-members and deactivated members may not.
- Owners hold the top role of every entitled application implicitly. Nobody
  else holds any by default, admins included.
- Removing a member removes their roles and grants in the same transaction.
- Demoting a member to collaborator deletes their application roles in the
  organization with the demotion. Promoting them again does not restore
  them; assign the roles again.
- Under authorization mode `rebac`, removing or lowering a role removes it
  from the graph inside the transaction, before the commit. If the graph
  refuses, nothing changes and the call returns the error, in both sync
  modes; retry it. See
  [Authorization mode](authorization-mode.md#keeping-the-graph-consistent-under-rebac).

## Endpoints

| Route | Needs |
|---|---|
| `GET /organizations/{slug}/app-roles[?application=]` | `change_role` |
| `GET /organizations/{slug}/members/{principal_id}/app-roles` | `change_role`, or `view` for your own; returns stored and effective roles |
| `PUT /organizations/{slug}/members/{principal_id}/app-roles/{application}` | `change_role`; body `{"role": "..."}`; assigns or changes |
| `DELETE /organizations/{slug}/members/{principal_id}/app-roles/{application}` | `change_role` |

Roles also travel on [invites](invites.md), and reach clients in the `orgs`
claim (`apps`, a map of application to role).

## Errors

| Status | Cause |
|---|---|
| `400` | `approle: unknown application`; `approle: role not declared by the application`; `approle: organization is not entitled to the application`; `approle: principal is not an active owner, admin or member` |
| `403` | The caller lacks `change_role`, or reads another member's roles without it |
| `404` | `approle: role not assigned` on `DELETE`; unknown organization or member |
| `409` | `approle: role already assigned` (service `Assign`); `approle: no seats available for the application` |
| `500` | `application roles failed`: an unexpected error, such as the authorization graph refusing a removal; nothing changed, so retry |
| `501` | `APIConfig.AppRoles` is not set |

`PUT` assigns when there is no role and changes it otherwise, so it does not
return `already assigned`.

Reducing or removing a role records an access change, so tokens issued
before it are refused by relying parties that run a revocation cache; see
[Access-change invalidation](access-change-invalidation.md).

## Operator commands

For recovery and bootstrap (restoring an owner who lost access, or granting
the first role in a product before the product can grant one itself), an
operator manages memberships and application roles from the command line,
without the API's authorization checks. The commands open the database
directly and go through the same services as the API, so removals record
access changes the same way:

```bash
systemauth org member add acme ada@example.com --org-role admin --role billing:admin
systemauth org member list acme            # --json, --include-inactive
systemauth org member remove acme ada@example.com --app billing   # only the role
systemauth org member remove acme ada@example.com                 # the membership
```

An organization is named by its slug (a slug it gave up within the
cooling-off period also works) and a person by their email or principal ID;
the person signs in once first. Adding an existing member changes their
organization role only when `--org-role` is given, and each `--role` is
assigned or changed. `--by` records the operator's principal ID as the
assigner.

The standalone `systemauth` binary registers no vocabularies, so it manages
memberships but refuses `--role`. A host that embeds SystemAuth mounts
`membercmd.Command` with its vocabularies and entitlements:

```go
root.AddCommand(membercmd.Command(open, membercmd.Options{
    Roles: membercmd.DefaultRoles(registry, marketplace.ApproleOptions(entitlements)...),
}))
```

Under authorization mode `rebac` the commands do not write the graph; the
running server's reconciler applies the change at its next run.
