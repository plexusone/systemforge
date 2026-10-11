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

## Rules

- Roles come from the application's vocabulary (`AppVocabulary.Roles()`);
  there are no custom roles.
- Only an active `owner`, `admin` or `member` may hold a role. Collaborators,
  non-members and deactivated members may not.
- Owners hold the top role of every entitled application implicitly. Nobody
  else holds any by default, admins included.
- Removing a member removes their roles and grants in the same transaction.

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
| `501` | `APIConfig.AppRoles` is not set |

`PUT` assigns when there is no role and changes it otherwise, so it does not
return `already assigned`.

Reducing or removing a role records an access change, so tokens issued
before it are refused by relying parties that run a revocation cache; see
[Access-change invalidation](access-change-invalidation.md).
