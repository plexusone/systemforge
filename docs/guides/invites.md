# Invites

An invite brings a person with a known email address into an organization.
It can also grant application roles on acceptance, or, for a collaborator, a
role on one resource. The design is in
[Organizations and Membership](../design/architecture/organizations.md#invites);
this guide is what a developer needs to wire and call it.

## Wiring

```go
invites := invite.NewService(db, baseURL,
    invite.WithAuthzSyncer(res.Syncer),
    invite.WithAppRoles(appRoles),          // optional: application roles on invites
    invite.WithResourceGrants(res.Grants),  // optional: resource-targeted invites
)
cfg := invite.DefaultAPIConfig()
cfg.Authorizer = authorizer
api := invite.NewAPI(invites, orgService, cfg)
```

Without `WithAppRoles`, `app_roles` on an invite is refused and no
application role is ever required. Without `WithResourceGrants`, a resource
target is refused.

## Creating an invite

`POST /organizations/{slug}/invites`

| Field | Meaning |
|---|---|
| `email` | The invitee; the invite is bound to this address (case-insensitive) |
| `role` | Required: `owner`, `admin`, `member` or `collaborator` |
| `app_roles` | Optional map of application identifier to role, granted on acceptance |
| `resource_type`, `resource_id`, `resource_role` | Optional, all or none: a resource and the resource role (`viewer`, `contributor`, `maintainer`) to grant |
| `message`, `expires_in_hours` | Optional note; expiry defaults to 7 days, at most 720 hours |
| `inviter_principal_id` | Optional; if given it must be the authenticated caller |

The response carries `invite_url` (`{baseURL}/invites/{token}`). The token
is shown once: only its SHA-256 is stored, so deliver the URL yourself.

### Application roles on an invite

With `WithAppRoles`:

- Each `app_roles` entry is validated: the application is registered, the
  role is one it declares, and the organization is entitled to it.
- An `admin` or `member` invitation to an organization that is entitled to
  any application must choose at least one role (`ErrAppRoleRequired`).
  Owners hold every role implicitly, so an owner invite needs none.
- A collaborator invite may carry none.
- Roles are granted in the same transaction as the membership. If one cannot
  be granted at acceptance (no seat left, entitlement gone) the invite is
  refused and stays pending.

### Resource-targeted invites

A resource target requires `role: collaborator` and
`WithResourceGrants`, and is validated against the application's
vocabulary: the type must be `{app}_{type}` of a registered application and,
when the vocabulary has a schema fragment, a collaborator-able definition.
On acceptance the collaborator membership and the grant are created together;
an existing member keeps their role and gains the grant.

A person may hold several pending invites to one organization if each
targets a different resource. A personal organization accepts only
resource-targeted collaborator invites. See
[Collaborators and resource grants](collaborators.md).

## Accepting and declining

| Route | Rule |
|---|---|
| `GET /invites/{token}` | Landing-page lookup |
| `POST /invites/{token}/accept` | The caller's verified email must match the invite |
| `POST /invites/{token}/decline` | Same match |
| `GET /invites` | Lists the caller's own pending invites; another address is `403` |

The email is the one `invite.DefaultService.PrincipalEmail` returns, which
is only an address with `email_verified_at` set: an address merely claimed
when a principal was created (a managed principal, an unverified signup, SCIM
provisioning without trusted emails) does not count. A custom
`APIConfig.PrincipalEmail` must apply the same rule.

Signing up through an invite (`signup.SignupWithInvite`) applies the same
email match (`signup.ErrInviteEmailMismatch`). Because the invite token was
delivered to that address, a successful invite signup marks the new
account's email verified.

An invite carries its inviter's current authority, not the authority it had
when it was sent. Accepting requires the inviter to still hold
`invite_member` on the organization, and the owner-only `delete` for an
owner invite; otherwise acceptance fails with
`invite.ErrInviterNotAuthorized`. By default the inviter's active membership
role is checked; `invite.WithAuthorizer(authorizer)` asks an authorizer
instead, for deployments where principals who are not members (platform
administrators) send invites. Removing or deactivating a member revokes the
pending invites it sent, and demoting it revokes those it may no longer send
(owner invites when it stops being an owner).

Every change of an invite's status (accept, decline, revoke, resend, expiry)
applies only to a pending invite, as one conditional update. An invite
revoked while it is being accepted is not accepted, and revoking an accepted
invite fails rather than marking it revoked (`invite.ErrNotPending`); remove
the member through the organization instead.

## Permissions

| Operation | Needs |
|---|---|
| Create, list, resend, revoke | `invite_member` on the organization (owner or admin) |
| Invite with `role: owner` | The owner-only permission (`delete`) |
| Accept, decline, list own | An authenticated principal whose verified email matches the invite |

## Errors

| Status | Cause |
|---|---|
| `400` | The service refused the request. The message names the cause: `pending invite already exists for this email`; `invite: choose an application role for at least one entitled application`; `invite: collaborators hold no application roles`; `invite: application roles are not configured`; `invite: invalid resource target` (incomplete target, role not `collaborator`, grants not configured, or a type or role the vocabulary rejects); a collaborator invite without a target to a personal organization; `invite is no longer pending`; `invite has expired`; `invite: the inviter may no longer invite to this organization`; `principal is already a member of this organization`; an application role that cannot be granted (`approle: no seats available for the application`, `approle: organization is not entitled to the application`) |
| `403` | `inviter_principal_id` is not the caller; an admin inviting an owner; a principal without a verified email (a managed principal, or one that has not verified its address) answering or listing invites; listing another address's invites; the caller can view the organization but may not invite |
| `404` | Unknown organization or invite; a caller who cannot even view the organization; an invite addressed to a different email (a mismatch looks like an unknown token) |
| `501` | No `Authorizer`, or no principal email lookup, is configured |

Manager invitations, which put an existing person under the management of a
guardian, are a separate flow; see
[Managed Principals](../identity/managed-principals.md).
