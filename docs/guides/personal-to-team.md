# Converting a personal organization to a team

Every person has a personal organization named after their handle. When
they need to share it, `ConvertToTeam` turns it into a team without moving
anything: the same organization (ID, data, settings, memberships) takes a
team slug and becomes `team`, and the owner receives a new personal
organization under their old handle. The design is in
[Organizations and Membership](../design/architecture/organizations.md#converting-a-personal-organization-to-a-team).

```go
res, err := orgs.ConvertToTeam(ctx, personalOrgID, "acme", ownerID)
// res.Team is the converted organization; res.Personal is the new one.
```

There is no HTTP endpoint; call it from your own handler after checking the
caller is the owner.

## What happens

In one transaction:

1. The organization must be `personal` and `ownerID` its owner.
2. It is renamed to the team slug with the normal
   [rename rules](organization-slugs.md): valid, not reserved, not taken, not
   held by someone else. The old handle is reserved for the owner.
3. Its type becomes `team`. It now accepts members like any team, and its
   existing collaborators stay.
4. A new personal organization is created for the owner under the handle,
   spending the reservation. It is named after the owner's display name and
   has the owner as its only member.

After commit, the new organization is registered with the authorization
syncer. Any failure rolls everything back.

## Rules for personal organizations

A personal organization has exactly one member, its owner. Adding a member,
inviting a non-collaborator, SCIM group membership and ownership transfer are
refused with `organization.ErrPersonalOrganization`; the members API answers
`409`. A collaborator, reached through a resource grant or a
resource-targeted invite, is allowed. `POST /organizations` accepts only
`team` and `enterprise`; personal organizations come from signup.

## Errors

| Error | Meaning |
|---|---|
| `organization.ErrOrganizationNotFound` | No such organization |
| `organization.ErrNotPersonal` | The organization is already a team or enterprise |
| `organization.ErrNotOwner` | `ownerID` is not the owner |
| `ErrInvalidSlug`, `ErrSlugReserved`, `ErrSlugTaken`, `ErrSlugCoolingOff` | The team slug is refused; see [Organization slugs](organization-slugs.md) |
