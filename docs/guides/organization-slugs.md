# Organization slugs

The slug is an organization's identity in URLs and in the API:
`/organizations/{slug}`, `/organizations/{slug}/members`, `/invites/...`.
The display name is cosmetic. The slug is unique across personal and team
organizations. The design is in
[Organizations and Membership](../design/architecture/organizations.md#slug-is-the-identity).

## Format and generation

A slug matches `^[a-z][a-z0-9-]*[a-z0-9]$` and is 3 to 63 characters
(`organization.IsValidSlug`). `GET /organizations/check-slug/{slug}` answers
`{"slug", "available"}`, and `available` is `false` for a taken, reserved or
cooling-off slug. `GenerateSlug(name)` slugifies a name and appends `-1` to
`-100`, then a UUID fragment, until one is free.

Social login derives the personal slug from the provider: the GitHub
username, the Google email local part, otherwise the username or local
part; collisions take `-1` to `-100` and then a random suffix. A managed
principal's slug is never taken from an email (`signup.SlugForManaged`).

## Reserved slugs

Names that would collide with a route or protocol path cannot be taken:
`about`, `admin`, `api`, `help`, `invites`, `login`, `logout`, `new`, `o`,
`oauth`, `organizations`, `scim`, `settings`, `support`, `well-known`, `www`
(`organization.ReservedSlugs`). Add product names when you build the
service:

```go
orgs := organization.NewService(db, organization.WithReservedSlugs("billing", "console"))
```

For signup, pass the same names in `PersonalOrgParams.ReservedSlugs`; a
reserved base slug gets a numeric suffix.

## Renaming

`Rename(ctx, orgID, newSlug, actor)` is a service method; there is no HTTP
endpoint. The actor must be an active owner. In one transaction the old slug
is written to `sf_slug_reservations` and held for the cooling-off period,
7 days by default (`organization.WithSlugCoolingOff(d)`).

| While the old slug is held | Rule |
|---|---|
| Who may take it | The principal who released it, or an owner of the organization that released it |
| Everyone else | `ErrSlugCoolingOff`; `check-slug` answers `available: false` |
| Alias | `ResolveSlug` returns the releasing organization with `alias = true`, and the organization and invite handlers resolve `{slug}` through it, so old links keep working and responses carry the current slug |
| After expiry | The reservation is ignored and deleted when next read |

`GetBySlug` stays an exact match. Update your own URLs to the current slug
from the response.

### Resolving slugs in a relying party

A relying party that puts slugs in its own URLs resolves them to the
SystemAuth organization ID, which it keys its data by, with the signed-in
person's access token (granted `openid`):

```go
m, alias, err := rp.ResolveOrganization(ctx, accessToken, slug)
switch {
case errors.Is(err, relyingparty.ErrOrganizationNotResolved):
    // 404: no such organization, or the person is not a member
case err != nil:
    return err
case alias:
    // the organization was renamed: redirect to m.OrganizationSlug
}
orgID := m.OrganizationID
```

It calls `GET /oauth/userinfo/memberships/resolve?slug=`, which answers
`{"org": {...}, "alias": bool}` with the organization in the full form of the
`orgs` claim and its current slug. It resolves only among the principal's
active memberships, so an unknown slug and someone else's organization both
answer 404, and an old slug stops resolving when its cooling-off period ends.
The organization API's `GET /organizations/{slug}` also follows the alias,
but it is served by a host that mounts that API for signed-in people, not by
SystemAuth to relying parties.

## Errors

| Error | HTTP | Meaning |
|---|---|---|
| `organization.ErrInvalidSlug` | 400 on create | Not lowercase alphanumeric with hyphens, or the wrong length |
| `organization.ErrSlugReserved` | 400 on create | On the built-in or configured reserved list |
| `organization.ErrSlugTaken` | 400 on create | Used by an organization |
| `organization.ErrSlugCoolingOff` | 400 on create | Held by someone else's reservation |
| `organization.ErrNotOwner` | n/a (service) | `Rename` by a principal who is not an active owner |

`PATCH /organizations/{slug}` cannot change the slug; it accepts only
`name`, `logo_url`, `description`, `website_url` and `settings`.
