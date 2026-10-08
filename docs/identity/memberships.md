# Memberships

A membership links a principal to an organization with a role. Any principal type can be a member, though most memberships belong to humans.

## Schema

The `sf_principal_memberships` table contains:

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Primary key |
| `principal_id` | UUID | The member principal |
| `organization_id` | UUID | The organization |
| `role` | string | Role within the organization |
| `permissions` | JSON | Optional fine-grained permissions (string list) |
| `active` | bool | Whether the membership is in effect |
| `created_at`, `updated_at` | time | Timestamps |

**Unique constraint**: one membership per principal per organization.

### The `active` Flag

`active` lets a membership be suspended without deleting it. A membership that is inactive should be treated as absent for access decisions. The SCIM store returns only active memberships and reactivates an existing row when a member is re-added. `organization.Service.ListMembers` and `ListMemberships` return memberships regardless of `active`, so filter on `Membership.Active` where it matters.

## Roles

Roles are strings, so each application defines its own vocabulary. The platform ladder used by the authorization conventions is `owner`, `admin`, `editor`, `member`, `viewer`; see [Authorization conventions](../authz-conventions.md) for registering domain roles.

## Managing Memberships

Use the organization service, which also syncs membership changes to the authorization backend:

```go
import "github.com/plexusone/systemforge/identity/organization"

orgs := organization.NewService(client)

m, err := orgs.AddMember(ctx, organization.AddMemberInput{
    OrganizationID: orgID,
    PrincipalID:    principalID,
    Role:           "member",
    Permissions:    []string{"projects:export"},
})
```

`AddMember` returns an error if the principal is already a member.

### Change Role or Suspend

```go
role := "admin"
m, err := orgs.UpdateMember(ctx, membershipID, organization.UpdateMemberInput{Role: &role})

inactive := false
m, err = orgs.UpdateMember(ctx, membershipID, organization.UpdateMemberInput{Active: &inactive})
```

### Remove

```go
err := orgs.RemoveMember(ctx, orgID, principalID)
```

## Querying Memberships

```go
// One principal's membership in one organization.
m, err := orgs.GetMembership(ctx, orgID, principalID)

// Everyone in an organization.
members, err := orgs.ListMembers(ctx, orgID)

// Every organization a principal belongs to.
memberships, err := orgs.ListMemberships(ctx, principalID)
```

### With Ent Directly

```go
import "github.com/plexusone/systemforge/identity/ent/principalmembership"

admins, err := client.PrincipalMembership.Query().
    Where(
        principalmembership.OrganizationIDEQ(orgID),
        principalmembership.ActiveEQ(true),
        principalmembership.RoleIn("owner", "admin"),
    ).
    WithPrincipal().
    All(ctx)

for _, m := range admins {
    fmt.Printf("Admin: %s\n", m.Edges.Principal.DisplayName)
}
```

## Role Hierarchy

Implement a role hierarchy in your application:

```go
var roleLevel = map[string]int{
    "owner":  100,
    "admin":  80,
    "editor": 60,
    "member": 40,
    "viewer": 20,
}

func HasMinRole(m *organization.Membership, required string) bool {
    return m.Active && roleLevel[m.Role] >= roleLevel[required]
}
```

## Permission Checks

```go
func HasPermission(m *organization.Membership, permission string) bool {
    if !m.Active {
        return false
    }
    if m.Role == "owner" {
        return true
    }
    return slices.Contains(m.Permissions, permission)
}
```

## Ownership Transfer

Transfer organization ownership from one member to another:

```go
err := orgs.TransferOwnership(ctx, organization.TransferOwnershipInput{
    OrganizationID: orgID,
    FromPrincipal:  currentOwnerID,
    ToPrincipal:    newOwnerID,
    NewRoleForOld:  "admin", // or "member"; defaults to "admin"
})
```

### Validation Rules

- The current owner must have the `owner` role
- The new owner must be an existing member
- The new role for the previous owner must be `admin` or `member`
- Ownership cannot be transferred to yourself

### Transaction Safety

The transfer runs in one transaction:

1. Demote the current owner to the specified role (default `admin`)
2. Promote the new owner to `owner`
3. Update the organization's `owner_principal_id`
4. Sync the changes to the authorization backend

### API Endpoint

```
POST /organizations/{slug}/transfer-ownership
```

**Request body:**

```json
{
  "new_owner_principal_id": "uuid",
  "new_role_for_old_owner": "admin"
}
```

**Response:**

```json
{
  "message": "Ownership transferred successfully"
}
```

Only the current owner can transfer ownership.
