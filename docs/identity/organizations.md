# Organizations

Organizations represent tenants in a multi-tenant application.

## Schema

The `sf_organizations` table contains:

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Primary key |
| `name` | string | Display name |
| `slug` | string | URL-safe identifier |
| `logo_url` | string | Organization logo |
| `settings` | JSON | Custom configuration |
| `org_type` | enum | `personal`, `team` (default) or `enterprise` |
| `owner_principal_id` | UUID | Owner of a personal organization |
| `active` | bool | Organization status |
| `created_at` | time | Creation timestamp |
| `updated_at` | time | Last modification |

## No plan column

An organization has no `plan`. What it may use is its entitlements, derived
from its marketplace subscriptions and licenses; see
[Entitlements via the marketplace](../design/architecture/organizations.md#entitlements-via-the-marketplace).
Existing databases drop the column with `migrations/0004_drop_organization_plan.sql`.

## Creating Organizations

```go
org, err := client.Organization.Create().
    SetName("Acme Corporation").
    SetSlug("acme-corp").
    SetSettings(map[string]any{
        "timezone": "America/New_York",
        "features": []string{"advanced_analytics"},
    }).
    Save(ctx)
```

## Slugs

Slugs must be unique and URL-safe:

```go
import "github.com/gosimple/slug"

orgSlug := slug.Make("Acme Corporation") // "acme-corporation"

org, err := client.Organization.Create().
    SetName("Acme Corporation").
    SetSlug(orgSlug).
    Save(ctx)
```

## Querying Organizations

### By Slug

```go
org, err := client.Organization.Query().
    Where(organization.SlugEQ("acme-corp")).
    Only(ctx)
```

### A Principal's Organizations

```go
orgs, err := client.Organization.Query().
    Where(organization.HasPrincipalMembershipsWith(
        principalmembership.PrincipalIDEQ(principalID),
        principalmembership.ActiveEQ(true),
    )).
    All(ctx)
```

### With Members

```go
org, err := client.Organization.Query().
    Where(organization.IDEQ(orgID)).
    WithPrincipalMemberships(func(q *ent.PrincipalMembershipQuery) {
        q.WithPrincipal()
    }).
    Only(ctx)

for _, m := range org.Edges.PrincipalMemberships {
    fmt.Printf("Member: %s, Role: %s\n", m.Edges.Principal.DisplayName, m.Role)
}
```

## Settings

Organization settings store custom configuration:

```go
// Update settings
org, err := client.Organization.UpdateOneID(orgID).
    SetSettings(map[string]any{
        "timezone": "Europe/London",
        "branding": map[string]any{
            "primary_color": "#3B82F6",
            "logo_url": "https://example.com/logo.png",
        },
    }).
    Save(ctx)

// Read settings
timezone := org.Settings["timezone"].(string)
```

## Feature Checks

Gate a feature on the organization's entitlements, not on a plan value. Each
`OrgResponse` carries an `entitlements` list, and application roles can be
granted only for entitled applications; see
[Application roles and entitlements](../guides/application-roles.md).

## Organization Edges

Organizations have relationships to:

| Edge | Target | Description |
|------|--------|-------------|
| `principal_memberships` | PrincipalMembership | Organization members |
| `principals` | Principal | Principals scoped to the organization |
| `oauth_apps` | OAuthApp | OAuth apps owned by org |
| `owner` | Principal | Owner of a personal organization |

## Multi-Tenant Queries

### Scope All Queries to Organization

```go
func getHumansInOrg(ctx context.Context, client *ent.Client, orgID uuid.UUID) ([]*ent.Principal, error) {
    return client.Principal.Query().
        Where(
            principal.TypeEQ(principal.TypeHuman),
            principal.HasPrincipalMembershipsWith(
                principalmembership.OrganizationIDEQ(orgID),
                principalmembership.ActiveEQ(true),
            ),
        ).
        WithHuman().
        All(ctx)
}
```

### Organization Context

Store organization ID in context for automatic scoping:

```go
type contextKey string

const orgKey contextKey = "organization_id"

func WithOrganization(ctx context.Context, orgID uuid.UUID) context.Context {
    return context.WithValue(ctx, orgKey, orgID)
}

func OrganizationFromContext(ctx context.Context) uuid.UUID {
    orgID, _ := ctx.Value(orgKey).(uuid.UUID)
    return orgID
}
```
