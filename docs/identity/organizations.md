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
| `plan` | enum | Subscription tier |
| `active` | bool | Organization status |
| `created_at` | time | Creation timestamp |
| `updated_at` | time | Last modification |

## Plans

Organizations have subscription plans:

- `free` - Free tier
- `starter` - Entry-level paid
- `pro` - Professional tier
- `enterprise` - Enterprise tier

## Creating Organizations

```go
org, err := client.Organization.Create().
    SetName("Acme Corporation").
    SetSlug("acme-corp").
    SetPlan("pro").
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

## Feature Checks by Plan

```go
func canUseFeature(org *ent.Organization, feature string) bool {
    switch org.Plan {
    case "enterprise":
        return true // All features
    case "pro":
        return feature != "sso" && feature != "audit_logs"
    case "starter":
        return feature == "basic_analytics"
    default:
        return false
    }
}
```

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
