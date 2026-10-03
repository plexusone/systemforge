# Identity Module Overview

The Identity module provides core user and organization management for multi-tenant SaaS applications.

## Core Concepts

### Users

Users are individual accounts that can authenticate and access the system. A user can belong to multiple organizations with different roles in each.

```go
user, err := client.User.Create().
    SetEmail("user@example.com").
    SetName("John Doe").
    SetPasswordHash(hashedPassword).
    Save(ctx)
```

### Organizations

Organizations (tenants) group users together with shared resources. Each organization has its own settings, members, and data.

```go
org, err := client.Organization.Create().
    SetName("Acme Corp").
    SetSlug("acme-corp").
    SetPlan("pro").
    Save(ctx)
```

### Memberships

Memberships link users to organizations with specific roles. A user can have different roles in different organizations.

```go
membership, err := client.Membership.Create().
    SetUserID(user.ID).
    SetOrganizationID(org.ID).
    SetRole("admin").
    Save(ctx)
```

## Database Schema

All tables use the `cf_` prefix to avoid conflicts:

| Table | Description |
|-------|-------------|
| `cf_users` | User accounts |
| `cf_organizations` | Organizations/tenants |
| `cf_memberships` | User-org relationships |
| `cf_oauth_accounts` | External OAuth logins |
| `cf_refresh_tokens` | Session refresh tokens |
| `cf_api_keys` | API key credentials |

## Entity Relationships

```
┌─────────┐     ┌─────────────┐     ┌──────────────┐
│  User   │────▶│ Membership  │◀────│ Organization │
└─────────┘     └─────────────┘     └──────────────┘
     │                                     │
     │                                     │
     ▼                                     ▼
┌─────────────┐                    ┌─────────────┐
│OAuthAccount │                    │   APIKey    │
└─────────────┘                    └─────────────┘
     │
     ▼
┌─────────────┐
│RefreshToken │
└─────────────┘
```

## Key Features

### Multi-Tenancy

Every resource can be scoped to an organization:

```go
// Query users in an organization
users, err := client.User.Query().
    Where(user.HasMembershipsWith(
        membership.OrganizationIDEQ(orgID),
    )).
    All(ctx)
```

### Platform Admins

Users can be marked as platform admins for cross-organization access:

```go
user.Update().
    SetIsPlatformAdmin(true).
    Save(ctx)
```

### OAuth Integration

Users can authenticate via external OAuth providers (GitHub, Google, SystemAuth). The [OAuth Client](oauthclient.md) package handles the OAuth flow:

```go
import cfoauth "github.com/plexusone/systemforge/identity/oauthclient"

// Exchange OAuth code for user info
user, err := cfoauth.FetchGitHubUser(ctx, githubConfig, code)
```

OAuth accounts are then linked to local users:

```go
oauthAccount, err := client.OAuthAccount.Create().
    SetUserID(user.ID).
    SetProvider("github").
    SetProviderUserID("12345").
    SetAccessToken(encryptedToken).
    Save(ctx)
```

## Next Steps

- [Users](users.md) - User management in detail
- [Organizations](organizations.md) - Organization setup
- [Memberships](memberships.md) - Role-based membership
- [API Keys](api-keys.md) - Server-to-server authentication
- [OAuth Client](oauthclient.md) - Accept OAuth logins from GitHub, Google, SystemAuth
