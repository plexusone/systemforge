# Identity Module Overview

The Identity module provides principal and organization management for multi-tenant SaaS applications.

## Core Concepts

### Principals

A **principal** is any actor that can authenticate: a human, an OAuth application, an AI agent, or a backend service. Every principal is a row in `sf_principals`, with a one-to-one extension table for its type. A person is a human principal; there is no separate user table. See [Humans](users.md).

```go
import "github.com/plexusone/systemforge/identity/principal"

principals := principal.NewService(client)

p, err := principals.CreateHuman(ctx, principal.CreateHumanInput{
    Email:       "user@example.com",
    DisplayName: "Jane Doe",
})
```

### Organizations

Organizations (tenants) group principals with shared resources. Each organization has its own settings, members, and data.

```go
org, err := client.Organization.Create().
    SetName("Acme Corp").
    SetSlug("acme-corp").
    SetPlan("pro").
    Save(ctx)
```

### Memberships

Memberships link principals to organizations with a role, and can be suspended with their `active` flag. See [Memberships](memberships.md).

```go
import "github.com/plexusone/systemforge/identity/organization"

orgs := organization.NewService(client)

m, err := orgs.AddMember(ctx, organization.AddMemberInput{
    OrganizationID: org.ID,
    PrincipalID:    p.ID,
    Role:           "admin",
})
```

### Credentials

Passwords, API keys, client secrets, and public keys are rows in `sf_credentials`, typed and owned by a principal, and managed by `identity/credential`.

## Database Schema

All tables use the `sf_` prefix:

| Table | Description |
|-------|-------------|
| `sf_principals` | Every actor: humans, applications, agents, services |
| `sf_humans` | Human extension (email, names, avatar, platform admin) |
| `sf_applications` | OAuth application extension |
| `sf_agents` | AI agent extension |
| `sf_service_principals` | Backend service extension |
| `sf_organizations` | Organizations (tenants) |
| `sf_principal_memberships` | Principal-organization memberships |
| `sf_credentials` | Passwords, API keys, client secrets, keypairs |
| `sf_external_identities` | Linked upstream logins (GitHub, Google, federation) |
| `sf_principal_tokens` | Tokens issued to principals |

## Entity Relationships

```
                      ┌────────────────────┐
                      │     Principal      │
                      │ human | application│
                      │ agent | service    │
                      └─────────┬──────────┘
          ┌──────────────┬──────┴───────┬────────────────┐
          ▼              ▼              ▼                ▼
   ┌────────────┐ ┌────────────┐ ┌──────────────┐ ┌─────────────────────┐
   │   Human    │ │ Credential │ │  External    │ │ PrincipalMembership │
   │ (extension)│ │            │ │  Identity    │ │                     │
   └────────────┘ └────────────┘ └──────────────┘ └──────────┬──────────┘
                                                             ▼
                                                     ┌──────────────┐
                                                     │ Organization │
                                                     └──────────────┘
```

## Key Features

### Multi-Tenancy

Every resource can be scoped to an organization. To find the human members of an organization:

```go
import (
    entprincipal "github.com/plexusone/systemforge/identity/ent/principal"
    "github.com/plexusone/systemforge/identity/ent/principalmembership"
)

members, err := client.Principal.Query().
    Where(
        entprincipal.TypeEQ(entprincipal.TypeHuman),
        entprincipal.HasPrincipalMembershipsWith(
            principalmembership.OrganizationIDEQ(orgID),
            principalmembership.ActiveEQ(true),
        ),
    ).
    WithHuman().
    All(ctx)
```

### Platform Admins

Humans can be marked as platform admins for cross-organization access:

```go
admin := true
_, err := principals.UpdateHuman(ctx, p.ID, principal.UpdateHumanInput{
    IsPlatformAdmin: &admin,
})
```

### Upstream Logins

Humans can authenticate through upstream OAuth providers (GitHub, Google, SystemAuth). The [OAuth Client](oauthclient.md) package handles the OAuth flow:

```go
import cfoauth "github.com/plexusone/systemforge/identity/oauthclient"

// Exchange an OAuth code for the provider's user info.
info, err := cfoauth.FetchGitHubUser(ctx, githubConfig, code)
```

The upstream identity is recorded as an external identity on the human principal, keyed by provider and subject, so later logins from the same provider resolve to the same person. SystemAuth's social login does this automatically.

## Next Steps

- [Humans](users.md) - Human principals, passwords, and SystemAuth storage
- [Organizations](organizations.md) - Organization setup
- [Memberships](memberships.md) - Role-based membership
- [API Keys](api-keys.md) - Server-to-server authentication
- [OAuth Client](oauthclient.md) - Accept OAuth logins from GitHub, Google, SystemAuth
