# Integrating with Existing Apps

This guide covers integrating SystemForge into an existing Go application that already has its own users, organizations, and memberships.

## How SystemForge Models People

Every actor in SystemForge is a **principal**. A person is a principal of type `human` plus a one-to-one `Human` row with their email and profile. Passwords are credentials, organizations are organizations, and membership links a principal to an organization with a role:

```
existing tables          SystemForge tables
─────────────────       ──────────────────────────────────────
users            ←──→   sf_principals (type = 'human') + sf_humans
                        sf_credentials (type = 'password')
organizations    ←──→   sf_organizations
user_orgs        ←──→   sf_principal_memberships
```

See the [schema reference](../reference/schemas.md) for every column.

## Integration Patterns

### Pattern 1: Side-by-Side Tables

Keep your existing tables and add the SystemForge tables alongside them, copying data across and switching reads over time. The [migration guide](migration.md) covers the copy in detail.

### Pattern 2: Extension Tables

Keep app-specific data in your own tables and reference the SystemForge principal by ID:

```go
type UserProfile struct {
    ent.Schema
}

func (UserProfile) Fields() []ent.Field {
    return []ent.Field{
        field.UUID("principal_id", uuid.UUID{}).Unique(),
        field.String("username").Unique(),
        field.String("bio").Optional(),
    }
}
```

The principal ID is stable across every sign-in method (password, social login, federation, SCIM), so it is the right key for application data.

## Step-by-Step Integration

### Step 1: Add the Dependency

```bash
go get github.com/plexusone/systemforge
```

### Step 2: Create the SystemForge Tables

Run `systemauth migrate`, or create the schema from your own code:

```go
import (
    "database/sql"

    "entgo.io/ent/dialect"
    entsql "entgo.io/ent/dialect/sql"
    _ "github.com/jackc/pgx/v5/stdlib"

    "github.com/plexusone/systemforge/identity/ent"
)

func migrate(ctx context.Context, dsn string) (*ent.Client, error) {
    db, err := sql.Open("pgx", dsn)
    if err != nil {
        return nil, err
    }
    client := ent.NewClient(ent.Driver(entsql.OpenDB(dialect.Postgres, db)))
    if err := client.Schema.Create(ctx); err != nil {
        return nil, errors.Join(err, client.Close())
    }
    return client, nil
}
```

### Step 3: Copy Existing Data

Copy users into `sf_principals` and `sf_humans`, compatible password hashes into `sf_credentials`, and then organizations and memberships. The [migration guide](migration.md#copying-data) has the SQL, including which password hash formats can be imported.

### Step 4: Set Up Dual-Write

Create people through the principal service, which writes the principal and its human row together and uses the email as the principal's identifier. Then write your own row with the returned principal ID:

```go
import (
    "github.com/plexusone/systemforge/identity/credential"
    "github.com/plexusone/systemforge/identity/principal"
)

type UserService struct {
    appClient  *appent.Client
    principals principal.Service
    creds      credential.Service
}

func NewUserService(appClient *appent.Client, sfClient *ent.Client) *UserService {
    return &UserService{
        appClient:  appClient,
        principals: principal.NewService(sfClient),
        creds:      credential.NewService(sfClient),
    }
}

func (s *UserService) CreateUser(ctx context.Context, email, name, password string) error {
    p, err := s.principals.CreateHuman(ctx, principal.CreateHumanInput{
        Email:       email,
        DisplayName: name,
    })
    if err != nil {
        return err
    }

    if password != "" {
        if err := s.creds.CreatePassword(ctx, credential.CreatePasswordInput{
            PrincipalID: p.ID,
            Password:    password,
        }); err != nil {
            return err
        }
    }

    // Write to app tables with the same ID.
    _, err = s.appClient.User.Create().
        SetID(p.ID).
        SetEmail(email).
        SetName(name).
        Save(ctx)
    return err
}
```

`CreatePassword` hashes with Argon2id, and `credential.Service.VerifyPassword` checks a password against it.

### Step 5: Switch Reads

Read people from SystemForge. `GetByID` returns the principal with its human extension populated in `Human`:

```go
func (s *UserService) GetUser(ctx context.Context, id uuid.UUID) (*User, error) {
    p, err := s.principals.GetByID(ctx, id)
    if err != nil {
        return nil, err
    }

    profile, err := s.appClient.UserProfile.Query().
        Where(userprofile.PrincipalIDEQ(id)).
        Only(ctx)
    if err != nil && !appent.IsNotFound(err) {
        return nil, err
    }

    return &User{Principal: p, Profile: profile}, nil
}
```

To find someone by email, query the human row without regard to case, since SystemForge treats emails case-insensitively:

```go
p, err := sfClient.Principal.Query().
    Where(
        principal.TypeEQ(principal.TypeHuman),
        principal.HasHumanWith(human.EmailEqualFold(email)),
    ).
    WithHuman().
    Only(ctx)
```

This query uses the Ent packages `identity/ent/principal` and `identity/ent/human`.

### Step 6: Remove Old Tables

After validation, archive and drop the old user tables:

```sql
CREATE TABLE users_archive AS SELECT * FROM users;
DROP TABLE users;
```

## OAuth Integration

SystemForge's OAuth 2.0 and OpenID Connect server is **SystemAuth**. An existing application has two supported ways to use it:

- **Run SystemAuth as an identity provider and federate to it.** The application becomes an OpenID Connect client with the `identity/relyingparty` package, which handles the authorization flow, token verification, and finding or creating the application's local record for each principal. See [Relying Parties](../systemauth/relying-party.md).
- **Embed SystemAuth in the application's binary.** The `identity/systemauthsvc` package runs the same server as the standalone `systemauth` binary inside your process, with the same configuration, production checks, and database setup. See [Embedding SystemAuth](../systemauth/embedding.md).

Either way, the subject of every token is the SystemForge principal ID, so it can be used directly as the key into your extension tables.

## Multi-Tenant Integration

### Map Existing Tenants

```go
func copyOrganizations(ctx context.Context, appClient *appent.Client, sfClient *ent.Client) error {
    tenants, err := appClient.Tenant.Query().All(ctx)
    if err != nil {
        return err
    }
    for _, t := range tenants {
        if _, err := sfClient.Organization.Create().
            SetID(t.ID).
            SetName(t.Name).
            SetSlug(t.Slug).
            Save(ctx); err != nil {
            return err
        }
    }
    return nil
}
```

Organizations have no `plan`; carry a tenant's paid tier over as a marketplace subscription or license.

### Map Existing Memberships

```go
func copyMemberships(ctx context.Context, appClient *appent.Client, sfClient *ent.Client) error {
    members, err := appClient.TenantMember.Query().All(ctx)
    if err != nil {
        return err
    }
    for _, m := range members {
        if _, err := sfClient.PrincipalMembership.Create().
            SetPrincipalID(m.UserID).
            SetOrganizationID(m.TenantID).
            SetRole(mapRole(m.Role)).
            Save(ctx); err != nil {
            return err
        }
    }
    return nil
}
```

`role` is an application-defined string; `PrincipalMembership` also has an `active` flag (default true) for deactivating a membership without deleting it.

## Validation Checklist

- [ ] SystemForge tables created (`sf_*`)
- [ ] People copied to `sf_principals` and `sf_humans`
- [ ] Compatible password hashes copied to `sf_credentials`; other users told to reset
- [ ] Organizations and memberships copied
- [ ] Dual-write enabled
- [ ] Read paths switched
- [ ] Sign-in through SystemAuth working, with token subjects mapped to principal IDs
- [ ] Old tables archived
- [ ] Dual-write disabled
- [ ] Old tables dropped
