# Multi-App Framework

The multiapp package enables multiple apps to share backend infrastructure while keeping each app's data in its own PostgreSQL schema. Apps can be deployed in two modes:

- **Multi-app mode**: Multiple apps share a server, routed by `X-App-ID` header
- **Single-app mode**: One app runs on dedicated infrastructure

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                           HTTP Request                          │
│                     X-App-ID: app1                              │
│                     Authorization: Bearer <jwt>                 │
└─────────────────────────────────┬───────────────────────────────┘
                                  │
┌─────────────────────────────────▼───────────────────────────────┐
│                          multiapp.Server                        │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  appContextMiddleware                                     │  │
│  │  - Extracts X-App-ID header                               │  │
│  │  - Looks up registered app                                │  │
│  │  - Sets AppContext in request context                     │  │
│  │  - Routes to app's router                                 │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────┬───────────────────────────────┘
                                  │
          ┌───────────────────────┼───────────────────────┐
          │                       │                       │
          ▼                       ▼                       ▼
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   App1     │     │   App2     │     │   App3    │
│   AppBackend    │     │   AppBackend    │     │   AppBackend    │
├─────────────────┤     ├─────────────────┤     ├─────────────────┤
│ Schema:         │     │ Schema:         │     │ Schema:         │
│ app_app1   │     │ app_app2   │     │ app_app3  │
├─────────────────┤     ├─────────────────┤     ├─────────────────┤
│ Own users       │     │ Own users       │     │ Own users       │
│ Own orgs        │     │ Own orgs        │     │ Own orgs        │
│ Own data        │     │ Own data        │     │ Own data        │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

## Key Concepts

### Schema-Per-App Isolation

Each app gets its own PostgreSQL schema (e.g., `app_app1`). This provides:

- Separate tables per app, chosen per transaction with `SET LOCAL search_path` (see [Database isolation](#database-isolation))
- Independent migrations per app
- Shared database infrastructure, with one database login per app

```
PostgreSQL Database
├── app_app1/          # App1 schema
│   ├── users
│   ├── organizations
│   ├── courses
│   └── ...
├── app_app2/          # App2 schema
│   ├── users
│   ├── organizations
│   ├── dashboards
│   └── ...
└── app_app3/         # App3 schema
    ├── users
    ├── organizations
    ├── proofs
    └── ...
```

### Database isolation

A schema name alone does not keep apps apart: `search_path` only picks
which schema unqualified names resolve to, and SQL running for one app (or
injected into it) can name another app's tables directly,
`app_other.users`. Switching roles inside one shared pool (`SET LOCAL
ROLE`) does not help either, because SQL in the same transaction can run
`RESET ROLE` or `SET ROLE` to get back out. multiapp therefore relies on
PostgreSQL privileges, with one database login per app.

**Each app has its own database login by default.** `Config.AppDatabases`
maps every app slug to the app's own credentials, and the server opens a
separate pool for each app. `RegisterApp` refuses an app without one
(`ErrAppDatabaseLoginRequired`). An `AppAwareDB` opened with an app's login
serves that app's schema only: `ForSchema`, `EntClientFactory` and
`EntConnHook` refuse a second schema with `ErrSharedDatabaseLogin`.

```go
server, err := multiapp.NewServer(multiapp.Config{
    Mode:                 multiapp.MultiAppMode,
    MigrationRole:        "sf_owner", // the owner role, for the isolation check
    AppDatabases: map[string]multiapp.AppDatabase{
        "app1": {URL: os.Getenv("APP1_DATABASE_URL")},
        "app2": {URL: os.Getenv("APP2_DATABASE_URL")},
    },
})
```

The same rule applies in single-app mode: the one app connects with its
own login, and migrations run with the owner login in a separate step.

**Migrations run as a separate step, with a separate migration (owner)
login.** The owner login owns the app schemas and creates their tables;
tables it creates reach the app's login through default privileges set at
provisioning. App servers do not hold it: run
`multiapp.Migrate(ctx, ownerURL, backends...)` before the servers start,
from a process that is given the owner's secret and nothing else to do,
such as the app binary's own `migrate` command (the example's
`main.go migrate`) run as a one-off task. `Migrate` runs every migration
on every call, so write migrations to be idempotent (`CREATE TABLE IF NOT
EXISTS`, and so on). The `multiappdb` command cannot run them, since they
are Go code compiled into the app.

The servers then leave `Config.MigrationDatabaseURL` empty. `RegisterApp`
creates no schema and runs no migration: it requires the app's schema to
exist and its login to have `USAGE` on it, refusing the app with
`ErrAppSchemaMissing` otherwise, and the isolation check runs as usual.
Set `Config.MigrationRole` to the owner role's name (no credentials), so
the check also verifies that no app login is a member of it or can act as
it.

**In-process migrations, for local development only.** Setting
`MigrationDatabaseURL` makes `RegisterApp` create each app's schema and run
its `Migrations` with the owner login when the app registers. `NewServer`
refuses it (`ErrInProcessMigrationsNotAllowed`) unless
`AllowInProcessMigrations` is also set, and logs a warning when it is: the
server process then holds the owner's credentials, and any code that takes
it over can use the owner's privileges on every app schema.

**Running migrations on AWS.** Package the migration step as a one-off
Amazon ECS task: a task definition that runs the app image's `migrate`
command, with its own task role and only the owner's secret (Secrets
Manager or an RDS IAM token for the owner role) injected. Run it with
`aws ecs run-task` (or a deployment pipeline step) and wait for it to
stop with exit code 0 before updating the app service. The app service's
task definition gets only the app's own database secret, and
`MigrationRole` as plain configuration.

**The server checks isolation at startup.** `RegisterApp` and `Run` call
`CheckDatabaseIsolation` (also available as
`Server.VerifyDatabaseIsolation`, and from the `multiappdb verify` command),
which connects with each app's login and fails, naming the app and the
problem but never a password, unless:

- the login is not a superuser and has neither `BYPASSRLS` nor `CREATEROLE`;
- it is not another app's login, owns no app schema, and is not a member of
  another app's role, the owner (migration) role, a superuser or
  `BYPASSRLS` role, `pg_read_all_data` or `pg_write_all_data`;
- it has `USAGE` on its own schema and neither `USAGE` nor `CREATE` on any
  other app's schema; reading a table there, creating a table there, and
  `SET ROLE` to another app's role or the owner role all fail with
  permission denied (the probes run in transactions that are rolled back);
- it cannot create objects in schema `public`, which every app's
  `search_path` includes;
- its default `search_path` does not reach another app's schema.

If you serve `Server.Router()` yourself instead of calling `Run`, call
`VerifyDatabaseIsolation` before serving.

**Shared login, for local development only.** Setting
`AllowSharedDatabaseLogin` lets apps without an `AppDatabases` entry share
the `MigrationDatabaseURL` login. The database then does not keep those
apps apart, and the server logs a warning at startup and for each such
app. Because the apps on it already hold the owner login, it implies
`AllowInProcessMigrations`: it needs `MigrationDatabaseURL`, and every app
registered, with or without its own login, is migrated in process. `SkipIsolationCheck` turns the check off and is accepted only together
with `AllowSharedDatabaseLogin`.

#### Provisioning the logins

`multiapp.RoleProvisioning` generates idempotent SQL for an app's login,
and `ApplyRoleProvisioning` runs it in one transaction with an admin
login. The `multiappdb` command wraps both:

```bash
# Print the SQL for review (it never contains a password).
go run ./cmd/multiappdb sql --with-owner --owner sf_owner \
    --app app1 --role app_app1_login

# Apply it; the admin DSN and the password come from environment variables.
go run ./cmd/multiappdb apply --admin-url-env ADMIN_DATABASE_URL \
    --create-owner --owner sf_owner --owner-password-env OWNER_DB_PASSWORD \
    --app app1 --role app_app1_login --password-env APP1_DB_PASSWORD

# Check the deployed logins.
go run ./cmd/multiappdb verify --owner sf_owner \
    --login app1=APP1_DATABASE_URL --login app2=APP2_DATABASE_URL
```

For each app, the SQL:

- creates the login role `LOGIN NOINHERIT NOSUPERUSER NOCREATEDB
  NOCREATEROLE NOBYPASSRLS NOREPLICATION` (an existing role keeps its
  `SUPERUSER`/`BYPASSRLS` attributes, which only a superuser can change,
  so the startup check reports them instead);
- creates the app schema owned by the owner role and revokes `PUBLIC`'s
  access to it and to its tables, sequences and functions;
- grants the login `USAGE` on its own schema and `SELECT, INSERT, UPDATE,
  DELETE` on its tables (`SELECT` only with `ReadOnly`), sequence and
  function privileges, and the same as default privileges on what the
  owner creates later;
- revokes `CREATE` on schema `public` from `PUBLIC`, and `EXECUTE` on the
  owner's future functions from `PUBLIC`;
- grants `SELECT` on the shared tables (by default
  `DefaultSharedReadTables`; see below), and sets the login's
  `search_path` to its schema and the shared schema.

Names are validated (lowercase letters, digits and underscores) and
quoted. Passwords are never generated or logged: they come from a
`PasswordSource` (`PasswordFromEnv`, or your secret manager), and
`ALTER ROLE ... PASSWORD` carries a SCRAM-SHA-256 verifier computed
client-side, so the plaintext never reaches the server or its statement
log. The admin login that applies the SQL must be able to act as the owner
role (a superuser, or a member of it).

**Shared SystemForge tables.** By default an app's login gets read-only
access (`SELECT`) to the identity tables in
`multiapp.DefaultSharedReadTables`, which an app reads to authorize
requests in process (what authz mode `rbac` reads):

| Table | Why an app reads it |
|-------|---------------------|
| `sf_principals` | who the caller is |
| `sf_organizations` | the caller's organizations |
| `sf_principal_memberships` | organization membership and role |
| `sf_app_roles` | app role definitions |
| `sf_resource_grants` | per-resource grants |

`RoleProvisioning.SharedReadTables` changes the list: nil (the default)
means `DefaultSharedReadTables`; `multiapp.NoSharedReadTables` (a non-nil
empty list) grants none, for an app that does not read the identity
tables; any other list replaces the default, so append to
`DefaultSharedReadTables` to add a table. The `multiappdb` flags match:
no flag grants the default list, `--no-shared-tables` grants none, and
`--shared-table` (repeatable) replaces the list, with
`--default-shared-tables` adding the defaults back.

Tables holding secrets or driving sign-in are never granted to apps and
stay with the identity service's own login: credentials, OAuth app secrets,
authorization codes and tokens, principal (API key) token hashes, SCIM
tokens, login states and sessions, invites and manager claims, signup and
external identities. `multiapp.RestrictedSharedTables` lists them, and
provisioning refuses a `SharedReadTables` entry that names one. Grants are
skipped for tables that do not exist yet, so apply
the provisioning again after the identity migrations create them.

**Amazon RDS.** The same SQL works on RDS for PostgreSQL; apply it with the
master user, which must be granted the owner role first (`GRANT sf_owner TO
<master user>`), because it is not a superuser. App logins can use IAM
database authentication instead of a password: pass `--member-of rds_iam`
(or `MemberOf: []string{"rds_iam"}`), omit the password, and give the app an
`AppDatabase.PoolConfig` whose `BeforeConnect` sets a fresh IAM
authentication token as the password. Alternatively, keep each app's
password in AWS Secrets Manager and read it at startup into that app's
`AppDatabase.URL`, or into a `PasswordSource` when provisioning.

#### What database logins do not contain

Per-app logins stop one app's SQL, including injected SQL, from reaching
another app's schema. They do not contain remote code execution in
multi-app mode: all apps run in one process, so code that takes over that
process can read every app's credentials, and the migration login's, from
memory and connect as any of them. For apps that hold sensitive data, use
single-app mode: run each app as its own binary or container, given only
its own database secret (migrations run as a separate step, so the owner
login is not in the process at all).

### Self-Contained Apps

Each app has its own:

- Users and authentication
- Organizations and memberships
- Business data
- API routes

No external dependencies (like SystemAuth) are required. SystemAuth integration is optional for SSO and centralized management.

## Integration Pattern

Apps integrate with multiapp by implementing the `AppBackend` interface and providing a factory function that accepts an Ent client:

```
┌────────────────────────────────────────────────────────────────┐
│                     Deployment Modes                           │
├─────────────────────────┬──────────────────────────────────────┤
│   Standalone Mode       │        Multi-App Mode                │
│   (dedicated infra)     │        (shared infra)                │
├─────────────────────────┼──────────────────────────────────────┤
│   cmd/server/main.go    │   systemforge-multi server             │
│          │              │          │                           │
│          ▼              │          ▼                           │
│   NewServer(cfg)        │   multiapp.Backend                   │
│          │              │          │                           │
│          ▼              │          ▼                           │
│   NewServerWithOptions  │   NewServerWithEntClient             │
│   (creates own DB)      │   (uses schema-isolated DB)          │
│          │              │          │                           │
│          └──────────────┴──────────┘                           │
│                         │                                      │
│                         ▼                                      │
│              newServerInternal(cfg, client)                    │
│              (shared: JWT, router, authz, storage, routes)     │
└────────────────────────────────────────────────────────────────┘
```

## Implementing AppBackend

### Step 1: Refactor Existing Server

Extract shared initialization into an internal function:

```go
// internal/api/server.go

// NewServerWithOptions - standalone mode, creates own DB
func NewServerWithOptions(cfg *config.Config, connectDB bool) (*Server, error) {
    var client *ent.Client
    if connectDB {
        // Create database connection
        db, err := sql.Open("postgres", cfg.Database.DSN())
        if err != nil {
            return nil, err
        }
        drv := entsql.OpenDB(dialect.Postgres, db)
        client = ent.NewClient(ent.Driver(drv))

        // Run migrations
        if err := client.Schema.Create(context.Background()); err != nil {
            return nil, err
        }
    }
    return newServerInternal(cfg, client)
}

// NewServerWithEntClient - multi-app mode, uses provided client
func NewServerWithEntClient(cfg *config.Config, client *ent.Client) (*Server, error) {
    return newServerInternal(cfg, client)
}

// newServerInternal - shared initialization logic
func newServerInternal(cfg *config.Config, client *ent.Client) (*Server, error) {
    // JWT service, router, middleware, authz, BFF, storage, routes...
    // All the shared setup code
}
```

### Step 2: Create AppBackend Adapter

```go
// internal/multiapp/backend.go

package multiapp

import (
    "github.com/grokify/myapp/ent"
    "github.com/grokify/myapp/internal/api"
    cfmultiapp "github.com/plexusone/systemforge/multiapp"
)

type Backend struct {
    cfg    *config.Config
    deps   cfmultiapp.Dependencies
    db     *ent.Client
    server *api.Server
}

func NewBackend(cfg *config.Config) *Backend {
    return &Backend{cfg: cfg}
}

func (b *Backend) Slug() string { return "myapp" }
func (b *Backend) Name() string { return "My App" }

func (b *Backend) Routes(deps cfmultiapp.Dependencies) chi.Router {
    b.deps = deps

    // Create Ent client with schema isolation
    b.db = createEntClient(deps.DB)

    // Run migrations
    b.db.Schema.Create(context.Background())

    // Create server using existing API package
    server, _ := api.NewServerWithEntClient(b.cfg, b.db)
    b.server = server

    return server.Router().(chi.Router)
}

func (b *Backend) OnRegister(ctx context.Context, cfg *cfmultiapp.AppConfig) error {
    return nil
}

func (b *Backend) OnShutdown(ctx context.Context) error {
    return b.server.Close()
}
```

### Step 3: Create Schema-Isolated Ent Client

```go
// deps.DB is the app's SchemaDB, connected with the app's own login.
// StdDB opens a database/sql pool on that login with search_path set to
// the app's schema; open it once and close it on shutdown.
func createEntClient(ctx context.Context, schemaDB *cfmultiapp.SchemaDB) (*ent.Client, error) {
    db, err := schemaDB.StdDB(ctx)
    if err != nil {
        return nil, err
    }
    return ent.NewClient(ent.Driver(entsql.OpenDB(dialect.Postgres, db))), nil
}
```

## Usage

### Standalone Deployment (Unchanged)

```bash
# Existing command works as before
go run ./cmd/server
```

### Multi-App Deployment

```go
package main

import (
    "os"

    "github.com/grokify/app1/internal/multiapp"
    cfmultiapp "github.com/plexusone/systemforge/multiapp"
)

func main() {
    server, _ := cfmultiapp.NewServer(cfmultiapp.Config{
        Mode:          cfmultiapp.MultiAppMode,
        MigrationRole: "sf_owner", // migrations ran beforehand with Migrate
        AppDatabases: map[string]cfmultiapp.AppDatabase{
            "app1": {URL: os.Getenv("APP1_DATABASE_URL")},
        },
        RedisURL: "redis://localhost:6379", // optional
    })

    // Register apps
    server.RegisterApp(multiapp.NewBackend(nil))
    // server.RegisterApp(app2.NewBackend(nil))
    // server.RegisterApp(app3.NewBackend(nil))

    server.Run(":8080")
}
```

### Testing Multi-App Mode

```bash
# Request to App1
curl -H "X-App-ID: app1" http://localhost:8080/api/courses

# Request to App2
curl -H "X-App-ID: app2" http://localhost:8080/api/dashboards
```

## Context Flow

The multiapp framework provides several context values:

```go
// In your handlers:
func (h *Handler) HandleRequest(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()

    // App context (from X-App-ID routing)
    appCtx := multiapp.AppContextFromContext(ctx)
    appCtx.AppID          // "app1"
    appCtx.DatabaseSchema // "app_app1"
    appCtx.Features       // ["auth", "tenancy"]

    // JWT claims (from auth middleware)
    claims := middleware.ClaimsFromContext(ctx)
    claims.PrincipalID    // user UUID
    claims.OrganizationID // org UUID

    // Full context (combines all)
    fc := multiapp.FullContextFromContext(ctx)
    fc.HasApp()           // true in multi-app mode
    fc.IsAuthenticated()  // true if JWT valid
}
```

## Tokens Are Bound to an App

The `X-App-ID` header chooses the app, and a client controls that header. So
that a token issued for one app cannot be used against another, `AuthMiddleware`
requires a token on an app route to be addressed to that app. By default the
required audience is the app's `AppID`; mint tokens for it with:

```go
pair, err := jwtService.GenerateTokenPairWithOptions(userID, email, name,
    jwt.TokenOptions{Audience: []string{appCtx.AppID}})
```

Set `MiddlewareConfig.AppAudiences` to derive a different audience per app.
Set `AllowCrossAppTokens` only when one token is meant to work in every app;
tokens are then checked against the JWT service's own `Config.Audience`.

## Tokens Are DPoP-Bound

`AuthMiddleware` requires DPoP (RFC 9449): a token must be bound to a key
(`cnf.jkt`, minted with `jwt.TokenOptions{DPoPThumbprint: ...}`) and come with
`Authorization: DPoP <token>` and a fresh proof by that key for the request,
carrying the token's hash. Configure it with a replay cache shared by every
instance and the external base URL clients use:

```go
auth, err := multiapp.AuthMiddleware(multiapp.MiddlewareConfig{
    JWTService:  jwtService,
    RequireAuth: true,
    DPoP: middleware.DPoPConfig{
        ReplayCache: middleware.NewRedisReplayCache(redisClient, "dpop-jti:"),
        BaseURL:     "https://apps.example.com",
    },
})
```

The proof's `htu` must equal `DPoP.BaseURL` plus the request path as this
server sees it. Behind a proxy that strips a path prefix, include the prefix
in `BaseURL` (for example `https://example.com/api`). Unbound bearer tokens
are refused unless `DPoP.AllowBearer` is set, an explicit opt-in for legacy
clients; a DPoP-bound token is never accepted as Bearer.

## Optional: SystemAuth Integration

Apps can optionally integrate with SystemAuth for:

- Single Sign-On (SSO) across apps
- Centralized user management
- Cross-app analytics

This is enabled by setting a `federation_id` on users when they authenticate via SystemAuth. See the [SystemAuth Integration Guide](../docs/systemauth-integration.md) for details.
