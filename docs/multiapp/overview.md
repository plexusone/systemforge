# Multi-App Framework

The multiapp package enables multiple apps to share backend infrastructure while keeping each app's data in its own PostgreSQL schema. Apps can be deployed in two modes:

- **Multi-app mode**: Multiple apps share a server, routed by `X-App-ID` header
- **Single-app mode**: One app runs on dedicated infrastructure

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                           HTTP Request                          │
│                     X-App-ID: app1                         │
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

## Quick Start

### Multi-App Server

```go
package main

import (
    "log"
    "os"

    "github.com/plexusone/systemforge/multiapp"
    app1 "github.com/grokify/app1/multiapp"
    app2 "github.com/plexusone/app2/multiapp"
)

func main() {
    server, err := multiapp.NewServer(multiapp.Config{
        Mode: multiapp.MultiAppMode,
        // Each app connects with its own database login...
        AppDatabases: map[string]multiapp.AppDatabase{
            "app1": {URL: os.Getenv("APP1_DATABASE_URL")},
            "app2": {URL: os.Getenv("APP2_DATABASE_URL")},
        },
        // ...and schemas and migrations use the migration (owner) login.
        MigrationDatabaseURL: os.Getenv("MIGRATION_DATABASE_URL"),
        RedisURL:             os.Getenv("REDIS_URL"), // optional
    })
    if err != nil {
        log.Fatal(err)
    }

    // Register apps: each gets its own schema, login and pool, and its
    // login must pass the isolation check.
    for _, b := range []multiapp.AppBackend{app1.NewBackend(nil), app2.NewBackend(nil)} {
        if err := server.RegisterApp(b); err != nil {
            log.Fatal(err)
        }
    }

    log.Fatal(server.Run(":8080"))
}
```

### Making Requests

```bash
# Request to App1
curl -H "X-App-ID: app1" http://localhost:8080/api/courses

# Request to App2
curl -H "X-App-ID: app2" http://localhost:8080/api/dashboards

# Requests without X-App-ID return 404 (security)
curl http://localhost:8080/api/health
# 404 Not Found
```

## Schema-Per-App Isolation

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
    MigrationDatabaseURL: os.Getenv("MIGRATION_DATABASE_URL"), // owner login
    AppDatabases: map[string]multiapp.AppDatabase{
        "app1": {URL: os.Getenv("APP1_DATABASE_URL")},
        "app2": {URL: os.Getenv("APP2_DATABASE_URL")},
    },
})
```

The same rule applies in single-app mode: the one app connects with its
own login, and migrations with the owner login.

**Migrations run with a separate migration (owner) login.**
`Config.MigrationDatabaseURL` owns the app schemas: `RegisterApp` uses it
to create each app's schema and run the app's `Migrations`, and never hands
it to app code. Tables the owner creates reach the app's login through
default privileges set at provisioning. To keep the owner's credentials out
of the server process entirely, leave `MigrationDatabaseURL` empty and run
`multiapp.Migrate(ctx, ownerURL, backends...)` from a separate deploy step;
`RegisterApp` then expects the schemas to exist.

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
app. `SkipIsolationCheck` turns the check off and is accepted only together
with `AllowSharedDatabaseLogin`.

#### Provisioning the logins

`multiapp.RoleProvisioning` generates idempotent SQL for an app's login,
and `ApplyRoleProvisioning` runs it in one transaction with an admin
login. The `multiappdb` command wraps both:

```bash
# Print the SQL for review (it never contains a password).
go run ./cmd/multiappdb sql --with-owner --owner sf_owner \
    --app app1 --role app_app1_login --default-shared-tables

# Apply it; the admin DSN and the password come from environment variables.
go run ./cmd/multiappdb apply --admin-url-env ADMIN_DATABASE_URL \
    --create-owner --owner sf_owner --owner-password-env OWNER_DB_PASSWORD \
    --app app1 --role app_app1_login --password-env APP1_DB_PASSWORD \
    --default-shared-tables

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
- grants `SELECT` on the shared tables listed in `SharedReadTables`, and
  sets the login's `search_path` to its schema and the shared schema.

Names are validated (lowercase letters, digits and underscores) and
quoted. Passwords are never generated or logged: they come from a
`PasswordSource` (`PasswordFromEnv`, or your secret manager), and
`ALTER ROLE ... PASSWORD` carries a SCRAM-SHA-256 verifier computed
client-side, so the plaintext never reaches the server or its statement
log. The admin login that applies the SQL must be able to act as the owner
role (a superuser, or a member of it).

**Shared SystemForge tables.** Apps get read-only access only to the
shared tables they name. `multiapp.DefaultSharedReadTables` lists the
identity tables an app reads to authorize requests in process (what authz
mode `rbac` reads):

| Table | Why an app reads it |
|-------|---------------------|
| `sf_principals` | who the caller is |
| `sf_organizations` | the caller's organizations |
| `sf_principal_memberships` | organization membership and role |
| `sf_app_roles` | app role definitions |
| `sf_resource_grants` | per-resource grants |

Tables holding secrets or driving sign-in are never granted to apps and
stay with the identity service's own login: credentials, OAuth app secrets,
authorization codes and tokens, principal (API key) token hashes, SCIM
tokens, login states and sessions, invites, signup and external
identities. Grants are skipped for tables that do not exist yet, so apply
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
its own database secret (and migrate out of band, so the owner login is
not in the process at all).

## AppBackend Interface

Apps integrate by implementing the `AppBackend` interface:

```go
type AppBackend interface {
    // Slug returns unique app identifier (used in X-App-ID header)
    Slug() string

    // Name returns human-readable app name
    Name() string

    // Routes returns the app's HTTP routes with injected dependencies
    Routes(deps Dependencies) chi.Router

    // Migrations returns database migrations (optional)
    Migrations() []Migration

    // OnRegister is called after app registration
    OnRegister(ctx context.Context, cfg *AppConfig) error

    // OnShutdown is called during graceful shutdown
    OnShutdown(ctx context.Context) error
}
```

### Dependencies

The `Routes` method receives injected dependencies:

```go
type Dependencies struct {
    DB     *SchemaDB      // App schema, on the app's own login
    Cache  Cache          // App-prefixed cache
    Logger *slog.Logger   // App-tagged logger
    Config *AppConfig     // App configuration
}
```

## Implementing AppBackend

### Step 1: Refactor Existing Server

Extract shared initialization to support external database:

```go
// internal/server/server.go

// New - standalone mode, creates own database
func New(cfg Config) (*Server, error) {
    db, err := sql.Open("postgres", cfg.DatabaseURL)
    if err != nil {
        return nil, err
    }
    return newServerInternal(cfg, db)
}

// NewServerWithDatabase - multi-app mode, uses provided database
func NewServerWithDatabase(cfg Config, db *sql.DB) (*Server, error) {
    return newServerInternal(cfg, db)
}

// newServerInternal - shared initialization logic
func newServerInternal(cfg Config, db *sql.DB) (*Server, error) {
    // JWT service, router, middleware, storage, routes...
}

// Router returns the HTTP handler
func (s *Server) Router() http.Handler {
    return s.mux
}
```

### Step 2: Create AppBackend Adapter

Create a public `multiapp/` package (not `internal/multiapp/`):

```go
// multiapp/backend.go
package multiapp

import (
    "context"

    "github.com/go-chi/chi/v5"
    cfmultiapp "github.com/plexusone/systemforge/multiapp"
    "github.com/yourapp/internal/server"
)

type Backend struct {
    cfg    *server.Config
    server *server.Server
}

func NewBackend(cfg *server.Config) *Backend {
    if cfg == nil {
        cfg = server.DefaultConfig()
    }
    return &Backend{cfg: cfg}
}

func (b *Backend) Slug() string { return "yourapp" }
func (b *Backend) Name() string { return "Your App" }

func (b *Backend) Routes(deps cfmultiapp.Dependencies) chi.Router {
    // Create server with schema-isolated database
    var err error
    b.server, err = server.NewServerWithDatabase(b.cfg, deps.DB.Pool())
    if err != nil {
        deps.Logger.Error("failed to create server", "error", err)
        return chi.NewRouter()  // Return empty router
    }

    // Wrap http.Handler as chi.Router if needed
    r := chi.NewRouter()
    r.Mount("/", b.server.Router())
    return r
}

func (b *Backend) Migrations() []cfmultiapp.Migration {
    return nil  // Let Ent handle migrations
}

func (b *Backend) OnRegister(ctx context.Context, cfg *cfmultiapp.AppConfig) error {
    return nil
}

func (b *Backend) OnShutdown(ctx context.Context) error {
    if b.server != nil {
        return b.server.Close()
    }
    return nil
}
```

### Step 3: Schema-Isolated Ent Client

For apps using Ent ORM:

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

## Context Helpers

Access app and auth context in handlers:

```go
func (h *Handler) HandleRequest(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()

    // App context (from X-App-ID routing)
    appCtx := multiapp.AppContextFromContext(ctx)
    appCtx.AppID          // "app1"
    appCtx.AppSlug        // "app1"
    appCtx.AppName        // "App1"
    appCtx.DatabaseSchema // "app_app1"
    appCtx.Features       // ["feature1", "feature2"]
    appCtx.Settings       // map[string]any

    // JWT claims (from auth middleware)
    claims := middleware.ClaimsFromContext(ctx)
    claims.PrincipalID    // user UUID
    claims.OrganizationID // org UUID
    claims.Email          // user email

    // Full context (combines all)
    fc := multiapp.FullContextFromContext(ctx)
    fc.HasApp()           // true in multi-app mode
    fc.IsAuthenticated()  // true if JWT valid
}
```

## Server Modes

### Multi-App Mode

Multiple apps share infrastructure, routed by header:

```go
server, _ := multiapp.NewServer(multiapp.Config{
    Mode:                 multiapp.MultiAppMode,
    MigrationDatabaseURL: os.Getenv("MIGRATION_DATABASE_URL"),
    AppDatabases: map[string]multiapp.AppDatabase{
        "app1": {URL: os.Getenv("APP1_DATABASE_URL")},
        "app2": {URL: os.Getenv("APP2_DATABASE_URL")},
        "app3": {URL: os.Getenv("APP3_DATABASE_URL")},
    },
})

server.RegisterApp(app1.NewBackend(nil))
server.RegisterApp(app2.NewBackend(nil))
server.RegisterApp(app3.NewBackend(nil))

server.Run(":8080")
```

### Single-App Mode

One app on dedicated infrastructure (no header routing). The app still
connects with its own login, never the migration login; this is the mode
to use for apps holding sensitive data (see
[What database logins do not contain](#what-database-logins-do-not-contain)):

```go
server, _ := multiapp.NewServer(multiapp.Config{
    Mode: multiapp.SingleAppMode,
    AppDatabases: map[string]multiapp.AppDatabase{
        "myapp": {URL: os.Getenv("MYAPP_DATABASE_URL")},
    },
    // Empty: schemas and migrations run out of band with multiapp.Migrate,
    // so the owner login never enters this process.
})

server.RegisterApp(myapp.NewBackend(nil))

server.Run(":8080")
```

## Caching

The multiapp framework provides app-scoped caching:

```go
// In Routes(), deps.Cache is pre-configured with app prefix
func (b *Backend) Routes(deps multiapp.Dependencies) chi.Router {
    // Cache keys are automatically prefixed: "app1:user:123"
    deps.Cache.Set(ctx, "user:123", userData, 5*time.Minute)

    userData, err := deps.Cache.Get(ctx, "user:123")
}
```

### Cache Implementations

- **Redis**: Production-ready with connection pooling
- **Memory**: In-memory for development/testing

```go
// Redis cache (from RedisURL config)
server, _ := multiapp.NewServer(multiapp.Config{
    RedisURL:     "redis://localhost:6379",
    AppDatabases: appDatabases,
})

// Memory cache (default when RedisURL empty)
server, _ := multiapp.NewServer(multiapp.Config{
    // No RedisURL = memory cache
    AppDatabases: appDatabases,
})
```

## Security

### Generic 404 Responses

Missing or invalid `X-App-ID` returns generic 404 to prevent:

- Routing mechanism disclosure
- App ID enumeration attacks
- Information leakage about valid apps

### Self-Contained Apps

Each app manages its own:

- Users and authentication
- Organizations and memberships
- Business data and logic
- API routes and middleware

No external dependencies required. SystemAuth integration is optional for SSO.

## Optional: SystemAuth Integration

Apps can optionally integrate with SystemAuth for:

- Single Sign-On (SSO) across apps
- Centralized user management
- Cross-app analytics

This works by linking each person's SystemAuth identity to their principal: relying parties store the SystemAuth `sub` as `sf_principal_id`, and federation sync records the hub identity as an external identity on the principal.
