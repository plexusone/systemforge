# Multi-App Framework

The multiapp package enables multiple apps to share backend infrastructure while maintaining complete data isolation. Apps can be deployed in two modes:

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

- Complete data isolation between apps
- Independent migrations per app
- Shared database infrastructure

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

### Self-Contained Apps

Each app is fully self-contained with its own:

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
func createEntClient(schemaDB *cfmultiapp.SchemaDB) *ent.Client {
    pool := schemaDB.Pool()
    config := pool.Config().ConnConfig.Copy()

    // Set search_path to app's schema
    if config.RuntimeParams == nil {
        config.RuntimeParams = make(map[string]string)
    }
    config.RuntimeParams["search_path"] = schemaDB.Schema() + ", public"

    // Create standard DB connection
    connStr := stdlib.RegisterConnConfig(config)
    db, _ := sql.Open("pgx", connStr)

    // Create Ent client
    drv := entsql.OpenDB(dialect.Postgres, db)
    return ent.NewClient(ent.Driver(drv))
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
    "github.com/grokify/app1/internal/multiapp"
    cfmultiapp "github.com/plexusone/systemforge/multiapp"
)

func main() {
    server, _ := cfmultiapp.NewServer(cfmultiapp.Config{
        Mode:        cfmultiapp.MultiAppMode,
        DatabaseURL: "postgres://localhost:5432/systemforge",
        RedisURL:    "redis://localhost:6379",  // optional
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

## Optional: SystemAuth Integration

Apps can optionally integrate with SystemAuth for:

- Single Sign-On (SSO) across apps
- Centralized user management
- Cross-app analytics

This is enabled by setting a `federation_id` on users when they authenticate via SystemAuth. See the [SystemAuth Integration Guide](../docs/systemauth-integration.md) for details.
