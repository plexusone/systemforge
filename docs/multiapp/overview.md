# Multi-App Framework

The multiapp package enables multiple apps to share backend infrastructure while maintaining complete data isolation. Apps can be deployed in two modes:

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
    "os"

    "github.com/plexusone/systemforge/multiapp"
    app1 "github.com/grokify/app1/multiapp"
    app2 "github.com/plexusone/app2/multiapp"
)

func main() {
    server, err := multiapp.NewServer(multiapp.Config{
        Mode:        multiapp.MultiAppMode,
        DatabaseURL: os.Getenv("DATABASE_URL"),
        RedisURL:    os.Getenv("REDIS_URL"),  // optional
    })
    if err != nil {
        panic(err)
    }

    // Register apps - each gets schema isolation
    server.RegisterApp(app1.NewBackend(nil))
    server.RegisterApp(app2.NewBackend(nil))

    server.Run(":8080")
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
    DB     *SchemaDB      // Schema-isolated database
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
    Mode:        multiapp.MultiAppMode,
    DatabaseURL: "postgres://localhost:5432/platform",
})

server.RegisterApp(app1.NewBackend(nil))
server.RegisterApp(app2.NewBackend(nil))
server.RegisterApp(app3.NewBackend(nil))

server.Run(":8080")
```

### Single-App Mode

One app on dedicated infrastructure (no header routing):

```go
server, _ := multiapp.NewServer(multiapp.Config{
    Mode:        multiapp.SingleAppMode,
    DatabaseURL: "postgres://localhost:5432/myapp",
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
    RedisURL: "redis://localhost:6379",
})

// Memory cache (default when RedisURL empty)
server, _ := multiapp.NewServer(multiapp.Config{
    // No RedisURL = memory cache
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

This is enabled by setting a `federation_id` on users when they authenticate via SystemAuth.
