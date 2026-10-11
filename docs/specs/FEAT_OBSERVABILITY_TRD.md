# OmniObserve Integration for SystemForge

## Overview

Integrate omniobserve/observops into SystemForge to provide vendor-agnostic observability (metrics, traces, logs) with support for Datadog, New Relic, Dynatrace, and OTLP backends.

**Goal:** Add observability to SystemAuth (OAuth flows) and CoreAPI (rate limiting) with minimal API surface.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        HTTP Request                              │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌───────────────────────────────────────────────────────────────────┐
│                  Observability Middleware                         │
│       Start span, record request attributes, inject trace ID     │
└───────────────────────────┬───────────────────────────────────────┘
                            │
         ┌──────────────────┼──────────────────┐
         │                  │                  │
         ▼                  ▼                  ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│   SystemAuth      │ │   CoreAPI       │ │   Your App      │
│  (OAuth spans)  │ │  (rate metrics) │ │   Handlers      │
└─────────────────┘ └─────────────────┘ └─────────────────┘
         │                  │                  │
         └──────────────────┼──────────────────┘
                            │
                            ▼
┌───────────────────────────────────────────────────────────────────┐
│                   observops.Provider                              │
│    (OTLP, Datadog, New Relic, Dynatrace - user's choice)         │
└───────────────────────────────────────────────────────────────────┘
```

---

## Phase 1: Core Integration Package

### 1.1 Observability Package

**File:** `observability/observability.go`

```go
package observability

import (
    "github.com/plexusone/omniobserve/observops"
)

// Config holds observability configuration
type Config struct {
    Provider     string // "otlp", "datadog", "newrelic", "dynatrace", ""
    ServiceName  string
    Version      string
    Endpoint     string
    APIKey       string
    Disabled     bool
}

// Observability wraps an observops.Provider with SystemForge-specific helpers
type Observability struct {
    provider observops.Provider

    // Pre-created metrics for SystemAuth
    authRequests     observops.Counter
    authLatency      observops.Histogram
    tokenIssued      observops.Counter
    tokenValidations observops.Counter

    // Pre-created metrics for CoreAPI
    rateLimitAllowed observops.Counter
    rateLimitDenied  observops.Counter
    rateLimitUsage   observops.Gauge
}

// New creates observability from config
func New(cfg Config) (*Observability, error)

// Provider returns the underlying observops.Provider
func (o *Observability) Provider() observops.Provider

// Shutdown gracefully shuts down the provider
func (o *Observability) Shutdown(ctx context.Context) error
```

### 1.2 HTTP Middleware

**File:** `observability/middleware.go`

```go
// Middleware creates Chi middleware for request tracing
func (o *Observability) Middleware() func(http.Handler) http.Handler

// Features:
// - Start span for each request
// - Record: method, path, status_code, duration
// - Inject trace_id into response headers
// - Propagate context for downstream spans
```

### 1.3 slog Integration

**File:** `observability/slog.go`

```go
// NewSlogHandler creates trace-correlated slog handler
func (o *Observability) NewSlogHandler(opts ...SlogOption) slog.Handler

// Options:
// - WithLocalHandler(h slog.Handler) - also log locally
// - WithMinLevel(level slog.Level) - minimum log level
```

---

## Phase 2: SystemAuth Observability

### 2.1 Server Integration

**File:** `identity/systemauth/server.go` (modify)

Add optional observability to Server:

```go
type Server struct {
    // ... existing fields
    observability *observability.Observability
}

// WithObservability sets the observability provider
func WithObservability(obs *observability.Observability) Option
```

### 2.2 OAuth Metrics

Record in existing handlers:

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `systemauth.auth_requests_total` | Counter | grant_type, client_id, status | Authorization requests |
| `systemauth.auth_latency_ms` | Histogram | grant_type, endpoint | Request latency |
| `systemauth.tokens_issued_total` | Counter | grant_type, client_id | Tokens issued |
| `systemauth.token_validations_total` | Counter | result (valid/invalid/expired) | Token validations |
| `systemauth.sessions_active` | Gauge | - | Active sessions |

### 2.3 Tracing Integration

Add spans to OAuth handlers in `handler_fosite.go`:

- `systemauth.authorize` - Authorization endpoint
- `systemauth.token` - Token endpoint
- `systemauth.introspect` - Token introspection
- `systemauth.revoke` - Token revocation

---

## Phase 3: CoreAPI Observability

### 3.1 Rate Limit Metrics

**File:** `coreapi/observability.go`

```go
// WithObservability adds metrics to rate limit operations
func (s *MemoryPolicyStore) WithObservability(obs *observability.Observability)
```

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `coreapi.ratelimit_requests_total` | Counter | policy_id, client_id, allowed | Rate limit checks |
| `coreapi.ratelimit_quota_usage` | Gauge | policy_id, client_id, window | Current usage ratio |

### 3.2 Rate Limiter Integration

**File:** `session/ratelimit/ratelimit.go` (modify)

Add metrics recording to `Allow()` method when observability is configured.

---

## Phase 4: Session Middleware Observability

### 4.1 JWT Middleware Metrics

**File:** `session/middleware/http.go` (modify)

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `session.jwt_validations_total` | Counter | result | JWT validation results |
| `session.jwt_validation_latency_ms` | Histogram | - | Validation latency |

### 4.2 API Key Middleware Metrics

**File:** `session/middleware/apikey.go` (modify)

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `session.apikey_validations_total` | Counter | result | API key validations |

---

## Implementation Order

### Step 1: Add Dependency

```bash
go get github.com/plexusone/omniobserve@latest
```

### Step 2: Create observability package

1. `observability/observability.go` - Core wrapper
2. `observability/middleware.go` - HTTP middleware
3. `observability/slog.go` - slog handler integration
4. `observability/metrics.go` - Pre-defined metric names

### Step 3: Integrate with SystemAuth

1. Add `WithObservability` option to Server
2. Add metrics recording to OAuth handlers
3. Add span creation in `handler_fosite.go`

### Step 4: Integrate with CoreAPI

1. Add observability to MemoryPolicyStore
2. Add metrics to rate limiter middleware

### Step 5: Integrate with Session Middleware

1. Add metrics to JWT middleware
2. Add metrics to API key middleware

### Step 6: Documentation

1. Update docs with observability configuration
2. Add examples for each backend

---

## Key Files to Create/Modify

| File | Action |
|------|--------|
| `go.mod` | Add omniobserve dependency |
| `observability/observability.go` | New - Core package |
| `observability/middleware.go` | New - HTTP middleware |
| `observability/slog.go` | New - slog integration |
| `observability/metrics.go` | New - Metric definitions |
| `identity/systemauth/server.go` | Modify - Add WithObservability option |
| `identity/systemauth/handler_fosite.go` | Modify - Add spans and metrics |
| `coreapi/store_memory.go` | Modify - Add observability |
| `session/ratelimit/ratelimit.go` | Modify - Add metrics |
| `session/middleware/http.go` | Modify - Add JWT metrics |
| `docs/observability/overview.md` | New - Documentation |

---

## Configuration

```go
// Example usage
import (
    "github.com/plexusone/systemforge/observability"
    _ "github.com/plexusone/omniobserve/observops/otlp"     // or datadog, newrelic
)

obs, err := observability.New(observability.Config{
    Provider:    "otlp",
    ServiceName: "my-app",
    Version:     "1.0.0",
    Endpoint:    "localhost:4317",
})
defer obs.Shutdown(ctx)

// SystemAuth with observability
server, _ := systemauth.NewEmbedded(cfg, systemauth.WithObservability(obs))

// HTTP middleware
router.Use(obs.Middleware())

// slog integration
slog.SetDefault(slog.New(obs.NewSlogHandler()))
```

---

## Environment Variables

```bash
OBSERVABILITY_PROVIDER=otlp          # otlp, datadog, newrelic, dynatrace
OBSERVABILITY_ENDPOINT=localhost:4317
OBSERVABILITY_API_KEY=               # Required for datadog/newrelic
OBSERVABILITY_SERVICE_NAME=my-app
OBSERVABILITY_SERVICE_VERSION=1.0.0
OBSERVABILITY_DISABLED=false
```

---

## Verification

```bash
# Build
go build ./...

# Run tests
go test ./observability/... ./identity/systemauth/... ./coreapi/...

# Test with OTLP (Jaeger)
docker run -d --name jaeger \
  -p 16686:16686 -p 4317:4317 \
  jaegertracing/all-in-one:latest

# Run app with observability
OBSERVABILITY_PROVIDER=otlp \
OBSERVABILITY_ENDPOINT=localhost:4317 \
go run ./cmd/server

# View traces at http://localhost:16686
```

---

## Metric Naming Conventions

Follow OpenTelemetry semantic conventions:

- Prefix: `systemforge.` for all metrics
- Use snake_case
- Include unit in name when relevant (`_ms`, `_bytes`, `_total`)
- Use `_total` suffix for counters

Examples:

- `systemforge.systemauth.tokens_issued_total`
- `systemforge.systemauth.auth_latency_ms`
- `systemforge.coreapi.ratelimit_requests_total`
- `systemforge.session.jwt_validations_total`
