# Observability

SystemForge integrates with [omniobserve](https://github.com/plexusone/omniobserve) to provide vendor-agnostic observability including metrics, traces, and logs with support for multiple backends.

## Supported Backends

- **OTLP** - OpenTelemetry Protocol (vendor-agnostic)
- **Datadog**
- **New Relic**
- **Dynatrace**

## Quick Start

### 1. Import the Provider

Import the observability package and the provider you want to use:

```go
import (
    "github.com/plexusone/systemforge/observability"
    _ "github.com/plexusone/omniobserve/observops/otlp"     // OTLP
    // or
    _ "github.com/plexusone/omniobserve/observops/datadog"  // Datadog
    // or
    _ "github.com/plexusone/omniobserve/observops/newrelic" // New Relic
)
```

### 2. Create Observability Instance

```go
obs, err := observability.New(observability.Config{
    Provider:       "otlp",
    ServiceName:    "my-app",
    ServiceVersion: "1.0.0",
    Endpoint:       "localhost:4317",
})
if err != nil {
    log.Fatal(err)
}
defer obs.Shutdown(context.Background())
```

### 3. Integrate with SystemForge Components

#### SystemAuth (OAuth Server)

```go
server, err := systemauth.NewEmbedded(cfg,
    systemauth.WithObservability(obs),
)
```

#### Rate Limiting

```go
limiter := ratelimit.New(storage,
    ratelimit.WithObservability(obs),
)
router.Use(limiter.Middleware())
```

#### JWT Middleware

```go
router.Use(middleware.HTTPAuthWithObservability(jwtService, obs))
```

#### API Key Middleware

```go
config := middleware.DefaultAPIKeyMiddlewareConfig()
config.Service = apikeyService
config.Observability = obs
router.Use(middleware.APIKeyMiddleware(config))
```

#### HTTP Request Tracing

```go
router.Use(obs.Middleware())
```

#### slog Integration

```go
// Use observability-integrated logging
handler := obs.SlogHandler(
    observops.WithSlogLocalHandler(slog.NewJSONHandler(os.Stdout, nil)),
)
slog.SetDefault(slog.New(handler))
```

## Configuration

### Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `OBSERVABILITY_PROVIDER` | Backend provider | `otlp`, `datadog`, `newrelic`, `dynatrace` |
| `OBSERVABILITY_ENDPOINT` | Backend endpoint | `localhost:4317` |
| `OBSERVABILITY_API_KEY` | API key (if required) | |
| `OBSERVABILITY_SERVICE_NAME` | Service name | `my-app` |
| `OBSERVABILITY_SERVICE_VERSION` | Service version | `1.0.0` |
| `OBSERVABILITY_DISABLED` | Disable observability | `true`, `false` |
| `OBSERVABILITY_INSECURE` | Disable TLS | `true`, `false` |
| `OBSERVABILITY_DEBUG` | Enable debug logging | `true`, `false` |

### Configuration from Environment

```go
obs, err := observability.New(observability.ConfigFromEnv())
```

## Metrics

### SystemAuth Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `systemforge.systemauth.auth_requests_total` | Counter | grant_type, client_id, status | Authentication requests |
| `systemforge.systemauth.auth_latency_ms` | Histogram | grant_type, endpoint | Request latency |
| `systemforge.systemauth.tokens_issued_total` | Counter | grant_type, client_id | Tokens issued |
| `systemforge.systemauth.token_validations_total` | Counter | result | Token validations |
| `systemforge.systemauth.sessions_active` | Gauge | | Active sessions |

### Rate Limiting Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `systemforge.coreapi.ratelimit_requests_total` | Counter | policy_id, client_id, allowed | Rate limit checks |
| `systemforge.coreapi.ratelimit_quota_usage` | Gauge | policy_id, client_id, window | Current usage ratio |

### Session Middleware Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `systemforge.session.jwt_validations_total` | Counter | result | JWT validations |
| `systemforge.session.jwt_validation_latency_ms` | Histogram | | Validation latency |
| `systemforge.session.apikey_validations_total` | Counter | result | API key validations |

## Traces

### Span Names

| Span | Description |
|------|-------------|
| `systemforge.systemauth.authorize` | OAuth authorization endpoint |
| `systemforge.systemauth.token` | OAuth token endpoint |
| `systemforge.systemauth.introspect` | Token introspection |
| `systemforge.systemauth.revoke` | Token revocation |
| `systemforge.http.request` | HTTP request |
| `systemforge.session.jwt_validation` | JWT validation |
| `systemforge.session.apikey_validation` | API key validation |
| `systemforge.ratelimit.check` | Rate limit check |

## Testing with Jaeger

Run Jaeger locally to test OTLP integration:

```bash
docker run -d --name jaeger \
  -p 16686:16686 -p 4317:4317 \
  jaegertracing/all-in-one:latest
```

Configure your app:

```bash
OBSERVABILITY_PROVIDER=otlp \
OBSERVABILITY_ENDPOINT=localhost:4317 \
OBSERVABILITY_INSECURE=true \
go run ./cmd/server
```

View traces at http://localhost:16686

## Recording Custom Metrics

Use the underlying observops.Provider for custom metrics:

```go
meter := obs.Meter()

counter, _ := meter.Counter("my_custom_counter",
    observops.WithDescription("My custom counter"),
)

counter.Add(ctx, 1, observops.WithAttributes(
    observops.Attribute("key", "value"),
))
```

## Creating Custom Spans

```go
ctx, span := obs.StartSpan(ctx, "my.custom.operation",
    observops.WithSpanKind(observops.SpanKindInternal),
    observops.WithSpanAttributes(
        observops.Attribute("user.id", userID),
    ),
)
defer span.End()

// ... your code here ...

if err != nil {
    span.RecordError(err)
    span.SetStatus(observops.StatusCodeError, err.Error())
}
```

## Disabling Observability

To disable observability entirely:

```go
obs, _ := observability.New(observability.Config{
    Disabled: true,
})
```

Or via environment:

```bash
OBSERVABILITY_DISABLED=true
```

When disabled, all operations are no-ops with minimal overhead.

## ProductGraph Integration

SystemForge integrates with [ProductGraph](https://github.com/plexusone/productgraph) for product analytics, enabling frontend-backend correlation and user journey tracking.

### Quick Start

```go
import (
    "github.com/plexusone/systemforge/observability"
    "github.com/plexusone/systemforge/productgraph"
)

// Create observability instance
obs, err := observability.New(observability.ConfigFromEnv())
if err != nil {
    log.Fatal(err)
}

// Configure ProductGraph
err = obs.SetProductGraph(productgraph.Config{
    ProjectID: "my-project",
    Endpoint:  "https://api.productgraph.io/v1/events",
    APIKey:    os.Getenv("PRODUCTGRAPH_API_KEY"),
})
// Or from environment:
// err = obs.SetProductGraphFromEnv()

defer obs.Shutdown(context.Background())
```

### Middleware

Use the combined middleware for automatic request tracking with frontend correlation:

```go
router := chi.NewRouter()

// Combined middleware (recommended)
router.Use(obs.ProductGraphMiddleware())

// Or use components separately:
// router.Use(productgraph.CorrelationMiddleware)           // Extract headers
// router.Use(obs.ProductGraphRequestTrackerMiddleware())   // Track requests
```

### Frontend Correlation Headers

ProductGraph correlates backend requests with frontend sessions using these headers:

| Header | Description |
|--------|-------------|
| `X-Session-ID` | Frontend session identifier |
| `X-Request-ID` | Per-request identifier (auto-generated if missing) |
| `X-User-ID` | Authenticated user identifier |

Access correlation IDs in handlers:

```go
func handler(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    sessionID := productgraph.SessionIDFromContext(ctx)
    requestID := productgraph.RequestIDFromContext(ctx)
    userID := productgraph.UserIDFromContext(ctx)
}
```

### Manual Event Tracking

```go
// Track API calls
obs.TrackAPICall(ctx, "POST", "/api/checkout", 200, 150*time.Millisecond)

// Track errors
obs.TrackError(ctx, "ValidationError", "invalid card number")

// Track user journey steps
obs.TrackJourneyStep(ctx, "checkout_flow", "payment", "Enter Payment")

// Track custom events
obs.TrackProductGraphEvent(ctx, productgraph.Event{
    EventType: productgraph.EventTypeUIClick,
    UIElement: "checkout_button",
})
```

### Configuration

#### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PRODUCTGRAPH_PROJECT_ID` | Project identifier | |
| `PRODUCTGRAPH_ENDPOINT` | API endpoint | |
| `PRODUCTGRAPH_API_KEY` | Authentication key | |
| `PRODUCTGRAPH_BATCH_SIZE` | Events per batch | `50` |
| `PRODUCTGRAPH_BATCH_INTERVAL` | Flush interval (seconds) | `5` |
| `PRODUCTGRAPH_DEBUG` | Enable debug logging | `false` |

### Event Types

ProductGraph follows OTel semantic conventions for event types:

| Event Type | Description |
|------------|-------------|
| `page.view` | Page navigation |
| `ui.click`, `ui.input`, `ui.scroll`, `ui.submit` | User interactions |
| `api.request`, `api.response` | API calls |
| `journey.step` | User journey progression |
| `error` | Application errors |
| `performance` | Performance metrics |

See [ProductGraph Design Docs](../design/productgraph/TRD.md) for detailed architecture.
