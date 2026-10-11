# ProductGraph Integration TRD

**Author:** PlexusOne
**Date:** 2026-04-27
**Status:** Draft

## Overview

This document describes the technical architecture for integrating systemforge's observability with ProductGraph for backend-frontend correlation and analytics forwarding.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Frontend                                        │
│   ┌──────────────────────────────────────────────────────────────────────┐  │
│   │                    @systemforge/telemetry                               │  │
│   │  TelemetryProvider → ProductGraphAdapter → POST /v1/events           │  │
│   │                                                                       │  │
│   │  Headers: X-Session-ID, X-Request-ID                                 │  │
│   └───────────────────────────────────┬──────────────────────────────────┘  │
└───────────────────────────────────────┼─────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         systemforge Backend Service                            │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                      Correlation Middleware                             │ │
│  │  Extract: X-Session-ID, X-Request-ID → Context                         │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                        │                                     │
│  ┌─────────────────┐  ┌────────────────┴───────────────┐  ┌──────────────┐  │
│  │   omniobserve   │  │      productgraph Client       │  │   Business   │  │
│  │    Provider     │  │                                │  │    Logic     │  │
│  │  (Traces/Metrics)│  │  - Event batching             │  │              │  │
│  │                 │  │  - OTel semantics              │  │              │  │
│  │                 │  │  - Session correlation         │  │              │  │
│  └────────┬────────┘  └────────────────┬───────────────┘  └──────────────┘  │
└───────────┼────────────────────────────┼────────────────────────────────────┘
            │                            │
            ▼                            ▼
┌──────────────────────┐      ┌─────────────────────────────────────────────┐
│   OTLP / Datadog /   │      │              ProductGraph                   │
│   New Relic / etc    │      │                                             │
└──────────────────────┘      │  ┌─────────────────┐  ┌──────────────────┐  │
                              │  │ Storage (PG)   │  │ Analytics Adapter│  │
                              │  └─────────────────┘  └────────┬─────────┘  │
                              └─────────────────────────────────┼───────────┘
                                                                │
                                         ┌──────────────────────┴───────┐
                                         ▼                              ▼
                              ┌──────────────────┐           ┌──────────────────┐
                              │    Amplitude     │           │     Mixpanel     │
                              └──────────────────┘           └──────────────────┘
```

## Components

### Correlation Middleware

**Package:** `systemforge/observability/correlation`

**Purpose:** Extract frontend correlation IDs and inject into context.

```go
package correlation

import (
    "context"
    "net/http"
)

type ContextKey string

const (
    SessionIDKey  ContextKey = "session_id"
    RequestIDKey  ContextKey = "request_id"
    UserIDKey     ContextKey = "user_id"
)

// Middleware extracts correlation headers and injects into context.
func Middleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        ctx := r.Context()

        // Extract correlation headers
        if sessionID := r.Header.Get("X-Session-ID"); sessionID != "" {
            ctx = context.WithValue(ctx, SessionIDKey, sessionID)
        }
        if requestID := r.Header.Get("X-Request-ID"); requestID != "" {
            ctx = context.WithValue(ctx, RequestIDKey, requestID)
        }

        // Echo back for debugging
        if requestID := r.Header.Get("X-Request-ID"); requestID != "" {
            w.Header().Set("X-Request-ID", requestID)
        }

        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

// SessionIDFromContext extracts session ID from context.
func SessionIDFromContext(ctx context.Context) string {
    if v, ok := ctx.Value(SessionIDKey).(string); ok {
        return v
    }
    return ""
}

// RequestIDFromContext extracts request ID from context.
func RequestIDFromContext(ctx context.Context) string {
    if v, ok := ctx.Value(RequestIDKey).(string); ok {
        return v
    }
    return ""
}
```

### ProductGraph Client

**Package:** `systemforge/productgraph`

**Purpose:** Send events to ProductGraph from Go backend.

```go
package productgraph

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "sync"
    "time"

    "github.com/google/uuid"
)

// Config configures the ProductGraph client.
type Config struct {
    ProjectID     string        // Required: project identifier
    Endpoint      string        // Required: ProductGraph endpoint
    APIKey        string        // Optional: X-PG-API-Key header
    BatchSize     int           // Default: 50
    BatchInterval time.Duration // Default: 5s
    HTTPClient    *http.Client  // Default: http.DefaultClient
}

// Client sends events to ProductGraph.
type Client struct {
    config  Config
    buffer  []Event
    mu      sync.Mutex
    done    chan struct{}
    wg      sync.WaitGroup
}

// Event represents a ProductGraph event.
type Event struct {
    EventID     string                 `json:"event_id"`
    ProjectID   string                 `json:"project_id"`
    SessionID   string                 `json:"session.id"`
    UserID      string                 `json:"user.id,omitempty"`
    EventType   string                 `json:"event.type"`
    EventName   string                 `json:"event.name,omitempty"`
    Timestamp   string                 `json:"event.timestamp"`
    PagePath    string                 `json:"page.path,omitempty"`
    APIMethod   string                 `json:"api.method,omitempty"`
    APIPath     string                 `json:"api.path,omitempty"`
    APIStatus   int                    `json:"api.status_code,omitempty"`
    APIDuration int                    `json:"api.duration_ms,omitempty"`
    ErrorType   string                 `json:"error.type,omitempty"`
    ErrorMsg    string                 `json:"error.message,omitempty"`
    JourneyID   string                 `json:"gen_ai.journey.id,omitempty"`
    JourneyStep string                 `json:"gen_ai.journey.step.id,omitempty"`
    JourneyName string                 `json:"gen_ai.journey.step.name,omitempty"`
    Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// New creates a ProductGraph client.
func New(cfg Config) *Client {
    if cfg.BatchSize == 0 {
        cfg.BatchSize = 50
    }
    if cfg.BatchInterval == 0 {
        cfg.BatchInterval = 5 * time.Second
    }
    if cfg.HTTPClient == nil {
        cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
    }

    c := &Client{
        config: cfg,
        buffer: make([]Event, 0, cfg.BatchSize),
        done:   make(chan struct{}),
    }

    c.wg.Add(1)
    go c.flusher()

    return c
}

// Track sends an event to ProductGraph.
func (c *Client) Track(ctx context.Context, event Event) {
    // Fill defaults
    if event.EventID == "" {
        event.EventID = uuid.New().String()
    }
    if event.ProjectID == "" {
        event.ProjectID = c.config.ProjectID
    }
    if event.Timestamp == "" {
        event.Timestamp = time.Now().UTC().Format(time.RFC3339)
    }

    // Extract session from context if not set
    if event.SessionID == "" {
        if sessionID, ok := ctx.Value("session_id").(string); ok {
            event.SessionID = sessionID
        }
    }

    c.mu.Lock()
    c.buffer = append(c.buffer, event)
    shouldFlush := len(c.buffer) >= c.config.BatchSize
    c.mu.Unlock()

    if shouldFlush {
        c.flush()
    }
}

// TrackAPICall tracks an API request/response.
func (c *Client) TrackAPICall(ctx context.Context, method, path string, status int, duration time.Duration) {
    c.Track(ctx, Event{
        EventType:   "api.response",
        APIMethod:   method,
        APIPath:     path,
        APIStatus:   status,
        APIDuration: int(duration.Milliseconds()),
    })
}

// TrackError tracks an error event.
func (c *Client) TrackError(ctx context.Context, errType, message string) {
    c.Track(ctx, Event{
        EventType: "error",
        ErrorType: errType,
        ErrorMsg:  message,
    })
}

// TrackJourneyStep tracks a journey step completion.
func (c *Client) TrackJourneyStep(ctx context.Context, journeyID, stepID, stepName string) {
    c.Track(ctx, Event{
        EventType:   "journey.step",
        JourneyID:   journeyID,
        JourneyStep: stepID,
        JourneyName: stepName,
    })
}

func (c *Client) flusher() {
    defer c.wg.Done()
    ticker := time.NewTicker(c.config.BatchInterval)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            c.flush()
        case <-c.done:
            c.flush() // Final flush
            return
        }
    }
}

func (c *Client) flush() {
    c.mu.Lock()
    if len(c.buffer) == 0 {
        c.mu.Unlock()
        return
    }
    events := c.buffer
    c.buffer = make([]Event, 0, c.config.BatchSize)
    c.mu.Unlock()

    body, _ := json.Marshal(map[string]interface{}{
        "events": events,
    })

    req, _ := http.NewRequest("POST", c.config.Endpoint, bytes.NewReader(body))
    req.Header.Set("Content-Type", "application/json")
    if c.config.APIKey != "" {
        req.Header.Set("X-PG-API-Key", c.config.APIKey)
    }

    resp, err := c.config.HTTPClient.Do(req)
    if err != nil {
        // Log error, consider retry
        return
    }
    defer resp.Body.Close()
}

// Close gracefully shuts down the client.
func (c *Client) Close() error {
    close(c.done)
    c.wg.Wait()
    return nil
}
```

### Observability Integration

**Package:** `systemforge/observability`

Extend existing observability to include ProductGraph.

```go
// Add to observability/observability.go

// WithProductGraph adds ProductGraph client to provider.
func WithProductGraph(cfg productgraph.Config) ProviderOption {
    return func(p *Provider) {
        p.productgraph = productgraph.New(cfg)
    }
}

// TrackEvent sends event to ProductGraph (if configured).
func (p *Provider) TrackEvent(ctx context.Context, event productgraph.Event) {
    if p.productgraph != nil {
        p.productgraph.Track(ctx, event)
    }
}
```

### Request Tracking Middleware

**Package:** `systemforge/observability`

Automatically track API requests.

```go
// RequestTracker middleware tracks requests to ProductGraph.
func (p *Provider) RequestTracker(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        start := time.Now()

        // Wrap response writer to capture status
        ww := &responseWriter{ResponseWriter: w, status: 200}

        next.ServeHTTP(ww, r)

        duration := time.Since(start)

        // Track to ProductGraph
        if p.productgraph != nil {
            p.productgraph.TrackAPICall(
                r.Context(),
                r.Method,
                r.URL.Path,
                ww.status,
                duration,
            )
        }
    })
}

type responseWriter struct {
    http.ResponseWriter
    status int
}

func (w *responseWriter) WriteHeader(status int) {
    w.status = status
    w.ResponseWriter.WriteHeader(status)
}
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PRODUCTGRAPH_ENABLED` | Enable ProductGraph integration | `false` |
| `PRODUCTGRAPH_PROJECT_ID` | Project identifier | - |
| `PRODUCTGRAPH_ENDPOINT` | API endpoint | - |
| `PRODUCTGRAPH_API_KEY` | API key (optional) | - |
| `PRODUCTGRAPH_BATCH_SIZE` | Events per batch | `50` |
| `PRODUCTGRAPH_BATCH_INTERVAL` | Flush interval | `5s` |

### Configuration Loading

```go
func ConfigFromEnv() productgraph.Config {
    return productgraph.Config{
        ProjectID:     os.Getenv("PRODUCTGRAPH_PROJECT_ID"),
        Endpoint:      os.Getenv("PRODUCTGRAPH_ENDPOINT"),
        APIKey:        os.Getenv("PRODUCTGRAPH_API_KEY"),
        BatchSize:     getEnvInt("PRODUCTGRAPH_BATCH_SIZE", 50),
        BatchInterval: getEnvDuration("PRODUCTGRAPH_BATCH_INTERVAL", 5*time.Second),
    }
}
```

## Event Schema

### API Response Event

```json
{
  "event_id": "uuid",
  "project_id": "proj_backend",
  "session.id": "sess_frontend_123",
  "event.type": "api.response",
  "event.timestamp": "2026-04-27T10:30:00Z",
  "api.method": "POST",
  "api.path": "/api/v1/checkout",
  "api.status_code": 200,
  "api.duration_ms": 150
}
```

### Error Event

```json
{
  "event_id": "uuid",
  "project_id": "proj_backend",
  "session.id": "sess_frontend_123",
  "event.type": "error",
  "event.timestamp": "2026-04-27T10:30:00Z",
  "error.type": "ValidationError",
  "error.message": "invalid card number"
}
```

### Journey Step Event

```json
{
  "event_id": "uuid",
  "project_id": "proj_backend",
  "session.id": "sess_frontend_123",
  "event.type": "journey.step",
  "event.timestamp": "2026-04-27T10:30:00Z",
  "gen_ai.journey.id": "checkout_flow",
  "gen_ai.journey.step.id": "payment_confirmed",
  "gen_ai.journey.step.name": "Payment Confirmed"
}
```

## Usage Example

```go
package main

import (
    "net/http"

    "github.com/go-chi/chi/v5"
    "github.com/plexusone/systemforge/observability"
    "github.com/plexusone/systemforge/observability/correlation"
    "github.com/plexusone/systemforge/productgraph"
)

func main() {
    // Create ProductGraph client
    pgClient := productgraph.New(productgraph.Config{
        ProjectID: "proj_demo",
        Endpoint:  "https://api.productgraph.io/v1/events",
        APIKey:    os.Getenv("PRODUCTGRAPH_API_KEY"),
    })
    defer pgClient.Close()

    // Create observability provider with ProductGraph
    provider := observability.New(
        observability.ConfigFromEnv(),
        observability.WithProductGraph(pgClient),
    )
    defer provider.Shutdown()

    // Setup router
    r := chi.NewRouter()

    // Middleware chain
    r.Use(correlation.Middleware)        // Extract session/request IDs
    r.Use(provider.TracingMiddleware)    // OpenTelemetry tracing
    r.Use(provider.RequestTracker)       // ProductGraph tracking

    r.Post("/api/checkout", func(w http.ResponseWriter, r *http.Request) {
        ctx := r.Context()

        // Business logic...

        // Track journey step from backend
        pgClient.TrackJourneyStep(ctx, "checkout_flow", "payment_confirmed", "Payment Confirmed")

        w.WriteHeader(http.StatusOK)
    })

    http.ListenAndServe(":8080", r)
}
```

## Testing

### Unit Tests

```go
func TestCorrelationMiddleware(t *testing.T) {
    handler := correlation.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        sessionID := correlation.SessionIDFromContext(r.Context())
        assert.Equal(t, "sess_123", sessionID)
    }))

    req := httptest.NewRequest("GET", "/", nil)
    req.Header.Set("X-Session-ID", "sess_123")

    handler.ServeHTTP(httptest.NewRecorder(), req)
}

func TestProductGraphClient(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        assert.Equal(t, "POST", r.Method)
        assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

        var payload map[string]interface{}
        json.NewDecoder(r.Body).Decode(&payload)
        events := payload["events"].([]interface{})
        assert.Len(t, events, 1)

        w.WriteHeader(http.StatusAccepted)
    }))
    defer server.Close()

    client := productgraph.New(productgraph.Config{
        ProjectID:     "test",
        Endpoint:      server.URL,
        BatchSize:     1, // Immediate flush
    })
    defer client.Close()

    ctx := context.WithValue(context.Background(), correlation.SessionIDKey, "sess_test")
    client.Track(ctx, productgraph.Event{
        EventType: "test",
    })

    time.Sleep(100 * time.Millisecond) // Wait for flush
}
```

## Security

### Header Validation

- Validate session ID format (UUID)
- Sanitize header values
- Rate limit by session

### Data Protection

- No PII in event payloads
- Redact sensitive fields
- TLS required in production

## Performance

### Targets

| Metric | Target |
|--------|--------|
| Tracking overhead | < 1ms |
| Memory per event | < 1 KB |
| Batch flush latency | < 50ms |

### Optimizations

- Async batching (non-blocking Track)
- Connection pooling
- Gzip compression for large batches

## Related Documents

- [PRD.md](PRD.md) - Product requirements
- [PLAN.md](PLAN.md) - Implementation plan
- [TASKS.md](TASKS.md) - Task breakdown
- [Observability TRD](../../specs/FEAT_OBSERVABILITY_TRD.md)
