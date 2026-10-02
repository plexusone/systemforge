# ProductGraph Integration Plan

**Author:** PlexusOne
**Date:** 2026-04-27
**Status:** Draft

## Executive Summary

Integrate systemforge observability with ProductGraph to enable frontend-backend correlation, backend event forwarding, and unified analytics via omnidxi.

## Current State

### systemforge Observability

- omniobserve integration with multiple providers (OTLP, Datadog, New Relic, Dynatrace)
- Pre-defined metrics for SystemAuth and CoreAPI
- HTTP middleware for request tracing
- OpenTelemetry span creation

### Missing

- Frontend session correlation
- Backend event forwarding to ProductGraph
- Journey tracking from backend
- Unified analytics pipeline

## Implementation Phases

### Phase 1: Correlation Middleware

**Goal:** Extract frontend correlation IDs and inject into context.

**Deliverables:**

1. `observability/correlation` package
2. Middleware extracting X-Session-ID, X-Request-ID
3. Context helper functions
4. Unit tests

**Files:**

```
observability/
├── correlation/
│   ├── correlation.go      # Middleware and context helpers
│   └── correlation_test.go # Unit tests
```

**Implementation:**

```go
// correlation/correlation.go
package correlation

type ContextKey string

const (
    SessionIDKey ContextKey = "session_id"
    RequestIDKey ContextKey = "request_id"
)

func Middleware(next http.Handler) http.Handler { ... }
func SessionIDFromContext(ctx context.Context) string { ... }
func RequestIDFromContext(ctx context.Context) string { ... }
```

### Phase 2: ProductGraph Client

**Goal:** Go client for sending events to ProductGraph.

**Deliverables:**

1. `productgraph` package
2. Event struct with OTel semantics
3. Async batching and flushing
4. Graceful shutdown

**Files:**

```
productgraph/
├── client.go       # Client implementation
├── event.go        # Event types
├── config.go       # Configuration
└── client_test.go  # Unit tests
```

**API:**

```go
client := productgraph.New(config)
defer client.Close()

client.Track(ctx, event)
client.TrackAPICall(ctx, method, path, status, duration)
client.TrackError(ctx, errType, message)
client.TrackJourneyStep(ctx, journeyID, stepID, stepName)
```

### Phase 3: Observability Integration

**Goal:** Integrate ProductGraph into existing observability provider.

**Deliverables:**

1. WithProductGraph option
2. RequestTracker middleware
3. Environment configuration
4. Integration tests

**Changes:**

```go
// observability/observability.go
func WithProductGraph(cfg productgraph.Config) ProviderOption

// observability/middleware.go
func (p *Provider) RequestTracker(next http.Handler) http.Handler
```

### Phase 4: Documentation and Examples

**Goal:** Complete documentation and example usage.

**Deliverables:**

1. Package documentation
2. Usage examples
3. Integration guide
4. Migration guide from direct omniobserve

**Files:**

```
docs/
├── design/productgraph/
│   ├── PRD.md      # Product requirements
│   ├── TRD.md      # Technical requirements
│   ├── PLAN.md     # This document
│   └── TASKS.md    # Task breakdown
productgraph/
├── README.md       # Package documentation
└── example_test.go # Example usage
```

## Timeline

| Phase | Duration | Target |
|-------|----------|--------|
| Phase 1: Correlation | 2 days | 2026-05-02 |
| Phase 2: Client | 3 days | 2026-05-07 |
| Phase 3: Integration | 2 days | 2026-05-09 |
| Phase 4: Documentation | 2 days | 2026-05-13 |

## Dependencies

### Internal

| Dependency | Version | Status |
|------------|---------|--------|
| ProductGraph | v0.2.0 | Ready |
| omniobserve | v0.8.0 | In use |

### External

| Dependency | Version | Purpose |
|------------|---------|---------|
| google/uuid | v1.6.0 | Event ID generation |
| go-chi/chi | v5.0.0 | HTTP router (optional) |

## Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| Latency impact | Medium | Async batching |
| Data loss on crash | Low | Graceful shutdown, retry |
| Memory pressure | Low | Bounded buffer |
| Network failures | Medium | Retry with backoff |

## Success Criteria

1. **Correlation**: 95%+ requests have session ID in context
2. **Delivery**: 99.9%+ event delivery rate
3. **Performance**: < 1ms tracking overhead
4. **Adoption**: Used in 2+ systemforge-based services

## Architecture Decision Records

### ADR-1: Direct Client vs omniobserve Extension

**Context:** Should ProductGraph be a new omniobserve provider or a separate client?

**Decision:** Separate client (`productgraph` package).

**Rationale:**

- ProductGraph is event-focused, not trace/metric focused
- Different batching semantics (events vs spans)
- Simpler to maintain independently
- Can still integrate with observability provider via composition

### ADR-2: Sync vs Async Tracking

**Context:** Should Track() be synchronous or asynchronous?

**Decision:** Asynchronous with batching.

**Rationale:**

- Minimal latency impact on request path
- Better throughput with batching
- Graceful degradation on network issues
- Trade-off: Potential event loss on crash (acceptable)

## Related Documents

- [PRD.md](PRD.md) - Product requirements
- [TRD.md](TRD.md) - Technical requirements
- [TASKS.md](TASKS.md) - Task breakdown
- [Observability TRD](../FEAT_OBSERVABILITY_TRD.md)
