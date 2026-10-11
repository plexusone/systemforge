# ProductGraph Integration Tasks

**Last Updated:** 2026-04-28

## Overview

Task breakdown for integrating systemforge observability with ProductGraph.

## Phase 1: Correlation Middleware

### P1.1: Design Documents

- [x] Create PRD.md with product requirements
- [x] Create TRD.md with technical specification
- [x] Create PLAN.md with implementation phases
- [x] Create TASKS.md (this file)

### P1.2: Correlation Package

- [x] Create productgraph/correlation.go
- [x] Implement Middleware function
- [x] Implement SessionIDFromContext helper
- [x] Implement RequestIDFromContext helper
- [x] Implement UserIDFromContext helper
- [x] Add header constants (X-Session-ID, X-Request-ID, X-User-ID)
- [x] Create productgraph/correlation_test.go
- [x] Test middleware extracts headers
- [x] Test context helpers

## Phase 2: ProductGraph Client

### P2.1: Core Client

- [x] Create productgraph/config.go
- [x] Define Config struct with defaults
- [x] Implement ConfigFromEnv function
- [x] Implement Validate method
- [x] Create productgraph/event.go
- [x] Define Event struct with OTel fields
- [x] Define event type constants (page.view, ui.click, api.response, etc.)
- [x] Implement event constructors (APIResponseEvent, ErrorEvent, JourneyStepEvent)
- [x] Create productgraph/client.go
- [x] Implement New constructor
- [x] Implement Track method
- [x] Implement async batching with background flusher
- [x] Implement Close with graceful shutdown

### P2.2: Convenience Methods

- [x] Implement TrackAPICall method
- [x] Implement TrackError method
- [x] Implement TrackJourneyStep method
- [x] Add context session ID extraction

### P2.3: Client Tests

- [x] Create productgraph/client_test.go
- [x] Test event batching
- [x] Test flush on batch size
- [x] Test flush on close
- [x] Test HTTP request format
- [x] Test API key header
- [x] Test session ID from context

## Phase 3: Observability Integration

### P3.1: Provider Integration

- [x] Add productgraph field to Observability struct
- [x] Implement SetProductGraph method
- [x] Implement SetProductGraphFromEnv method
- [x] Add ProductGraph close to Shutdown method

### P3.2: Request Tracking Middleware

- [x] Create productgraph/middleware.go
- [x] Implement RequestTrackerMiddleware
- [x] Implement ChainMiddleware (correlation + tracking)
- [x] Capture response status code
- [x] Capture request duration
- [x] Track api.response events

### P3.3: Helper Methods

- [x] Create observability/productgraph.go
- [x] Implement ProductGraphClient accessor
- [x] Implement ProductGraphEnabled check
- [x] Implement TrackProductGraphEvent wrapper
- [x] Implement TrackAPICall wrapper
- [x] Implement TrackError wrapper
- [x] Implement TrackJourneyStep wrapper
- [x] Implement ProductGraphMiddleware wrapper

### P3.4: Integration Tests

- [x] Create productgraph/middleware_test.go
- [x] Test request tracking
- [x] Test correlation + tracking
- [x] Test with mock ProductGraph server
- [x] Test nil client handling

## Phase 4: Documentation

### P4.1: Package Documentation

- [x] Create productgraph/doc.go
- [x] Document configuration options
- [x] Document event schema
- [x] Add usage examples

### P4.2: Integration Guide

- [x] Update docs/observability/overview.md with ProductGraph section
- [x] Document middleware chain setup
- [x] Document environment variables
- [x] Document correlation headers
- [ ] Add troubleshooting section

### P4.3: Example Code

- [ ] Create productgraph/example_test.go
- [ ] Example: Basic tracking
- [ ] Example: Journey tracking
- [ ] Example: Error tracking
- [ ] Example: Full middleware chain

### P4.4: MkDocs Navigation

- [x] Add ProductGraph design docs to mkdocs.yml

## Backlog

### Future Enhancements

- [ ] Retry with exponential backoff
- [ ] Gzip compression for batches
- [ ] Circuit breaker for failures
- [ ] Metrics for tracking (events sent, failures)
- [ ] Health check endpoint contribution
- [ ] OpenTelemetry span linking
- [ ] Sampling support
- [ ] PII redaction filters

## Completed

- [x] Design documents created (PRD, TRD, PLAN, TASKS)
- [x] Correlation middleware (Phase 1)
- [x] ProductGraph client (Phase 2)
- [x] Observability integration (Phase 3)
- [x] Core documentation (Phase 4 partial)

## Notes

### Priority Legend

- P0: Critical path, blocks release
- P1: Important, should have for release
- P2: Nice to have
- P3: Future consideration

### Current Focus

Phase 4: Completing remaining documentation and examples.

### Blockers

None currently identified.

### Dependencies on Other Work

- ProductGraph v0.2.0 must be released (DONE)
- @systemforge/telemetry ProductGraphAdapter provides correlation headers (DONE)

## Test Coverage Goals

| Package | Target | Status |
|---------|--------|--------|
| productgraph | 85% | ✓ 15 tests passing |
| observability (new code) | 80% | ✓ lint clean |

## Related Documents

- [PRD.md](PRD.md) - Product requirements
- [TRD.md](TRD.md) - Technical requirements
- [PLAN.md](PLAN.md) - Implementation plan
- [Observability TRD](../../specs/FEAT_OBSERVABILITY_TRD.md)
