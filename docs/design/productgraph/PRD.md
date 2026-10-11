# ProductGraph Integration PRD

**Author:** PlexusOne
**Date:** 2026-04-27
**Status:** Draft

## Overview

This document defines the product requirements for integrating systemforge's observability package with ProductGraph for backend telemetry correlation and analytics forwarding.

## Problem Statement

Backend services need to:

1. **Correlate with frontend events** - Link backend spans to frontend sessions
2. **Forward events to analytics** - Send backend events to Amplitude/Mixpanel
3. **Track business metrics** - Auth, API usage, journeys from backend perspective
4. **Unified observability** - Single destination for all telemetry

## Goals

### Primary Goals

1. **Frontend-backend correlation** via session ID propagation
2. **Backend event forwarding** to ProductGraph
3. **Analytics integration** via omnidxi (Amplitude, Mixpanel)
4. **Journey tracking** from backend (API-driven flows)

### Secondary Goals

1. **Unified metrics dashboard** in ProductGraph
2. **Error correlation** between frontend and backend
3. **Performance analysis** end-to-end

## User Stories

### US-1: Session Correlation

As a DevOps engineer, I want to correlate backend requests with frontend sessions so that I can debug user-reported issues end-to-end.

**Acceptance Criteria:**

- Extract X-Session-ID from request headers
- Attach session ID to OpenTelemetry spans
- Events appear in ProductGraph linked to session

### US-2: Backend Analytics

As a product manager, I want backend events forwarded to Amplitude so that I can analyze API usage patterns.

**Acceptance Criteria:**

- Backend events (auth, API calls) forward to ProductGraph
- ProductGraph forwards to Amplitude/Mixpanel via omnidxi
- Events include user ID when available

### US-3: Journey Completion

As a developer, I want to track journey completions from the backend so that I can measure server-confirmed conversions.

**Acceptance Criteria:**

- Backend can emit journey.step events
- Journey includes step ID and name
- Correlates with frontend journey tracking

### US-4: Error Aggregation

As a SRE, I want frontend and backend errors unified in ProductGraph so that I can triage issues efficiently.

**Acceptance Criteria:**

- Backend errors include session ID
- Error events follow OTel semantic conventions
- Errors appear alongside frontend errors in dashboard

## Requirements

### Functional Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-1 | Extract session ID from X-Session-ID header | P0 |
| FR-2 | Attach session ID to OpenTelemetry spans | P0 |
| FR-3 | HTTP client for POST /v1/events | P1 |
| FR-4 | Event batching (configurable size/interval) | P1 |
| FR-5 | OTel semantic convention compliance | P0 |
| FR-6 | Journey step emission from backend | P2 |
| FR-7 | Error event emission with context | P1 |
| FR-8 | Middleware for automatic request tracking | P1 |

### Non-Functional Requirements

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-1 | Event dispatch latency | < 10ms async |
| NFR-2 | Memory footprint | < 10 MB |
| NFR-3 | Retry on failure | 3 attempts |
| NFR-4 | No data loss on shutdown | Graceful flush |

## Architecture Options

### Option A: Direct ProductGraph Client

Send events directly to ProductGraph from Go backend.

```
systemforge → ProductGraph → omnidxi → Amplitude/Mixpanel
```

**Pros:** Simple, direct control
**Cons:** Duplicate logic, another client to maintain

### Option B: Via omniobserve Extension

Extend omniobserve to forward to ProductGraph.

```
systemforge → omniobserve → ProductGraph → omnidxi → Amplitude/Mixpanel
```

**Pros:** Unified observability, existing patterns
**Cons:** More complex, couples packages

### Option C: Via omnidxi Directly

Use omnidxi directly from systemforge, bypassing ProductGraph.

```
systemforge → omnidxi → Amplitude/Mixpanel
```

**Pros:** Simpler, fewer hops
**Cons:** Loses ProductGraph aggregation and dashboard

### Recommendation

**Option A** for Phase 1: Direct ProductGraph client with session correlation. This keeps the architecture simple and allows ProductGraph to be the single source of truth.

## Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Session correlation rate | > 95% | Correlated events / total |
| Event delivery rate | > 99.9% | Delivered / sent |
| Latency impact | < 5ms p99 | Added overhead |

## Out of Scope

- Real-time streaming (WebSocket)
- Custom ProductGraph dashboard
- Mobile backend correlation
- Distributed tracing via ProductGraph (use OTel)

## Dependencies

| Dependency | Version | Purpose |
|------------|---------|---------|
| ProductGraph | v0.2.0+ | Event ingestion |
| omniobserve | v0.8.0 | Backend observability |
| omnidxi | v0.1.0 | Analytics forwarding |

## Timeline

| Milestone | Target Date |
|-----------|-------------|
| Design approval | 2026-05-01 |
| Phase 1 implementation | 2026-05-10 |
| Testing | 2026-05-15 |
| v1.0.0 release | 2026-05-20 |

## Related Documents

- [TRD.md](TRD.md) - Technical requirements
- [PLAN.md](PLAN.md) - Implementation plan
- [TASKS.md](TASKS.md) - Task breakdown
- [systemforge observability TRD](../../specs/FEAT_OBSERVABILITY_TRD.md)
