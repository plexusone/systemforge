# PRD: SystemForge Authorization (SpiceDB)

> **Status**: Draft
>
> This PRD defines the requirements for SystemForge's relationship-based authorization system using SpiceDB (Zanzibar-style ReBAC).

## Overview

SystemForge Authorization provides a unified, scalable authorization framework for multi-tenant SaaS applications. It replaces simple RBAC with relationship-based access control (ReBAC) using SpiceDB, enabling fine-grained permissions based on object relationships.

## Goals

1. **Relationship-Based Access**: Model permissions as relationships between subjects and objects
2. **Scalable Performance**: Sub-10ms permission checks at scale
3. **Unified Schema**: Shared authorization patterns across SystemForge apps
4. **Marketplace Integration**: Native support for licensing and entitlements
5. **Migration Path**: Smooth transition from existing RBAC/Casbin

## Why SpiceDB?

| Feature | Simple RBAC | Casbin | SpiceDB |
|---------|-------------|--------|---------|
| Relationship modeling | No | Limited | Native |
| Nested permissions | No | Complex | Native (`->` syntax) |
| Performance at scale | Good | Good | Excellent |
| Caching | Manual | Manual | Built-in |
| Consistency guarantees | App-managed | App-managed | ZedTokens |
| Schema validation | None | Limited | Comprehensive |

## User Stories

### Developer Stories

**US-1**: As a developer, I can define authorization schemas using SpiceDB's Zed language.

**US-2**: As a developer, I can check permissions with a simple `Can(subject, action, resource)` API.

**US-3**: As a developer, I can sync database changes to SpiceDB automatically.

**US-4**: As a developer, I can test authorization rules without a running SpiceDB instance.

### Application Stories

**US-5**: As an app, I can model organization hierarchies (owner > admin > member > viewer).

**US-6**: As an app, I can model resource ownership and sharing.

**US-7**: As an app, I can model marketplace licensing (creator org -> listing -> licensed org).

**US-8**: As an app, I can check if a user has access through any valid path (direct, org membership, license).

### Operations Stories

**US-9**: As an operator, I can deploy SpiceDB with PostgreSQL or CockroachDB backend.

**US-10**: As an operator, I can monitor authorization performance and errors.

**US-11**: As an operator, I can migrate schemas without downtime.

## Architecture

### System Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         APPLICATION LAYER                                    │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │ App1   │  │  App2  │  │  Future App │  │  SystemForge Identity │ │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘ │
│         │                │                │                     │            │
│         └────────────────┴────────────────┴─────────────────────┘            │
│                                     │                                        │
│                                     ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                    SystemForge Authz Package                               ││
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐ ││
│  │  │  Provider   │  │   Syncer    │  │ Middleware  │  │    Testing      │ ││
│  │  │  Interface  │  │             │  │             │  │    Utilities    │ ││
│  │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └─────────────────┘ ││
│  └─────────┼────────────────┼────────────────┼─────────────────────────────┘│
│            │                │                │                               │
└────────────┼────────────────┼────────────────┼───────────────────────────────┘
             │                │                │
             ▼                ▼                ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              SpiceDB                                         │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │  Schema (Zed)                                                            ││
│  │  ├── principal                                                           ││
│  │  ├── organization (consumer_org)                                         ││
│  │  ├── creator_org (publisher/tenant)                                      ││
│  │  ├── listing                                                             ││
│  │  ├── license                                                             ││
│  │  └── [app-specific definitions]                                          ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │  Relationships (Tuples)                                                  ││
│  │  principal:user-123 | member | organization:acme                         ││
│  │  organization:acme | licensed_org | listing:course-456                   ││
│  └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
```

### Module Structure

```
systemforge/
├── authz/
│   ├── types.go           # Principal, Resource, Action types
│   ├── roles.go           # Role hierarchy utilities
│   ├── provider.go        # Provider interface
│   ├── middleware.go      # HTTP middleware
│   │
│   ├── spicedb/           # SpiceDB implementation
│   │   ├── provider.go    # SpiceDB provider
│   │   ├── client.go      # gRPC client wrapper
│   │   ├── schema.go      # Schema management
│   │   └── syncer.go      # Relationship syncer
│   │
│   ├── simple/            # Simple in-memory provider
│   │   └── provider.go
│   │
│   └── providertest/      # Conformance testing
│       ├── providertest.go
│       └── mock.go
│
├── marketplace/           # Marketplace integration (NEW)
│   ├── types.go
│   ├── service.go
│   └── authz.go           # SpiceDB sync for licenses
│
└── docs/specs/
    ├── FEAT_AUTHZ_PRD.md  # This document
    └── FEAT_AUTHZ_TRD.md  # Technical reference
```

## Authorization Model

### Core Concepts

| Concept | Description | Example |
|---------|-------------|---------|
| **Principal** | Entity requesting access | User, Service, API Key |
| **Resource** | Object being accessed | Organization, Course, Dashboard |
| **Relation** | Relationship between principal and resource | owner, admin, member, viewer |
| **Permission** | Action that can be performed | manage, edit, view, delete |

### Relationship Hierarchy

```
Permission Flow (computed via relations):

  owner ────────────────────────────────────────┐
    │                                            │
    ▼                                            ▼
  admin ─────────────────────────────────┐    manage
    │                                     │      │
    ▼                                     ▼      ▼
  editor/creator ────────────────────┐  edit ◀──┤
    │                                 │    │     │
    ▼                                 ▼    ▼     │
  viewer/member ─────────────────┐  view ◀──────┘
                                  │    │
                                  ▼    │
                                use ◀──┘
```

### SpiceDB Schema (Shared Base)

```zed
// =============================================================================
// PRINCIPALS
// =============================================================================

definition principal {}

// =============================================================================
// ORGANIZATIONS
// =============================================================================

// Consumer organization - uses products, subscribes to platform
definition organization {
    relation owner: principal
    relation admin: principal
    relation member: principal
    relation viewer: principal

    // Membership hierarchy
    permission manage = owner + admin
    permission edit = manage + member
    permission view = edit + viewer
    permission use = view

    // Operations
    permission delete = owner
    permission settings = manage
    permission billing = owner + admin
    permission invite_member = manage
    permission purchase = manage
}

// Creator organization - creates and sells products
definition creator_org {
    relation owner: principal
    relation admin: principal
    relation creator: principal
    relation reviewer: principal

    // Membership hierarchy
    permission manage = owner + admin
    permission create = manage + creator
    permission review = manage + reviewer

    // Operations
    permission delete = owner
    permission settings = manage
    permission billing = owner + admin
    permission publish = manage
    permission view_analytics = manage
}

// =============================================================================
// MARKETPLACE
// =============================================================================

definition listing {
    relation creator_org: creator_org
    relation owner: principal
    relation licensed_org: organization

    permission manage = owner + creator_org->manage
    permission edit = manage + creator_org->create
    permission review = creator_org->review
    permission publish = creator_org->publish
    permission use = licensed_org->use
    permission view = use + edit
}

definition license {
    relation listing: listing
    relation organization: organization
    relation purchased_by: principal
    relation seat_holder: principal

    permission view = organization->manage + purchased_by
    permission use = seat_holder + organization->use
    permission manage = organization->manage
    permission transfer = organization->manage
}
```

### App-Specific Extensions

Applications extend the base schema with domain-specific definitions:

**App1:**
```zed
definition course {
    relation tenant: creator_org
    relation owner: principal
    relation listing: listing
    relation enrolled: principal

    permission manage = owner + tenant->manage
    permission edit = manage + tenant->create
    permission view = enrolled + listing->use + edit
    permission enroll = listing->use
}
```

**App2:**
```zed
definition dashboard_template {
    relation publisher: creator_org
    relation owner: principal
    relation listing: listing

    permission manage = owner + publisher->manage
    permission edit = manage + publisher->create
    permission use = listing->use
    permission view = use + edit
}
```

## Provider Interface

```go
// Provider defines the authorization interface.
type Provider interface {
    // Can checks if the principal can perform the action on the resource.
    Can(ctx context.Context, principal Principal, action Action, resource Resource) (bool, error)

    // CanAll checks if the principal can perform all actions on the resource.
    CanAll(ctx context.Context, principal Principal, actions []Action, resource Resource) (bool, error)

    // CanAny checks if the principal can perform any of the actions on the resource.
    CanAny(ctx context.Context, principal Principal, actions []Action, resource Resource) (bool, error)

    // ListPermissions returns all permissions the principal has on the resource.
    ListPermissions(ctx context.Context, principal Principal, resource Resource) ([]Action, error)

    // ListResources returns all resources of the given type the principal can access.
    ListResources(ctx context.Context, principal Principal, resourceType ResourceType, action Action) ([]Resource, error)
}

// Syncer syncs relationships to the authorization backend.
type Syncer interface {
    // WriteRelationship creates or updates a relationship.
    WriteRelationship(ctx context.Context, resource Resource, relation string, subject Principal) error

    // DeleteRelationship removes a relationship.
    DeleteRelationship(ctx context.Context, resource Resource, relation string, subject Principal) error

    // BulkWrite performs multiple relationship operations atomically.
    BulkWrite(ctx context.Context, ops []RelationshipOp) error
}
```

## Sync Strategy

### Event-Driven Sync

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Database   │     │   Syncer    │     │   SpiceDB   │
│  (Ent)      │     │             │     │             │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │
       │  Hook: OnCreate   │                   │
       │──────────────────▶│                   │
       │                   │  WriteRelationship│
       │                   │──────────────────▶│
       │                   │                   │
       │  Hook: OnUpdate   │                   │
       │──────────────────▶│                   │
       │                   │  Update Relations │
       │                   │──────────────────▶│
       │                   │                   │
       │  Hook: OnDelete   │                   │
       │──────────────────▶│                   │
       │                   │  DeleteRelationship
       │                   │──────────────────▶│
```

### Sync Events

| Entity | Event | SpiceDB Action |
|--------|-------|----------------|
| Organization | Created | Create org with owner relation |
| Organization | Member added | Add member relation |
| Organization | Member role changed | Update relation |
| Organization | Member removed | Delete relation |
| License | Created | Add licensed_org relation to listing |
| License | Seat assigned | Add seat_holder relation |
| License | Revoked | Delete licensed_org relation |
| CreatorOrg | Created | Create creator_org with owner relation |
| Listing | Published | Add to marketplace |

## Performance Requirements

| Operation | Target | Notes |
|-----------|--------|-------|
| Permission check | < 10ms p99 | With caching |
| Relationship write | < 50ms | Single operation |
| Bulk write (100 ops) | < 200ms | Atomic |
| List resources (100) | < 100ms | Paginated |

### Caching Strategy

1. **ZedTokens**: Use SpiceDB's consistency tokens for cache invalidation
2. **Local Cache**: Cache positive permission results (5 min TTL)
3. **Negative Cache**: Short TTL (30s) for negative results
4. **Cache Keys**: `{principal_type}:{principal_id}:{action}:{resource_type}:{resource_id}`

## Migration Path

### From Casbin

1. **Phase 1**: Deploy SpiceDB alongside Casbin
2. **Phase 2**: Dual-write to both systems
3. **Phase 3**: Read from SpiceDB, write to both
4. **Phase 4**: Read and write from SpiceDB only
5. **Phase 5**: Remove Casbin

### From Simple RBAC

1. **Phase 1**: Map existing roles to SpiceDB relations
2. **Phase 2**: Sync existing memberships to SpiceDB
3. **Phase 3**: Switch permission checks to SpiceDB
4. **Phase 4**: Remove old RBAC code

## Testing Strategy

### Unit Tests

- Mock provider for fast tests
- Conformance tests for all providers
- Schema validation tests

### Integration Tests

- SpiceDB container for CI
- Full flow tests (sync + check)
- Performance benchmarks

### Conformance Test Suite

```go
// providertest/providertest.go
func RunConformanceTests(t *testing.T, provider Provider, syncer Syncer) {
    t.Run("OwnerCanManage", func(t *testing.T) { ... })
    t.Run("AdminCanManage", func(t *testing.T) { ... })
    t.Run("MemberCanView", func(t *testing.T) { ... })
    t.Run("NonMemberCannotAccess", func(t *testing.T) { ... })
    t.Run("LicenseGrantsAccess", func(t *testing.T) { ... })
    // ...
}
```

## Success Metrics

1. **Latency**: p99 permission check < 10ms
2. **Availability**: 99.9% uptime for authorization service
3. **Accuracy**: Zero false positives/negatives in permission checks
4. **Developer Experience**: < 1 hour to integrate new app

## Out of Scope (v1)

- Cedar policy language support (future)
- OPA integration (future)
- Custom policy expressions (future)
- Real-time permission streaming (future)

## Dependencies

- SpiceDB v1.x
- PostgreSQL or CockroachDB (for SpiceDB backend)
- SystemForge identity module

## References

- [SpiceDB Documentation](https://authzed.com/docs)
- [Google Zanzibar Paper](https://research.google/pubs/pub48190/)
- [Relationship-Based Access Control](https://www.osohq.com/post/what-is-relationship-based-access-control)
- [SystemForge FEAT_AUTHN_PRD.md](./FEAT_AUTHN_PRD.md)
