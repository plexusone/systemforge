# TRD: SystemForge Authorization (SpiceDB)

> **Status**: Draft
>
> This TRD defines the technical implementation for SystemForge's SpiceDB-based authorization system.

## Overview

This document provides the technical design for implementing relationship-based access control (ReBAC) using SpiceDB in SystemForge applications.

## Architecture

### Component Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              APPLICATION                                     │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                           HTTP Layer                                     ││
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐ ││
│  │  │   Router    │─▶│   Authz     │─▶│   Handler   │─▶│   Response      │ ││
│  │  │   (Chi)     │  │ Middleware  │  │             │  │                 │ ││
│  │  └─────────────┘  └──────┬──────┘  └─────────────┘  └─────────────────┘ ││
│  └──────────────────────────┼──────────────────────────────────────────────┘│
│                             │                                                │
│  ┌──────────────────────────┼──────────────────────────────────────────────┐│
│  │                     Authorization Package                                ││
│  │                          │                                               ││
│  │  ┌─────────────┐  ┌──────▼──────┐  ┌─────────────┐  ┌─────────────────┐ ││
│  │  │  Provider   │◀─│  SpiceDB    │──│   Cache     │──│   Metrics       │ ││
│  │  │  Interface  │  │  Provider   │  │  (Optional) │  │                 │ ││
│  │  └─────────────┘  └──────┬──────┘  └─────────────┘  └─────────────────┘ ││
│  │                          │                                               ││
│  │  ┌─────────────┐  ┌──────▼──────┐  ┌─────────────┐                      ││
│  │  │   Syncer    │──│   Client    │──│   Schema    │                      ││
│  │  │             │  │   (gRPC)    │  │  Manager    │                      ││
│  │  └──────┬──────┘  └─────────────┘  └─────────────┘                      ││
│  └─────────┼───────────────────────────────────────────────────────────────┘│
│            │                                                                 │
│  ┌─────────▼───────────────────────────────────────────────────────────────┐│
│  │                         Database (Ent)                                   ││
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                      ││
│  │  │  Org Hooks  │  │License Hooks│  │Member Hooks │                      ││
│  │  └─────────────┘  └─────────────┘  └─────────────┘                      ││
│  └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
                              │
                              │ gRPC
                              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              SpiceDB                                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   Schema    │  │ Relationships│  │   Check     │  │    Lookup          │ │
│  │   Store     │  │   Store     │  │   Engine    │  │    Engine          │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────────────┘ │
│                              │                                               │
│  ┌───────────────────────────▼─────────────────────────────────────────────┐│
│  │                     PostgreSQL / CockroachDB                             ││
│  └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
```

## SpiceDB Client

### Client Configuration

```go
// spicedb/client.go
package spicedb

import (
    "context"
    "crypto/tls"
    "time"

    v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
    "github.com/authzed/authzed-go/v1"
    "github.com/authzed/grpcutil"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
    "google.golang.org/grpc/credentials/insecure"
)

// Config configures the SpiceDB client.
type Config struct {
    // Endpoint is the SpiceDB gRPC endpoint.
    Endpoint string `env:"SPICEDB_ENDPOINT, default=localhost:50051"`

    // Token is the pre-shared key for authentication.
    Token string `env:"SPICEDB_TOKEN"`

    // Insecure disables TLS (for development only).
    Insecure bool `env:"SPICEDB_INSECURE, default=false"`

    // MaxRetries is the maximum number of retry attempts.
    MaxRetries int `env:"SPICEDB_MAX_RETRIES, default=3"`

    // Timeout is the default request timeout.
    Timeout time.Duration `env:"SPICEDB_TIMEOUT, default=5s"`
}

// Client wraps the SpiceDB gRPC client.
type Client struct {
    permissions v1.PermissionsServiceClient
    schema      v1.SchemaServiceClient
    conn        *grpc.ClientConn
    config      Config
}

// NewClient creates a new SpiceDB client.
func NewClient(cfg Config) (*Client, error) {
    var opts []grpc.DialOption

    if cfg.Insecure {
        opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
    } else {
        opts = append(opts, grpc.WithTransportCredentials(
            credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12}),
        ))
    }

    if cfg.Token != "" {
        opts = append(opts, grpcutil.WithInsecureBearerToken(cfg.Token))
    }

    conn, err := grpc.NewClient(cfg.Endpoint, opts...)
    if err != nil {
        return nil, fmt.Errorf("connecting to SpiceDB: %w", err)
    }

    return &Client{
        permissions: v1.NewPermissionsServiceClient(conn),
        schema:      v1.NewSchemaServiceClient(conn),
        conn:        conn,
        config:      cfg,
    }, nil
}

// Close closes the client connection.
func (c *Client) Close() error {
    return c.conn.Close()
}
```

### Permission Checking

```go
// spicedb/provider.go
package spicedb

import (
    "context"

    v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
    "github.com/plexusone/systemforge/authz"
)

// Provider implements authz.Provider using SpiceDB.
type Provider struct {
    client *Client
    cache  Cache // Optional cache
}

// NewProvider creates a new SpiceDB authorization provider.
func NewProvider(client *Client, opts ...ProviderOption) *Provider {
    p := &Provider{client: client}
    for _, opt := range opts {
        opt(p)
    }
    return p
}

// Can checks if the principal can perform the action on the resource.
func (p *Provider) Can(ctx context.Context, principal authz.Principal, action authz.Action, resource authz.Resource) (bool, error) {
    // Check cache first
    if p.cache != nil {
        if result, ok := p.cache.Get(principal, action, resource); ok {
            return result, nil
        }
    }

    req := &v1.CheckPermissionRequest{
        Resource: &v1.ObjectReference{
            ObjectType: string(resource.Type),
            ObjectId:   resource.ID.String(),
        },
        Permission: string(action),
        Subject: &v1.SubjectReference{
            Object: &v1.ObjectReference{
                ObjectType: "principal",
                ObjectId:   principal.ID.String(),
            },
        },
        Consistency: &v1.Consistency{
            Requirement: &v1.Consistency_FullyConsistent{
                FullyConsistent: true,
            },
        },
    }

    ctx, cancel := context.WithTimeout(ctx, p.client.config.Timeout)
    defer cancel()

    resp, err := p.client.permissions.CheckPermission(ctx, req)
    if err != nil {
        return false, fmt.Errorf("checking permission: %w", err)
    }

    result := resp.Permissionship == v1.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION

    // Cache result
    if p.cache != nil {
        p.cache.Set(principal, action, resource, result)
    }

    return result, nil
}

// CanAll checks if the principal can perform all actions on the resource.
func (p *Provider) CanAll(ctx context.Context, principal authz.Principal, actions []authz.Action, resource authz.Resource) (bool, error) {
    for _, action := range actions {
        can, err := p.Can(ctx, principal, action, resource)
        if err != nil {
            return false, err
        }
        if !can {
            return false, nil
        }
    }
    return true, nil
}

// CanAny checks if the principal can perform any of the actions on the resource.
func (p *Provider) CanAny(ctx context.Context, principal authz.Principal, actions []authz.Action, resource authz.Resource) (bool, error) {
    for _, action := range actions {
        can, err := p.Can(ctx, principal, action, resource)
        if err != nil {
            return false, err
        }
        if can {
            return true, nil
        }
    }
    return false, nil
}

// ListPermissions returns all permissions the principal has on the resource.
func (p *Provider) ListPermissions(ctx context.Context, principal authz.Principal, resource authz.Resource) ([]authz.Action, error) {
    // SpiceDB doesn't have a direct "list permissions" API
    // We check common permissions and return those that are allowed
    commonActions := []authz.Action{
        authz.ActionManage,
        authz.ActionCreate,
        authz.ActionRead,
        authz.ActionUpdate,
        authz.ActionDelete,
        authz.ActionList,
    }

    var allowed []authz.Action
    for _, action := range commonActions {
        can, err := p.Can(ctx, principal, action, resource)
        if err != nil {
            return nil, err
        }
        if can {
            allowed = append(allowed, action)
        }
    }

    return allowed, nil
}

// ListResources returns all resources of the given type the principal can access.
func (p *Provider) ListResources(ctx context.Context, principal authz.Principal, resourceType authz.ResourceType, action authz.Action) ([]authz.Resource, error) {
    req := &v1.LookupResourcesRequest{
        ResourceObjectType: string(resourceType),
        Permission:         string(action),
        Subject: &v1.SubjectReference{
            Object: &v1.ObjectReference{
                ObjectType: "principal",
                ObjectId:   principal.ID.String(),
            },
        },
        Consistency: &v1.Consistency{
            Requirement: &v1.Consistency_FullyConsistent{
                FullyConsistent: true,
            },
        },
    }

    ctx, cancel := context.WithTimeout(ctx, p.client.config.Timeout)
    defer cancel()

    stream, err := p.client.permissions.LookupResources(ctx, req)
    if err != nil {
        return nil, fmt.Errorf("looking up resources: %w", err)
    }

    var resources []authz.Resource
    for {
        resp, err := stream.Recv()
        if err == io.EOF {
            break
        }
        if err != nil {
            return nil, fmt.Errorf("receiving resource: %w", err)
        }

        id, err := uuid.Parse(resp.ResourceObjectId)
        if err != nil {
            continue // Skip invalid IDs
        }

        resources = append(resources, authz.Resource{
            Type: resourceType,
            ID:   &id,
        })
    }

    return resources, nil
}
```

## Relationship Syncer

### Syncer Implementation

```go
// spicedb/syncer.go
package spicedb

import (
    "context"

    v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
    "github.com/plexusone/systemforge/authz"
)

// Syncer syncs relationships to SpiceDB.
type Syncer struct {
    client *Client
}

// NewSyncer creates a new SpiceDB relationship syncer.
func NewSyncer(client *Client) *Syncer {
    return &Syncer{client: client}
}

// WriteRelationship creates or updates a relationship.
func (s *Syncer) WriteRelationship(ctx context.Context, resource authz.Resource, relation string, subject authz.Principal) error {
    req := &v1.WriteRelationshipsRequest{
        Updates: []*v1.RelationshipUpdate{
            {
                Operation: v1.RelationshipUpdate_OPERATION_TOUCH,
                Relationship: &v1.Relationship{
                    Resource: &v1.ObjectReference{
                        ObjectType: string(resource.Type),
                        ObjectId:   resource.ID.String(),
                    },
                    Relation: relation,
                    Subject: &v1.SubjectReference{
                        Object: &v1.ObjectReference{
                            ObjectType: "principal",
                            ObjectId:   subject.ID.String(),
                        },
                    },
                },
            },
        },
    }

    ctx, cancel := context.WithTimeout(ctx, s.client.config.Timeout)
    defer cancel()

    _, err := s.client.permissions.WriteRelationships(ctx, req)
    if err != nil {
        return fmt.Errorf("writing relationship: %w", err)
    }

    return nil
}

// DeleteRelationship removes a relationship.
func (s *Syncer) DeleteRelationship(ctx context.Context, resource authz.Resource, relation string, subject authz.Principal) error {
    req := &v1.WriteRelationshipsRequest{
        Updates: []*v1.RelationshipUpdate{
            {
                Operation: v1.RelationshipUpdate_OPERATION_DELETE,
                Relationship: &v1.Relationship{
                    Resource: &v1.ObjectReference{
                        ObjectType: string(resource.Type),
                        ObjectId:   resource.ID.String(),
                    },
                    Relation: relation,
                    Subject: &v1.SubjectReference{
                        Object: &v1.ObjectReference{
                            ObjectType: "principal",
                            ObjectId:   subject.ID.String(),
                        },
                    },
                },
            },
        },
    }

    ctx, cancel := context.WithTimeout(ctx, s.client.config.Timeout)
    defer cancel()

    _, err := s.client.permissions.WriteRelationships(ctx, req)
    if err != nil {
        return fmt.Errorf("deleting relationship: %w", err)
    }

    return nil
}

// RelationshipOp represents a relationship operation.
type RelationshipOp struct {
    Operation RelationshipOperation
    Resource  authz.Resource
    Relation  string
    Subject   authz.Principal
}

// RelationshipOperation is the type of relationship operation.
type RelationshipOperation int

const (
    OpCreate RelationshipOperation = iota
    OpDelete
)

// BulkWrite performs multiple relationship operations atomically.
func (s *Syncer) BulkWrite(ctx context.Context, ops []RelationshipOp) error {
    updates := make([]*v1.RelationshipUpdate, len(ops))

    for i, op := range ops {
        var operation v1.RelationshipUpdate_Operation
        switch op.Operation {
        case OpCreate:
            operation = v1.RelationshipUpdate_OPERATION_TOUCH
        case OpDelete:
            operation = v1.RelationshipUpdate_OPERATION_DELETE
        }

        updates[i] = &v1.RelationshipUpdate{
            Operation: operation,
            Relationship: &v1.Relationship{
                Resource: &v1.ObjectReference{
                    ObjectType: string(op.Resource.Type),
                    ObjectId:   op.Resource.ID.String(),
                },
                Relation: op.Relation,
                Subject: &v1.SubjectReference{
                    Object: &v1.ObjectReference{
                        ObjectType: "principal",
                        ObjectId:   op.Subject.ID.String(),
                    },
                },
            },
        }
    }

    req := &v1.WriteRelationshipsRequest{Updates: updates}

    ctx, cancel := context.WithTimeout(ctx, s.client.config.Timeout)
    defer cancel()

    _, err := s.client.permissions.WriteRelationships(ctx, req)
    if err != nil {
        return fmt.Errorf("bulk writing relationships: %w", err)
    }

    return nil
}

// WriteObjectRelationship writes a relationship where the subject is another object.
func (s *Syncer) WriteObjectRelationship(ctx context.Context, resource authz.Resource, relation string, subjectType string, subjectID string) error {
    req := &v1.WriteRelationshipsRequest{
        Updates: []*v1.RelationshipUpdate{
            {
                Operation: v1.RelationshipUpdate_OPERATION_TOUCH,
                Relationship: &v1.Relationship{
                    Resource: &v1.ObjectReference{
                        ObjectType: string(resource.Type),
                        ObjectId:   resource.ID.String(),
                    },
                    Relation: relation,
                    Subject: &v1.SubjectReference{
                        Object: &v1.ObjectReference{
                            ObjectType: subjectType,
                            ObjectId:   subjectID,
                        },
                    },
                },
            },
        },
    }

    ctx, cancel := context.WithTimeout(ctx, s.client.config.Timeout)
    defer cancel()

    _, err := s.client.permissions.WriteRelationships(ctx, req)
    if err != nil {
        return fmt.Errorf("writing object relationship: %w", err)
    }

    return nil
}
```

## Schema Management

### Schema Definition

```go
// spicedb/schema.go
package spicedb

import (
    "context"
    _ "embed"

    v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
)

//go:embed schema/base.zed
var BaseSchema string

// SchemaManager manages SpiceDB schema.
type SchemaManager struct {
    client *Client
}

// NewSchemaManager creates a new schema manager.
func NewSchemaManager(client *Client) *SchemaManager {
    return &SchemaManager{client: client}
}

// WriteSchema writes the schema to SpiceDB.
func (m *SchemaManager) WriteSchema(ctx context.Context, schema string) error {
    req := &v1.WriteSchemaRequest{
        Schema: schema,
    }

    ctx, cancel := context.WithTimeout(ctx, m.client.config.Timeout)
    defer cancel()

    _, err := m.client.schema.WriteSchema(ctx, req)
    if err != nil {
        return fmt.Errorf("writing schema: %w", err)
    }

    return nil
}

// ReadSchema reads the current schema from SpiceDB.
func (m *SchemaManager) ReadSchema(ctx context.Context) (string, error) {
    req := &v1.ReadSchemaRequest{}

    ctx, cancel := context.WithTimeout(ctx, m.client.config.Timeout)
    defer cancel()

    resp, err := m.client.schema.ReadSchema(ctx, req)
    if err != nil {
        return "", fmt.Errorf("reading schema: %w", err)
    }

    return resp.SchemaText, nil
}

// MergeSchema merges app-specific schema with the base schema.
func MergeSchema(baseSchema, appSchema string) string {
    return baseSchema + "\n\n" + appSchema
}
```

### Base Schema File

```zed
// spicedb/schema/base.zed

// =============================================================================
// PRINCIPALS
// =============================================================================

definition principal {}

// =============================================================================
// CONSUMER ORGANIZATIONS
// =============================================================================

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

    // Organization operations
    permission delete = owner
    permission settings = manage
    permission billing = owner + admin
    permission invite_member = manage
    permission remove_member = manage
    permission purchase = manage
}

// =============================================================================
// CREATOR ORGANIZATIONS
// =============================================================================

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

definition subscription {
    relation organization: organization
    relation subscriber: principal

    permission view = organization->view
    permission manage = organization->manage
}
```

## Ent Hooks Integration

### Hook Registration

```go
// ent/hooks/authz.go
package hooks

import (
    "context"

    "entgo.io/ent"
    "github.com/plexusone/systemforge/authz"
    "github.com/plexusone/systemforge/authz/rebac/spicedb"
)

// AuthzHooks creates Ent hooks for SpiceDB synchronization.
func AuthzHooks(syncer *spicedb.Syncer) []ent.Hook {
    return []ent.Hook{
        OrganizationHook(syncer),
        MembershipHook(syncer),
        LicenseHook(syncer),
    }
}

// OrganizationHook syncs organization changes to SpiceDB.
func OrganizationHook(syncer *spicedb.Syncer) ent.Hook {
    return func(next ent.Mutator) ent.Mutator {
        return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
            // Execute mutation
            v, err := next.Mutate(ctx, m)
            if err != nil {
                return nil, err
            }

            // Sync to SpiceDB on create
            if m.Op().Is(ent.OpCreate) {
                org, ok := v.(*ent.Organization)
                if !ok {
                    return v, nil
                }

                // Get owner from context or mutation
                ownerID, _ := m.Field("owner_id")
                if ownerID != nil {
                    resource := authz.NewResourceWithID(authz.ResourceTypeOrganization, org.ID)
                    subject := authz.NewUserPrincipal(ownerID.(uuid.UUID))
                    if err := syncer.WriteRelationship(ctx, resource, "owner", subject); err != nil {
                        // Log error but don't fail the mutation
                        slog.Error("failed to sync org owner to SpiceDB", "error", err)
                    }
                }
            }

            return v, nil
        })
    }
}

// MembershipHook syncs membership changes to SpiceDB.
func MembershipHook(syncer *spicedb.Syncer) ent.Hook {
    return func(next ent.Mutator) ent.Mutator {
        return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
            // Execute mutation
            v, err := next.Mutate(ctx, m)
            if err != nil {
                return nil, err
            }

            membership, ok := v.(*ent.Membership)
            if !ok {
                return v, nil
            }

            resource := authz.NewResourceWithID(authz.ResourceTypeOrganization, membership.OrganizationID)
            subject := authz.NewUserPrincipal(membership.UserID)

            switch {
            case m.Op().Is(ent.OpCreate):
                // Add member relation
                if err := syncer.WriteRelationship(ctx, resource, membership.Role, subject); err != nil {
                    slog.Error("failed to sync membership to SpiceDB", "error", err)
                }

            case m.Op().Is(ent.OpUpdate):
                // Role change: remove old, add new
                oldRole, _ := m.OldField("role")
                if oldRole != nil && oldRole != membership.Role {
                    _ = syncer.DeleteRelationship(ctx, resource, oldRole.(string), subject)
                    _ = syncer.WriteRelationship(ctx, resource, membership.Role, subject)
                }

            case m.Op().Is(ent.OpDelete):
                // Remove all possible relations
                for _, role := range []string{"owner", "admin", "member", "viewer"} {
                    _ = syncer.DeleteRelationship(ctx, resource, role, subject)
                }
            }

            return v, nil
        })
    }
}

// LicenseHook syncs license changes to SpiceDB.
func LicenseHook(syncer *spicedb.Syncer) ent.Hook {
    return func(next ent.Mutator) ent.Mutator {
        return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
            v, err := next.Mutate(ctx, m)
            if err != nil {
                return nil, err
            }

            license, ok := v.(*ent.License)
            if !ok {
                return v, nil
            }

            // Sync licensed_org relation to listing
            listingResource := authz.Resource{
                Type: "listing",
                ID:   &license.ListingID,
            }

            switch {
            case m.Op().Is(ent.OpCreate):
                // Add licensed_org relation
                if err := syncer.WriteObjectRelationship(ctx, listingResource, "licensed_org", "organization", license.OrganizationID.String()); err != nil {
                    slog.Error("failed to sync license to SpiceDB", "error", err)
                }

            case m.Op().Is(ent.OpDelete):
                // Remove licensed_org relation
                _ = syncer.DeleteObjectRelationship(ctx, listingResource, "licensed_org", "organization", license.OrganizationID.String())
            }

            return v, nil
        })
    }
}
```

## HTTP Middleware

### Authorization Middleware

```go
// authz/middleware.go
package authz

import (
    "context"
    "net/http"

    "github.com/go-chi/chi/v5"
)

// MiddlewareConfig configures the authorization middleware.
type MiddlewareConfig struct {
    Provider     Provider
    ResourceType ResourceType
    IDParam      string // URL parameter name for resource ID
    Action       Action
    Optional     bool // If true, allow unauthenticated access
}

// Middleware returns HTTP middleware that checks authorization.
func Middleware(cfg MiddlewareConfig) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            ctx := r.Context()

            // Get principal from context (set by auth middleware)
            principal, ok := PrincipalFromContext(ctx)
            if !ok {
                if cfg.Optional {
                    next.ServeHTTP(w, r)
                    return
                }
                http.Error(w, "Unauthorized", http.StatusUnauthorized)
                return
            }

            // Build resource
            var resource Resource
            if cfg.IDParam != "" {
                idStr := chi.URLParam(r, cfg.IDParam)
                id, err := uuid.Parse(idStr)
                if err != nil {
                    http.Error(w, "Invalid resource ID", http.StatusBadRequest)
                    return
                }
                resource = NewResourceWithID(cfg.ResourceType, id)
            } else {
                resource = NewResource(cfg.ResourceType)
            }

            // Check authorization
            allowed, err := cfg.Provider.Can(ctx, principal, cfg.Action, resource)
            if err != nil {
                http.Error(w, "Authorization error", http.StatusInternalServerError)
                return
            }

            if !allowed {
                http.Error(w, "Forbidden", http.StatusForbidden)
                return
            }

            next.ServeHTTP(w, r)
        })
    }
}

// RequirePermission creates middleware that requires a specific permission.
func RequirePermission(provider Provider, resourceType ResourceType, idParam string, action Action) func(http.Handler) http.Handler {
    return Middleware(MiddlewareConfig{
        Provider:     provider,
        ResourceType: resourceType,
        IDParam:      idParam,
        Action:       action,
    })
}
```

## Caching

### Cache Interface

```go
// spicedb/cache.go
package spicedb

import (
    "sync"
    "time"

    "github.com/plexusone/systemforge/authz"
)

// Cache caches permission check results.
type Cache interface {
    Get(principal authz.Principal, action authz.Action, resource authz.Resource) (bool, bool)
    Set(principal authz.Principal, action authz.Action, resource authz.Resource, allowed bool)
    Invalidate(resource authz.Resource)
    InvalidateAll()
}

// MemoryCache is an in-memory permission cache.
type MemoryCache struct {
    mu       sync.RWMutex
    entries  map[string]cacheEntry
    ttl      time.Duration
    maxSize  int
}

type cacheEntry struct {
    allowed   bool
    expiresAt time.Time
}

// NewMemoryCache creates a new in-memory cache.
func NewMemoryCache(ttl time.Duration, maxSize int) *MemoryCache {
    c := &MemoryCache{
        entries: make(map[string]cacheEntry),
        ttl:     ttl,
        maxSize: maxSize,
    }

    // Start cleanup goroutine
    go c.cleanup()

    return c
}

func (c *MemoryCache) cacheKey(principal authz.Principal, action authz.Action, resource authz.Resource) string {
    return fmt.Sprintf("%s:%s:%s:%s:%s",
        principal.Type, principal.ID,
        action,
        resource.Type, resource.ID,
    )
}

// Get retrieves a cached result.
func (c *MemoryCache) Get(principal authz.Principal, action authz.Action, resource authz.Resource) (bool, bool) {
    c.mu.RLock()
    defer c.mu.RUnlock()

    key := c.cacheKey(principal, action, resource)
    entry, ok := c.entries[key]
    if !ok || time.Now().After(entry.expiresAt) {
        return false, false
    }

    return entry.allowed, true
}

// Set stores a result in the cache.
func (c *MemoryCache) Set(principal authz.Principal, action authz.Action, resource authz.Resource, allowed bool) {
    c.mu.Lock()
    defer c.mu.Unlock()

    // Evict if at max size
    if len(c.entries) >= c.maxSize {
        c.evictOldest()
    }

    key := c.cacheKey(principal, action, resource)
    c.entries[key] = cacheEntry{
        allowed:   allowed,
        expiresAt: time.Now().Add(c.ttl),
    }
}

// Invalidate removes all cached entries for a resource.
func (c *MemoryCache) Invalidate(resource authz.Resource) {
    c.mu.Lock()
    defer c.mu.Unlock()

    prefix := fmt.Sprintf(":%s:%s", resource.Type, resource.ID)
    for key := range c.entries {
        if strings.HasSuffix(key, prefix) {
            delete(c.entries, key)
        }
    }
}

// InvalidateAll clears the entire cache.
func (c *MemoryCache) InvalidateAll() {
    c.mu.Lock()
    defer c.mu.Unlock()
    c.entries = make(map[string]cacheEntry)
}

func (c *MemoryCache) cleanup() {
    ticker := time.NewTicker(time.Minute)
    for range ticker.C {
        c.mu.Lock()
        now := time.Now()
        for key, entry := range c.entries {
            if now.After(entry.expiresAt) {
                delete(c.entries, key)
            }
        }
        c.mu.Unlock()
    }
}

func (c *MemoryCache) evictOldest() {
    var oldestKey string
    var oldestTime time.Time

    for key, entry := range c.entries {
        if oldestKey == "" || entry.expiresAt.Before(oldestTime) {
            oldestKey = key
            oldestTime = entry.expiresAt
        }
    }

    if oldestKey != "" {
        delete(c.entries, oldestKey)
    }
}
```

## Testing

### Test Utilities

```go
// spicedb/testing.go
package spicedb

import (
    "context"
    "testing"

    "github.com/ory/dockertest/v3"
)

// TestContainer manages a SpiceDB test container.
type TestContainer struct {
    pool     *dockertest.Pool
    resource *dockertest.Resource
    Endpoint string
    Token    string
}

// StartTestContainer starts a SpiceDB container for testing.
func StartTestContainer(t *testing.T) *TestContainer {
    t.Helper()

    pool, err := dockertest.NewPool("")
    if err != nil {
        t.Fatalf("Could not connect to docker: %v", err)
    }

    resource, err := pool.Run("authzed/spicedb", "latest", []string{
        "SPICEDB_GRPC_PRESHARED_KEY=testkey",
        "SPICEDB_DATASTORE_ENGINE=memory",
    })
    if err != nil {
        t.Fatalf("Could not start SpiceDB: %v", err)
    }

    endpoint := fmt.Sprintf("localhost:%s", resource.GetPort("50051/tcp"))

    // Wait for SpiceDB to be ready
    if err := pool.Retry(func() error {
        client, err := NewClient(Config{
            Endpoint: endpoint,
            Token:    "testkey",
            Insecure: true,
        })
        if err != nil {
            return err
        }
        defer client.Close()
        return nil
    }); err != nil {
        t.Fatalf("Could not connect to SpiceDB: %v", err)
    }

    t.Cleanup(func() {
        _ = pool.Purge(resource)
    })

    return &TestContainer{
        pool:     pool,
        resource: resource,
        Endpoint: endpoint,
        Token:    "testkey",
    }
}

// NewTestClient creates a client connected to the test container.
func (tc *TestContainer) NewTestClient() (*Client, error) {
    return NewClient(Config{
        Endpoint: tc.Endpoint,
        Token:    tc.Token,
        Insecure: true,
    })
}
```

### Conformance Tests

```go
// authz/providertest/providertest.go
package providertest

import (
    "context"
    "testing"

    "github.com/google/uuid"
    "github.com/plexusone/systemforge/authz"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

// RunConformanceTests runs the authorization provider conformance test suite.
func RunConformanceTests(t *testing.T, provider authz.Provider, syncer authz.Syncer) {
    ctx := context.Background()

    // Setup test data
    orgID := uuid.New()
    ownerID := uuid.New()
    adminID := uuid.New()
    memberID := uuid.New()
    outsiderID := uuid.New()

    org := authz.NewResourceWithID(authz.ResourceTypeOrganization, orgID)
    owner := authz.NewUserPrincipal(ownerID)
    admin := authz.NewUserPrincipal(adminID)
    member := authz.NewUserPrincipal(memberID)
    outsider := authz.NewUserPrincipal(outsiderID)

    // Create relationships
    require.NoError(t, syncer.WriteRelationship(ctx, org, "owner", owner))
    require.NoError(t, syncer.WriteRelationship(ctx, org, "admin", admin))
    require.NoError(t, syncer.WriteRelationship(ctx, org, "member", member))

    t.Run("OwnerCanManage", func(t *testing.T) {
        can, err := provider.Can(ctx, owner, authz.ActionManage, org)
        require.NoError(t, err)
        assert.True(t, can)
    })

    t.Run("OwnerCanDelete", func(t *testing.T) {
        can, err := provider.Can(ctx, owner, authz.ActionDelete, org)
        require.NoError(t, err)
        assert.True(t, can)
    })

    t.Run("AdminCanManage", func(t *testing.T) {
        can, err := provider.Can(ctx, admin, authz.ActionManage, org)
        require.NoError(t, err)
        assert.True(t, can)
    })

    t.Run("AdminCannotDelete", func(t *testing.T) {
        can, err := provider.Can(ctx, admin, authz.ActionDelete, org)
        require.NoError(t, err)
        assert.False(t, can)
    })

    t.Run("MemberCanView", func(t *testing.T) {
        can, err := provider.Can(ctx, member, authz.ActionRead, org)
        require.NoError(t, err)
        assert.True(t, can)
    })

    t.Run("MemberCannotManage", func(t *testing.T) {
        can, err := provider.Can(ctx, member, authz.ActionManage, org)
        require.NoError(t, err)
        assert.False(t, can)
    })

    t.Run("OutsiderCannotAccess", func(t *testing.T) {
        can, err := provider.Can(ctx, outsider, authz.ActionRead, org)
        require.NoError(t, err)
        assert.False(t, can)
    })

    t.Run("ListResources", func(t *testing.T) {
        resources, err := provider.ListResources(ctx, owner, authz.ResourceTypeOrganization, authz.ActionManage)
        require.NoError(t, err)
        assert.Len(t, resources, 1)
        assert.Equal(t, orgID, *resources[0].ID)
    })
}
```

## Deployment

### Docker Compose (Development)

```yaml
# docker-compose.yml
services:
  spicedb:
    image: authzed/spicedb:latest
    command: serve
    restart: unless-stopped
    ports:
      - "50051:50051"  # gRPC
      - "8080:8080"    # HTTP gateway
      - "9090:9090"    # Metrics
    environment:
      SPICEDB_GRPC_PRESHARED_KEY: ${SPICEDB_TOKEN:-devkey}
      SPICEDB_DATASTORE_ENGINE: postgres
      SPICEDB_DATASTORE_CONN_URI: postgres://postgres:postgres@postgres:5432/spicedb?sslmode=disable
    depends_on:
      postgres:
        condition: service_healthy

  postgres:
    image: postgres:16-alpine
    restart: unless-stopped
    ports:
      - "5432:5432"
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
      POSTGRES_DB: spicedb
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 5s
      timeout: 5s
      retries: 5

volumes:
  postgres_data:
```

### Environment Variables

```bash
# SpiceDB Configuration
SPICEDB_ENDPOINT=localhost:50051
SPICEDB_TOKEN=your-preshared-key
SPICEDB_INSECURE=false
SPICEDB_TIMEOUT=5s
SPICEDB_MAX_RETRIES=3

# Cache Configuration
AUTHZ_CACHE_ENABLED=true
AUTHZ_CACHE_TTL=5m
AUTHZ_CACHE_MAX_SIZE=10000
```

## Performance Benchmarks

```go
// spicedb/benchmark_test.go
func BenchmarkPermissionCheck(b *testing.B) {
    tc := StartTestContainer(b)
    client, _ := tc.NewTestClient()
    provider := NewProvider(client)

    // Setup
    ctx := context.Background()
    syncer := NewSyncer(client)
    orgID := uuid.New()
    userID := uuid.New()
    org := authz.NewResourceWithID(authz.ResourceTypeOrganization, orgID)
    user := authz.NewUserPrincipal(userID)
    _ = syncer.WriteRelationship(ctx, org, "member", user)

    b.ResetTimer()
    b.RunParallel(func(pb *testing.PB) {
        for pb.Next() {
            _, _ = provider.Can(ctx, user, authz.ActionRead, org)
        }
    })
}

func BenchmarkPermissionCheckCached(b *testing.B) {
    tc := StartTestContainer(b)
    client, _ := tc.NewTestClient()
    cache := NewMemoryCache(5*time.Minute, 10000)
    provider := NewProvider(client, WithCache(cache))

    // Setup
    ctx := context.Background()
    syncer := NewSyncer(client)
    orgID := uuid.New()
    userID := uuid.New()
    org := authz.NewResourceWithID(authz.ResourceTypeOrganization, orgID)
    user := authz.NewUserPrincipal(userID)
    _ = syncer.WriteRelationship(ctx, org, "member", user)

    // Warm cache
    _, _ = provider.Can(ctx, user, authz.ActionRead, org)

    b.ResetTimer()
    b.RunParallel(func(pb *testing.PB) {
        for pb.Next() {
            _, _ = provider.Can(ctx, user, authz.ActionRead, org)
        }
    })
}
```

## References

- [SpiceDB Documentation](https://authzed.com/docs)
- [authzed-go Client](https://github.com/authzed/authzed-go)
- [Zed Language Reference](https://authzed.com/docs/reference/schema-lang)
- [Google Zanzibar Paper](https://research.google/pubs/pub48190/)
