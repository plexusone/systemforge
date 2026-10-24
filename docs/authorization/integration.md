# Authorization Integration Guide

This guide covers integrating SpiceDB authorization with your SystemForge application.

For applications that expose SQL-like or domain-specific query languages, see
[Query Policy Engines](query-policy-engines.md). That pattern keeps parsing and
AST validation in the query language while using SystemForge and SpiceDB for
principal/action/resource authorization decisions.

## Architecture Overview

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│   API Handler    │────▶│   AuthZ Check    │────▶│     SpiceDB      │
└──────────────────┘     └──────────────────┘     └──────────────────┘
         │                                                  ▲
         ▼                                                  │
┌──────────────────┐     ┌──────────────────┐              │
│ Identity Service │────▶│  Authz Syncer    │──────────────┘
└──────────────────┘     └──────────────────┘
```

- **API Handlers** check permissions before performing operations
- **Identity Services** sync changes to SpiceDB via the syncer
- **SpiceDB** stores relationships and evaluates permissions

## Setup

### 1. Initialize SpiceDB Client

```go
package main

import (
    "context"
    "log/slog"

    "github.com/plexusone/systemforge/authz/rebac/spicedb"
)

func initAuthz(ctx context.Context) (*spicedb.Client, *spicedb.Provider, *spicedb.Syncer, error) {
    // Create client
    client, err := spicedb.NewClient(ctx, spicedb.Config{
        Mode:     "remote",
        Endpoint: os.Getenv("SPICEDB_ENDPOINT"),
        Token:    os.Getenv("SPICEDB_TOKEN"),
    }, slog.Default())
    if err != nil {
        return nil, nil, nil, err
    }

    // Write schema on startup (idempotent)
    schema := spicedb.BaseSchema + spicedb.ResourceSchema("project")
    if err := client.WriteSchema(ctx, schema); err != nil {
        client.Close()
        return nil, nil, nil, err
    }

    // Create provider and syncer
    provider := spicedb.NewProvider(client)
    syncer := spicedb.NewSyncer(client)

    return client, provider, syncer, nil
}
```

### 2. Wire Identity Services

```go
func initServices(entClient *ent.Client, syncer authz.RelationshipSyncer) {
    // Organization service with authz sync
    orgService := organization.NewService(
        entClient,
        organization.WithAuthzSyncer(syncer),
        organization.WithSyncMode(authz.SyncModeStrict),
        organization.WithLogger(slog.Default()),
    )

    // Principal service with authz sync
    principalService := principal.NewService(
        entClient,
        principal.WithAuthzSyncer(syncer),
        principal.WithSyncMode(authz.SyncModeStrict),
        principal.WithLogger(slog.Default()),
    )
}
```

## Permission Checks in Handlers

### Basic Permission Check

```go
func (h *Handler) GetProject(ctx context.Context, req *GetProjectRequest) (*Project, error) {
    // Get principal from context (set by auth middleware)
    principal := getPrincipalFromContext(ctx)

    // Check permission
    canView, err := h.provider.Can(ctx, principal, "view", authz.Resource{
        Type: "project",
        ID:   &req.ProjectID,
    })
    if err != nil {
        return nil, fmt.Errorf("permission check failed: %w", err)
    }
    if !canView {
        return nil, ErrForbidden
    }

    // Proceed with operation
    return h.projectRepo.GetByID(ctx, req.ProjectID)
}
```

### Organization-Scoped Checks

```go
func (h *Handler) CreateProject(ctx context.Context, req *CreateProjectRequest) (*Project, error) {
    principal := getPrincipalFromContext(ctx)

    // Check if user can create in this org
    canCreate, err := h.provider.CanForOrg(ctx, principal, req.OrgID, "edit", authz.Resource{
        Type: "organization",
        ID:   &req.OrgID,
    })
    if err != nil {
        return nil, err
    }
    if !canCreate {
        return nil, ErrForbidden
    }

    // Create project
    project, err := h.projectRepo.Create(ctx, req)
    if err != nil {
        return nil, err
    }

    // Sync to SpiceDB
    h.syncer.AddRelationship(ctx,
        spicedb.TypePrincipal, principal.ID.String(),
        "owner",
        "project", project.ID.String(),
    )

    // Link to org
    h.syncer.AddRelationship(ctx,
        "organization", req.OrgID.String(),
        "org",
        "project", project.ID.String(),
    )

    return project, nil
}
```

### Multiple Permission Checks

```go
// Check if user can perform ANY of the actions
canAny, err := h.provider.CanAny(ctx, principal,
    []authz.Action{"edit", "manage"},
    resource,
)

// Check if user can perform ALL of the actions
canAll, err := h.provider.CanAll(ctx, principal,
    []authz.Action{"view", "edit"},
    resource,
)
```

### Filtering Resources

```go
func (h *Handler) ListProjects(ctx context.Context, req *ListProjectsRequest) ([]*Project, error) {
    principal := getPrincipalFromContext(ctx)

    // Get all projects (from DB)
    allProjects, err := h.projectRepo.ListByOrg(ctx, req.OrgID)
    if err != nil {
        return nil, err
    }

    // Convert to authz resources
    resources := make([]authz.Resource, len(allProjects))
    for i, p := range allProjects {
        id := p.ID
        resources[i] = authz.Resource{Type: "project", ID: &id}
    }

    // Filter to only those the user can view
    allowed, err := h.provider.Filter(ctx, principal, "view", resources)
    if err != nil {
        return nil, err
    }

    // Map back to projects
    allowedIDs := make(map[uuid.UUID]bool)
    for _, r := range allowed {
        allowedIDs[*r.ID] = true
    }

    var result []*Project
    for _, p := range allProjects {
        if allowedIDs[p.ID] {
            result = append(result, p)
        }
    }

    return result, nil
}
```

## Authorization Middleware

### HTTP Middleware

```go
func RequirePermission(provider authz.Authorizer, resourceType string, action string) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            ctx := r.Context()
            principal := getPrincipalFromContext(ctx)
            resourceID := getResourceIDFromRequest(r)

            can, err := provider.Can(ctx, principal, authz.Action(action), authz.Resource{
                Type: authz.ResourceType(resourceType),
                ID:   &resourceID,
            })
            if err != nil {
                http.Error(w, "authorization error", http.StatusInternalServerError)
                return
            }
            if !can {
                http.Error(w, "forbidden", http.StatusForbidden)
                return
            }

            next.ServeHTTP(w, r)
        })
    }
}

// Usage
router.With(RequirePermission(provider, "project", "edit")).
    Put("/projects/{id}", updateProjectHandler)
```

### Role-Based Shortcuts

```go
func (h *Handler) requireOrgAdmin(ctx context.Context, orgID uuid.UUID) error {
    principal := getPrincipalFromContext(ctx)

    role, err := h.provider.GetRole(ctx, principal, orgID)
    if err != nil {
        return err
    }

    if role != spicedb.RelOwner && role != spicedb.RelAdmin {
        return ErrForbidden
    }

    return nil
}
```

## Common Patterns

### Signup Flow

```go
func (s *SignupService) Signup(ctx context.Context, input SignupInput) (*User, error) {
    // Create principal (synced to SpiceDB automatically)
    principal, err := s.principalService.CreateHuman(ctx, principal.CreateHumanInput{
        Email:       input.Email,
        DisplayName: input.DisplayName,
    })
    if err != nil {
        return nil, err
    }

    // Create personal organization (synced to SpiceDB automatically)
    org, err := s.orgService.CreatePersonalOrg(ctx, organization.CreatePersonalOrgInput{
        Name:             input.DisplayName,
        Slug:             generateSlug(input.Email),
        OwnerPrincipalID: principal.ID,
    })
    if err != nil {
        return nil, err
    }

    // User is now org owner with full permissions
    return &User{Principal: principal, PersonalOrg: org}, nil
}
```

### Invite Flow

```go
func (s *InviteService) AcceptInvite(ctx context.Context, token string) error {
    invite, err := s.inviteRepo.GetByToken(ctx, token)
    if err != nil {
        return err
    }

    // Add member to org (synced to SpiceDB automatically)
    _, err = s.orgService.AddMember(ctx, organization.AddMemberInput{
        OrganizationID: invite.OrgID,
        PrincipalID:    invite.InviteeID,
        Role:           invite.Role,
    })

    return err
}
```

### Resource Deletion

```go
func (h *Handler) DeleteProject(ctx context.Context, req *DeleteRequest) error {
    principal := getPrincipalFromContext(ctx)

    // Check delete permission
    canDelete, err := h.provider.Can(ctx, principal, "delete", authz.Resource{
        Type: "project",
        ID:   &req.ProjectID,
    })
    if err != nil || !canDelete {
        return ErrForbidden
    }

    // Delete from DB
    if err := h.projectRepo.Delete(ctx, req.ProjectID); err != nil {
        return err
    }

    // Clean up SpiceDB relationships (optional - SpiceDB handles orphans gracefully)
    // This is only needed if you want immediate cleanup
    h.syncer.RemoveRelationship(ctx,
        spicedb.TypePrincipal, principal.ID.String(),
        "owner",
        "project", req.ProjectID.String(),
    )

    return nil
}
```

## Error Handling

### Sync Failures

Revocations and grants fail differently, so that the graph never grants
more than the database records.

A revocation removes the relationship inside its database transaction,
before the commit, and rolls the transaction back when the graph refuses.
The caller gets the error in either sync mode and nothing has changed, so
it retries the same call; removing a relationship that is already gone
succeeds.

```go
// Removing a member: the graph is changed first, then the database.
if err := orgs.RemoveMember(ctx, orgID, principalID); err != nil {
    // Nothing was removed; retry later.
    return err
}
```

A grant commits first and writes the relationship after. `SyncModeStrict`
returns a failed write to the caller; `SyncModeEventual`, the default, logs
it and lets the operation succeed:

```go
// In service code, after the grant committed
if syncErr := s.syncer.AddOrgMembership(ctx, principalID, orgID, role); syncErr != nil {
    if s.syncMode == authz.SyncModeStrict {
        return nil, fmt.Errorf("authz sync failed: %w", syncErr)
    }
    s.logger.Warn("authz sync failed",
        "principal_id", principalID,
        "org_id", orgID,
        "error", syncErr,
    )
}
```

Either way the access is missing rather than extra. In mode `rebac` the graph
reconciler of `authz/mode` writes it on its next run, and also removes
anything a revocation left behind when its commit failed after the graph
change; see
[Configuring the authorization mode](../guides/authorization-mode.md#keeping-the-graph-consistent-under-rebac).
A deployment that builds its syncer without `authz/mode` can run the
reconciler itself:

```go
rc := mode.NewReconciler(db, spicedbClient, mode.WithReconcileRegistry(registry))
go func() {
    schedule := mode.ReconcileSchedule{OnStartup: true, Interval: 15 * time.Minute, Jitter: time.Minute}
    if err := rc.Run(ctx, schedule); err != nil {
        logger.Error("graph reconciler stopped", "error", err)
    }
}()
```

## Testing

### Unit Tests with No-Op Syncer

```go
func TestOrganizationService(t *testing.T) {
    // Use no-op syncer for unit tests
    service := organization.NewService(
        entClient,
        organization.WithAuthzSyncer(noop.NewSyncer()),
    )

    // Test service logic without SpiceDB
}
```

### Integration Tests with Embedded SpiceDB

```go
//go:build integration

func TestAuthzIntegration(t *testing.T) {
    ctx := context.Background()

    client, _ := spicedb.NewClient(ctx, spicedb.DefaultConfig(), nil)
    defer client.Close()

    client.WriteSchema(ctx, spicedb.BaseSchema)

    syncer := spicedb.NewSyncer(client)
    provider := spicedb.NewProvider(client)

    // Test full flow
    orgID := uuid.New()
    ownerID := uuid.New()

    syncer.RegisterOrganization(ctx, orgID, ownerID)

    canManage, _ := provider.Can(ctx, authz.Principal{ID: ownerID}, "manage",
        authz.Resource{Type: "organization", ID: &orgID})

    assert.True(t, canManage)
}
```

## Performance Considerations

1. **Batch Relationship Writes**: Use `WriteRelationships()` for multiple changes
2. **Cache Permission Results**: For frequently-checked permissions
3. **Use LookupResources**: Instead of checking each resource individually
4. **Minimize Round Trips**: Group permission checks where possible

## Next Steps

- [SpiceDB Setup](spicedb-setup.md) - Deployment configuration
- [SpiceDB Schema](spicedb-schema.md) - Understanding the schema
