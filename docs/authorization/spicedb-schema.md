# SpiceDB Schema Guide

This guide explains the SpiceDB authorization schema used in SystemForge.

## Base Schema

SystemForge provides a base schema for common authorization patterns:

```zed
definition principal {}

definition organization {
    relation owner: principal
    relation admin: principal
    relation member: principal
    relation collaborator: principal

    // Owners and admins can manage the organization
    permission manage = owner + admin

    // Owners and admins edit; members contribute and view
    permission edit = manage
    permission contribute = edit + member
    permission view = contribute

    // Every membership, collaborators included, can see the organization
    permission list = view + collaborator

    // Only owners can delete
    permission delete = owner
}

definition platform {
    relation admin: principal

    // Platform admins have all permissions
    permission manage = admin
    permission view = admin
}
```

### Entity Types

| Type | Description |
|------|-------------|
| `principal` | A user, application, agent, or service that can perform actions |
| `organization` | A tenant or workspace containing resources |
| `platform` | The global platform (singleton: `platform:global`) |

### Organization Roles

| Role | Relations | Permissions |
|------|-----------|-------------|
| **Owner** | `owner` | manage, edit, contribute, view, list, delete |
| **Admin** | `admin` | manage, edit, contribute, view, list |
| **Member** | `member` | contribute, view, list |
| **Collaborator** | `collaborator` | list |

`editor` and `viewer` are not organization roles. Access to one resource
without membership of the organization is a collaborator holding a resource
role (`viewer`, `contributor` or `maintainer`) on that resource; see
[Authorization conventions](../authz-conventions.md#resource-roles).

### Permission Inheritance

```
owner
  └── manage (owner + admin)
        └── edit (manage)
              └── contribute (edit + member)
                    └── view (contribute)
                          └── list (view + collaborator)
```

## Custom Resource Schemas

Use `ResourceSchema()` to generate schemas for your application's resources:

```go
// Generate schema for "project" resource type
schema := spicedb.ResourceSchema("project")
```

Query engines and analytics products often need more granular resources than a
single project/document type. Model queryable objects explicitly, for example
`analytics_source`, `analytics_dataset`, and `analytics_field`, so field-level
policy checks use concrete SpiceDB tuples. See
[Query Policy Engines](query-policy-engines.md) for the recommended pattern.

This produces:

```zed
definition project {
    relation org: organization
    relation owner: principal
    relation viewer: principal
    relation contributor: principal
    relation maintainer: principal

    // The owner and maintainers manage; organization admins do too
    permission manage = owner + maintainer + org->manage

    // Contributors edit, and so does anyone who manages
    permission edit = manage + contributor + org->edit

    // Viewers view, and so does anyone who edits or is a member
    permission view = edit + viewer + org->view

    // Only the owner and organization managers delete
    permission delete = owner + org->manage
}
```

### Resource Permission Model

| Permission | Who Has Access |
|------------|----------------|
| `manage` | Resource owner, maintainers, org admins and owners |
| `edit` | Manage + contributors + org admins and owners |
| `view` | Edit + viewers + org members |
| `delete` | Resource owner + org admins and owners |

### Using Custom Resources

```go
// Write combined schema
fullSchema := spicedb.BaseSchema + spicedb.ResourceSchema("project")
if err := client.WriteSchema(ctx, fullSchema); err != nil {
    return err
}

// Create a project owned by a user in an organization
client.WriteRelationship(ctx, &spicedb.Relationship{
    ResourceType: "project",
    ResourceID:   projectID.String(),
    Relation:     "owner",
    SubjectType:  "principal",
    SubjectID:    userID.String(),
})

// Link project to organization
client.WriteRelationship(ctx, &spicedb.Relationship{
    ResourceType: "project",
    ResourceID:   projectID.String(),
    Relation:     "org",
    SubjectType:  "organization",
    SubjectID:    orgID.String(),
})
```

## Relationship Types

### Direct Relationships

A principal has a direct relationship to a resource:

```
organization:acme#owner@principal:user-123
```

### Computed Permissions

Permissions can be computed from relationships:

```zed
permission view = contribute
```

If a principal has `manage` permission (via `owner` or `admin` relation), they automatically have `view`.

### Organization-Scoped Access

Resources linked to organizations inherit permissions:

```zed
definition project {
    relation org: organization
    permission view = ... + org->view
}
```

Organization members automatically get view access to projects in that org.
A collaborator does not: the organization grants a collaborator only
`list`, so a collaborator reaches a project only through a resource role
on it.

## Common Patterns

### Personal Organizations

Every user has a personal organization where they are the owner:

```go
// On user signup
syncer.RegisterOrganization(ctx, personalOrgID, userID)
```

### Team Organizations

Team organizations have multiple members:

```go
// Create team org with creator as owner
syncer.RegisterOrganization(ctx, teamOrgID, creatorID)

// Invite members
syncer.AddOrgMembership(ctx, inviteeID, teamOrgID, "member")

// Promote to admin
syncer.UpdateOrgMembership(ctx, inviteeID, teamOrgID, "member", "admin")
```

### Platform Administrators

Platform admins have elevated access across all organizations:

```go
syncer.SetPlatformAdmin(ctx, adminID, true)

// Check if user is platform admin
isAdmin, _ := provider.IsPlatformAdmin(ctx, authz.Principal{ID: adminID})
```

### Hierarchical Resources

For nested resources (e.g., projects contain tasks):

```zed
definition task {
    relation project: project
    relation assignee: principal

    permission edit = assignee + project->edit
    permission view = edit + project->view
}
```

## Best Practices

### 1. Use Organization Scoping

Always link resources to organizations for consistent access patterns:

```zed
definition document {
    relation org: organization  // Always include
    relation owner: principal
    // ...
}
```

### 2. Follow Least Privilege

Start with minimal permissions and add explicitly:

```go
// Add as a collaborator first, with a resource role on what they need
syncer.AddOrgMembership(ctx, userID, orgID, "collaborator")

// Promote later if needed
syncer.UpdateOrgMembership(ctx, userID, orgID, "collaborator", "member")
```

### 3. Use Consistent Role Names

Stick to the standard roles:

- `owner` - Full control including deletion
- `admin` - Management except deletion
- `member` - Standard access
- `collaborator` - Access to individual resources only

### 4. Check Permissions at API Boundaries

```go
func (h *Handler) UpdateProject(ctx context.Context, req *UpdateRequest) error {
    principal := getPrincipalFromContext(ctx)

    canEdit, err := h.provider.Can(ctx, principal, "edit", authz.Resource{
        Type: "project",
        ID:   &req.ProjectID,
    })
    if err != nil {
        return err
    }
    if !canEdit {
        return ErrForbidden
    }

    // Proceed with update
}
```

## Debugging

### Read Current Schema

```go
schema, err := client.ReadSchema(ctx)
fmt.Println(schema)
```

### Check Relationships

Use the SpiceDB CLI or API to inspect relationships:

```bash
# With zed CLI
zed relationship read organization:acme
```

### Test Permission Checks

```go
// Quick permission test
can, _ := provider.Can(ctx, principal, "edit", resource)
log.Printf("Principal %s can edit %s: %v", principal.ID, resource.ID, can)
```

## Next Steps

- [Integration Guide](integration.md) - Detailed integration patterns
- [SpiceDB Setup](spicedb-setup.md) - Deployment configuration
