package spicedb

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/plexusone/systemforge/authz"
)

// Provider implements the authz.Authorizer interface using SpiceDB.
type Provider struct {
	client *Client
}

// NewProvider creates a new SpiceDB authorization provider.
func NewProvider(client *Client) *Provider {
	return &Provider{client: client}
}

// Client returns the underlying SpiceDB client for advanced operations.
func (p *Provider) Client() *Client {
	return p.client
}

// Can checks if a principal can perform an action on a resource.
func (p *Provider) Can(ctx context.Context, principal authz.Principal, action authz.Action, resource authz.Resource) (bool, error) {
	resourceID := ""
	if resource.ID != nil {
		resourceID = resource.ID.String()
	}

	return p.client.Check(ctx, &CheckRequest{
		ResourceType: string(resource.Type),
		ResourceID:   resourceID,
		Permission:   string(action),
		SubjectType:  TypePrincipal,
		SubjectID:    principal.ID.String(),
	})
}

// CanAll checks if a principal can perform all specified actions on a resource.
func (p *Provider) CanAll(ctx context.Context, principal authz.Principal, actions []authz.Action, resource authz.Resource) (bool, error) {
	for _, action := range actions {
		allowed, err := p.Can(ctx, principal, action, resource)
		if err != nil {
			return false, err
		}
		if !allowed {
			return false, nil
		}
	}
	return true, nil
}

// CanAny checks if a principal can perform any of the specified actions on a resource.
func (p *Provider) CanAny(ctx context.Context, principal authz.Principal, actions []authz.Action, resource authz.Resource) (bool, error) {
	for _, action := range actions {
		allowed, err := p.Can(ctx, principal, action, resource)
		if err != nil {
			return false, err
		}
		if allowed {
			return true, nil
		}
	}
	return false, nil
}

// Filter returns only the resources the principal can access with the given action.
func (p *Provider) Filter(ctx context.Context, principal authz.Principal, action authz.Action, resources []authz.Resource) ([]authz.Resource, error) {
	var allowed []authz.Resource
	for _, resource := range resources {
		can, err := p.Can(ctx, principal, action, resource)
		if err != nil {
			return nil, err
		}
		if can {
			allowed = append(allowed, resource)
		}
	}
	return allowed, nil
}

// CanForOrg checks permission scoped to a specific organization.
func (p *Provider) CanForOrg(ctx context.Context, principal authz.Principal, orgID uuid.UUID, action authz.Action, resource authz.Resource) (bool, error) {
	// First check if principal is a member of the org
	isMember, err := p.IsMember(ctx, principal, orgID)
	if err != nil {
		return false, err
	}
	if !isMember {
		return false, nil
	}

	// Then check the specific permission on the resource
	return p.Can(ctx, principal, action, resource)
}

// GetRole returns the principal's role in an organization.
func (p *Provider) GetRole(ctx context.Context, principal authz.Principal, orgID uuid.UUID) (string, error) {
	orgIDStr := orgID.String()

	// Check roles in order of privilege
	roles := []string{RelOwner, RelAdmin, RelMember, RelViewer}
	for _, role := range roles {
		hasRole, err := p.client.Check(ctx, &CheckRequest{
			ResourceType: TypeOrganization,
			ResourceID:   orgIDStr,
			Permission:   role,
			SubjectType:  TypePrincipal,
			SubjectID:    principal.ID.String(),
		})
		if err != nil {
			return "", err
		}
		if hasRole {
			return role, nil
		}
	}
	return "", nil
}

// IsMember checks if a principal is a member of an organization.
func (p *Provider) IsMember(ctx context.Context, principal authz.Principal, orgID uuid.UUID) (bool, error) {
	// Check if principal has any membership relation (view permission implies membership)
	return p.client.Check(ctx, &CheckRequest{
		ResourceType: TypeOrganization,
		ResourceID:   orgID.String(),
		Permission:   PermView,
		SubjectType:  TypePrincipal,
		SubjectID:    principal.ID.String(),
	})
}

// IsPlatformAdmin checks if a principal has platform-wide admin access.
func (p *Provider) IsPlatformAdmin(ctx context.Context, principal authz.Principal) (bool, error) {
	// Check for platform-level admin permission
	return p.client.Check(ctx, &CheckRequest{
		ResourceType: "platform",
		ResourceID:   "global",
		Permission:   RelAdmin,
		SubjectType:  TypePrincipal,
		SubjectID:    principal.ID.String(),
	})
}

// AddRelationship adds a relationship between a subject and a resource.
func (p *Provider) AddRelationship(ctx context.Context, subjectType, subjectID, relation, resourceType, resourceID string) error {
	return p.client.WriteRelationship(ctx, &Relationship{
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Relation:     relation,
		SubjectType:  subjectType,
		SubjectID:    subjectID,
	})
}

// RemoveRelationship removes a relationship between a subject and a resource.
func (p *Provider) RemoveRelationship(ctx context.Context, subjectType, subjectID, relation, resourceType, resourceID string) error {
	return p.client.DeleteRelationship(ctx, &Relationship{
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Relation:     relation,
		SubjectType:  subjectType,
		SubjectID:    subjectID,
	})
}

// AddOrgMember adds a principal as a member of an organization with a specific role.
func (p *Provider) AddOrgMember(ctx context.Context, principalID string, orgID uuid.UUID, role string) error {
	return p.AddRelationship(ctx, TypePrincipal, principalID, role, TypeOrganization, orgID.String())
}

// RemoveOrgMember removes a principal from an organization.
func (p *Provider) RemoveOrgMember(ctx context.Context, principalID string, orgID uuid.UUID, role string) error {
	return p.RemoveRelationship(ctx, TypePrincipal, principalID, role, TypeOrganization, orgID.String())
}

// Close closes the provider and underlying client.
func (p *Provider) Close() error {
	return p.client.Close()
}

// Verify interface compliance at compile time.
var (
	_ authz.Authorizer         = (*Provider)(nil)
	_ authz.OrgAuthorizer      = (*Provider)(nil)
	_ authz.PlatformAuthorizer = (*Provider)(nil)
)

// BaseSchema provides a minimal SpiceDB schema for SystemForge applications.
// Applications can extend this with their own resource types.
const BaseSchema = `
definition principal {
    // Manager relations (ADR-005): a guardian or educator manages this
    // principal. Applications add domain permissions in their facets.
    relation guardian: principal
    relation educator: principal

    permission manage_account     = guardian
    permission manage_credentials = guardian + educator
    permission view_profile       = guardian + educator
    permission manage_managers    = guardian
}

definition organization {
    relation owner: principal
    relation admin: principal
    relation member: principal
    relation viewer: principal

    // Owners and admins can manage the organization
    permission manage = owner + admin

    // Anyone in the org can view it
    permission view = manage + member + viewer

    // Editors can edit (owners, admins, members)
    permission edit = manage + member

    // Only owners can delete
    permission delete = owner
}

definition platform {
    relation admin: principal

    // Platform admins have all permissions
    permission manage = admin
    permission view = admin
}
`

// ResourceSchema returns a SpiceDB schema definition for a custom resource type.
// This can be used to define app-specific resources that integrate with organizations.
func ResourceSchema(resourceType string) string {
	return fmt.Sprintf(`
definition %s {
    relation org: organization
    relation owner: principal
    relation editor: principal
    relation viewer: principal

    // Owners can do everything
    permission manage = owner + org->admin

    // Editors can edit (includes owners and org admins)
    permission edit = manage + editor + org->member

    // Viewers can view (includes editors and org viewers)
    permission view = edit + viewer + org->viewer

    // Only owners and org admins can delete
    permission delete = owner + org->admin
}
`, resourceType)
}
