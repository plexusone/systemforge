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

	// Check roles in order of privilege; a principal holding several
	// relations reports the highest.
	for _, role := range orgRoles {
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
	// Every membership grants list, collaborators included, so it is the
	// membership test; view excludes collaborators.
	return p.client.Check(ctx, &CheckRequest{
		ResourceType: TypeOrganization,
		ResourceID:   orgID.String(),
		Permission:   PermList,
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

// BaseSchema is the SystemForge base SpiceDB schema.
//
// Deprecated: use authz.BaseSpiceDBSchema, or compose a deployment schema
// with authz.VocabularyRegistry.ComposeSpiceDBSchema. BaseSchema is the
// same schema; it previously diverged (no editor role, and members held
// edit), so the providers disagreed.
const BaseSchema = authz.BaseSpiceDBSchema

// ResourceSchema returns a SpiceDB schema definition for a custom resource
// type that accepts collaborators (ADR-008). It declares the resource-role
// ladder (viewer, contributor, maintainer) and attaches the resource to its
// organization, so members keep their organization-wide access and a
// collaborator has only the direct grant. Applications prefix resourceType
// with their identifier ("myapp_project") and write the fragment into their
// vocabulary.
func ResourceSchema(resourceType string) string {
	return fmt.Sprintf(`
definition %s {
    relation org: organization
    relation viewer: principal
    relation contributor: principal
    relation maintainer: principal

    permission view = viewer + contributor + maintainer + org->view
    permission edit = contributor + maintainer + org->edit
    permission manage = maintainer + org->manage
}
`, resourceType)
}
