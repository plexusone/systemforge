package spicedb

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/google/uuid"
	"github.com/plexusone/systemforge/authz"
)

// Provider implements the authz.Authorizer interface using SpiceDB.
type Provider struct {
	client *Client
	grants authz.ResourceGranter
}

// ProviderOption configures a Provider.
type ProviderOption func(*Provider)

// WithResourceGrants gives the provider the store of resource grants
// (ADR-008). The store owns what the graph cannot: the collaborator
// membership rows behind the "orgs" claim, the last-grant test and the
// access-change records; it mirrors grants and memberships into the graph
// through this package's Syncer (resourcegrant.WithAuthzSyncer). The
// provider delegates the grant operations to it and answers ListResources
// from the engine with LookupResources.
func WithResourceGrants(g authz.ResourceGranter) ProviderOption {
	return func(p *Provider) { p.grants = g }
}

// NewProvider creates a new SpiceDB authorization provider.
func NewProvider(client *Client, opts ...ProviderOption) *Provider {
	p := &Provider{client: client}
	for _, o := range opts {
		o(p)
	}
	return p
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

// ErrNoResourceGrants is returned by the grant operations of a Provider
// built without WithResourceGrants.
var ErrNoResourceGrants = errors.New("spicedb: resource grants are not configured (use WithResourceGrants)")

// GrantResourceRole gives the principal a role on the resource through the
// configured store, which writes the relationship to the graph. Granting
// to a principal with no membership in the resource's organization adds a
// collaborator membership.
func (p *Provider) GrantResourceRole(ctx context.Context, principalID uuid.UUID, resource authz.ResourceRef, role string, grantedBy uuid.UUID) error {
	if p.grants == nil {
		return ErrNoResourceGrants
	}
	return p.grants.GrantResourceRole(ctx, principalID, resource, role, grantedBy)
}

// RevokeResourceRole removes the principal's grant on the resource;
// revoking a collaborator's last grant removes the membership.
func (p *Provider) RevokeResourceRole(ctx context.Context, principalID uuid.UUID, resource authz.ResourceRef) error {
	if p.grants == nil {
		return ErrNoResourceGrants
	}
	return p.grants.RevokeResourceRole(ctx, principalID, resource)
}

// ListResourceGrants lists the grants on one resource, highest role first.
func (p *Provider) ListResourceGrants(ctx context.Context, resource authz.ResourceRef) ([]authz.Grant, error) {
	if p.grants == nil {
		return nil, ErrNoResourceGrants
	}
	return p.grants.ListResourceGrants(ctx, resource)
}

// ListResources returns the resources of resourceType the principal holds
// permission (view, edit or manage) on, by SpiceDB's LookupResources. The
// lookup follows every relationship the schema expresses, so an
// organization member's access through the "org" relation is in IDs and
// OrganizationIDs is empty.
func (p *Provider) ListResources(ctx context.Context, principalID uuid.UUID, resourceType string, permission authz.Action) (authz.ResourceSet, error) {
	if !authz.IsResourcePermission(permission) {
		return authz.ResourceSet{}, fmt.Errorf("%w: %q is not view, edit or manage", authz.ErrInvalidResource, permission)
	}
	ids, err := p.client.LookupResources(ctx, &LookupResourcesRequest{
		ResourceType: resourceType,
		Permission:   string(permission),
		SubjectType:  TypePrincipal,
		SubjectID:    principalID.String(),
	})
	if err != nil {
		return authz.ResourceSet{}, err
	}
	slices.Sort(ids)
	if ids == nil {
		ids = []string{}
	}
	return authz.ResourceSet{IDs: ids}, nil
}

// Verify interface compliance at compile time.
var (
	_ authz.ResourceGranter    = (*Provider)(nil)
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
// collaborator has only the direct grant. An optional owner relation holds
// the resource's creator. Applications prefix resourceType with their
// identifier ("myapp_project") and write the fragment into their
// vocabulary.
func ResourceSchema(resourceType string) string {
	return fmt.Sprintf(`
definition %s {
    relation org: organization
    relation owner: principal
    relation viewer: principal
    relation contributor: principal
    relation maintainer: principal

    // The owner and maintainers manage; organization admins do too.
    permission manage = owner + maintainer + org->manage

    // Contributors edit, and so does anyone who manages.
    permission edit = manage + contributor + org->edit

    // Viewers view, and so does anyone who edits or is a member.
    permission view = edit + viewer + org->view

    // Only the owner and organization managers delete.
    permission delete = owner + org->manage
}
`, resourceType)
}
