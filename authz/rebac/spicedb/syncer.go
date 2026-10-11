package spicedb

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/plexusone/systemforge/authz"
)

// Syncer implements RelationshipSyncer using SpiceDB as the authorization backend.
type Syncer struct {
	client *Client
}

// NewSyncer creates a new SpiceDB-backed relationship syncer.
func NewSyncer(client *Client) *Syncer {
	return &Syncer{client: client}
}

// AddOrgMembership adds a principal's membership in an organization.
func (s *Syncer) AddOrgMembership(ctx context.Context, principalID, orgID uuid.UUID, role string) error {
	return s.client.WriteRelationship(ctx, &Relationship{
		ResourceType: TypeOrganization,
		ResourceID:   orgID.String(),
		Relation:     role,
		SubjectType:  TypePrincipal,
		SubjectID:    principalID.String(),
	})
}

// RemoveOrgMembership removes a principal's membership from an organization.
func (s *Syncer) RemoveOrgMembership(ctx context.Context, principalID, orgID uuid.UUID, role string) error {
	return s.client.DeleteRelationship(ctx, &Relationship{
		ResourceType: TypeOrganization,
		ResourceID:   orgID.String(),
		Relation:     role,
		SubjectType:  TypePrincipal,
		SubjectID:    principalID.String(),
	})
}

// UpdateOrgMembership changes a principal's role in an organization.
// This is implemented as an atomic batch operation: remove old role, add new role.
func (s *Syncer) UpdateOrgMembership(ctx context.Context, principalID, orgID uuid.UUID, oldRole, newRole string) error {
	if oldRole == newRole {
		return nil
	}

	// Use batch write for atomicity
	orgIDStr := orgID.String()
	principalIDStr := principalID.String()

	// Delete old relationship and create new one
	if err := s.client.DeleteRelationship(ctx, &Relationship{
		ResourceType: TypeOrganization,
		ResourceID:   orgIDStr,
		Relation:     oldRole,
		SubjectType:  TypePrincipal,
		SubjectID:    principalIDStr,
	}); err != nil {
		return fmt.Errorf("failed to remove old role: %w", err)
	}

	if err := s.client.WriteRelationship(ctx, &Relationship{
		ResourceType: TypeOrganization,
		ResourceID:   orgIDStr,
		Relation:     newRole,
		SubjectType:  TypePrincipal,
		SubjectID:    principalIDStr,
	}); err != nil {
		return fmt.Errorf("failed to add new role: %w", err)
	}

	return nil
}

// RegisterPrincipal creates a principal entity in SpiceDB.
// SpiceDB doesn't require explicit entity creation - entities are created implicitly
// when relationships are added. This is a no-op but kept for interface compliance.
func (s *Syncer) RegisterPrincipal(_ context.Context, _ uuid.UUID) error {
	// SpiceDB creates entities implicitly when relationships are created.
	// No explicit registration needed.
	return nil
}

// UnregisterPrincipal removes every base-schema relationship involving a
// principal: its organization memberships, its platform administration,
// the managers of the principal, and the principals it manages.
// Relationships an application's own definitions hold to the principal are
// the application's to remove. Every deletion is attempted, and the
// failures are returned together.
func (s *Syncer) UnregisterPrincipal(ctx context.Context, principalID uuid.UUID) error {
	id := principalID.String()
	return s.deleteAll(ctx, "unregister principal "+id, []*RelationshipFilter{
		{ResourceType: TypeOrganization, SubjectType: TypePrincipal, SubjectID: id},
		{ResourceType: "platform", SubjectType: TypePrincipal, SubjectID: id},
		{ResourceType: TypePrincipal, ResourceID: id},
		{ResourceType: TypePrincipal, SubjectType: TypePrincipal, SubjectID: id},
	})
}

// RegisterOrganization creates an organization with an initial owner.
func (s *Syncer) RegisterOrganization(ctx context.Context, orgID, ownerID uuid.UUID) error {
	return s.client.WriteRelationship(ctx, &Relationship{
		ResourceType: TypeOrganization,
		ResourceID:   orgID.String(),
		Relation:     RelOwner,
		SubjectType:  TypePrincipal,
		SubjectID:    ownerID.String(),
	})
}

// UnregisterOrganization removes every relationship stored on an
// organization. Relationships an application's own definitions hold to the
// organization are the application's to remove.
func (s *Syncer) UnregisterOrganization(ctx context.Context, orgID uuid.UUID) error {
	return s.deleteAll(ctx, "unregister organization "+orgID.String(), []*RelationshipFilter{
		{ResourceType: TypeOrganization, ResourceID: orgID.String()},
	})
}

// deleteAll deletes the relationships matching each filter, attempting
// every filter and joining the failures.
func (s *Syncer) deleteAll(ctx context.Context, op string, filters []*RelationshipFilter) error {
	var errs []error
	for _, f := range filters {
		if err := s.client.DeleteRelationships(ctx, f); err != nil {
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

// SetPlatformAdmin grants or revokes platform admin privileges.
func (s *Syncer) SetPlatformAdmin(ctx context.Context, principalID uuid.UUID, isAdmin bool) error {
	rel := &Relationship{
		ResourceType: "platform",
		ResourceID:   "global",
		Relation:     RelAdmin,
		SubjectType:  TypePrincipal,
		SubjectID:    principalID.String(),
	}

	if isAdmin {
		return s.client.WriteRelationship(ctx, rel)
	}
	return s.client.DeleteRelationship(ctx, rel)
}

// AddPrincipalManager writes a manager relation on the managed principal.
func (s *Syncer) AddPrincipalManager(ctx context.Context, managedID, managerID uuid.UUID, role string) error {
	return s.client.WriteRelationship(ctx, managerRelationship(managedID, managerID, role))
}

// RemovePrincipalManager deletes a manager relation.
func (s *Syncer) RemovePrincipalManager(ctx context.Context, managedID, managerID uuid.UUID, role string) error {
	return s.client.DeleteRelationship(ctx, managerRelationship(managedID, managerID, role))
}

func managerRelationship(managedID, managerID uuid.UUID, role string) *Relationship {
	return &Relationship{
		ResourceType: TypePrincipal,
		ResourceID:   managedID.String(),
		Relation:     role,
		SubjectType:  TypePrincipal,
		SubjectID:    managerID.String(),
	}
}

// AddAppRole writes the principal's role in an application as a relation on
// the application's organization facet, "{application}_org".
func (s *Syncer) AddAppRole(ctx context.Context, principalID, orgID uuid.UUID, application, role string) error {
	rel, err := appRoleRelationship(principalID, orgID, application, role)
	if err != nil {
		return err
	}
	return s.client.WriteRelationship(ctx, rel)
}

// RemoveAppRole deletes the principal's role in an application.
func (s *Syncer) RemoveAppRole(ctx context.Context, principalID, orgID uuid.UUID, application, role string) error {
	rel, err := appRoleRelationship(principalID, orgID, application, role)
	if err != nil {
		return err
	}
	return s.client.DeleteRelationship(ctx, rel)
}

func appRoleRelationship(principalID, orgID uuid.UUID, application, role string) (*Relationship, error) {
	if !authz.ValidAppName(application) {
		return nil, fmt.Errorf("spicedb: invalid application identifier %q", application)
	}
	if role == "" {
		return nil, errors.New("spicedb: empty application role")
	}
	return &Relationship{
		ResourceType: application + "_org",
		ResourceID:   orgID.String(),
		Relation:     role,
		SubjectType:  TypePrincipal,
		SubjectID:    principalID.String(),
	}, nil
}

// SetResourceGrant writes the principal's resource role as a relationship,
// "{type}:{id}#{role}@principal:{principal}", and deletes the other two
// ladder roles it may hold on the resource in the same request, so a
// change of role is never seen half-applied. It writes only the grant:
// the resource's org relation is the application's, written when it
// creates the resource.
func (s *Syncer) SetResourceGrant(ctx context.Context, principalID uuid.UUID, resource authz.ResourceRef, role string) error {
	if !authz.ValidResourceRole(role) {
		return fmt.Errorf("spicedb: %w: %q", authz.ErrInvalidResourceRole, role)
	}
	if err := validateGrantRef(resource); err != nil {
		return err
	}
	var stale []*Relationship
	for _, other := range authz.ResourceRoles() {
		if other != role {
			stale = append(stale, grantRelationship(principalID, resource, other))
		}
	}
	return s.client.ReplaceRelationships(ctx, stale, []*Relationship{grantRelationship(principalID, resource, role)})
}

// RemoveResourceGrant deletes every resource role the principal holds on
// the resource.
func (s *Syncer) RemoveResourceGrant(ctx context.Context, principalID uuid.UUID, resource authz.ResourceRef) error {
	if err := validateGrantRef(resource); err != nil {
		return err
	}
	var all []*Relationship
	for _, role := range authz.ResourceRoles() {
		all = append(all, grantRelationship(principalID, resource, role))
	}
	return s.client.ReplaceRelationships(ctx, all, nil)
}

// validateGrantRef checks the parts of a reference the relationship uses;
// the organization is the store's, not the graph's.
func validateGrantRef(resource authz.ResourceRef) error {
	ref := resource
	if ref.OrganizationID == uuid.Nil {
		ref.OrganizationID = uuid.New()
	}
	return authz.ValidateResourceRef(ref)
}

func grantRelationship(principalID uuid.UUID, resource authz.ResourceRef, role string) *Relationship {
	return &Relationship{
		ResourceType: resource.Type,
		ResourceID:   resource.ID,
		Relation:     role,
		SubjectType:  TypePrincipal,
		SubjectID:    principalID.String(),
	}
}

// Verify interface compliance at compile time.
var (
	_ authz.RelationshipSyncer  = (*Syncer)(nil)
	_ authz.AppRoleSyncer       = (*Syncer)(nil)
	_ authz.ResourceGrantSyncer = (*Syncer)(nil)
)
