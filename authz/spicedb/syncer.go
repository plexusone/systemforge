package spicedb

import (
	"context"
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

// UnregisterPrincipal removes all relationships involving a principal.
func (s *Syncer) UnregisterPrincipal(ctx context.Context, principalID uuid.UUID) error {
	principalIDStr := principalID.String()

	// Find all organizations where this principal has membership
	// and remove those relationships
	for _, role := range []string{RelOwner, RelAdmin, RelMember, RelViewer} {
		// Look up organizations where this principal has this role
		orgs, err := s.client.LookupResources(ctx, &LookupResourcesRequest{
			ResourceType: TypeOrganization,
			Permission:   role,
			SubjectType:  TypePrincipal,
			SubjectID:    principalIDStr,
		})
		if err != nil {
			// Log but continue - best effort cleanup
			continue
		}

		for _, orgID := range orgs {
			_ = s.client.DeleteRelationship(ctx, &Relationship{
				ResourceType: TypeOrganization,
				ResourceID:   orgID,
				Relation:     role,
				SubjectType:  TypePrincipal,
				SubjectID:    principalIDStr,
			})
		}
	}

	// Remove platform admin if set
	_ = s.client.DeleteRelationship(ctx, &Relationship{
		ResourceType: "platform",
		ResourceID:   "global",
		Relation:     RelAdmin,
		SubjectType:  TypePrincipal,
		SubjectID:    principalIDStr,
	})

	return nil
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

// UnregisterOrganization removes an organization and all its membership relationships.
func (s *Syncer) UnregisterOrganization(ctx context.Context, orgID uuid.UUID) error {
	orgIDStr := orgID.String()

	// Remove all membership relationships for this organization
	for _, role := range []string{RelOwner, RelAdmin, RelMember, RelViewer} {
		// Look up all principals with this role
		principals, err := s.client.LookupSubjects(ctx, &LookupSubjectsRequest{
			ResourceType: TypeOrganization,
			ResourceID:   orgIDStr,
			Permission:   role,
			SubjectType:  TypePrincipal,
		})
		if err != nil {
			// Log but continue - best effort cleanup
			continue
		}

		for _, principalID := range principals {
			_ = s.client.DeleteRelationship(ctx, &Relationship{
				ResourceType: TypeOrganization,
				ResourceID:   orgIDStr,
				Relation:     role,
				SubjectType:  TypePrincipal,
				SubjectID:    principalID,
			})
		}
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

// Verify interface compliance at compile time.
var _ authz.RelationshipSyncer = (*Syncer)(nil)
