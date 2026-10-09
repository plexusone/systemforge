package authz

import (
	"context"

	"github.com/google/uuid"
)

// RelationshipSyncer defines the interface for syncing identity changes to an authorization backend.
// Identity services use this interface to keep the authorization layer in sync with membership
// and principal lifecycle events.
type RelationshipSyncer interface {
	// AddOrgMembership registers a principal's membership in an organization with a specific role.
	// Called when a user joins an organization or is invited.
	AddOrgMembership(ctx context.Context, principalID, orgID uuid.UUID, role string) error

	// RemoveOrgMembership removes a principal's membership from an organization.
	// Called when a user leaves or is removed from an organization.
	RemoveOrgMembership(ctx context.Context, principalID, orgID uuid.UUID, role string) error

	// UpdateOrgMembership changes a principal's role in an organization.
	// Implemented as remove old role + add new role atomically.
	UpdateOrgMembership(ctx context.Context, principalID, orgID uuid.UUID, oldRole, newRole string) error

	// RegisterPrincipal creates a principal entity in the authorization system.
	// Called when a new user, application, agent, or service principal is created.
	RegisterPrincipal(ctx context.Context, principalID uuid.UUID) error

	// UnregisterPrincipal removes a principal and all its relationships from the authorization system.
	// Called when a principal is deleted.
	UnregisterPrincipal(ctx context.Context, principalID uuid.UUID) error

	// RegisterOrganization creates an organization in the authorization system with an initial owner.
	// Called when a new organization is created.
	RegisterOrganization(ctx context.Context, orgID, ownerID uuid.UUID) error

	// UnregisterOrganization removes an organization and all its relationships from the authorization system.
	// Called when an organization is deleted.
	UnregisterOrganization(ctx context.Context, orgID uuid.UUID) error

	// SetPlatformAdmin grants or revokes platform admin privileges for a principal.
	SetPlatformAdmin(ctx context.Context, principalID uuid.UUID, isAdmin bool) error

	// AddPrincipalManager records that managerID manages managedID with a
	// manager role such as guardian or educator (ADR-005).
	AddPrincipalManager(ctx context.Context, managedID, managerID uuid.UUID, role string) error

	// RemovePrincipalManager removes a manager relation.
	RemovePrincipalManager(ctx context.Context, managedID, managerID uuid.UUID, role string) error
}

// AppRoleSyncer is implemented by a RelationshipSyncer that also writes
// application roles (ADR-007) to the authorization graph. It is a separate
// interface so existing RelationshipSyncer implementers keep compiling;
// callers type-assert a syncer to it and skip application roles when it does
// not implement it. The relationship-based provider writes
// "{application}_org:{org}#{role}@principal:{principal}", the facet an
// application's schema fragment attaches to the base organization.
type AppRoleSyncer interface {
	// AddAppRole records that the principal holds role in application for
	// the organization. Called when an application role is assigned or
	// changed.
	AddAppRole(ctx context.Context, principalID, orgID uuid.UUID, application, role string) error

	// RemoveAppRole removes the principal's role in application for the
	// organization. Called when an application role is removed or changed.
	RemoveAppRole(ctx context.Context, principalID, orgID uuid.UUID, application, role string) error
}

// ValidAppName reports whether application is a valid application
// identifier (lowercase letters and digits, 2 to 32 characters, starting
// with a letter), the form AppVocabulary.App must have.
func ValidAppName(application string) bool {
	return appNameRe.MatchString(application)
}

// SyncMode determines how sync failures are handled.
type SyncMode string

const (
	// SyncModeStrict fails the operation if authorization sync fails.
	// Use when authorization must be consistent with identity.
	SyncModeStrict SyncMode = "strict"

	// SyncModeEventual logs sync failures but allows the operation to succeed.
	// Use when eventual consistency is acceptable and a retry mechanism exists.
	SyncModeEventual SyncMode = "eventual"
)
