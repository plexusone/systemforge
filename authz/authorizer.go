// Package authz provides a pluggable authorization interface for SystemForge applications.
//
// The package defines a core Authorizer interface that applications use for access control,
// with two modes, named for the model they evaluate (ADR-008):
//
//   - rbac (package authz/rbac): role-based. Organization roles, application roles and
//     direct grants on resources, evaluated in process from the membership, role and grant
//     tables. No external dependencies.
//   - rebac (package authz/rebac/spicedb): relationship-based. Permissions derived through
//     relationships by an engine, SpiceDB today (Zanzibar-style).
//
// Both implement the same platform contract (Authorizer, OrgAuthorizer, PlatformAuthorizer
// and ResourceGranter, assembled as Provider) with the same semantics, verified by the
// authz/providertest suite. ModeConfig selects between them (the `authz` configuration key)
// and authz/mode builds the provider, so applications depend only on the interfaces and a
// deployment switches by configuration. The former paths authz/simple and authz/spicedb
// forward to the new packages and are deprecated.
package authz

import (
	"context"

	"github.com/google/uuid"
)

// Authorizer defines the core authorization interface.
// All authorization backends must implement this interface.
type Authorizer interface {
	// Can checks if a principal can perform an action on a resource.
	// This is the primary authorization method.
	Can(ctx context.Context, principal Principal, action Action, resource Resource) (bool, error)

	// CanAll checks if a principal can perform all specified actions on a resource.
	// Implementations must deny an empty action list.
	CanAll(ctx context.Context, principal Principal, actions []Action, resource Resource) (bool, error)

	// CanAny checks if a principal can perform any of the specified actions on a resource.
	CanAny(ctx context.Context, principal Principal, actions []Action, resource Resource) (bool, error)

	// Filter returns only the resources the principal can access with the given action.
	Filter(ctx context.Context, principal Principal, action Action, resources []Resource) ([]Resource, error)
}

// OrgAuthorizer extends Authorizer with organization-scoped methods.
// Use this for multi-tenant SaaS applications.
type OrgAuthorizer interface {
	Authorizer

	// CanForOrg checks permission scoped to a specific organization.
	CanForOrg(ctx context.Context, principal Principal, orgID uuid.UUID, action Action, resource Resource) (bool, error)

	// GetRole returns the principal's role in an organization.
	GetRole(ctx context.Context, principal Principal, orgID uuid.UUID) (string, error)

	// IsMember checks if a principal is a member of an organization.
	IsMember(ctx context.Context, principal Principal, orgID uuid.UUID) (bool, error)
}

// PlatformAuthorizer extends OrgAuthorizer with platform-level checks.
type PlatformAuthorizer interface {
	OrgAuthorizer

	// IsPlatformAdmin checks if a principal has platform-wide admin access.
	IsPlatformAdmin(ctx context.Context, principal Principal) (bool, error)
}

// FeatureAuthorizer extends authorization with feature flag awareness.
type FeatureAuthorizer interface {
	Authorizer

	// CanWithFeature checks both permission and feature flag.
	CanWithFeature(ctx context.Context, principal Principal, action Action, resource Resource, feature string) (bool, error)
}

// Decision represents an authorization decision with optional explanation.
type Decision struct {
	// Allowed indicates whether the action is permitted.
	Allowed bool

	// Reason provides context for the decision (useful for debugging/auditing).
	Reason string

	// PolicyID identifies which policy made the decision (if applicable).
	PolicyID string
}

// DecisionAuthorizer provides detailed authorization decisions.
type DecisionAuthorizer interface {
	Authorizer

	// Decide returns a detailed authorization decision.
	Decide(ctx context.Context, principal Principal, action Action, resource Resource) (Decision, error)
}
