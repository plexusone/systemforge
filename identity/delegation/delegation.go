// Package delegation provides delegation chain management for agent principals.
// Delegation allows principals to authorize other principals (particularly agents)
// to act on their behalf with constrained capabilities.
package delegation

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/plexusone/systemforge/identity/principal"
)

// Link represents a single link in a delegation chain.
type Link struct {
	PrincipalID   uuid.UUID      `json:"principal_id"`
	PrincipalType principal.Type `json:"principal_type"`
	DisplayName   string         `json:"display_name"`
	Constraints   Constraints    `json:"constraints"`
	GrantedAt     time.Time      `json:"granted_at"`
	// Active reports whether the principal is active; a chain with an
	// inactive principal authorizes nothing.
	Active bool `json:"active"`
}

// Chain represents a full delegation chain from root to current principal.
type Chain struct {
	// Links ordered from root (human/service) to current (typically agent)
	Links []Link `json:"links"`
	// Effective constraints computed by intersecting all links
	EffectiveConstraints Constraints `json:"effective_constraints"`
}

// Root returns the root principal in the chain.
func (c *Chain) Root() *Link {
	if len(c.Links) == 0 {
		return nil
	}
	return &c.Links[0]
}

// Current returns the current (last) principal in the chain.
func (c *Chain) Current() *Link {
	if len(c.Links) == 0 {
		return nil
	}
	return &c.Links[len(c.Links)-1]
}

// Depth returns the delegation depth.
func (c *Chain) Depth() int {
	return len(c.Links)
}

// Constraints defines what a delegated principal can do. In a delegation
// request, an empty list leaves that dimension unrestricted by the
// delegation. In a chain's effective constraints, a nil list is
// unrestricted and an empty, non-nil list allows nothing, which is what
// constraints that do not overlap leave.
type Constraints struct {
	// AllowedCapabilities lists capabilities the delegate can use.
	// Empty means all capabilities of the parent are available.
	AllowedCapabilities []string `json:"allowed_capabilities,omitempty"`

	// AllowedScopes lists scopes the delegate can request.
	// Empty means all scopes of the parent are available.
	AllowedScopes []string `json:"allowed_scopes,omitempty"`

	// AllowedResources lists resource patterns the delegate can access.
	// Supports glob patterns like "project/*" or "org/123/*"
	AllowedResources []string `json:"allowed_resources,omitempty"`

	// AllowedActions lists actions the delegate can perform.
	// Example: ["read", "write"], ["*"]
	AllowedActions []string `json:"allowed_actions,omitempty"`

	// MaxTokenLifetime limits token duration for the delegate.
	MaxTokenLifetime time.Duration `json:"max_token_lifetime,omitempty"`

	// RequiresConfirmation indicates actions need human approval.
	RequiresConfirmation bool `json:"requires_confirmation"`

	// ExpiresAt is when the delegation expires.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// CreateInput contains fields for creating a delegation.
type CreateInput struct {
	// DelegatorID is the principal granting the delegation.
	DelegatorID uuid.UUID

	// DelegateID is the principal receiving the delegation.
	DelegateID uuid.UUID

	// Constraints on what the delegate can do.
	Constraints Constraints

	// Reason for the delegation (audit).
	Reason string
}

// ActionValidation represents the result of validating an action.
type ActionValidation struct {
	Allowed      bool   `json:"allowed"`
	Reason       string `json:"reason,omitempty"`
	Confirmation bool   `json:"confirmation_required"`
}

// Service defines the business logic interface for delegation.
type Service interface {
	// CreateDelegation creates a delegation from one principal to another.
	CreateDelegation(ctx context.Context, input CreateInput) (*Link, error)

	// GetChain retrieves the full delegation chain for a principal.
	GetChain(ctx context.Context, principalID uuid.UUID) (*Chain, error)

	// ValidateAction checks if a principal can perform an action on a resource.
	ValidateAction(ctx context.Context, principalID uuid.UUID, action, resource string) (*ActionValidation, error)

	// RevokeDelegation revokes a delegation.
	RevokeDelegation(ctx context.Context, delegatorID, delegateID uuid.UUID, reason string) error

	// ListDelegations lists all delegations granted by a principal.
	ListDelegations(ctx context.Context, delegatorID uuid.UUID) ([]*Link, error)

	// ComputeEffectiveConstraints computes the effective constraints
	// by intersecting constraints through the delegation chain.
	ComputeEffectiveConstraints(chain *Chain) Constraints
}

var (
	// ErrNotFound is returned for an unknown principal.
	ErrNotFound = errors.New("delegation: principal not found")
	// ErrNotAgent is returned when the delegate is not an agent.
	ErrNotAgent = errors.New("delegation: delegate must be an agent principal")
	// ErrCannotDelegate is returned when the delegator lacks the
	// can_delegate capability or is not active.
	ErrCannotDelegate = errors.New("delegation: delegator cannot delegate")
	// ErrSelfDelegation is returned when a principal delegates to itself.
	ErrSelfDelegation = errors.New("delegation: a principal cannot delegate to itself")
	// ErrCircularDelegation is returned when a delegation would make the
	// delegate its own ancestor.
	ErrCircularDelegation = errors.New("delegation: circular delegation")
	// ErrDelegatorMismatch is returned when revoking a delegation the
	// principal did not grant.
	ErrDelegatorMismatch = errors.New("delegation: delegator mismatch")
	// ErrAlreadyDelegated is returned when the agent already acts for
	// another principal. That delegator must revoke it first.
	ErrAlreadyDelegated = errors.New("delegation: agent is delegated by another principal")
	// ErrCrossOrganization is returned when the agent belongs to an
	// organization the delegator is not an active member of.
	ErrCrossOrganization = errors.New("delegation: agent belongs to an organization the delegator is not a member of")
)
