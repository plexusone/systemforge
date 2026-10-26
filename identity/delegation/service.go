package delegation

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/agent"
	entprincipal "github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/ent/principalmembership"
	"github.com/plexusone/systemforge/identity/principal"
)

// DefaultService implements the Service interface.
type DefaultService struct {
	client *ent.Client
}

// NewService creates a new DelegationService.
func NewService(client *ent.Client) Service {
	return &DefaultService{client: client}
}

func (s *DefaultService) loadPrincipal(ctx context.Context, id uuid.UUID) (*ent.Principal, error) {
	p, err := s.client.Principal.Query().Where(entprincipal.ID(id)).WithAgent().Only(ctx)
	if ent.IsNotFound(err) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get principal %s: %w", id, err)
	}
	return p, nil
}

// CreateDelegation makes an agent act for a delegator under constraints.
// The delegator must be active with the can_delegate capability and, when
// the agent belongs to an organization, an active member of it
// (ErrCrossOrganization). An agent already delegated by another principal
// is refused (ErrAlreadyDelegated) until that delegation is revoked; the
// same delegator may replace its own.
//
// Every constraint is stored and intersected along the chain.
// ValidateAction enforces actions, resources, expiry and confirmation;
// AllowedScopes, AllowedCapabilities and MaxTokenLifetime limit tokens and
// must be enforced by whatever issues tokens for the agent, from
// GetChain's EffectiveConstraints.
func (s *DefaultService) CreateDelegation(ctx context.Context, input CreateInput) (*Link, error) {
	if input.DelegatorID == input.DelegateID {
		return nil, ErrSelfDelegation
	}
	delegator, err := s.loadPrincipal(ctx, input.DelegatorID)
	if err != nil {
		return nil, err
	}
	if !delegator.Active || !delegator.Capabilities["can_delegate"] {
		return nil, ErrCannotDelegate
	}
	delegate, err := s.loadPrincipal(ctx, input.DelegateID)
	if err != nil {
		return nil, err
	}
	if delegate.Type != entprincipal.TypeAgent || delegate.Edges.Agent == nil {
		return nil, ErrNotAgent
	}

	// The delegate may not already be among the delegator's ancestors.
	chain, err := s.GetChain(ctx, input.DelegatorID)
	if err != nil {
		return nil, err
	}
	for _, l := range chain.Links {
		if l.PrincipalID == input.DelegateID {
			return nil, ErrCircularDelegation
		}
	}

	// Another principal's delegation is not silently taken over.
	if current := delegate.Edges.Agent.DelegatingPrincipalID; current != nil && *current != input.DelegatorID {
		return nil, ErrAlreadyDelegated
	}
	// An agent of an organization acts only for members of it.
	if delegate.OrganizationID != nil {
		member, err := s.inOrganization(ctx, delegator, *delegate.OrganizationID)
		if err != nil {
			return nil, err
		}
		if !member {
			return nil, ErrCrossOrganization
		}
	}

	c := input.Constraints
	update := s.client.Agent.UpdateOne(delegate.Edges.Agent).
		SetDelegatingPrincipalID(input.DelegatorID).
		SetCapabilityConstraints(stored(c.AllowedCapabilities)).
		SetResourceConstraints(stored(c.AllowedResources)).
		SetActionConstraints(stored(c.AllowedActions)).
		SetScopeConstraints(stored(c.AllowedScopes)).
		SetRequiresConfirmation(c.RequiresConfirmation)
	if c.MaxTokenLifetime > 0 {
		update.SetMaxTokenLifetime(int(c.MaxTokenLifetime.Seconds()))
	}
	if c.ExpiresAt != nil {
		update.SetDelegationExpiresAt(*c.ExpiresAt)
	} else {
		update.ClearDelegationExpiresAt()
	}
	a, err := update.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to update agent delegation: %w", err)
	}

	return &Link{
		PrincipalID:   delegate.ID,
		PrincipalType: principal.Type(delegate.Type.String()),
		DisplayName:   delegate.DisplayName,
		Constraints:   agentConstraints(a),
		GrantedAt:     time.Now(),
		Active:        delegate.Active,
	}, nil
}

// inOrganization reports whether p belongs to orgID: as its home
// organization, or through an active membership.
func (s *DefaultService) inOrganization(ctx context.Context, p *ent.Principal, orgID uuid.UUID) (bool, error) {
	if p.OrganizationID != nil && *p.OrganizationID == orgID {
		return true, nil
	}
	ok, err := s.client.PrincipalMembership.Query().
		Where(
			principalmembership.PrincipalIDEQ(p.ID),
			principalmembership.OrganizationIDEQ(orgID),
			principalmembership.ActiveEQ(true),
		).
		Exist(ctx)
	if err != nil {
		return false, fmt.Errorf("checking membership of %s in %s: %w", p.ID, orgID, err)
	}
	return ok, nil
}

// GetChain retrieves the delegation chain ending at a principal, from its
// root to the principal.
func (s *DefaultService) GetChain(ctx context.Context, principalID uuid.UUID) (*Chain, error) {
	var links []Link
	currentID := principalID
	visited := make(map[uuid.UUID]bool)

	for {
		if visited[currentID] {
			return nil, ErrCircularDelegation
		}
		visited[currentID] = true

		p, err := s.loadPrincipal(ctx, currentID)
		if err != nil {
			return nil, err
		}

		var constraints Constraints
		if p.Edges.Agent != nil {
			constraints = agentConstraints(p.Edges.Agent)
		}
		links = append([]Link{{
			PrincipalID:   p.ID,
			PrincipalType: principal.Type(p.Type.String()),
			DisplayName:   p.DisplayName,
			Constraints:   constraints,
			GrantedAt:     p.CreatedAt,
			Active:        p.Active,
		}}, links...)

		if p.Edges.Agent == nil || p.Edges.Agent.DelegatingPrincipalID == nil {
			break
		}
		currentID = *p.Edges.Agent.DelegatingPrincipalID
	}

	chain := &Chain{Links: links}
	chain.EffectiveConstraints = s.ComputeEffectiveConstraints(chain)
	return chain, nil
}

// ValidateAction checks whether a principal may perform an action on a
// resource. A principal that is not an agent acts for itself. An agent
// acts only through a delegation from an active root, with every principal
// in its chain active, and within the chain's effective constraints.
func (s *DefaultService) ValidateAction(ctx context.Context, principalID uuid.UUID, action, resource string) (*ActionValidation, error) {
	chain, err := s.GetChain(ctx, principalID)
	if err != nil {
		return nil, err
	}

	for _, l := range chain.Links {
		if !l.Active {
			return deny("principal %s in the delegation chain is not active", l.PrincipalID), nil
		}
	}
	if root := chain.Root(); root.PrincipalType == principal.TypeAgent {
		// An agent without a delegation, for example after it was
		// revoked, acts for no one.
		return deny("agent has no delegation"), nil
	}
	if chain.Depth() == 1 {
		return &ActionValidation{Allowed: true, Reason: "direct principal access"}, nil
	}

	effective := chain.EffectiveConstraints
	if effective.ExpiresAt != nil && !effective.ExpiresAt.After(time.Now()) {
		return deny("delegation expired"), nil
	}
	if effective.AllowedActions != nil && !containsOrWildcard(effective.AllowedActions, action) {
		return deny("action %q not in allowed actions", action), nil
	}
	if effective.AllowedResources != nil && !matchesAny(effective.AllowedResources, resource) {
		return deny("resource %q not in allowed resources", resource), nil
	}

	return &ActionValidation{
		Allowed:      true,
		Confirmation: effective.RequiresConfirmation,
	}, nil
}

// RevokeDelegation ends an agent's delegation. The agent then acts for no
// one.
func (s *DefaultService) RevokeDelegation(ctx context.Context, delegatorID, delegateID uuid.UUID, reason string) error {
	delegate, err := s.loadPrincipal(ctx, delegateID)
	if err != nil {
		return err
	}
	if delegate.Edges.Agent == nil {
		return ErrNotAgent
	}
	if delegate.Edges.Agent.DelegatingPrincipalID == nil || *delegate.Edges.Agent.DelegatingPrincipalID != delegatorID {
		return ErrDelegatorMismatch
	}

	_, err = s.client.Agent.UpdateOne(delegate.Edges.Agent).
		ClearDelegatingPrincipalID().
		SetCapabilityConstraints([]string{}).
		SetResourceConstraints([]string{}).
		SetActionConstraints([]string{}).
		SetScopeConstraints([]string{}).
		ClearDelegationExpiresAt().
		Save(ctx)
	if err != nil {
		return fmt.Errorf("failed to revoke delegation: %w", err)
	}
	return nil
}

// ListDelegations lists all delegations granted by a principal.
func (s *DefaultService) ListDelegations(ctx context.Context, delegatorID uuid.UUID) ([]*Link, error) {
	agents, err := s.client.Agent.Query().
		Where(agent.DelegatingPrincipalIDEQ(delegatorID)).
		WithPrincipal().
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list delegations: %w", err)
	}

	links := make([]*Link, 0, len(agents))
	for _, a := range agents {
		p := a.Edges.Principal
		if p == nil {
			return nil, fmt.Errorf("agent %s has no principal", a.ID)
		}
		links = append(links, &Link{
			PrincipalID:   p.ID,
			PrincipalType: principal.Type(p.Type.String()),
			DisplayName:   p.DisplayName,
			Constraints:   agentConstraints(a),
			GrantedAt:     p.CreatedAt,
			Active:        p.Active,
		})
	}
	return links, nil
}

// ComputeEffectiveConstraints computes the effective constraints
// by intersecting constraints through the delegation chain.
func (s *DefaultService) ComputeEffectiveConstraints(chain *Chain) Constraints {
	if chain == nil || len(chain.Links) == 0 {
		return Constraints{}
	}
	effective := chain.Links[0].Constraints
	for i := 1; i < len(chain.Links); i++ {
		effective = intersectConstraints(effective, chain.Links[i].Constraints)
	}
	return effective
}

// intersectConstraints returns what both constraint sets allow. A nil list
// is unrestricted; lists that do not overlap leave an empty, non-nil list,
// which allows nothing.
func intersectConstraints(a, b Constraints) Constraints {
	result := Constraints{
		RequiresConfirmation: a.RequiresConfirmation || b.RequiresConfirmation,
		AllowedCapabilities:  intersectLists(a.AllowedCapabilities, b.AllowedCapabilities),
		AllowedScopes:        intersectLists(a.AllowedScopes, b.AllowedScopes),
		AllowedResources:     intersectLists(a.AllowedResources, b.AllowedResources),
		AllowedActions:       intersectLists(a.AllowedActions, b.AllowedActions),
	}

	switch {
	case a.MaxTokenLifetime > 0 && b.MaxTokenLifetime > 0:
		result.MaxTokenLifetime = min(a.MaxTokenLifetime, b.MaxTokenLifetime)
	case b.MaxTokenLifetime > 0:
		result.MaxTokenLifetime = b.MaxTokenLifetime
	default:
		result.MaxTokenLifetime = a.MaxTokenLifetime
	}

	switch {
	case a.ExpiresAt != nil && b.ExpiresAt != nil:
		if a.ExpiresAt.Before(*b.ExpiresAt) {
			result.ExpiresAt = a.ExpiresAt
		} else {
			result.ExpiresAt = b.ExpiresAt
		}
	case b.ExpiresAt != nil:
		result.ExpiresAt = b.ExpiresAt
	default:
		result.ExpiresAt = a.ExpiresAt
	}
	return result
}

// intersectLists intersects two restriction lists, where nil is
// unrestricted. The result of two restrictions is never nil.
func intersectLists(a, b []string) []string {
	switch {
	case a == nil:
		return b
	case b == nil:
		return a
	}
	set := make(map[string]bool, len(a))
	for _, s := range a {
		set[s] = true
	}
	result := []string{}
	for _, s := range b {
		if set[s] {
			result = append(result, s)
		}
	}
	return result
}

// agentConstraints reads an agent's stored delegation constraints. An
// empty stored list is unrestricted by this delegation.
func agentConstraints(a *ent.Agent) Constraints {
	c := Constraints{
		AllowedCapabilities:  restriction(a.CapabilityConstraints),
		AllowedResources:     restriction(a.ResourceConstraints),
		AllowedActions:       restriction(a.ActionConstraints),
		AllowedScopes:        restriction(a.ScopeConstraints),
		RequiresConfirmation: a.RequiresConfirmation,
		MaxTokenLifetime:     time.Duration(a.MaxTokenLifetime) * time.Second,
		ExpiresAt:            a.DelegationExpiresAt,
	}
	return c
}

// restriction turns an input or stored list into a restriction: empty is
// unrestricted (nil).
func restriction(list []string) []string {
	if len(list) == 0 {
		return nil
	}
	return list
}

// stored turns a requested list into its stored form.
func stored(list []string) []string {
	if list == nil {
		return []string{}
	}
	return list
}

func containsOrWildcard(list []string, v string) bool {
	for _, x := range list {
		if x == "*" || x == v {
			return true
		}
	}
	return false
}

// matchesAny reports whether resource matches one of the glob patterns. A
// malformed pattern matches nothing.
func matchesAny(patterns []string, resource string) bool {
	for _, pattern := range patterns {
		if pattern == "*" {
			return true
		}
		matched, err := filepath.Match(pattern, resource)
		if errors.Is(err, filepath.ErrBadPattern) {
			continue
		}
		if matched {
			return true
		}
	}
	return false
}

func deny(format string, args ...any) *ActionValidation {
	return &ActionValidation{Allowed: false, Reason: fmt.Sprintf(format, args...)}
}
