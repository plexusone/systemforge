package invite

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/human"
	"github.com/plexusone/systemforge/identity/ent/principalmembership"
	"github.com/plexusone/systemforge/identity/organization"
	"github.com/plexusone/systemforge/identity/requestprincipal"
)

// PrincipalEmailFunc returns a principal's email, or "" when it has none
// (a managed principal).
type PrincipalEmailFunc func(ctx context.Context, principalID uuid.UUID) (string, error)

// PrincipalEmail returns a principal's email from the identity database,
// or "" when it has none. It is the API's default PrincipalEmailFunc.
func (s *DefaultService) PrincipalEmail(ctx context.Context, principalID uuid.UUID) (string, error) {
	h, err := s.client.Human.Query().Where(human.PrincipalID(principalID)).Only(ctx)
	if ent.IsNotFound(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("invite: principal email: %w", err)
	}
	if h.Email == nil {
		return "", nil
	}
	return *h.Email, nil
}

// inviterActions are the organization permissions an invite's inviter must
// still hold for it to be accepted: those the API required to create it.
func inviterActions(inv *ent.Invite) []authz.Action {
	actions := []authz.Action{authz.PermOrgInviteMember}
	if inv.Role == organization.RoleOwner {
		actions = append(actions, authz.PermOrgDelete)
	}
	return actions
}

// requireInviterMembership checks, through c, that the inviter of inv holds
// an active membership in the invite's organization whose role grants
// inviterActions.
func requireInviterMembership(ctx context.Context, c *ent.Client, inv *ent.Invite) error {
	m, err := c.PrincipalMembership.Query().
		Where(
			principalmembership.OrganizationID(inv.OrganizationID),
			principalmembership.PrincipalID(inv.InviterPrincipalID),
			principalmembership.Active(true),
		).
		Only(ctx)
	if ent.IsNotFound(err) {
		return ErrInviterNotAuthorized
	}
	if err != nil {
		return fmt.Errorf("invite: reading the inviter's membership: %w", err)
	}
	for _, action := range inviterActions(inv) {
		if !authz.OrgRoleAllows(m.Role, action) {
			return ErrInviterNotAuthorized
		}
	}
	return nil
}

// checkInviterWithAuthorizer asks the configured authorizer whether the
// inviter of inv still holds inviterActions on the organization.
func (s *DefaultService) checkInviterWithAuthorizer(ctx context.Context, inv *ent.Invite) error {
	ok, err := s.authorizer.CanAll(ctx, authz.NewUserPrincipal(inv.InviterPrincipalID), inviterActions(inv),
		authz.NewResourceWithID(authz.ResourceTypeOrganization, inv.OrganizationID))
	if err != nil {
		return fmt.Errorf("invite: checking the inviter's authority: %w", err)
	}
	if !ok {
		return ErrInviterNotAuthorized
	}
	return nil
}

// callerID returns the authenticated caller, or a 401.
func (a *API) callerID(ctx context.Context) (uuid.UUID, error) {
	resolve := a.config.Caller
	if resolve == nil {
		resolve = requestprincipal.PrincipalUUID
	}
	id, err := resolve(ctx)
	if errors.Is(err, requestprincipal.ErrNoPrincipal) {
		return uuid.Nil, huma.Error401Unauthorized("authentication required")
	}
	if err != nil {
		a.config.Logger.ErrorContext(ctx, "invite: identifying caller", "error", err)
		return uuid.Nil, huma.Error500InternalServerError("identifying caller")
	}
	return id, nil
}

// orgForInvites loads the organization named by slug and returns it with
// the caller after checking that the caller may manage its invites;
// outsiders get 404.
func (a *API) orgForInvites(ctx context.Context, slug string) (*organization.Organization, uuid.UUID, error) {
	const action = authz.PermOrgInviteMember
	if a.config.Authorizer == nil {
		return nil, uuid.Nil, huma.Error501NotImplemented("invite authorization not configured")
	}
	caller, err := a.callerID(ctx)
	if err != nil {
		return nil, uuid.Nil, err
	}
	org, _, err := a.orgSvc.ResolveSlug(ctx, slug)
	if err != nil {
		return nil, uuid.Nil, huma.Error404NotFound("organization not found")
	}
	for _, check := range []authz.Action{action, authz.PermOrgView} {
		ok, err := a.can(ctx, caller, org.ID, check)
		if err != nil {
			return nil, uuid.Nil, err
		}
		if ok && check == action {
			return org, caller, nil
		}
		if ok {
			return nil, uuid.Nil, huma.Error403Forbidden("not allowed for this organization")
		}
	}
	return nil, uuid.Nil, huma.Error404NotFound("organization not found")
}

func (a *API) can(ctx context.Context, principalID, orgID uuid.UUID, action authz.Action) (bool, error) {
	ok, err := a.config.Authorizer.Can(ctx, authz.NewUserPrincipal(principalID), action, authz.NewResourceWithID(authz.ResourceTypeOrganization, orgID))
	if err != nil {
		a.config.Logger.ErrorContext(ctx, "invite: authorization check", "action", action, "organization_id", orgID, "error", err)
		return false, huma.Error500InternalServerError("checking authorization")
	}
	return ok, nil
}

// inviteInOrg loads an invite and requires it to belong to org.
func (a *API) inviteInOrg(ctx context.Context, rawID string, org *organization.Organization) (uuid.UUID, error) {
	id, err := uuid.Parse(rawID)
	if err != nil {
		return uuid.Nil, huma.Error400BadRequest("invalid invite_id")
	}
	inv, err := a.service.GetByID(ctx, id)
	if err != nil || inv.OrganizationID != org.ID {
		return uuid.Nil, huma.Error404NotFound("invite not found")
	}
	return id, nil
}

// callerEmail returns the caller and its email; the caller must have one.
func (a *API) callerEmail(ctx context.Context) (uuid.UUID, string, error) {
	caller, err := a.callerID(ctx)
	if err != nil {
		return uuid.Nil, "", err
	}
	lookup := a.config.PrincipalEmail
	if lookup == nil {
		if svc, ok := a.service.(interface {
			PrincipalEmail(context.Context, uuid.UUID) (string, error)
		}); ok {
			lookup = svc.PrincipalEmail
		}
	}
	if lookup == nil {
		return uuid.Nil, "", huma.Error501NotImplemented("principal email lookup not configured")
	}
	email, err := lookup(ctx, caller)
	if err != nil {
		a.config.Logger.ErrorContext(ctx, "invite: looking up caller email", "error", err)
		return uuid.Nil, "", huma.Error500InternalServerError("looking up caller")
	}
	if email == "" {
		return uuid.Nil, "", huma.Error403Forbidden("invites are for principals with an email")
	}
	return caller, email, nil
}

// callerForInvite returns the caller after requiring the invite a token
// names to be addressed to the caller's email, so a forwarded or leaked
// link cannot be used by anyone else. A mismatch looks like an unknown
// token.
func (a *API) callerForInvite(ctx context.Context, token string) (uuid.UUID, error) {
	caller, email, err := a.callerEmail(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	inv, err := a.service.GetByToken(ctx, token)
	if err != nil || !strings.EqualFold(inv.Email, email) {
		return uuid.Nil, huma.Error404NotFound("invite not found")
	}
	return caller, nil
}
