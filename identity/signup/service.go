package signup

import (
	"context"
	"fmt"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/invite"
	"github.com/plexusone/systemforge/identity/organization"
	"github.com/plexusone/systemforge/identity/principal"
)

// Service defines the signup service interface.
type Service interface {
	// Signup creates a new user with their personal organization.
	// This is the standard signup flow for new users.
	Signup(ctx context.Context, input SignupInput) (*SignupResult, error)

	// SignupWithInvite creates a new user, their personal org, and accepts an invite.
	// This is used when a user signs up by accepting an invitation to an org.
	SignupWithInvite(ctx context.Context, input AcceptInviteOnSignupInput) (*AcceptInviteOnSignupResult, error)

	// SignupOrGetExisting handles the OAuth login flow:
	// - If user exists, returns them and their personal org
	// - If user doesn't exist, creates them with personal org
	SignupOrGetExisting(ctx context.Context, input SignupInput) (*SignupResult, bool, error)
}

// DefaultService implements the Service interface.
type DefaultService struct {
	client       *ent.Client
	principalSvc principal.Service
	orgSvc       organization.Service
	inviteSvc    invite.Service
}

// NewService creates a new signup service.
func NewService(
	client *ent.Client,
	principalSvc principal.Service,
	orgSvc organization.Service,
	inviteSvc invite.Service,
) Service {
	return &DefaultService{
		client:       client,
		principalSvc: principalSvc,
		orgSvc:       orgSvc,
		inviteSvc:    inviteSvc,
	}
}

// Signup creates a new user with their personal organization.
func (s *DefaultService) Signup(ctx context.Context, input SignupInput) (*SignupResult, error) {
	// Validate input
	if input.Email == "" {
		return nil, fmt.Errorf("email is required")
	}
	if input.DisplayName == "" {
		return nil, fmt.Errorf("display name is required")
	}
	if input.PersonalOrgSlug == "" {
		return nil, fmt.Errorf("personal org slug is required")
	}

	// Check if email already exists
	existing, err := s.principalSvc.GetByIdentifier(ctx, input.Email)
	if err == nil && existing != nil {
		return nil, fmt.Errorf("user with email %s already exists", input.Email)
	}

	// Check if slug is available
	_, err = s.orgSvc.GetBySlug(ctx, input.PersonalOrgSlug)
	if err == nil {
		return nil, fmt.Errorf("slug %s is already taken", input.PersonalOrgSlug)
	}

	// Start transaction
	tx, err := s.client.Tx(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to start transaction: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	// Create human principal
	humanPrincipal, err := s.principalSvc.CreateHuman(ctx, principal.CreateHumanInput{
		Email:         input.Email,
		DisplayName:   input.DisplayName,
		GivenName:     input.GivenName,
		FamilyName:    input.FamilyName,
		AvatarURL:     input.AvatarURL,
		Locale:        input.Locale,
		Timezone:      input.Timezone,
		AllowedScopes: []string{"openid", "profile", "email"},
		Metadata:      input.Metadata,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Determine personal org name
	orgName := input.PersonalOrgName
	if orgName == "" {
		orgName = input.DisplayName
	}

	// Create personal organization (this also creates the owner membership)
	personalOrg, err := s.orgSvc.CreatePersonalOrg(ctx, organization.CreatePersonalOrgInput{
		OwnerPrincipalID: humanPrincipal.ID,
		Name:             orgName,
		Slug:             input.PersonalOrgSlug,
		LogoURL:          input.AvatarURL,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create personal organization: %w", err)
	}

	// Get the membership that was created
	membership, err := s.orgSvc.GetMembership(ctx, personalOrg.ID, humanPrincipal.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get owner membership: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit: %w", err)
	}

	return &SignupResult{
		Principal:            humanPrincipal,
		PersonalOrganization: personalOrg,
		Membership:           membership,
	}, nil
}

// SignupWithInvite creates a new user, their personal org, and accepts an invite.
func (s *DefaultService) SignupWithInvite(ctx context.Context, input AcceptInviteOnSignupInput) (*AcceptInviteOnSignupResult, error) {
	// Get the invite first to validate it
	inv, err := s.inviteSvc.GetByToken(ctx, input.InviteToken)
	if err != nil {
		return nil, fmt.Errorf("invalid invite token: %w", err)
	}

	// Check invite is still valid
	if !inv.CanAccept() {
		return nil, fmt.Errorf("invite is no longer valid (status: %s)", inv.Status)
	}

	// Check email matches if we want to enforce that
	// For now, we allow any email to accept an invite (GitHub style)

	// First, do the standard signup
	result, err := s.Signup(ctx, input.SignupInput)
	if err != nil {
		return nil, err
	}

	// Accept the invite to join the organization
	_, err = s.inviteSvc.Accept(ctx, invite.AcceptInviteInput{
		Token:       input.InviteToken,
		PrincipalID: result.Principal.ID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to accept invite: %w", err)
	}

	return &AcceptInviteOnSignupResult{
		SignupResult:          *result,
		InvitedOrganizationID: inv.OrganizationID,
		InvitedRole:           inv.Role,
	}, nil
}

// SignupOrGetExisting handles OAuth login - gets existing user or creates new one.
func (s *DefaultService) SignupOrGetExisting(ctx context.Context, input SignupInput) (*SignupResult, bool, error) {
	// Try to find existing user by email
	existing, err := s.principalSvc.GetByIdentifier(ctx, input.Email)
	if err == nil && existing != nil {
		// User exists, get their personal org
		personalOrg, err := s.orgSvc.GetPersonalOrg(ctx, existing.ID)
		if err != nil {
			// User exists but doesn't have a personal org (shouldn't happen but handle it)
			return &SignupResult{
				Principal: existing,
			}, false, nil
		}

		// Get the owner membership
		memberships, err := s.orgSvc.ListMembers(ctx, personalOrg.ID)
		if err != nil {
			return nil, false, fmt.Errorf("failed to get memberships: %w", err)
		}

		var ownerMembership *organization.Membership
		for _, m := range memberships {
			if m.PrincipalID == existing.ID && m.Role == organization.RoleOwner {
				ownerMembership = m
				break
			}
		}

		return &SignupResult{
			Principal:            existing,
			PersonalOrganization: personalOrg,
			Membership:           ownerMembership,
		}, false, nil
	}

	// User doesn't exist, create them
	result, err := s.Signup(ctx, input)
	if err != nil {
		return nil, false, err
	}

	return result, true, nil
}
