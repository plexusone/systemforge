package signup

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/human"
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
	if err := validateEmail(input.Email); err != nil {
		return nil, err
	}
	if input.DisplayName == "" {
		return nil, fmt.Errorf("display name is required")
	}
	if input.PersonalOrgSlug == "" {
		return nil, fmt.Errorf("personal org slug is required")
	}

	// Check if email already exists
	if _, err := s.principalSvc.GetByIdentifier(ctx, input.Email); err == nil {
		return nil, fmt.Errorf("%w: %s", ErrEmailTaken, input.Email)
	} else if !errors.Is(err, principal.ErrNotFound) {
		return nil, fmt.Errorf("failed to check email: %w", err)
	}

	// Check if slug is available
	if _, err := s.orgSvc.GetBySlug(ctx, input.PersonalOrgSlug); err == nil {
		return nil, fmt.Errorf("slug %s is already taken", input.PersonalOrgSlug)
	}

	humanInput := principal.CreateHumanInput{
		Email:         input.Email,
		DisplayName:   input.DisplayName,
		GivenName:     input.GivenName,
		FamilyName:    input.FamilyName,
		AvatarURL:     input.AvatarURL,
		Locale:        input.Locale,
		Timezone:      input.Timezone,
		AllowedScopes: []string{"openid", "profile", "email"},
		Metadata:      input.Metadata,
	}

	// Determine personal org name
	orgName := input.PersonalOrgName
	if orgName == "" {
		orgName = input.DisplayName
	}
	orgInput := organization.CreatePersonalOrgInput{
		Name:    orgName,
		Slug:    input.PersonalOrgSlug,
		LogoURL: input.AvatarURL,
	}

	// With services that can write inside a caller's transaction (the
	// default ones), the principal, the organization and the owner
	// membership commit together and a failure leaves nothing behind.
	humanTx, humanOK := s.principalSvc.(principal.HumanTxCreator)
	orgTx, orgOK := s.orgSvc.(organization.PersonalOrgTxCreator)
	if humanOK && orgOK && s.client != nil {
		return s.signupInTx(ctx, humanTx, orgTx, humanInput, orgInput, input.EmailVerified)
	}
	return s.signupSeparately(ctx, humanInput, orgInput, input.EmailVerified)
}

// emailVerificationMarker is implemented by principal services that can
// record a verified email, such as principal.DefaultService.
type emailVerificationMarker interface {
	MarkEmailVerified(ctx context.Context, id uuid.UUID) error
}

// signupInTx creates the principal, personal organization and owner
// membership in one transaction, then registers them with the authorization
// syncers. Registration runs after the commit, so a rolled-back signup is
// never synced; in strict sync mode a failed registration is returned with
// the rows already committed.
func (s *DefaultService) signupInTx(
	ctx context.Context,
	humanTx principal.HumanTxCreator,
	orgTx organization.PersonalOrgTxCreator,
	humanInput principal.CreateHumanInput,
	orgInput organization.CreatePersonalOrgInput,
	emailVerified bool,
) (*SignupResult, error) {
	tx, err := s.client.Tx(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to start transaction: %w", err)
	}
	rollback := func(cause error) error {
		if rbErr := tx.Rollback(); rbErr != nil {
			return errors.Join(cause, fmt.Errorf("rolling back signup: %w", rbErr))
		}
		return cause
	}

	humanPrincipal, syncPrincipal, err := humanTx.CreateHumanInTx(ctx, tx, humanInput)
	if err != nil {
		return nil, rollback(fmt.Errorf("failed to create user: %w", err))
	}
	if emailVerified {
		now := time.Now()
		if err := tx.Human.Update().Where(human.PrincipalID(humanPrincipal.ID)).SetEmailVerifiedAt(now).Exec(ctx); err != nil {
			return nil, rollback(fmt.Errorf("failed to record verified email: %w", err))
		}
		if humanPrincipal.Human != nil {
			humanPrincipal.Human.EmailVerifiedAt = &now
		}
	}
	orgInput.OwnerPrincipalID = humanPrincipal.ID
	personalOrg, membership, syncOrg, err := orgTx.CreatePersonalOrgInTx(ctx, tx, orgInput)
	if err != nil {
		return nil, rollback(fmt.Errorf("failed to create personal organization: %w", err))
	}
	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit signup: %w", err)
	}

	if err = syncPrincipal(ctx); err != nil {
		return nil, err
	}
	if err = syncOrg(ctx); err != nil {
		return nil, err
	}
	return &SignupResult{
		Principal:            humanPrincipal,
		PersonalOrganization: personalOrg,
		Membership:           membership,
	}, nil
}

// signupSeparately is the fallback for principal and organization services
// that cannot write inside a caller's transaction. They each commit their
// own, so a failure after the principal exists is undone by deleting it;
// otherwise a retry would find the email taken.
func (s *DefaultService) signupSeparately(ctx context.Context, humanInput principal.CreateHumanInput, orgInput organization.CreatePersonalOrgInput, emailVerified bool) (*SignupResult, error) {
	humanPrincipal, err := s.principalSvc.CreateHuman(ctx, humanInput)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}
	if emailVerified {
		if err := s.markEmailVerified(ctx, humanPrincipal); err != nil {
			return nil, errors.Join(err, s.deletePrincipal(ctx, humanPrincipal.ID))
		}
	}

	// Create personal organization (this also creates the owner membership)
	orgInput.OwnerPrincipalID = humanPrincipal.ID
	personalOrg, err := s.orgSvc.CreatePersonalOrg(ctx, orgInput)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("failed to create personal organization: %w", err), s.deletePrincipal(ctx, humanPrincipal.ID))
	}

	// Get the membership that was created
	membership, err := s.orgSvc.GetMembership(ctx, personalOrg.ID, humanPrincipal.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get owner membership: %w", err)
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

	// The invite was sent to one address; holding its link does not let
	// someone sign up under another and join the organization.
	if !strings.EqualFold(inv.Email, input.Email) {
		return nil, ErrInviteEmailMismatch
	}

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

	// The invite token was delivered to this address, and the address
	// matches the invite, so holding it shows the person controls the
	// address. Without this the new member's own invitations would stay
	// hidden from them, since listing and answering them needs a verified
	// email.
	if _, err := s.client.Human.Update().
		Where(human.PrincipalIDEQ(result.Principal.ID), human.EmailVerifiedAtIsNil()).
		SetEmailVerifiedAt(time.Now()).
		Save(ctx); err != nil {
		return nil, fmt.Errorf("failed to mark email verified: %w", err)
	}

	return &AcceptInviteOnSignupResult{
		SignupResult:          *result,
		InvitedOrganizationID: inv.OrganizationID,
		InvitedRole:           inv.Role,
	}, nil
}

// SignupOrGetExisting handles OAuth login - gets existing user or creates new one.
func (s *DefaultService) SignupOrGetExisting(ctx context.Context, input SignupInput) (*SignupResult, bool, error) {
	// The lookup is by identifier, which for a managed principal is
	// human:<id>, so only a real address may be looked up.
	if err := validateEmail(input.Email); err != nil {
		return nil, false, err
	}
	// Try to find existing user by email
	existing, err := s.principalSvc.GetByIdentifier(ctx, input.Email)
	if err != nil && !errors.Is(err, principal.ErrNotFound) {
		return nil, false, fmt.Errorf("failed to look up email: %w", err)
	}
	if err == nil {
		// Returning an account for an unverified address would let anyone
		// who claims it sign in as its owner.
		if !input.EmailVerified {
			return nil, false, ErrEmailNotVerified
		}
		// Nor may a verified login take over an account whose own email
		// was never proven: whoever registered it, possibly before the
		// address's owner, could still hold its other credentials.
		if existing.Human == nil || existing.Human.EmailVerifiedAt == nil {
			return nil, false, ErrAccountEmailUnverified
		}
		// User exists, get their personal org
		personalOrg, err := s.orgSvc.GetPersonalOrg(ctx, existing.ID)
		if err != nil {
			// User exists but doesn't have a personal org (shouldn't happen but handle it)
			return &SignupResult{
				Principal: existing,
			}, false, nil
		}

		// Get the owner membership
		// Include inactive memberships: the result reports the stored owner
		// membership whatever its status.
		memberships, err := s.orgSvc.ListMembers(ctx, personalOrg.ID, organization.IncludeInactive())
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

// ErrInvalidEmail is returned for a signup email that is not a plain
// address.
var ErrInvalidEmail = errors.New("signup: invalid email address")

// ErrEmailTaken is returned when signing up with an email that already
// has an account.
var ErrEmailTaken = errors.New("signup: email already has an account")

// ErrEmailNotVerified is returned by SignupOrGetExisting when an account
// exists for an email the caller has not verified.
var ErrEmailNotVerified = errors.New("signup: email not verified; cannot sign in to the existing account")

// ErrAccountEmailUnverified is returned by SignupOrGetExisting when an
// account exists for the email but its own email was never verified. The
// verified login is not linked to it: the account's holder must sign in
// with its existing credentials and verify the address first.
var ErrAccountEmailUnverified = errors.New("signup: the existing account's email is not verified; cannot sign in to it with this login")

// ErrInviteEmailMismatch is returned when signing up with an invite under
// an email other than the one invited.
var ErrInviteEmailMismatch = errors.New("signup: email does not match the invite")

// deletePrincipal removes a principal created by a signup that failed
// afterwards.
func (s *DefaultService) deletePrincipal(ctx context.Context, id uuid.UUID) error {
	if _, err := s.client.Human.Delete().Where(human.PrincipalID(id)).Exec(ctx); err != nil {
		return fmt.Errorf("undoing signup: deleting human: %w", err)
	}
	if err := s.client.Principal.DeleteOneID(id).Exec(ctx); err != nil {
		return fmt.Errorf("undoing signup: deleting principal: %w", err)
	}
	return nil
}

// markEmailVerified records that p's email is verified, through the
// principal service when it can, else directly in the database.
func (s *DefaultService) markEmailVerified(ctx context.Context, p *principal.Principal) error {
	now := time.Now()
	switch m, ok := s.principalSvc.(emailVerificationMarker); {
	case ok:
		if err := m.MarkEmailVerified(ctx, p.ID); err != nil {
			return fmt.Errorf("failed to record verified email: %w", err)
		}
	case s.client != nil:
		if err := s.client.Human.Update().Where(human.PrincipalID(p.ID)).SetEmailVerifiedAt(now).Exec(ctx); err != nil {
			return fmt.Errorf("failed to record verified email: %w", err)
		}
	default:
		return errors.New("signup: the principal service cannot record a verified email")
	}
	if p.Human != nil {
		p.Human.EmailVerifiedAt = &now
	}
	return nil
}

// validateEmail requires a bare address such as kim@example.com. Signup
// looks principals up by identifier, so this also keeps a managed
// principal's human:<id> identifier from matching.
func validateEmail(email string) error {
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email {
		return ErrInvalidEmail
	}
	return nil
}
