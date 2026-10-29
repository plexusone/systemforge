package invite

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/authz/noop"
	"github.com/plexusone/systemforge/identity/approle"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/invite"
	"github.com/plexusone/systemforge/identity/ent/principalmembership"
	"github.com/plexusone/systemforge/identity/graphlock"
	"github.com/plexusone/systemforge/identity/graphstate"
	"github.com/plexusone/systemforge/identity/organization"
	"github.com/plexusone/systemforge/identity/resourcegrant"
)

// Service defines the invite service interface.
type Service interface {
	// Create creates a new invite.
	Create(ctx context.Context, input CreateInviteInput) (*InviteResult, error)

	// GetByToken retrieves an invite by its token.
	GetByToken(ctx context.Context, token string) (*Invite, error)

	// GetByID retrieves an invite by ID.
	GetByID(ctx context.Context, id uuid.UUID) (*Invite, error)

	// Accept accepts an invite and creates the membership.
	Accept(ctx context.Context, input AcceptInviteInput) (*Invite, error)

	// Decline declines an invite.
	Decline(ctx context.Context, token string) (*Invite, error)

	// Revoke revokes an invite.
	Revoke(ctx context.Context, id uuid.UUID) error

	// Resend resends an invite with a new token.
	Resend(ctx context.Context, id uuid.UUID) (*InviteResult, error)

	// List lists invites with optional filters.
	List(ctx context.Context, input ListInvitesInput) ([]*Invite, error)

	// ListPendingForEmail lists pending invites for an email address.
	ListPendingForEmail(ctx context.Context, email string) ([]*Invite, error)

	// ExpireOld expires invites that have passed their expiration time.
	ExpireOld(ctx context.Context) (int, error)

	// HasPendingInvite checks if there's already a pending invite for this email/org.
	HasPendingInvite(ctx context.Context, organizationID uuid.UUID, email string) (bool, error)
}

// DefaultService implements the Service interface.
type DefaultService struct {
	client   *ent.Client
	baseURL  string // Base URL for invite links
	syncer   authz.RelationshipSyncer
	syncMode authz.SyncMode
	logger   *slog.Logger
	appRoles *approle.Service
	grants   *resourcegrant.Service
	// authorizer, when set, decides whether an invite's inviter still
	// holds the authority the invite carries.
	authorizer authz.Authorizer
}

// ServiceOption configures a DefaultService.
type ServiceOption func(*DefaultService)

// WithAuthzSyncer sets the authorization syncer used to register accepted
// memberships in the authorization graph.
func WithAuthzSyncer(syncer authz.RelationshipSyncer) ServiceOption {
	return func(s *DefaultService) { s.syncer = syncer }
}

// WithSyncMode sets the sync mode (strict or eventual).
func WithSyncMode(mode authz.SyncMode) ServiceOption {
	return func(s *DefaultService) { s.syncMode = mode }
}

// WithAppRoles lets invitations carry application roles: Create validates
// them and Accept grants them in the same transaction as the membership.
// Without it, an invitation's AppRoles are rejected.
func WithAppRoles(svc *approle.Service) ServiceOption {
	return func(s *DefaultService) { s.appRoles = svc }
}

// WithResourceGrants lets invitations target a resource (ADR-008): Create
// validates the target against the grant service's rules and Accept
// creates the collaborator membership and the grant in one transaction,
// through the service's GrantInTx. Without it, a resource target is
// refused. Memberships are written to the authorization graph through this
// service's own syncer, grants through the grant service's.
func WithResourceGrants(svc *resourcegrant.Service) ServiceOption {
	return func(s *DefaultService) { s.grants = svc }
}

// WithAuthorizer makes Accept ask authorizer whether an invite's inviter
// still holds authz.PermOrgInviteMember on the organization (and the
// owner-only authz.PermOrgDelete for an owner invite), the permissions the
// API required to create it. Use it when invitations may be created by
// principals whose authority is not an organization membership, such as
// platform administrators. Without it, the inviter must hold an active
// membership whose role grants those permissions (authz.OrgRoleAllows).
func WithAuthorizer(a authz.Authorizer) ServiceOption {
	return func(s *DefaultService) { s.authorizer = a }
}

// WithLogger sets the logger for the service.
func WithLogger(logger *slog.Logger) ServiceOption {
	return func(s *DefaultService) { s.logger = logger }
}

// NewService creates a new invite service.
func NewService(client *ent.Client, baseURL string, opts ...ServiceOption) Service {
	s := &DefaultService{
		client:   client,
		baseURL:  baseURL,
		syncer:   noop.NewSyncer(),
		syncMode: authz.SyncModeEventual,
		logger:   slog.Default(),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Create creates a new invite.
func (s *DefaultService) Create(ctx context.Context, input CreateInviteInput) (*InviteResult, error) {
	if err := organization.RequireMembersAllowed(ctx, s.client, input.OrganizationID, input.Role); err != nil {
		return nil, err
	}
	if err := s.validateResourceTarget(ctx, input); err != nil {
		return nil, err
	}

	if err := s.validateAppRoles(ctx, input); err != nil {
		return nil, err
	}

	// Check for existing pending invite: one per email for the
	// organization, and one per email for each resource.
	hasPending, err := s.hasPendingFor(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing invites: %w", err)
	}
	if hasPending {
		return nil, ErrPendingInviteExists
	}

	// Check if user is already a member
	// This would require checking if there's a principal with this email who's already a member
	// We'll skip this check for now and let the Accept flow handle it

	// Generate secure token
	token, err := generateToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	// Calculate expiry
	expiry := input.ExpiresIn
	if expiry == 0 {
		expiry = DefaultInviteExpiry
	}
	expiresAt := time.Now().Add(expiry)

	// Create invite
	create := s.client.Invite.Create().
		SetOrganizationID(input.OrganizationID).
		SetInviterPrincipalID(input.InviterPrincipalID).
		SetEmail(input.Email).
		SetRole(input.Role).
		SetToken(hashToken(token)).
		SetStatus(invite.StatusPending).
		SetExpiresAt(expiresAt).
		SetLastSentAt(time.Now())

	if input.Message != nil {
		create.SetMessage(*input.Message)
	}
	if len(input.AppRoles) > 0 {
		create.SetAppRoles(input.AppRoles)
	}
	if input.ResourceType != "" {
		create.SetResourceType(input.ResourceType).
			SetResourceID(input.ResourceID).
			SetResourceRole(input.ResourceRole)
	}

	inv, err := create.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create invite: %w", err)
	}

	return &InviteResult{
		Invite:    entInviteToModel(inv),
		InviteURL: s.buildInviteURL(token),
	}, nil
}

// validateResourceTarget checks the resource target of a new invitation:
// complete, for a collaborator, valid for the grant service, and present
// when the organization is personal.
func (s *DefaultService) validateResourceTarget(ctx context.Context, input CreateInviteInput) error {
	if input.ResourceType == "" && input.ResourceID == "" && input.ResourceRole == "" {
		if input.Role != organization.RoleCollaborator {
			return nil
		}
		personal, err := organization.IsPersonal(ctx, s.client, input.OrganizationID)
		if err != nil {
			return err
		}
		if personal {
			return fmt.Errorf("%w: a personal organization accepts only resource-targeted invites", organization.ErrPersonalOrganization)
		}
		return nil
	}
	if input.ResourceType == "" || input.ResourceID == "" || input.ResourceRole == "" {
		return fmt.Errorf("%w: resource type, id and role are given together", ErrResourceInvite)
	}
	if input.Role != organization.RoleCollaborator {
		return fmt.Errorf("%w: a resource invite is for a collaborator, not %q", ErrResourceInvite, input.Role)
	}
	if s.grants == nil {
		return fmt.Errorf("%w: resource grants are not configured", ErrResourceInvite)
	}
	return s.grants.Validate(authz.ResourceRef{Type: input.ResourceType, ID: input.ResourceID, OrganizationID: input.OrganizationID}, input.ResourceRole)
}

// hasPendingFor reports whether a pending invite blocks input: for an
// organization invite, any pending invite of the email to the
// organization; for a resource invite, a pending invite of the email to
// the same resource, since one person may be invited to several.
func (s *DefaultService) hasPendingFor(ctx context.Context, input CreateInviteInput) (bool, error) {
	q := s.client.Invite.Query().
		Where(
			invite.OrganizationID(input.OrganizationID),
			invite.EmailEqualFold(input.Email),
			invite.StatusEQ(invite.StatusPending),
			invite.ExpiresAtGT(time.Now()),
		)
	if input.ResourceType != "" {
		q = q.Where(invite.ResourceType(input.ResourceType), invite.ResourceID(input.ResourceID))
	} else {
		q = q.Where(invite.ResourceTypeIsNil())
	}
	return q.Exist(ctx)
}

// validateAppRoles checks the application roles of a new invitation.
func (s *DefaultService) validateAppRoles(ctx context.Context, input CreateInviteInput) error {
	if len(input.AppRoles) > 0 {
		if s.appRoles == nil {
			return ErrAppRolesNotConfigured
		}
		if input.Role == organization.RoleCollaborator {
			return ErrCollaboratorAppRoles
		}
		return s.appRoles.ValidateRoles(ctx, input.OrganizationID, input.AppRoles)
	}
	if s.appRoles == nil || (input.Role != organization.RoleAdmin && input.Role != organization.RoleMember) {
		return nil
	}
	apps, err := s.appRoles.EntitledApplications(ctx, input.OrganizationID)
	if err != nil {
		return err
	}
	if len(apps) > 0 {
		return ErrAppRoleRequired
	}
	return nil
}

// GetByToken retrieves an invite by its token.
func (s *DefaultService) GetByToken(ctx context.Context, token string) (*Invite, error) {
	inv, err := s.client.Invite.Query().
		Where(invite.Token(hashToken(token))).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrInviteNotFound
		}
		return nil, fmt.Errorf("failed to get invite: %w", err)
	}
	return entInviteToModel(inv), nil
}

// GetByID retrieves an invite by ID.
func (s *DefaultService) GetByID(ctx context.Context, id uuid.UUID) (*Invite, error) {
	inv, err := s.client.Invite.Get(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, fmt.Errorf("%w: %s", ErrInviteNotFound, id)
		}
		return nil, fmt.Errorf("failed to get invite: %w", err)
	}
	return entInviteToModel(inv), nil
}

// Accept accepts an invite and creates the membership.
//
// The invite must still be pending and unexpired when the acceptance is
// written: the status change is a conditional update in the same
// transaction as the membership, so an invite revoked or declined while it
// is being accepted is not accepted. The inviter must still be allowed to
// invite to the organization, and to invite an owner when the invite is
// for one; otherwise Accept returns ErrInviterNotAuthorized.
func (s *DefaultService) Accept(ctx context.Context, input AcceptInviteInput) (*Invite, error) {
	// Get invite
	inv, err := s.client.Invite.Query().
		Where(invite.Token(hashToken(input.Token))).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrInviteNotFound
		}
		return nil, fmt.Errorf("failed to get invite: %w", err)
	}

	// Check status
	if inv.Status != invite.StatusPending {
		return nil, fmt.Errorf("%w (status: %s)", ErrNotPending, inv.Status)
	}

	// Check expiry
	if time.Now().After(inv.ExpiresAt) {
		if err := s.markExpired(ctx, inv.ID); err != nil {
			return nil, err
		}
		return nil, ErrExpired
	}

	// An organization may have become personal after the invite was sent.
	if err = organization.RequireMembersAllowed(ctx, s.client, inv.OrganizationID, inv.Role); err != nil {
		return nil, err
	}

	// With an authorizer, the inviter's authority is asked of it.
	if s.authorizer != nil {
		if err = s.checkInviterWithAuthorizer(ctx, inv); err != nil {
			return nil, err
		}
	}

	// Start transaction
	tx, err := s.client.Tx(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to start transaction: %w", err)
	}
	defer func() {
		if err != nil {
			if rerr := tx.Rollback(); rerr != nil {
				s.logger.ErrorContext(ctx, "invite: rolling back acceptance", "invite_id", inv.ID, "error", rerr)
			}
		}
	}()

	// Without an authorizer, the inviter's authority is its active
	// membership role, read in this transaction.
	if s.authorizer == nil {
		if err = requireInviterMembership(ctx, tx.Client(), inv); err != nil {
			return nil, err
		}
	}

	// Check if already a member
	exists, err := tx.PrincipalMembership.Query().
		Where(
			principalmembership.OrganizationID(inv.OrganizationID),
			principalmembership.PrincipalID(input.PrincipalID),
		).
		Exist(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to check membership: %w", err)
	}
	resourceInvite := inv.ResourceType != nil && inv.ResourceID != nil && inv.ResourceRole != nil
	var afterCommit []func(context.Context) error
	membershipCreated := !exists
	if resourceInvite {
		// The collaborator membership and the grant are written together
		// by the grant service, in this transaction. A principal who is
		// already a member keeps their membership and gains the grant.
		if s.grants == nil {
			err = fmt.Errorf("%w: resource grants are not configured", ErrResourceInvite)
			return nil, err
		}
		var after func(context.Context) error
		after, err = s.grants.GrantInTx(ctx, tx, input.PrincipalID,
			authz.ResourceRef{Type: *inv.ResourceType, ID: *inv.ResourceID, OrganizationID: inv.OrganizationID},
			*inv.ResourceRole, inv.InviterPrincipalID)
		if err != nil {
			return nil, fmt.Errorf("failed to grant %s on %s: %w", *inv.ResourceRole, *inv.ResourceType, err)
		}
		afterCommit = append(afterCommit, after)
	} else {
		if exists {
			err = ErrAlreadyMember
			return nil, err
		}

		// Create membership
		_, err = tx.PrincipalMembership.Create().
			SetOrganizationID(inv.OrganizationID).
			SetPrincipalID(input.PrincipalID).
			SetRole(inv.Role).
			SetActive(true).
			Save(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create membership: %w", err)
		}
	}

	// Grant the application roles the inviter chose, in the same
	// transaction: an invitation that cannot grant them (no seat left, the
	// entitlement gone) is not accepted.
	if len(inv.AppRoles) > 0 {
		if s.appRoles == nil {
			err = ErrAppRolesNotConfigured
			return nil, err
		}
		for _, app := range sortedApps(inv.AppRoles) {
			var after func(context.Context) error
			_, after, err = s.appRoles.AssignInTx(ctx, tx, approle.AssignInput{
				OrganizationID: inv.OrganizationID,
				PrincipalID:    input.PrincipalID,
				Application:    app,
				Role:           inv.AppRoles[app],
				AssignedBy:     inv.InviterPrincipalID,
			})
			if err != nil {
				return nil, fmt.Errorf("failed to grant %s role: %w", app, err)
			}
			afterCommit = append(afterCommit, after)
		}
	}

	// Update invite status, only while it is still pending and
	// unexpired: a revoke, decline or acceptance that committed first
	// wins.
	now := time.Now()
	n, err := tx.Invite.Update().
		Where(
			invite.ID(inv.ID),
			invite.StatusEQ(invite.StatusPending),
			invite.ExpiresAtGT(now),
		).
		SetStatus(invite.StatusAccepted).
		SetAcceptedAt(now).
		SetAcceptedByPrincipalID(input.PrincipalID).
		Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to update invite: %w", err)
	}
	if n != 1 {
		err = ErrNotPending
		return nil, err
	}
	inv, err = tx.Invite.Get(ctx, inv.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to read invite: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit: %w", err)
	}

	// Sync the new membership to the authorization backend after commit.
	// A resource invite to an existing member created none.
	if membershipCreated {
		if syncErr := s.grantMembership(ctx, input.PrincipalID, inv.OrganizationID, inv.Role); syncErr != nil {
			if s.syncMode == authz.SyncModeStrict {
				return nil, fmt.Errorf("failed to sync membership to authz: %w", syncErr)
			}
			s.logger.Warn("failed to sync membership to authz",
				"principal_id", input.PrincipalID,
				"org_id", inv.OrganizationID,
				"role", inv.Role,
				"error", syncErr)
		}
	}

	for _, after := range afterCommit {
		if syncErr := after(ctx); syncErr != nil {
			return nil, syncErr
		}
	}

	return entInviteToModel(inv), nil
}

func sortedApps(roles map[string]string) []string {
	apps := make([]string, 0, len(roles))
	for app := range roles {
		apps = append(apps, app)
	}
	sort.Strings(apps)
	return apps
}

// Decline declines an invite. Only a pending invite can be declined.
func (s *DefaultService) Decline(ctx context.Context, token string) (*Invite, error) {
	inv, err := s.client.Invite.Query().
		Where(invite.Token(hashToken(token))).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrInviteNotFound
		}
		return nil, fmt.Errorf("failed to get invite: %w", err)
	}

	if err := s.transition(ctx, inv.ID, invite.StatusDeclined); err != nil {
		return nil, err
	}
	return s.GetByID(ctx, inv.ID)
}

// Revoke revokes an invite. Only a pending invite can be revoked; an
// accepted invite's membership is removed through the organization.
func (s *DefaultService) Revoke(ctx context.Context, id uuid.UUID) error {
	return s.transition(ctx, id, invite.StatusRevoked)
}

// transition moves a pending invite to status with a conditional update,
// so it never overwrites a transition that committed first.
func (s *DefaultService) transition(ctx context.Context, id uuid.UUID, status invite.Status) error {
	n, err := s.client.Invite.Update().
		Where(invite.ID(id), invite.StatusEQ(invite.StatusPending)).
		SetStatus(status).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("failed to set invite %s: %w", status, err)
	}
	if n == 1 {
		return nil
	}
	exists, err := s.client.Invite.Query().Where(invite.ID(id)).Exist(ctx)
	if err != nil {
		return fmt.Errorf("failed to get invite: %w", err)
	}
	if !exists {
		return fmt.Errorf("%w: %s", ErrInviteNotFound, id)
	}
	return ErrNotPending
}

// markExpired records that a pending invite has expired.
func (s *DefaultService) markExpired(ctx context.Context, id uuid.UUID) error {
	if _, err := s.client.Invite.Update().
		Where(invite.ID(id), invite.StatusEQ(invite.StatusPending)).
		SetStatus(invite.StatusExpired).
		Save(ctx); err != nil {
		return fmt.Errorf("failed to mark invite expired: %w", err)
	}
	return nil
}

// Resend resends an invite with a new token.
func (s *DefaultService) Resend(ctx context.Context, id uuid.UUID) (*InviteResult, error) {
	inv, err := s.client.Invite.Get(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, fmt.Errorf("%w: %s", ErrInviteNotFound, id)
		}
		return nil, fmt.Errorf("failed to get invite: %w", err)
	}

	if inv.Status != invite.StatusPending {
		return nil, fmt.Errorf("%w: can only resend pending invites", ErrNotPending)
	}

	// Generate new token
	token, err := generateToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	// Update invite, only while it is still pending.
	n, err := s.client.Invite.Update().
		Where(invite.ID(inv.ID), invite.StatusEQ(invite.StatusPending)).
		SetToken(hashToken(token)).
		SetResendCount(inv.ResendCount + 1).
		SetLastSentAt(time.Now()).
		SetExpiresAt(time.Now().Add(DefaultInviteExpiry)). // Reset expiry
		Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to update invite: %w", err)
	}
	if n != 1 {
		return nil, ErrNotPending
	}
	inv, err = s.client.Invite.Get(ctx, inv.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get invite: %w", err)
	}

	return &InviteResult{
		Invite:    entInviteToModel(inv),
		InviteURL: s.buildInviteURL(token),
	}, nil
}

// List lists invites with optional filters.
func (s *DefaultService) List(ctx context.Context, input ListInvitesInput) ([]*Invite, error) {
	query := s.client.Invite.Query()

	if input.OrganizationID != nil {
		query.Where(invite.OrganizationID(*input.OrganizationID))
	}
	if input.Email != nil {
		query.Where(invite.EmailEqualFold(*input.Email))
	}
	if input.Status != nil {
		query.Where(invite.StatusEQ(invite.Status(*input.Status)))
	}

	if input.Limit > 0 {
		query.Limit(input.Limit)
	}
	if input.Offset > 0 {
		query.Offset(input.Offset)
	}

	query.Order(ent.Desc(invite.FieldCreatedAt))

	invites, err := query.All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list invites: %w", err)
	}

	result := make([]*Invite, len(invites))
	for i, inv := range invites {
		result[i] = entInviteToModel(inv)
	}

	return result, nil
}

// ListPendingForEmail lists pending invites for an email address.
func (s *DefaultService) ListPendingForEmail(ctx context.Context, email string) ([]*Invite, error) {
	status := StatusPending
	return s.List(ctx, ListInvitesInput{
		Email:  &email,
		Status: &status,
	})
}

// ExpireOld expires invites that have passed their expiration time.
func (s *DefaultService) ExpireOld(ctx context.Context) (int, error) {
	count, err := s.client.Invite.Update().
		Where(
			invite.StatusEQ(invite.StatusPending),
			invite.ExpiresAtLT(time.Now()),
		).
		SetStatus(invite.StatusExpired).
		Save(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to expire old invites: %w", err)
	}
	return count, nil
}

// HasPendingInvite checks if there's already a pending invite for this email/org.
func (s *DefaultService) HasPendingInvite(ctx context.Context, organizationID uuid.UUID, email string) (bool, error) {
	return s.client.Invite.Query().
		Where(
			invite.OrganizationID(organizationID),
			invite.EmailEqualFold(email),
			invite.StatusEQ(invite.StatusPending),
			invite.ExpiresAtGT(time.Now()),
		).
		Exist(ctx)
}

// Helper functions

// hashToken returns the stored form of an invite token. Tokens carry 256
// bits of randomness, so an unsalted SHA-256 is enough to make a leaked
// table useless for accepting invites.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func generateToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func (s *DefaultService) buildInviteURL(token string) string {
	return fmt.Sprintf("%s/invites/%s", s.baseURL, token)
}

func entInviteToModel(inv *ent.Invite) *Invite {
	model := &Invite{
		ID:                 inv.ID,
		OrganizationID:     inv.OrganizationID,
		InviterPrincipalID: inv.InviterPrincipalID,
		Email:              inv.Email,
		Role:               inv.Role,
		AppRoles:           inv.AppRoles,
		Status:             Status(inv.Status),
		Message:            inv.Message,
		ExpiresAt:          inv.ExpiresAt,
		AcceptedAt:         inv.AcceptedAt,
		ResendCount:        inv.ResendCount,
		LastSentAt:         inv.LastSentAt,
		CreatedAt:          inv.CreatedAt,
		UpdatedAt:          inv.UpdatedAt,
	}

	if inv.AcceptedByPrincipalID != nil {
		model.AcceptedByPrincipalID = inv.AcceptedByPrincipalID
	}
	if inv.ResourceType != nil && inv.ResourceID != nil && inv.ResourceRole != nil {
		model.ResourceType, model.ResourceID, model.ResourceRole = *inv.ResourceType, *inv.ResourceID, *inv.ResourceRole
	}

	return model
}

// grantMembership writes an accepted invitation's membership to the
// authorization graph after the acceptance committed, holding the graph
// locks of the organization and the principal, and only if the membership
// still holds the role: a removal or demotion that committed in between is
// not undone. Without a graph (the no-op syncer) it does nothing.
func (s *DefaultService) grantMembership(ctx context.Context, principalID, orgID uuid.UUID, role string) error {
	if _, isNoop := s.syncer.(*noop.Syncer); isNoop {
		return nil
	}
	keys := []string{graphlock.Organization(orgID), graphlock.Principal(principalID)}
	return graphlock.Grant(ctx, s.client, keys, func(ctx context.Context, c *ent.Client) error {
		held, err := graphstate.Membership(ctx, c, orgID, principalID, role)
		if err != nil || !held {
			return err
		}
		return s.syncer.AddOrgMembership(ctx, principalID, orgID, role)
	})
}
