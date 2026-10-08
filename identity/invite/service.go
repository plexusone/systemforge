package invite

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/invite"
	"github.com/plexusone/systemforge/identity/ent/principalmembership"
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
	client  *ent.Client
	baseURL string // Base URL for invite links
}

// NewService creates a new invite service.
func NewService(client *ent.Client, baseURL string) Service {
	return &DefaultService{
		client:  client,
		baseURL: baseURL,
	}
}

// Create creates a new invite.
func (s *DefaultService) Create(ctx context.Context, input CreateInviteInput) (*InviteResult, error) {
	// Check for existing pending invite
	hasPending, err := s.HasPendingInvite(ctx, input.OrganizationID, input.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing invites: %w", err)
	}
	if hasPending {
		return nil, fmt.Errorf("pending invite already exists for this email")
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

	inv, err := create.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create invite: %w", err)
	}

	return &InviteResult{
		Invite:    entInviteToModel(inv),
		InviteURL: s.buildInviteURL(token),
	}, nil
}

// GetByToken retrieves an invite by its token.
func (s *DefaultService) GetByToken(ctx context.Context, token string) (*Invite, error) {
	inv, err := s.client.Invite.Query().
		Where(invite.Token(hashToken(token))).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, fmt.Errorf("invite not found")
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
			return nil, fmt.Errorf("invite not found: %s", id)
		}
		return nil, fmt.Errorf("failed to get invite: %w", err)
	}
	return entInviteToModel(inv), nil
}

// Accept accepts an invite and creates the membership.
func (s *DefaultService) Accept(ctx context.Context, input AcceptInviteInput) (*Invite, error) {
	// Get invite
	inv, err := s.client.Invite.Query().
		Where(invite.Token(hashToken(input.Token))).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, fmt.Errorf("invite not found")
		}
		return nil, fmt.Errorf("failed to get invite: %w", err)
	}

	// Check status
	if inv.Status != invite.StatusPending {
		return nil, fmt.Errorf("invite is no longer pending (status: %s)", inv.Status)
	}

	// Check expiry
	if time.Now().After(inv.ExpiresAt) {
		// Mark as expired
		_, _ = s.client.Invite.UpdateOne(inv).
			SetStatus(invite.StatusExpired).
			Save(ctx)
		return nil, fmt.Errorf("invite has expired")
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
	if exists {
		return nil, fmt.Errorf("principal is already a member of this organization")
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

	// Update invite status
	now := time.Now()
	inv, err = tx.Invite.UpdateOne(inv).
		SetStatus(invite.StatusAccepted).
		SetAcceptedAt(now).
		SetAcceptedByPrincipalID(input.PrincipalID).
		Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to update invite: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit: %w", err)
	}

	return entInviteToModel(inv), nil
}

// Decline declines an invite.
func (s *DefaultService) Decline(ctx context.Context, token string) (*Invite, error) {
	inv, err := s.client.Invite.Query().
		Where(invite.Token(hashToken(token))).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, fmt.Errorf("invite not found")
		}
		return nil, fmt.Errorf("failed to get invite: %w", err)
	}

	if inv.Status != invite.StatusPending {
		return nil, fmt.Errorf("invite is no longer pending")
	}

	inv, err = s.client.Invite.UpdateOne(inv).
		SetStatus(invite.StatusDeclined).
		Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to decline invite: %w", err)
	}

	return entInviteToModel(inv), nil
}

// Revoke revokes an invite.
func (s *DefaultService) Revoke(ctx context.Context, id uuid.UUID) error {
	_, err := s.client.Invite.UpdateOneID(id).
		SetStatus(invite.StatusRevoked).
		Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return fmt.Errorf("invite not found: %s", id)
		}
		return fmt.Errorf("failed to revoke invite: %w", err)
	}
	return nil
}

// Resend resends an invite with a new token.
func (s *DefaultService) Resend(ctx context.Context, id uuid.UUID) (*InviteResult, error) {
	inv, err := s.client.Invite.Get(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, fmt.Errorf("invite not found: %s", id)
		}
		return nil, fmt.Errorf("failed to get invite: %w", err)
	}

	if inv.Status != invite.StatusPending {
		return nil, fmt.Errorf("can only resend pending invites")
	}

	// Generate new token
	token, err := generateToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	// Update invite
	inv, err = s.client.Invite.UpdateOne(inv).
		SetToken(hashToken(token)).
		SetResendCount(inv.ResendCount + 1).
		SetLastSentAt(time.Now()).
		SetExpiresAt(time.Now().Add(DefaultInviteExpiry)). // Reset expiry
		Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to update invite: %w", err)
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

	return model
}
