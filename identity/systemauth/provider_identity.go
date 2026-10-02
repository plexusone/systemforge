package systemauth

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

// EmbeddedIdentityProvider implements IdentityProvider using the embedded storage.
type EmbeddedIdentityProvider struct {
	storage Storage
}

// NewEmbeddedIdentityProvider creates an IdentityProvider backed by SystemAuth storage.
func NewEmbeddedIdentityProvider(storage Storage) *EmbeddedIdentityProvider {
	return &EmbeddedIdentityProvider{storage: storage}
}

// CreateIdentity implements IdentityProvider.
func (p *EmbeddedIdentityProvider) CreateIdentity(ctx context.Context, identity *Identity) error {
	if identity.ID == uuid.Nil {
		identity.ID = uuid.New()
	}

	now := time.Now()
	user := &User{
		ID:            identity.ID,
		Email:         identity.Traits.Email,
		EmailVerified: identity.Traits.EmailVerified,
		Name:          identity.Traits.Name,
		GivenName:     identity.Traits.GivenName,
		FamilyName:    identity.Traits.FamilyName,
		Picture:       identity.Traits.Picture,
		Locale:        identity.Traits.Locale,
		Active:        identity.State == IdentityStateActive,
		Metadata:      identity.Metadata,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	return p.storage.CreateUser(ctx, user)
}

// GetIdentity implements IdentityProvider.
func (p *EmbeddedIdentityProvider) GetIdentity(ctx context.Context, id uuid.UUID) (*Identity, error) {
	user, err := p.storage.GetUserByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return userToIdentity(user), nil
}

// GetIdentityByEmail implements IdentityProvider.
func (p *EmbeddedIdentityProvider) GetIdentityByEmail(ctx context.Context, email string) (*Identity, error) {
	user, err := p.storage.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	return userToIdentity(user), nil
}

// UpdateIdentity implements IdentityProvider.
func (p *EmbeddedIdentityProvider) UpdateIdentity(ctx context.Context, identity *Identity) error {
	user := &User{
		ID:            identity.ID,
		Email:         identity.Traits.Email,
		EmailVerified: identity.Traits.EmailVerified,
		Name:          identity.Traits.Name,
		GivenName:     identity.Traits.GivenName,
		FamilyName:    identity.Traits.FamilyName,
		Picture:       identity.Traits.Picture,
		Locale:        identity.Traits.Locale,
		Active:        identity.State == IdentityStateActive,
		Metadata:      identity.Metadata,
		UpdatedAt:     time.Now(),
	}

	return p.storage.UpdateUser(ctx, user)
}

// DeleteIdentity implements IdentityProvider.
func (p *EmbeddedIdentityProvider) DeleteIdentity(ctx context.Context, id uuid.UUID) error {
	return p.storage.DeleteUser(ctx, id)
}

// ListIdentities implements IdentityProvider.
// Note: The embedded storage doesn't support listing, so this returns an error.
func (p *EmbeddedIdentityProvider) ListIdentities(ctx context.Context, filter *IdentityFilter) ([]*Identity, error) {
	return nil, errors.New("listing identities not supported in embedded storage")
}

// userToIdentity converts a User to an Identity.
func userToIdentity(user *User) *Identity {
	state := IdentityStateActive
	if !user.Active {
		state = IdentityStateInactive
	}

	return &Identity{
		ID:    user.ID,
		State: state,
		Traits: IdentityTraits{
			Email:         user.Email,
			EmailVerified: user.EmailVerified,
			Name:          user.Name,
			GivenName:     user.GivenName,
			FamilyName:    user.FamilyName,
			Picture:       user.Picture,
			Locale:        user.Locale,
		},
		Metadata:  user.Metadata,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}
}

// Ensure EmbeddedIdentityProvider implements IdentityProvider.
var _ IdentityProvider = (*EmbeddedIdentityProvider)(nil)
