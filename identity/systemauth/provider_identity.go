package systemauth

import (
	"context"
	"errors"

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

	h := identityToHuman(identity)
	if err := p.storage.CreateHuman(ctx, h); err != nil {
		return err
	}
	identity.ID = h.ID
	return nil
}

// GetIdentity implements IdentityProvider.
func (p *EmbeddedIdentityProvider) GetIdentity(ctx context.Context, id uuid.UUID) (*Identity, error) {
	h, err := p.storage.GetHuman(ctx, id)
	if err != nil {
		return nil, err
	}
	return humanToIdentity(h), nil
}

// GetIdentityByEmail implements IdentityProvider.
func (p *EmbeddedIdentityProvider) GetIdentityByEmail(ctx context.Context, email string) (*Identity, error) {
	h, err := p.storage.GetHumanByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	return humanToIdentity(h), nil
}

// UpdateIdentity implements IdentityProvider.
func (p *EmbeddedIdentityProvider) UpdateIdentity(ctx context.Context, identity *Identity) error {
	return p.storage.UpdateHuman(ctx, identityToHuman(identity))
}

// DeleteIdentity implements IdentityProvider.
func (p *EmbeddedIdentityProvider) DeleteIdentity(ctx context.Context, id uuid.UUID) error {
	return p.storage.DeleteHuman(ctx, id)
}

// ListIdentities implements IdentityProvider.
// Note: The embedded storage doesn't support listing, so this returns an error.
func (p *EmbeddedIdentityProvider) ListIdentities(ctx context.Context, filter *IdentityFilter) ([]*Identity, error) {
	return nil, errors.New("listing identities not supported in embedded storage")
}

// identityToHuman converts an Identity to a HumanPrincipal.
func identityToHuman(identity *Identity) *HumanPrincipal {
	return &HumanPrincipal{
		ID:            identity.ID,
		Email:         identity.Traits.Email,
		EmailVerified: identity.Traits.EmailVerified,
		DisplayName:   identity.Traits.Name,
		GivenName:     identity.Traits.GivenName,
		FamilyName:    identity.Traits.FamilyName,
		AvatarURL:     identity.Traits.Picture,
		Locale:        identity.Traits.Locale,
		Active:        identity.State == IdentityStateActive,
		Metadata:      identity.Metadata,
	}
}

// humanToIdentity converts a HumanPrincipal to an Identity.
func humanToIdentity(h *HumanPrincipal) *Identity {
	state := IdentityStateActive
	if !h.Active {
		state = IdentityStateInactive
	}

	return &Identity{
		ID:    h.ID,
		State: state,
		Traits: IdentityTraits{
			Email:         h.Email,
			EmailVerified: h.EmailVerified,
			Name:          h.DisplayName,
			GivenName:     h.GivenName,
			FamilyName:    h.FamilyName,
			Picture:       h.AvatarURL,
			Locale:        h.Locale,
		},
		Metadata:  h.Metadata,
		CreatedAt: h.CreatedAt,
		UpdatedAt: h.UpdatedAt,
	}
}

// Ensure EmbeddedIdentityProvider implements IdentityProvider.
var _ IdentityProvider = (*EmbeddedIdentityProvider)(nil)
