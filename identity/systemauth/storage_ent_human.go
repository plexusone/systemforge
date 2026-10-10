package systemauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/credential"
	"github.com/plexusone/systemforge/identity/ent/externalidentity"
	"github.com/plexusone/systemforge/identity/ent/human"
	"github.com/plexusone/systemforge/identity/ent/managerrelationship"
	"github.com/plexusone/systemforge/identity/ent/principal"
)

// toHumanPrincipal converts a Principal loaded with its Human edge.
func toHumanPrincipal(p *ent.Principal) *HumanPrincipal {
	hp := &HumanPrincipal{
		Managed:     len(p.Edges.Managers) > 0,
		ID:          p.ID,
		DisplayName: p.DisplayName,
		Active:      p.Active,
		Metadata:    p.Metadata,
		CreatedAt:   p.CreatedAt,
		UpdatedAt:   p.UpdatedAt,
	}
	if h := p.Edges.Human; h != nil {
		if h.Email != nil {
			hp.Email = *h.Email
		}
		hp.EmailVerified = h.EmailVerifiedAt != nil
		hp.GivenName = h.GivenName
		hp.FamilyName = h.FamilyName
		hp.Locale = h.Locale
		if h.AvatarURL != nil {
			hp.AvatarURL = *h.AvatarURL
		}
	}
	return hp
}

// humanDisplayName falls back to the email when no display name is given,
// since a principal requires one.
func humanDisplayName(h *HumanPrincipal) string {
	if h.DisplayName != "" {
		return h.DisplayName
	}
	return h.Email
}

// createHumanRows inserts a human Principal and its Human extension inside
// tx. verifiedAt, when non-nil, marks the email verified at that time
// regardless of h.EmailVerified. It assigns h.ID when it is uuid.Nil.
func createHumanRows(ctx context.Context, tx *ent.Tx, h *HumanPrincipal, verifiedAt, lastLoginAt *time.Time) error {
	if h.Email == "" {
		return ErrEmailRequired
	}
	if h.ID == uuid.Nil {
		h.ID = uuid.New()
	}
	pc := tx.Principal.Create().
		SetID(h.ID).
		SetType(principal.TypeHuman).
		SetIdentifier(h.Email).
		SetDisplayName(humanDisplayName(h)).
		SetActive(h.Active)
	if h.Metadata != nil {
		pc.SetMetadata(h.Metadata)
	}
	if _, err := pc.Save(ctx); err != nil {
		return fmt.Errorf("creating principal: %w", err)
	}

	hc := tx.Human.Create().
		SetPrincipalID(h.ID).
		SetEmail(h.Email).
		SetGivenName(h.GivenName).
		SetFamilyName(h.FamilyName)
	if h.AvatarURL != "" {
		hc.SetAvatarURL(h.AvatarURL)
	}
	if h.Locale != "" {
		hc.SetLocale(h.Locale)
	}
	if verifiedAt == nil && h.EmailVerified {
		now := time.Now()
		verifiedAt = &now
	}
	if verifiedAt != nil {
		hc.SetEmailVerifiedAt(*verifiedAt)
	}
	if lastLoginAt != nil {
		hc.SetLastLoginAt(*lastLoginAt)
	}
	if _, err := hc.Save(ctx); err != nil {
		return fmt.Errorf("creating human: %w", err)
	}
	return nil
}

// emailTakenInTx reports whether another human already uses email, ignoring
// case. The unique index on Human.email is case-sensitive, while lookups are
// not, so writes must check case-insensitively to keep lookups unambiguous.
func emailTakenInTx(ctx context.Context, tx *ent.Tx, email string, exceptID uuid.UUID) (bool, error) {
	return tx.Human.Query().
		Where(human.EmailEqualFold(email), human.PrincipalIDNEQ(exceptID)).
		Exist(ctx)
}

// withTx runs fn in a transaction, rolling back on error.
func (s *EntStorage) withTx(ctx context.Context, fn func(tx *ent.Tx) error) error {
	tx, err := s.db.Tx(ctx)
	if err != nil {
		return fmt.Errorf("starting transaction: %w", err)
	}
	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return errors.Join(err, fmt.Errorf("rolling back: %w", rbErr))
		}
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing: %w", err)
	}
	return nil
}

// CreateHuman implements Storage.
func (s *EntStorage) CreateHuman(ctx context.Context, h *HumanPrincipal) error {
	err := s.withTx(ctx, func(tx *ent.Tx) error {
		taken, err := emailTakenInTx(ctx, tx, h.Email, uuid.Nil)
		if err != nil {
			return err
		}
		if taken {
			return ErrPrincipalExists
		}
		return createHumanRows(ctx, tx, h, nil, nil)
	})
	if err != nil {
		if errors.Is(err, ErrPrincipalExists) || errors.Is(err, ErrEmailRequired) {
			return err
		}
		if ent.IsConstraintError(err) {
			return fmt.Errorf("%w: %v", ErrPrincipalExists, err)
		}
		return fmt.Errorf("failed to create human: %w", err)
	}
	return nil
}

// queryHuman returns a query over human principals with the Human edge loaded.
func (s *EntStorage) queryHuman() *ent.PrincipalQuery {
	return s.db.Principal.Query().
		Where(principal.TypeEQ(principal.TypeHuman)).
		WithHuman().
		WithManagers(activeManagers)
}

// activeManagers restricts a loaded managers edge to active relationships,
// which is what makes a principal managed (ADR-009).
func activeManagers(q *ent.ManagerRelationshipQuery) {
	q.Where(managerrelationship.Active(true))
}

func (s *EntStorage) onlyHuman(ctx context.Context, q *ent.PrincipalQuery) (*HumanPrincipal, error) {
	p, err := q.Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrPrincipalNotFound
		}
		return nil, fmt.Errorf("failed to get human: %w", err)
	}
	return toHumanPrincipal(p), nil
}

// GetHuman implements Storage.
func (s *EntStorage) GetHuman(ctx context.Context, id uuid.UUID) (*HumanPrincipal, error) {
	return s.onlyHuman(ctx, s.queryHuman().Where(principal.IDEQ(id)))
}

// GetHumanByEmail implements Storage. The match is case-insensitive.
func (s *EntStorage) GetHumanByEmail(ctx context.Context, email string) (*HumanPrincipal, error) {
	return s.onlyHuman(ctx, s.queryHuman().Where(principal.HasHumanWith(human.EmailEqualFold(email))))
}

// GetHumanByExternalIdentity implements Storage.
func (s *EntStorage) GetHumanByExternalIdentity(ctx context.Context, provider, subject string) (*HumanPrincipal, error) {
	return s.onlyHuman(ctx, s.queryHuman().Where(principal.HasExternalIdentitiesWith(
		externalidentity.ProviderEQ(provider),
		externalidentity.SubjectEQ(subject),
	)))
}

// LinkExternalIdentity implements Storage.
func (s *EntStorage) LinkExternalIdentity(ctx context.Context, principalID uuid.UUID, provider, subject string) error {
	existing, err := s.db.ExternalIdentity.Query().
		Where(externalidentity.ProviderEQ(provider), externalidentity.SubjectEQ(subject)).
		Only(ctx)
	switch {
	case err == nil:
		if existing.PrincipalID == principalID {
			return nil
		}
		return ErrExternalIdentityExists
	case !ent.IsNotFound(err):
		return fmt.Errorf("failed to look up external identity: %w", err)
	}
	if _, err := s.GetHuman(ctx, principalID); err != nil {
		return err
	}
	if _, err := s.db.ExternalIdentity.Create().
		SetPrincipalID(principalID).
		SetProvider(provider).
		SetSubject(subject).
		Save(ctx); err != nil {
		if ent.IsConstraintError(err) {
			return ErrExternalIdentityExists
		}
		return fmt.Errorf("failed to link external identity: %w", err)
	}
	return nil
}

// UpdateHuman implements Storage. It replaces the profile fields of an
// existing human principal with those in h.
func (s *EntStorage) UpdateHuman(ctx context.Context, h *HumanPrincipal) error {
	err := s.withTx(ctx, func(tx *ent.Tx) error {
		p, err := tx.Principal.Query().
			Where(principal.IDEQ(h.ID), principal.TypeEQ(principal.TypeHuman)).
			WithHuman().WithManagers(activeManagers).
			Only(ctx)
		if err != nil {
			if ent.IsNotFound(err) {
				return ErrPrincipalNotFound
			}
			return err
		}
		if h.Email == "" {
			return ErrEmailRequired
		}
		taken, err := emailTakenInTx(ctx, tx, h.Email, h.ID)
		if err != nil {
			return err
		}
		if taken {
			return ErrPrincipalExists
		}
		pu := tx.Principal.UpdateOne(p).
			SetIdentifier(h.Email).
			SetDisplayName(humanDisplayName(h)).
			SetActive(h.Active)
		if h.Metadata != nil {
			pu.SetMetadata(h.Metadata)
		} else {
			pu.ClearMetadata()
		}
		if _, err := pu.Save(ctx); err != nil {
			return err
		}
		if p.Edges.Human == nil {
			return fmt.Errorf("principal %s has no human extension", h.ID)
		}
		hu := tx.Human.UpdateOne(p.Edges.Human).
			SetEmail(h.Email).
			SetGivenName(h.GivenName).
			SetFamilyName(h.FamilyName)
		if h.AvatarURL != "" {
			hu.SetAvatarURL(h.AvatarURL)
		} else {
			hu.ClearAvatarURL()
		}
		if h.Locale != "" {
			hu.SetLocale(h.Locale)
		}
		switch {
		case h.EmailVerified && p.Edges.Human.EmailVerifiedAt == nil:
			hu.SetEmailVerifiedAt(time.Now())
		case !h.EmailVerified:
			hu.ClearEmailVerifiedAt()
		}
		_, err = hu.Save(ctx)
		return err
	})
	if err != nil {
		if errors.Is(err, ErrPrincipalNotFound) || errors.Is(err, ErrPrincipalExists) || errors.Is(err, ErrEmailRequired) {
			return err
		}
		if ent.IsConstraintError(err) {
			return fmt.Errorf("%w: %v", ErrPrincipalExists, err)
		}
		return fmt.Errorf("failed to update human: %w", err)
	}
	return nil
}

// DeleteHuman implements Storage. It removes the principal together with its
// Human extension, external identities, and credentials. Other records that
// still reference the principal cause the delete to fail.
func (s *EntStorage) DeleteHuman(ctx context.Context, id uuid.UUID) error {
	err := s.withTx(ctx, func(tx *ent.Tx) error {
		exists, err := tx.Principal.Query().
			Where(principal.IDEQ(id), principal.TypeEQ(principal.TypeHuman)).
			Exist(ctx)
		if err != nil {
			return err
		}
		if !exists {
			return ErrPrincipalNotFound
		}
		if _, err := tx.Human.Delete().Where(human.PrincipalIDEQ(id)).Exec(ctx); err != nil {
			return err
		}
		if _, err := tx.ExternalIdentity.Delete().Where(externalidentity.PrincipalIDEQ(id)).Exec(ctx); err != nil {
			return err
		}
		if _, err := tx.Credential.Delete().Where(credential.PrincipalIDEQ(id)).Exec(ctx); err != nil {
			return err
		}
		return tx.Principal.DeleteOneID(id).Exec(ctx)
	})
	if err != nil {
		if errors.Is(err, ErrPrincipalNotFound) {
			return err
		}
		return fmt.Errorf("failed to delete human: %w", err)
	}
	return nil
}
