package organization

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/organization"
	"github.com/plexusone/systemforge/identity/ent/principalmembership"
	"github.com/plexusone/systemforge/identity/ent/slugreservation"
)

// SlugCoolingOff is how long a slug an organization gave up stays reserved
// for the principal who released it (ADR-006 decision 4). Override per
// service with WithSlugCoolingOff.
const SlugCoolingOff = 7 * 24 * time.Hour

var (
	// ErrSlugCoolingOff is returned when a slug is held by a reservation
	// that belongs to someone else.
	ErrSlugCoolingOff = errors.New("slug is in its cooling-off period")
	// ErrSlugTaken is returned when another organization uses the slug.
	ErrSlugTaken = errors.New("slug is already taken")
	// ErrInvalidSlug is returned for a slug that is not well formed.
	ErrInvalidSlug = errors.New("invalid slug format: must be lowercase alphanumeric with hyphens")
	// ErrNotOwner is returned when the acting principal is not an active
	// owner of the organization.
	ErrNotOwner = errors.New("principal is not an owner of the organization")
	// ErrNotPersonal is returned when an operation needs a personal
	// organization and the organization is not one.
	ErrNotPersonal = errors.New("organization is not a personal organization")
	// ErrOrganizationNotFound is returned when an organization does not exist.
	ErrOrganizationNotFound = errors.New("organization not found")
	// ErrOwnerRequired is returned when a personal organization is created
	// without an owner.
	ErrOwnerRequired = errors.New("personal organizations require an owner principal ID")
	// ErrAlreadyMember is returned when adding a principal that is already
	// a member of the organization.
	ErrAlreadyMember = errors.New("principal is already a member of this organization")
	// ErrNewOwnerNotMember is returned when ownership is transferred to a
	// principal that is not a member of the organization.
	ErrNewOwnerNotMember = errors.New("new owner must be an existing member")
	// ErrInvalidOwnerRole is returned when a transfer of ownership names a
	// role for the previous owner other than admin or member.
	ErrInvalidOwnerRole = errors.New("new role for previous owner must be 'admin' or 'member'")
)

// WithSlugCoolingOff sets how long a released slug stays reserved
// (default SlugCoolingOff).
func WithSlugCoolingOff(d time.Duration) ServiceOption {
	return func(s *DefaultService) {
		if d > 0 {
			s.coolingOff = d
		}
	}
}

func (s *DefaultService) coolingOffPeriod() time.Duration {
	if s.coolingOff > 0 {
		return s.coolingOff
	}
	return SlugCoolingOff
}

// slugCheck reports why slug cannot be used by actor (nil actor: by
// nobody in particular). It returns nil when the slug is free, which
// includes a slug whose live reservation belongs to actor, or to an
// organization actor owns. An expired reservation is deleted.
func (s *DefaultService) slugCheck(ctx context.Context, c *ent.Client, slug string, actor *uuid.UUID) error {
	if s.isReserved(slug) {
		return fmt.Errorf("%w: %s", ErrSlugReserved, slug)
	}
	exists, err := c.Organization.Query().Where(organization.Slug(slug)).Exist(ctx)
	if err != nil {
		return fmt.Errorf("failed to check slug: %w", err)
	}
	if exists {
		return fmt.Errorf("%w: %s", ErrSlugTaken, slug)
	}
	res, err := liveReservation(ctx, c, slug)
	if err != nil || res == nil {
		return err
	}
	if actor != nil {
		holds, err := holdsReservation(ctx, c, res, *actor)
		if err != nil {
			return err
		}
		if holds {
			return nil
		}
	}
	return fmt.Errorf("%w: %s", ErrSlugCoolingOff, slug)
}

// liveReservation returns the unexpired reservation for slug, or nil. An
// expired reservation is deleted on the way.
func liveReservation(ctx context.Context, c *ent.Client, slug string) (*ent.SlugReservation, error) {
	res, err := c.SlugReservation.Query().Where(slugreservation.SlugEQ(slug)).Only(ctx)
	if ent.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read slug reservation: %w", err)
	}
	if !res.ExpiresAt.After(time.Now()) {
		if err := c.SlugReservation.DeleteOne(res).Exec(ctx); err != nil && !ent.IsNotFound(err) {
			return nil, fmt.Errorf("failed to delete expired slug reservation: %w", err)
		}
		return nil, nil
	}
	return res, nil
}

// holdsReservation reports whether actor released the reservation or owns
// the organization that did.
func holdsReservation(ctx context.Context, c *ent.Client, res *ent.SlugReservation, actor uuid.UUID) (bool, error) {
	if res.ReleasedByPrincipalID == actor {
		return true, nil
	}
	if res.ReleasedFromOrganizationID == nil {
		return false, nil
	}
	owns, err := c.PrincipalMembership.Query().Where(
		principalmembership.OrganizationIDEQ(*res.ReleasedFromOrganizationID),
		principalmembership.PrincipalIDEQ(actor),
		principalmembership.RoleEQ(RoleOwner),
		principalmembership.ActiveEQ(true),
	).Exist(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to check reservation owner: %w", err)
	}
	return owns, nil
}

// ResolveSlug returns the active organization with slug. When no
// organization uses it but one released it within the cooling-off period,
// it returns that organization and alias true, so old links keep working.
// A deleted (inactive) organization does not resolve: its API routes answer
// as for an unknown organization.
func (s *DefaultService) ResolveSlug(ctx context.Context, slug string) (*Organization, bool, error) {
	org, err := s.client.Organization.Query().Where(organization.Slug(slug), organization.Active(true)).Only(ctx)
	if err == nil {
		return entOrgToModel(org), false, nil
	}
	if !ent.IsNotFound(err) {
		return nil, false, fmt.Errorf("failed to get organization: %w", err)
	}
	res, err := liveReservation(ctx, s.client, slug)
	if err != nil {
		return nil, false, err
	}
	if res != nil && res.ReleasedFromOrganizationID != nil {
		org, err := s.client.Organization.Get(ctx, *res.ReleasedFromOrganizationID)
		if err == nil && org.Active {
			return entOrgToModel(org), true, nil
		}
		if err == nil {
			return nil, false, fmt.Errorf("%w: %s", ErrOrganizationNotFound, slug)
		}
		if !ent.IsNotFound(err) {
			return nil, false, fmt.Errorf("failed to get organization: %w", err)
		}
	}
	return nil, false, fmt.Errorf("%w: %s", ErrOrganizationNotFound, slug)
}

// Rename changes an organization's slug. The old slug is reserved for
// actor for the cooling-off period and keeps resolving to the organization
// meanwhile; the new slug must be free, or reserved for actor (or an
// organization actor owns). It works the same for personal and team
// organizations, in every direction.
func (s *DefaultService) Rename(ctx context.Context, orgID uuid.UUID, slug string, actor uuid.UUID) error {
	return s.inTx(ctx, func(tx *ent.Tx) error {
		_, err := s.renameInTx(ctx, tx, orgID, slug, actor)
		return err
	})
}

// renameInTx is Rename inside a caller's transaction. It returns the
// previous slug.
func (s *DefaultService) renameInTx(ctx context.Context, tx *ent.Tx, orgID uuid.UUID, slug string, actor uuid.UUID) (string, error) {
	if !isValidSlug(slug) {
		return "", ErrInvalidSlug
	}
	c := tx.Client()
	org, err := c.Organization.Get(ctx, orgID)
	if ent.IsNotFound(err) {
		return "", fmt.Errorf("%w: %s", ErrOrganizationNotFound, orgID)
	}
	if err != nil {
		return "", fmt.Errorf("failed to get organization: %w", err)
	}
	if err := s.requireOwner(ctx, c, orgID, actor); err != nil {
		return "", err
	}
	old := org.Slug
	if old == slug {
		return "", fmt.Errorf("%w: %s", ErrSlugTaken, slug)
	}
	if err := s.slugCheck(ctx, c, slug, &actor); err != nil {
		return "", err
	}
	// The new slug is consumed; the old one is reserved (replacing any
	// stale row for it, since the slug column is unique).
	if _, err := c.SlugReservation.Delete().Where(slugreservation.SlugIn(slug, old)).Exec(ctx); err != nil {
		return "", fmt.Errorf("failed to clear slug reservations: %w", err)
	}
	if _, err := c.Organization.UpdateOneID(orgID).SetSlug(slug).Save(ctx); err != nil {
		return "", fmt.Errorf("failed to rename organization: %w", err)
	}
	now := time.Now()
	if _, err := c.SlugReservation.Create().
		SetSlug(old).
		SetReleasedByPrincipalID(actor).
		SetReleasedFromOrganizationID(orgID).
		SetReleasedAt(now).
		SetExpiresAt(now.Add(s.coolingOffPeriod())).
		Save(ctx); err != nil {
		return "", fmt.Errorf("failed to reserve old slug: %w", err)
	}
	return old, nil
}

func (s *DefaultService) requireOwner(ctx context.Context, c *ent.Client, orgID, actor uuid.UUID) error {
	ok, err := c.PrincipalMembership.Query().Where(
		principalmembership.OrganizationIDEQ(orgID),
		principalmembership.PrincipalIDEQ(actor),
		principalmembership.RoleEQ(RoleOwner),
		principalmembership.ActiveEQ(true),
	).Exist(ctx)
	if err != nil {
		return fmt.Errorf("failed to check ownership: %w", err)
	}
	if !ok {
		return ErrNotOwner
	}
	return nil
}

// inTx runs fn in a transaction, committing when it returns nil and rolling
// back otherwise.
func (s *DefaultService) inTx(ctx context.Context, fn func(tx *ent.Tx) error) error {
	tx, err := s.client.Tx(ctx)
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return errors.Join(err, fmt.Errorf("rollback: %w", rbErr))
		}
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}
