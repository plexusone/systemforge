package organization

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/organization"
	"github.com/plexusone/systemforge/identity/ent/slugreservation"
)

// ConvertResult is the outcome of ConvertToTeam.
type ConvertResult struct {
	// Team is the converted organization: same ID, data and memberships.
	Team *Organization
	// Personal is the new personal organization holding the owner's handle.
	Personal *Organization
}

// ConvertToTeam turns a personal organization into a team without moving
// anything: the organization keeps its ID, data and memberships, takes
// teamSlug and becomes a team, and the owner gets a new personal
// organization with the handle the old one had. It all happens in one
// transaction. actor must be the organization's owner.
func (s *DefaultService) ConvertToTeam(ctx context.Context, orgID uuid.UUID, teamSlug string, actor uuid.UUID) (*ConvertResult, error) {
	var team, personal *ent.Organization
	err := s.inTx(ctx, func(tx *ent.Tx) error {
		c := tx.Client()
		org, err := c.Organization.Get(ctx, orgID)
		if ent.IsNotFound(err) {
			return fmt.Errorf("%w: %s", ErrOrganizationNotFound, orgID)
		}
		if err != nil {
			return fmt.Errorf("failed to get organization: %w", err)
		}
		if org.OrgType != organization.OrgTypePersonal {
			return ErrNotPersonal
		}
		if org.OwnerPrincipalID == nil || *org.OwnerPrincipalID != actor {
			return ErrNotOwner
		}
		handle, err := s.renameInTx(ctx, tx, orgID, teamSlug, actor)
		if err != nil {
			return err
		}
		team, err = c.Organization.UpdateOneID(orgID).SetOrgType(organization.OrgTypeTeam).Save(ctx)
		if err != nil {
			return fmt.Errorf("failed to convert organization: %w", err)
		}
		// The new personal organization takes the handle the rename just
		// reserved for the actor; the reservation is consumed.
		if err := s.slugCheck(ctx, c, handle, &actor); err != nil {
			return err
		}
		if _, err := c.SlugReservation.Delete().Where(slugreservation.SlugEQ(handle)).Exec(ctx); err != nil {
			return fmt.Errorf("failed to consume handle reservation: %w", err)
		}
		owner, err := c.Principal.Get(ctx, actor)
		if err != nil {
			return fmt.Errorf("failed to get owner: %w", err)
		}
		pc := c.Organization.Create().
			SetName(owner.DisplayName).
			SetSlug(handle).
			SetOrgType(organization.OrgTypePersonal).
			SetOwnerPrincipalID(actor).
			SetActive(true)
		if org.LogoURL != nil && *org.LogoURL != "" {
			pc.SetLogoURL(*org.LogoURL)
		}
		personal, err = pc.Save(ctx)
		if err != nil {
			return fmt.Errorf("failed to create personal organization: %w", err)
		}
		if _, err := c.PrincipalMembership.Create().
			SetPrincipalID(actor).
			SetOrganizationID(personal.ID).
			SetRole(RoleOwner).
			SetActive(true).
			Save(ctx); err != nil {
			return fmt.Errorf("failed to create owner membership: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	if syncErr := s.syncer.RegisterOrganization(ctx, personal.ID, actor); syncErr != nil {
		if s.syncMode == authz.SyncModeStrict {
			return nil, fmt.Errorf("failed to sync organization to authz: %w", syncErr)
		}
		s.logger.Warn("failed to sync organization to authz", "org_id", personal.ID, "error", syncErr)
	}
	return &ConvertResult{Team: entOrgToModel(team), Personal: entOrgToModel(personal)}, nil
}
