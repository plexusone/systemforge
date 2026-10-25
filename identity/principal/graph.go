package principal

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/authz/noop"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/approle"
	"github.com/plexusone/systemforge/identity/ent/human"
	"github.com/plexusone/systemforge/identity/ent/managerrelationship"
	"github.com/plexusone/systemforge/identity/ent/principalmembership"
	"github.com/plexusone/systemforge/identity/ent/resourcegrant"
	"github.com/plexusone/systemforge/identity/graphlock"
	"github.com/plexusone/systemforge/identity/graphstate"
)

// access is what a principal's rows grant it in the authorization graph.
type access struct {
	memberships []*ent.PrincipalMembership
	appRoles    []*ent.AppRole
	grants      []*ent.ResourceGrant
	admin       bool
	managing    []*ent.ManagerRelationship // relations where it is the manager
}

// readAccess reads the rows that grant the principal access, whatever their
// state, through c.
func readAccess(ctx context.Context, c *ent.Client, id uuid.UUID) (access, error) {
	var a access
	var err error
	if a.memberships, err = c.PrincipalMembership.Query().Where(principalmembership.PrincipalID(id)).All(ctx); err != nil {
		return a, fmt.Errorf("failed to read memberships: %w", err)
	}
	if a.appRoles, err = c.AppRole.Query().Where(approle.PrincipalID(id)).All(ctx); err != nil {
		return a, fmt.Errorf("failed to read application roles: %w", err)
	}
	if a.grants, err = c.ResourceGrant.Query().Where(resourcegrant.PrincipalID(id)).All(ctx); err != nil {
		return a, fmt.Errorf("failed to read resource grants: %w", err)
	}
	if a.admin, err = c.Human.Query().Where(human.PrincipalID(id), human.IsPlatformAdmin(true)).Exist(ctx); err != nil {
		return a, fmt.Errorf("failed to read platform administration: %w", err)
	}
	if a.managing, err = c.ManagerRelationship.Query().Where(managerrelationship.ManagerPrincipalID(id)).All(ctx); err != nil {
		return a, fmt.Errorf("failed to read manager relationships: %w", err)
	}
	return a, nil
}

// locks returns the graph locks of the principal's relationships: its own
// and those of the principals it manages, and with orgs those of the
// organizations it belongs to.
func (a access) locks(id uuid.UUID, orgs bool) []string {
	keys := []string{graphlock.Principal(id)}
	for _, m := range a.managing {
		keys = append(keys, graphlock.Principal(m.ManagedPrincipalID))
	}
	if orgs {
		for _, m := range a.memberships {
			keys = append(keys, graphlock.Organization(m.OrganizationID))
		}
	}
	return keys
}

// revokeGraphAccess removes every relationship the principal holds from the
// authorization graph: its organization roles, application roles,
// resource grants, platform administration and the manager relations in
// which it is the manager. It runs inside tx, the transaction that
// deactivates the principal, before the commit and holding the graph
// locks; its error aborts the deactivation whatever the sync mode.
// Removing a relationship that is absent succeeds, so it does not depend
// on what the graph holds.
func (s *DefaultService) revokeGraphAccess(ctx context.Context, tx *ent.Tx, id uuid.UUID) error {
	if !s.hasGraph() {
		return nil
	}
	a, err := readAccess(ctx, tx.Client(), id)
	if err != nil {
		return err
	}
	if err = graphlock.Lock(ctx, tx, a.locks(id, false)...); err != nil {
		return err
	}
	refused := func(what string, err error) error {
		return fmt.Errorf("failed to remove %s from authz, change not saved: %w", what, err)
	}
	for _, m := range a.memberships {
		if err := s.syncer.RemoveOrgMembership(ctx, id, m.OrganizationID, m.Role); err != nil {
			return refused("membership", err)
		}
	}
	if appSyncer, ok := s.syncer.(authz.AppRoleSyncer); ok {
		for _, r := range a.appRoles {
			if err := appSyncer.RemoveAppRole(ctx, id, r.OrganizationID, r.Application, r.Role); err != nil {
				return refused("application role", err)
			}
		}
	}
	if grantSyncer, ok := s.syncer.(authz.ResourceGrantSyncer); ok {
		for _, g := range a.grants {
			ref := authz.ResourceRef{Type: g.ResourceType, ID: g.ResourceID, OrganizationID: g.OrganizationID}
			if err := grantSyncer.RemoveResourceGrant(ctx, id, ref); err != nil {
				return refused("resource grant", err)
			}
		}
	}
	if a.admin {
		if err := s.syncer.SetPlatformAdmin(ctx, id, false); err != nil {
			return refused("platform admin", err)
		}
	}
	for _, m := range a.managing {
		if err := s.syncer.RemovePrincipalManager(ctx, m.ManagedPrincipalID, id, m.Role); err != nil {
			return refused("manager relation", err)
		}
	}
	return nil
}

// restoreGraphAccess writes back, after a reactivation committed, the
// relationships the principal's rows call for (identity/graphstate),
// holding the graph locks of the principal, its organizations and the
// principals it manages. A grant made after the locks were chosen writes
// its own relationship, and the reconciler repairs anything else. Failures
// are returned in SyncModeStrict and logged otherwise.
func (s *DefaultService) restoreGraphAccess(ctx context.Context, id uuid.UUID) error {
	if !s.hasGraph() {
		return nil
	}
	a, err := readAccess(ctx, s.client, id)
	if err != nil {
		return s.reportGrant("reactivated access", id, err)
	}
	var reported []error
	report := func(what string, err error) { reported = append(reported, s.reportGrant(what, id, err)) }
	err = s.writeGranted(ctx, a.locks(id, true), func(ctx context.Context, c *ent.Client) error {
		for _, m := range a.memberships {
			held, err := graphstate.Membership(ctx, c, m.OrganizationID, id, m.Role)
			if err == nil && held {
				err = s.syncer.AddOrgMembership(ctx, id, m.OrganizationID, m.Role)
			}
			report("membership", err)
		}
		if appSyncer, ok := s.syncer.(authz.AppRoleSyncer); ok {
			for _, r := range a.appRoles {
				held, err := graphstate.AppRole(ctx, c, r.OrganizationID, id, r.Application, r.Role)
				if err == nil && held {
					err = appSyncer.AddAppRole(ctx, id, r.OrganizationID, r.Application, r.Role)
				}
				report("application role", err)
			}
		}
		if grantSyncer, ok := s.syncer.(authz.ResourceGrantSyncer); ok {
			for _, g := range a.grants {
				held, err := graphstate.ResourceGrant(ctx, c, g.OrganizationID, id, g.ResourceType, g.ResourceID, g.Role)
				if err == nil && held {
					ref := authz.ResourceRef{Type: g.ResourceType, ID: g.ResourceID, OrganizationID: g.OrganizationID}
					err = grantSyncer.SetResourceGrant(ctx, id, ref, g.Role)
				}
				report("resource grant", err)
			}
		}
		held, err := graphstate.PlatformAdmin(ctx, c, id)
		if err == nil && held {
			err = s.syncer.SetPlatformAdmin(ctx, id, true)
		}
		report("platform admin", err)
		for _, m := range a.managing {
			held, err := graphstate.Manager(ctx, c, m.ManagedPrincipalID, id, m.Role)
			if err == nil && held {
				err = s.syncer.AddPrincipalManager(ctx, m.ManagedPrincipalID, id, m.Role)
			}
			report("manager relation", err)
		}
		return nil
	})
	report("reactivated access", err)
	return errors.Join(reported...)
}

// hasGraph reports whether the service writes to an authorization graph.
func (s *DefaultService) hasGraph() bool {
	_, isNoop := s.syncer.(*noop.Syncer)
	return !isNoop
}

// writeGranted writes to the authorization graph access a committed change
// granted. write runs holding the graph locks named by keys
// (graphlock.Grant) and reads the rows again through c, so a revocation
// that committed after the change is not undone. Without a graph it does
// nothing.
func (s *DefaultService) writeGranted(ctx context.Context, keys []string, write func(ctx context.Context, c *ent.Client) error) error {
	if !s.hasGraph() {
		return nil
	}
	return graphlock.Grant(ctx, s.client, keys, write)
}

// grantPlatformAdmin writes a principal's platform administration to the
// graph after the change granting it committed, if the principal still
// holds it.
func (s *DefaultService) grantPlatformAdmin(ctx context.Context, id uuid.UUID) error {
	err := s.writeGranted(ctx, []string{graphlock.Principal(id)}, func(ctx context.Context, c *ent.Client) error {
		held, err := graphstate.PlatformAdmin(ctx, c, id)
		if err != nil || !held {
			return err
		}
		return s.syncer.SetPlatformAdmin(ctx, id, true)
	})
	return s.reportGrant("platform admin", id, err)
}

// reportGrant handles a failed write of granted access after its change
// committed: returned in SyncModeStrict, logged otherwise.
func (s *DefaultService) reportGrant(what string, id uuid.UUID, syncErr error) error {
	if syncErr == nil {
		return nil
	}
	if s.syncMode == authz.SyncModeStrict {
		return fmt.Errorf("failed to sync %s to authz: %w", what, syncErr)
	}
	s.logger.Warn("failed to sync "+what+" to authz", "principal_id", id, "error", syncErr)
	return nil
}
