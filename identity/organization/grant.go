package organization

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/authz/noop"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/graphlock"
	"github.com/plexusone/systemforge/identity/graphstate"
)

// writeGranted writes to the authorization graph access a committed change
// granted to principalID in orgID. write runs holding the graph locks of
// the organization and of every principal in principals (graphlock.Grant)
// and reads the rows again through c, so a revocation that committed after
// the change is not undone. Without a graph (the no-op syncer) it does
// nothing.
func (s *DefaultService) writeGranted(ctx context.Context, orgID uuid.UUID, principals []uuid.UUID, write func(ctx context.Context, c *ent.Client) error) error {
	if _, ok := s.syncer.(*noop.Syncer); ok {
		return nil
	}
	keys := []string{graphlock.Organization(orgID)}
	for _, p := range principals {
		keys = append(keys, graphlock.Principal(p))
	}
	return graphlock.Grant(ctx, s.client, keys, write)
}

// grantMembership writes principalID's role in orgID with add, after the
// change granting it committed, if the membership still holds that role.
// A failure is returned in SyncModeStrict and logged otherwise.
func (s *DefaultService) grantMembership(ctx context.Context, what string, orgID, principalID uuid.UUID, role string, add func(ctx context.Context) error) error {
	err := s.writeGranted(ctx, orgID, []uuid.UUID{principalID}, func(ctx context.Context, c *ent.Client) error {
		held, err := graphstate.Membership(ctx, c, orgID, principalID, role)
		if err != nil || !held {
			return err
		}
		return add(ctx)
	})
	return s.reportGrant(what, err, "principal_id", principalID, "org_id", orgID, "role", role)
}

// grantAccess writes a member's organization role, application roles and
// resource grants to the authorization graph after the change that grants
// them committed, each only if the rows still call for it. Failures are
// returned in SyncModeStrict and logged otherwise.
func (s *DefaultService) grantAccess(ctx context.Context, principalID, organizationID uuid.UUID, role string, appRoles []*ent.AppRole, grants []*ent.ResourceGrant) error {
	attrs := []any{"principal_id", principalID, "org_id", organizationID}
	var reported []error
	report := func(what string, err error, more ...any) {
		reported = append(reported, s.reportGrant(what, err, append(attrs, more...)...))
	}
	err := s.writeGranted(ctx, organizationID, []uuid.UUID{principalID}, func(ctx context.Context, c *ent.Client) error {
		held, err := graphstate.Membership(ctx, c, organizationID, principalID, role)
		if err != nil || !held {
			return err
		}
		report("membership addition", s.syncer.AddOrgMembership(ctx, principalID, organizationID, role), "role", role)
		if appSyncer, ok := s.syncer.(authz.AppRoleSyncer); ok {
			for _, r := range appRoles {
				held, err := graphstate.AppRole(ctx, c, organizationID, principalID, r.Application, r.Role)
				if err == nil && held {
					err = appSyncer.AddAppRole(ctx, principalID, organizationID, r.Application, r.Role)
				}
				report("application role addition", err, "application", r.Application)
			}
		}
		if grantSyncer, ok := s.syncer.(authz.ResourceGrantSyncer); ok {
			for _, g := range grants {
				held, err := graphstate.ResourceGrant(ctx, c, organizationID, principalID, g.ResourceType, g.ResourceID, g.Role)
				if err == nil && held {
					ref := authz.ResourceRef{Type: g.ResourceType, ID: g.ResourceID, OrganizationID: organizationID}
					err = grantSyncer.SetResourceGrant(ctx, principalID, ref, g.Role)
				}
				report("resource grant addition", err, "resource_type", g.ResourceType, "resource_id", g.ResourceID)
			}
		}
		return nil
	})
	report("membership access", err)
	return errors.Join(reported...)
}
