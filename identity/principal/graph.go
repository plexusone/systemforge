package principal

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/authz/noop"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/graphlock"
	"github.com/plexusone/systemforge/identity/graphstate"
)

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
