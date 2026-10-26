package managedprincipal

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/identity/accesschange"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/human"
	"github.com/plexusone/systemforge/identity/ent/managerrelationship"
	"github.com/plexusone/systemforge/identity/principal"
)

// ErrEmailNotVerified is returned by Release when the principal has no
// verified email: management ends only for a principal that can be reached
// and has proven it controls its address (ADR-009).
var ErrEmailNotVerified = errors.New("managedprincipal: release requires a verified email")

// Release ends a principal's management: it removes the principal's
// remaining managers and restores its default human capabilities in one
// transaction, after which the principal is self-managed. It requires a
// verified email (ErrEmailNotVerified otherwise) and the manage_managers
// permission, which guardians hold and which is checked under the
// principal's row lock. The manager relations leave the authorization
// graph before the release commits; if the graph refuses, the principal
// stays managed and the error is returned. Release is an explicit,
// audited event (managed_principal.released); whether the person being
// released must confirm first is the application's decision.
func (s *Service) Release(ctx context.Context, actorID, managedID uuid.UUID) error {
	var (
		released []Relationship
		change   accesschange.Change
	)
	err := s.withTx(ctx, func(tx *ent.Tx) error {
		h, err := s.lockAndAuthorize(ctx, tx, actorID, managedID)
		if err != nil {
			return err
		}
		if !emailVerified(h) {
			return ErrEmailNotVerified
		}
		rels, err := tx.ManagerRelationship.Query().
			Where(managerrelationship.ManagedPrincipalID(managedID), managerrelationship.Active(true)).
			All(ctx)
		if err != nil {
			return fmt.Errorf("managedprincipal: list managers: %w", err)
		}
		if len(rels) == 0 {
			return ErrNotManaged
		}
		if _, err := tx.ManagerRelationship.Update().
			Where(managerrelationship.ManagedPrincipalID(managedID), managerrelationship.Active(true)).
			SetActive(false).
			Save(ctx); err != nil {
			return fmt.Errorf("managedprincipal: deactivate relationships: %w", err)
		}
		for _, r := range rels {
			released = append(released, Relationship{
				ManagedPrincipalID: r.ManagedPrincipalID, ManagerPrincipalID: r.ManagerPrincipalID, Role: r.Role,
			})
		}
		if err := s.revoke(ctx, tx, managedID, "remove managers", func() error {
			for _, r := range rels {
				if err := s.syncer.RemovePrincipalManager(ctx, managedID, r.ManagerPrincipalID, r.Role); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return err
		}
		change, err = endManagement(ctx, tx, managedID)
		return err
	})
	if err != nil {
		return err
	}
	accesschange.Publish(s.accessSink, change)
	managers := make([]ManagerInput, 0, len(released))
	for _, r := range released {
		managers = append(managers, ManagerInput{PrincipalID: r.ManagerPrincipalID, Role: r.Role})
	}
	s.emit(ctx, EventReleased, "release", actorID, managedID, map[string]any{"managers": managerDetails(managers)})
	return nil
}

// endManagement restores the capabilities a managed principal gave up
// while managed and records that its management ended, so tokens issued
// while it was managed, which say so, are refreshed (ADR-010). The caller
// has removed its last manager and publishes the returned change after the
// transaction commits.
func endManagement(ctx context.Context, tx *ent.Tx, id uuid.UUID) (accesschange.Change, error) {
	caps := principal.DefaultCapabilitiesForType(principal.TypeHuman)
	if err := tx.Principal.UpdateOneID(id).SetCapabilities(caps.ToMap()).Exec(ctx); err != nil {
		return accesschange.Change{}, fmt.Errorf("managedprincipal: restore capabilities: %w", err)
	}
	return accesschange.Record(ctx, tx, accesschange.Change{PrincipalID: id, Reason: accesschange.ManagementEnded})
}

// authorizeProfile requires actorID to hold view_profile on a managed
// principal.
func (s *Service) authorizeProfile(ctx context.Context, actorID, managedID uuid.UUID) error {
	managed, err := s.client.Human.Query().
		Where(human.PrincipalID(managedID), hasActiveManager()).
		Exist(ctx)
	if err != nil {
		return fmt.Errorf("managedprincipal: check principal: %w", err)
	}
	if !managed {
		return ErrNotManaged
	}
	ok, err := s.authz.Can(ctx, authz.NewUserPrincipal(actorID), authz.PermViewProfile, authz.NewPrincipalResource(managedID))
	if err != nil {
		return fmt.Errorf("managedprincipal: authorize: %w", err)
	}
	if !ok {
		return ErrForbidden
	}
	return nil
}
