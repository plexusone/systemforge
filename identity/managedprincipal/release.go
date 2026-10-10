package managedprincipal

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
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
// principal's row lock. Release is an explicit, audited event
// (managed_principal.released); whether the person being released must
// confirm first is the application's decision.
func (s *Service) Release(ctx context.Context, actorID, managedID uuid.UUID) error {
	var released []Relationship
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
		return clearManagedState(ctx, tx, managedID)
	})
	if err != nil {
		return err
	}
	managers := make([]ManagerInput, 0, len(released))
	for _, r := range released {
		managers = append(managers, ManagerInput{PrincipalID: r.ManagerPrincipalID, Role: r.Role})
	}
	s.emit(ctx, EventReleased, "release", actorID, managedID, map[string]any{"managers": managerDetails(managers)})

	var syncErr error
	for _, m := range managers {
		syncErr = errors.Join(syncErr, s.sync(ctx, "remove manager", managedID, s.syncer.RemovePrincipalManager(ctx, managedID, m.PrincipalID, m.Role)))
	}
	return syncErr
}

// clearManagedState restores the capabilities a managed principal gave up
// while managed. The caller has removed its last manager.
func clearManagedState(ctx context.Context, tx *ent.Tx, id uuid.UUID) error {
	caps := principal.DefaultCapabilitiesForType(principal.TypeHuman)
	if err := tx.Principal.UpdateOneID(id).SetCapabilities(caps.ToMap()).Exec(ctx); err != nil {
		return fmt.Errorf("managedprincipal: restore capabilities: %w", err)
	}
	return nil
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
