package managedprincipal

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/identity/accesschange"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/approle"
	"github.com/plexusone/systemforge/identity/ent/credential"
	"github.com/plexusone/systemforge/identity/ent/externalidentity"
	"github.com/plexusone/systemforge/identity/ent/loginsession"
	"github.com/plexusone/systemforge/identity/ent/managerclaim"
	"github.com/plexusone/systemforge/identity/ent/managerinvite"
	"github.com/plexusone/systemforge/identity/ent/managerrelationship"
	"github.com/plexusone/systemforge/identity/ent/oauthconsent"
	"github.com/plexusone/systemforge/identity/ent/oauthtoken"
	"github.com/plexusone/systemforge/identity/ent/principalmembership"
	"github.com/plexusone/systemforge/identity/ent/principaltoken"
	"github.com/plexusone/systemforge/identity/ent/resourcegrant"
)

// EventDeleted records that a managed principal was deleted.
const EventDeleted = "managed_principal.deleted"

// deletedDisplayName replaces the display name of a deleted principal.
const deletedDisplayName = "Deleted account"

// Delete deletes a managed principal. The actor needs manage_account, which
// guardians hold (ADR-005: deletion is a guardian or platform-administrator
// action; an educator cannot).
//
// Delete is the platform's soft delete, like organization deletion: the
// principal row stays so that identifiers elsewhere keep resolving, but
// everything that identifies or authenticates the person is removed in one
// transaction. The principal is deactivated; its email, names and avatar
// are cleared and its identifier becomes "deleted:<id>", which frees the
// address; its credentials, external identities, login sessions, consents
// and claims are removed; its OAuth and principal token families are
// revoked; its memberships and manager relationships are deactivated; and
// invitations to its address are withdrawn. An access change is recorded
// so tokens already issued stop being honored at once (ADR-010). The
// principal's relationships leave the authorization graph before the
// deletion commits; if the graph refuses, nothing is deleted and the error
// is returned, so the call can be retried. Data an
// application keeps about the person, and any personal organization it
// owns, are the application's to remove.
func (s *Service) Delete(ctx context.Context, actorID, managedID uuid.UUID) error {
	if err := s.authorizeAccount(ctx, actorID, managedID); err != nil {
		return err
	}
	now := s.now()
	var (
		rels   []*ent.ManagerRelationship
		counts = map[string]int{}
		change accesschange.Change
	)
	err := s.withTx(ctx, func(tx *ent.Tx) error {
		h, err := lockHuman(ctx, tx, managedID)
		if err != nil {
			return err
		}
		if err := requireManaged(ctx, tx, managedID); err != nil {
			return err
		}
		if rels, err = tx.ManagerRelationship.Query().
			Where(managerrelationship.ManagedPrincipalID(managedID), managerrelationship.Active(true)).
			All(ctx); err != nil {
			return fmt.Errorf("managedprincipal: list managers: %w", err)
		}
		// The application roles and resource grants the principal holds
		// through the memberships deactivated below leave the graph with
		// them.
		roles, grants, err := activeAccess(ctx, tx, managedID)
		if err != nil {
			return err
		}
		if h.Email != nil {
			if counts["invites"], err = tx.ManagerInvite.Update().
				Where(managerinvite.EmailEqualFold(*h.Email), managerinvite.AcceptedAtIsNil(), managerinvite.RevokedAtIsNil(), managerinvite.DeclinedAtIsNil()).
				SetRevokedAt(now).
				Save(ctx); err != nil {
				return fmt.Errorf("managedprincipal: withdraw invitations: %w", err)
			}
		}
		steps := []struct {
			name string
			run  func() (int, error)
		}{
			{"relationships", func() (int, error) {
				return tx.ManagerRelationship.Update().
					Where(managerrelationship.ManagedPrincipalID(managedID), managerrelationship.Active(true)).
					SetActive(false).Save(ctx)
			}},
			{"memberships", func() (int, error) {
				return tx.PrincipalMembership.Update().
					Where(principalmembership.PrincipalID(managedID), principalmembership.Active(true)).
					SetActive(false).Save(ctx)
			}},
			{"credentials", func() (int, error) {
				return tx.Credential.Delete().Where(credential.PrincipalID(managedID)).Exec(ctx)
			}},
			{"external_identities", func() (int, error) {
				return tx.ExternalIdentity.Delete().Where(externalidentity.PrincipalID(managedID)).Exec(ctx)
			}},
			{"login_sessions", func() (int, error) {
				return tx.LoginSession.Delete().Where(loginsession.PrincipalID(managedID)).Exec(ctx)
			}},
			{"consents", func() (int, error) {
				return tx.OAuthConsent.Delete().Where(oauthconsent.PrincipalID(managedID)).Exec(ctx)
			}},
			{"claims", func() (int, error) {
				return tx.ManagerClaim.Delete().Where(managerclaim.ManagedPrincipalID(managedID)).Exec(ctx)
			}},
			{"oauth_tokens", func() (int, error) {
				return tx.OAuthToken.Update().
					Where(oauthtoken.SubjectEQ(managedID.String()), oauthtoken.Revoked(false)).
					SetRevoked(true).SetRevokedAt(now).SetRevokedReason(revokedDeleted).Save(ctx)
			}},
			{"principal_tokens", func() (int, error) {
				return tx.PrincipalToken.Update().
					Where(principaltoken.PrincipalID(managedID), principaltoken.Revoked(false)).
					SetRevoked(true).SetRevokedAt(now).SetRevokedReason(revokedDeleted).Save(ctx)
			}},
		}
		for _, st := range steps {
			n, err := st.run()
			if err != nil {
				return fmt.Errorf("managedprincipal: delete %s: %w", st.name, err)
			}
			counts[st.name] = n
		}
		if err := tx.Human.UpdateOne(h).
			ClearEmail().
			ClearEmailVerifiedAt().
			ClearAvatarURL().
			SetGivenName("").
			SetFamilyName("").
			Exec(ctx); err != nil {
			return fmt.Errorf("managedprincipal: erase human: %w", err)
		}
		if err := tx.Principal.UpdateOneID(managedID).
			SetActive(false).
			SetIdentifier("deleted:" + managedID.String()).
			SetDisplayName(deletedDisplayName).
			Exec(ctx); err != nil {
			return fmt.Errorf("managedprincipal: deactivate principal: %w", err)
		}
		change, err = accesschange.Record(ctx, tx, accesschange.Change{PrincipalID: managedID, Reason: accesschange.Deactivated})
		if err != nil {
			return err
		}
		return s.revoke(ctx, tx, managedID, "remove deleted principal", func() error {
			return s.unregister(ctx, managedID, rels, roles, grants)
		})
	})
	if err != nil {
		return err
	}
	accesschange.Publish(s.accessSink, change)
	details := make(map[string]any, len(counts))
	for k, v := range counts {
		details[k] = v
	}
	s.emit(ctx, EventDeleted, "delete", actorID, managedID, details)
	return nil
}

// activeAccess returns the application roles and resource grants a
// principal holds in the organizations where its membership is active.
func activeAccess(ctx context.Context, tx *ent.Tx, principalID uuid.UUID) ([]*ent.AppRole, []*ent.ResourceGrant, error) {
	memberships, err := tx.PrincipalMembership.Query().
		Where(principalmembership.PrincipalID(principalID), principalmembership.Active(true)).
		All(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("managedprincipal: list memberships: %w", err)
	}
	orgIDs := make([]uuid.UUID, len(memberships))
	for i, m := range memberships {
		orgIDs[i] = m.OrganizationID
	}
	if len(orgIDs) == 0 {
		return nil, nil, nil
	}
	roles, err := tx.AppRole.Query().
		Where(approle.PrincipalID(principalID), approle.OrganizationIDIn(orgIDs...)).
		All(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("managedprincipal: list application roles: %w", err)
	}
	grants, err := tx.ResourceGrant.Query().
		Where(resourcegrant.PrincipalID(principalID), resourcegrant.OrganizationIDIn(orgIDs...)).
		All(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("managedprincipal: list resource grants: %w", err)
	}
	return roles, grants, nil
}

// unregister removes a deleted principal from the authorization graph: its
// managers, its memberships and platform administration (UnregisterPrincipal),
// and the application roles and resource grants of its memberships.
func (s *Service) unregister(ctx context.Context, managedID uuid.UUID, rels []*ent.ManagerRelationship, roles []*ent.AppRole, grants []*ent.ResourceGrant) error {
	for _, r := range rels {
		if err := s.syncer.RemovePrincipalManager(ctx, managedID, r.ManagerPrincipalID, r.Role); err != nil {
			return err
		}
	}
	if err := s.syncer.UnregisterPrincipal(ctx, managedID); err != nil {
		return err
	}
	if appSyncer, ok := s.syncer.(authz.AppRoleSyncer); ok {
		for _, r := range roles {
			if err := appSyncer.RemoveAppRole(ctx, managedID, r.OrganizationID, r.Application, r.Role); err != nil {
				return err
			}
		}
	}
	if grantSyncer, ok := s.syncer.(authz.ResourceGrantSyncer); ok {
		for _, g := range grants {
			ref := authz.ResourceRef{Type: g.ResourceType, ID: g.ResourceID, OrganizationID: g.OrganizationID}
			if err := grantSyncer.RemoveResourceGrant(ctx, managedID, ref); err != nil {
				return err
			}
		}
	}
	return nil
}
