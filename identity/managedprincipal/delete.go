package managedprincipal

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/accesschange"
	"github.com/plexusone/systemforge/identity/ent"
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
// so tokens already issued stop being honored at once (ADR-010). Data an
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
		return err
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

	var syncErr error
	for _, r := range rels {
		syncErr = errors.Join(syncErr, s.sync(ctx, "remove manager", managedID, s.syncer.RemovePrincipalManager(ctx, managedID, r.ManagerPrincipalID, r.Role)))
	}
	return errors.Join(syncErr, s.sync(ctx, "unregister principal", managedID, s.syncer.UnregisterPrincipal(ctx, managedID)))
}
