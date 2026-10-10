package managedprincipal

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/accesschange"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/managerinvite"
	"github.com/plexusone/systemforge/identity/ent/managerrelationship"
	"github.com/plexusone/systemforge/identity/ent/predicate"
	entprincipal "github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/principal"
)

const (
	// InviteCodePrefix starts every manager invitation token.
	InviteCodePrefix = "SFMI"
	// invitePrefixLen is the stored, displayable lookup prefix.
	invitePrefixLen = len(InviteCodePrefix) + 8

	// DefaultInviteTTL is how long a manager invitation stays acceptable.
	DefaultInviteTTL = 7 * 24 * time.Hour

	// Audit event types for manager invitations.
	EventManagerInvited        = "managed_principal.manager_invited"
	EventManagerInviteAccepted = "managed_principal.manager_invite_accepted"
	EventManagerInviteRevoked  = "managed_principal.manager_invite_revoked"
)

var (
	// ErrInvalidInvite is returned for every invitation that cannot be
	// accepted: unknown, malformed, expired, revoked, already accepted, or
	// addressed to someone other than the signed-in principal.
	ErrInvalidInvite = errors.New("managedprincipal: invalid manager invitation")
	// ErrAlreadyManaged is returned when accepting an invitation for a
	// principal that already has a manager. Its managers change the
	// relationships; an invitation is the way into management.
	ErrAlreadyManaged = errors.New("managedprincipal: principal is already managed")
	// ErrManagesOthers is returned when a principal that manages others
	// would enter management: a managed principal cannot manage.
	ErrManagesOthers = errors.New("managedprincipal: principal manages other principals")
	// ErrInviteEmailRequired is returned when inviting without an address.
	ErrInviteEmailRequired = errors.New("managedprincipal: invitee email is required")
)

// WithInviteTTL sets how long manager invitations stay acceptable.
// Defaults to DefaultInviteTTL.
func WithInviteTTL(d time.Duration) Option {
	return func(s *Service) {
		if d > 0 {
			s.inviteTTL = d
		}
	}
}

// InviteManagerInput describes a manager invitation.
type InviteManagerInput struct {
	// ClientID is the OAuth client making the request; it must allow
	// managed principals.
	ClientID string
	// ManagerID is the human offering to manage: an active human with an
	// email that is not itself managed. It is also the actor.
	ManagerID uuid.UUID
	// Email is the verified email of the human invited to be managed. Only
	// a principal whose verified email matches can accept.
	Email string
	// Role is the manager role the inviter will hold.
	Role string
}

// ManagerInvite is a newly issued manager invitation. Token is available
// only here; the application delivers it to the invitee.
type ManagerInvite struct {
	ID        uuid.UUID
	Token     string
	Email     string
	Role      string
	ExpiresAt time.Time
}

// InviteManager offers to manage the self-managed human with the given
// verified email. Nothing changes for that human until it accepts the
// invitation while signed in (AcceptManagerInvite): a manager relationship
// with an existing principal is never created without its consent
// (ADR-009).
func (s *Service) InviteManager(ctx context.Context, in InviteManagerInput) (*ManagerInvite, error) {
	email := strings.TrimSpace(in.Email)
	if email == "" {
		return nil, ErrInviteEmailRequired
	}
	if err := s.checkRole(in.Role); err != nil {
		return nil, err
	}
	allowed, err := s.gate.ManagedPrincipalsAllowed(ctx, in.ClientID)
	if err != nil {
		return nil, fmt.Errorf("managedprincipal: check client: %w", err)
	}
	if !allowed {
		return nil, ErrNotAllowed
	}
	err = s.withTx(ctx, func(tx *ent.Tx) error { return validateManager(ctx, tx, in.ManagerID) })
	if err != nil {
		return nil, err
	}
	randomBytes := make([]byte, claimCodeBytes)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, fmt.Errorf("managedprincipal: generate invitation token: %w", err)
	}
	token := InviteCodePrefix + claimEncoding.EncodeToString(randomBytes)
	now := s.now()
	expiresAt := now.Add(s.inviteTTL)
	row, err := s.client.ManagerInvite.Create().
		SetManagerPrincipalID(in.ManagerID).
		SetEmail(email).
		SetRole(in.Role).
		SetTokenPrefix(token[:invitePrefixLen]).
		SetTokenHash(hashCode(token)).
		SetExpiresAt(expiresAt).
		SetCreatedAt(now).
		Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("managedprincipal: store invitation: %w", err)
	}
	s.emit(ctx, EventManagerInvited, "invite_manager", in.ManagerID, in.ManagerID,
		map[string]any{"invite_id": row.ID.String(), "role": in.Role, "client_id": in.ClientID, "expires_at": expiresAt})
	return &ManagerInvite{ID: row.ID, Token: token, Email: email, Role: in.Role, ExpiresAt: expiresAt}, nil
}

// AcceptManagerInvite is the signed-in principal's consent to be managed:
// it spends the invitation, makes the inviter a manager with the invited
// role, and gives up the capabilities that managed principals do not have
// (profile management, delegation). principalID is the caller's own
// identity, never a value a manager supplies. It returns the manager's ID.
//
// The principal must be an active human whose verified email is the
// invited address, must have no manager yet (ErrAlreadyManaged), and must
// not manage others (ErrManagesOthers). Every failure to match is
// ErrInvalidInvite.
func (s *Service) AcceptManagerInvite(ctx context.Context, token string, principalID uuid.UUID) (uuid.UUID, error) {
	token = normalizeCode(token)
	if len(token) <= invitePrefixLen || !strings.HasPrefix(token, InviteCodePrefix) {
		return uuid.Nil, ErrInvalidInvite
	}
	var (
		managerID uuid.UUID
		role      string
		change    accesschange.Change
	)
	err := s.withTx(ctx, func(tx *ent.Tx) error {
		inv, err := tx.ManagerInvite.Query().Where(managerinvite.TokenPrefix(token[:invitePrefixLen])).Only(ctx)
		if ent.IsNotFound(err) {
			return ErrInvalidInvite
		}
		if err != nil {
			return fmt.Errorf("managedprincipal: find invitation: %w", err)
		}
		want, err := hex.DecodeString(inv.TokenHash)
		if err != nil {
			return fmt.Errorf("managedprincipal: corrupt invitation hash %s: %w", inv.ID, err)
		}
		got := sha256.Sum256([]byte(token))
		if subtle.ConstantTimeCompare(got[:], want) != 1 {
			return ErrInvalidInvite
		}
		now := s.now()
		if inv.AcceptedAt != nil || inv.RevokedAt != nil || !inv.ExpiresAt.After(now) {
			return ErrInvalidInvite
		}
		h, err := lockHuman(ctx, tx, principalID)
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrNotManaged) {
			return ErrInvalidInvite
		}
		if err != nil {
			return err
		}
		active, err := tx.Principal.Query().Where(principalActive(principalID)).Exist(ctx)
		if err != nil {
			return fmt.Errorf("managedprincipal: check principal: %w", err)
		}
		if !active || !emailVerified(h) || !strings.EqualFold(*h.Email, inv.Email) || inv.ManagerPrincipalID == principalID {
			return ErrInvalidInvite
		}
		if err := requireManaged(ctx, tx, principalID); err == nil {
			return ErrAlreadyManaged
		} else if !errors.Is(err, ErrNotManaged) {
			return err
		}
		manages, err := tx.ManagerRelationship.Query().
			Where(managerrelationship.ManagerPrincipalID(principalID), managerrelationship.Active(true)).
			Exist(ctx)
		if err != nil {
			return fmt.Errorf("managedprincipal: check managed principals: %w", err)
		}
		if manages {
			return ErrManagesOthers
		}
		if err := validateManager(ctx, tx, inv.ManagerPrincipalID); err != nil {
			return err
		}
		// Spend the invitation conditionally so concurrent acceptances
		// cannot both succeed.
		n, err := tx.ManagerInvite.Update().
			Where(managerinvite.ID(inv.ID), managerinvite.AcceptedAtIsNil(), managerinvite.RevokedAtIsNil()).
			SetAcceptedAt(now).
			SetAcceptedBy(principalID).
			Save(ctx)
		if err != nil {
			return fmt.Errorf("managedprincipal: spend invitation: %w", err)
		}
		if n != 1 {
			return ErrInvalidInvite
		}
		managerID, role = inv.ManagerPrincipalID, inv.Role
		if err := upsertRelationship(ctx, tx, principalID, ManagerInput{PrincipalID: managerID, Role: role}, principalID); err != nil {
			return err
		}
		if err := tx.Principal.UpdateOneID(principalID).
			SetCapabilities(principal.ManagedHumanCapabilities().ToMap()).
			Exec(ctx); err != nil {
			return fmt.Errorf("managedprincipal: restrict capabilities: %w", err)
		}
		// Tokens issued before may carry the capabilities just given up
		// (ADR-010).
		change, err = accesschange.Record(ctx, tx, accesschange.Change{PrincipalID: principalID, Reason: accesschange.ManagementGranted})
		return err
	})
	if err != nil {
		return uuid.Nil, err
	}
	accesschange.Publish(s.accessSink, change)
	s.emit(ctx, EventManagerInviteAccepted, "accept_manager_invite", principalID, principalID,
		map[string]any{"manager_principal_id": managerID.String(), "role": role})
	return managerID, s.sync(ctx, "add manager", principalID, s.syncer.AddPrincipalManager(ctx, principalID, managerID, role))
}

// RevokeManagerInvite withdraws a pending invitation. Only the inviter may.
func (s *Service) RevokeManagerInvite(ctx context.Context, actorID, inviteID uuid.UUID) error {
	n, err := s.client.ManagerInvite.Update().
		Where(
			managerinvite.ID(inviteID),
			managerinvite.ManagerPrincipalID(actorID),
			managerinvite.AcceptedAtIsNil(),
			managerinvite.RevokedAtIsNil(),
		).
		SetRevokedAt(s.now()).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("managedprincipal: revoke invitation: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	s.emit(ctx, EventManagerInviteRevoked, "revoke_manager_invite", actorID, actorID,
		map[string]any{"invite_id": inviteID.String()})
	return nil
}

func principalActive(id uuid.UUID) predicate.Principal {
	return entprincipal.And(entprincipal.ID(id), entprincipal.Active(true))
}
