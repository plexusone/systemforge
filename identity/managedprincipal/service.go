package managedprincipal

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/authz/noop"
	"github.com/plexusone/systemforge/authz/rbac"
	"github.com/plexusone/systemforge/contract/audit"
	"github.com/plexusone/systemforge/identity/accesschange"
	"github.com/plexusone/systemforge/identity/credential"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/human"
	"github.com/plexusone/systemforge/identity/ent/managerrelationship"
	"github.com/plexusone/systemforge/identity/ent/predicate"
	entprincipal "github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/principal"
)

// Audit event types emitted by the service.
const (
	EventCreated        = "managed_principal.created"
	EventManagerAdded   = "managed_principal.manager_added"
	EventManagerRemoved = "managed_principal.manager_removed"
	EventTokenIssued    = "managed_principal.login_token_issued"
	// EventReleased records that a principal's management ended.
	EventReleased = "managed_principal.released"
)

// Service creates managed principals and maintains their managers.
type Service struct {
	client    *ent.Client
	creds     credential.Service
	now       func() time.Time
	gate      Gate
	audit     audit.Emitter
	syncer    authz.RelationshipSyncer
	syncMode  authz.SyncMode
	authz     authz.Authorizer
	claimTTL  time.Duration
	inviteTTL time.Duration
	logger    *slog.Logger
	roles     []string

	accessSink accesschange.Sink
}

// Option configures a Service.
type Option func(*Service)

// WithAuditEmitter records every action through the given emitter.
func WithAuditEmitter(e audit.Emitter) Option {
	return func(s *Service) { s.audit = e }
}

// WithAuthzSyncer mirrors manager relationships into the authorization
// backend as guardian and educator relations on the managed principal. In
// authz.SyncModeStrict a sync failure is returned, after the database
// change has committed; otherwise it is logged.
func WithAuthzSyncer(syncer authz.RelationshipSyncer, mode authz.SyncMode) Option {
	return func(s *Service) {
		s.syncer = syncer
		s.syncMode = mode
	}
}

// WithAuthorizer sets the authorizer that checks managers' permissions on
// managed principals, such as a SpiceDB provider or a simple provider with
// a platform-administrator check. Defaults to a simple provider backed by
// ManagerRoles.
func WithAuthorizer(a authz.Authorizer) Option {
	return func(s *Service) { s.authz = a }
}

// WithAccessChangeSink announces session revocations (RevokeSession and
// RevokeAll) to sink after they commit (ADR-010). The access-change record
// is written whether or not a sink is set.
func WithAccessChangeSink(sink accesschange.Sink) Option {
	return func(s *Service) { s.accessSink = sink }
}

// WithLogger sets the logger used for failures that cannot be returned,
// such as an audit emission after the change committed.
func WithLogger(l *slog.Logger) Option {
	return func(s *Service) { s.logger = l }
}

// WithRoles registers manager roles in addition to the built-in guardian
// and educator roles.
func WithRoles(roles ...string) Option {
	return func(s *Service) {
		for _, r := range roles {
			if r != "" && !slices.Contains(s.roles, r) {
				s.roles = append(s.roles, r)
			}
		}
	}
}

// NewService returns a Service. The gate decides whether a client may
// create managed principals; pass the SystemAuth server.
func NewService(client *ent.Client, gate Gate, opts ...Option) *Service {
	s := &Service{
		client:    client,
		creds:     credential.NewService(client),
		now:       time.Now,
		claimTTL:  DefaultClaimTTL,
		inviteTTL: DefaultInviteTTL,
		gate:      gate,
		syncer:    noop.NewSyncer(),
		syncMode:  authz.SyncModeEventual,
		logger:    slog.Default(),
		roles:     []string{RoleGuardian, RoleEducator},
	}
	for _, opt := range opts {
		opt(s)
	}
	if s.authz == nil {
		s.authz = rbac.New(rbac.WithManagerRoleGetter(s.ManagerRoles))
	}
	return s
}

// Roles returns the registered manager roles.
func (s *Service) Roles() []string {
	return slices.Clone(s.roles)
}

// Create creates a managed principal with its managers in one transaction.
// It returns the new principal's ID. The actor must be one of the managers,
// the manager creating the principal, or a platform administrator
// (ErrForbidden otherwise).
func (s *Service) Create(ctx context.Context, in CreateInput) (uuid.UUID, error) {
	if in.DisplayName == "" {
		return uuid.Nil, ErrDisplayNameRequired
	}
	if len(in.Managers) == 0 {
		return uuid.Nil, ErrNoManagers
	}
	for _, m := range in.Managers {
		if err := s.checkRole(m.Role); err != nil {
			return uuid.Nil, err
		}
	}
	if err := s.authorizeCreate(ctx, in.ActorID, in.Managers); err != nil {
		return uuid.Nil, err
	}
	allowed, err := s.gate.ManagedPrincipalsAllowed(ctx, in.ClientID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("managedprincipal: check client: %w", err)
	}
	if !allowed {
		return uuid.Nil, ErrNotAllowed
	}

	email := strings.TrimSpace(in.Email)
	id := uuid.New()
	err = s.withTx(ctx, func(tx *ent.Tx) error {
		for _, m := range in.Managers {
			if err := validateManager(ctx, tx, m.PrincipalID); err != nil {
				return err
			}
		}
		identifier := "human:" + id.String()
		if email != "" {
			taken, err := tx.Human.Query().Where(human.EmailEqualFold(email)).Exist(ctx)
			if err != nil {
				return fmt.Errorf("managedprincipal: check email: %w", err)
			}
			if taken {
				return ErrEmailInUse
			}
			identifier = email
		}
		if _, err := tx.Principal.Create().
			SetID(id).
			SetType(entprincipal.TypeHuman).
			SetIdentifier(identifier).
			SetDisplayName(in.DisplayName).
			SetActive(true).
			SetCapabilities(principal.ManagedHumanCapabilities().ToMap()).
			Save(ctx); err != nil {
			return fmt.Errorf("managedprincipal: create principal: %w", err)
		}
		hc := tx.Human.Create().SetPrincipalID(id)
		if email != "" {
			hc.SetEmail(email)
		}
		if _, err := hc.Save(ctx); err != nil {
			if ent.IsConstraintError(err) && email != "" {
				return ErrEmailInUse
			}
			return fmt.Errorf("managedprincipal: create human: %w", err)
		}
		for _, m := range in.Managers {
			if err := upsertRelationship(ctx, tx, id, m, in.ActorID); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return uuid.Nil, err
	}

	details := map[string]any{"client_id": in.ClientID, "managers": managerDetails(in.Managers), "has_email": email != ""}
	s.emit(ctx, EventCreated, "create", in.ActorID, id, details)

	syncErr := s.sync(ctx, "register principal", id, s.syncer.RegisterPrincipal(ctx, id))
	for _, m := range in.Managers {
		syncErr = errors.Join(syncErr, s.sync(ctx, "add manager", id, s.syncer.AddPrincipalManager(ctx, id, m.PrincipalID, m.Role)))
	}
	if syncErr != nil {
		return id, syncErr
	}
	return id, nil
}

// AddManager makes manager a manager of managed with the given role. It is
// a no-op when the relationship is already active and reactivates it when
// inactive. The actor needs manage_managers on the managed principal,
// which guardians hold; the permission is checked under the principal's
// row lock, in the transaction that writes.
func (s *Service) AddManager(ctx context.Context, managedID uuid.UUID, m ManagerInput, actorID uuid.UUID) error {
	if err := s.checkRole(m.Role); err != nil {
		return err
	}
	err := s.withTx(ctx, func(tx *ent.Tx) error {
		// Only a principal that already has a manager can gain another;
		// a self-managed human enters management by accepting an
		// invitation (ADR-009). The check, and the actor's authority, are
		// made under the principal's row lock.
		if _, err := s.lockAndAuthorize(ctx, tx, actorID, managedID); err != nil {
			return err
		}
		if m.PrincipalID == managedID {
			return ErrInvalidManager
		}
		if err := validateManager(ctx, tx, m.PrincipalID); err != nil {
			return err
		}
		return upsertRelationship(ctx, tx, managedID, m, actorID)
	})
	if err != nil {
		return err
	}
	s.emit(ctx, EventManagerAdded, "add_manager", actorID, managedID,
		map[string]any{"manager_principal_id": m.PrincipalID.String(), "role": m.Role})
	return s.sync(ctx, "add manager", managedID, s.syncer.AddPrincipalManager(ctx, managedID, m.PrincipalID, m.Role))
}

// RemoveManager deactivates a manager relationship. It refuses with
// ErrLastManager when this is the last active manager of a principal
// without a verified email; deactivate or delete the principal instead.
// Removing the last manager of a principal with a verified email releases
// it, as Release does. The actor needs manage_managers on the managed
// principal, which guardians hold; the permission is checked under the
// principal's row lock, in the transaction that writes, so of two
// concurrent removals that each withdraw the other's authority exactly one
// succeeds.
func (s *Service) RemoveManager(ctx context.Context, managedID uuid.UUID, m ManagerInput, actorID uuid.UUID) error {
	var (
		released bool
		change   accesschange.Change
	)
	err := s.withTx(ctx, func(tx *ent.Tx) error {
		h, err := s.lockAndAuthorize(ctx, tx, actorID, managedID)
		if err != nil {
			return err
		}
		rel, err := tx.ManagerRelationship.Query().
			Where(
				managerrelationship.ManagedPrincipalID(managedID),
				managerrelationship.ManagerPrincipalID(m.PrincipalID),
				managerrelationship.Role(m.Role),
				managerrelationship.Active(true),
			).
			Only(ctx)
		if ent.IsNotFound(err) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("managedprincipal: find relationship: %w", err)
		}
		if !emailVerified(h) {
			n, err := tx.ManagerRelationship.Query().
				Where(
					managerrelationship.ManagedPrincipalID(managedID),
					managerrelationship.Active(true),
				).
				Count(ctx)
			if err != nil {
				return fmt.Errorf("managedprincipal: count managers: %w", err)
			}
			if n <= 1 {
				return ErrLastManager
			}
		}
		if err := tx.ManagerRelationship.UpdateOne(rel).SetActive(false).Exec(ctx); err != nil {
			return fmt.Errorf("managedprincipal: deactivate relationship: %w", err)
		}
		// Only a principal with a verified email gets here with no manager
		// left: removing its last manager releases it (ADR-009).
		remaining, err := tx.ManagerRelationship.Query().
			Where(managerrelationship.ManagedPrincipalID(managedID), managerrelationship.Active(true)).
			Count(ctx)
		if err != nil {
			return fmt.Errorf("managedprincipal: count managers: %w", err)
		}
		if remaining == 0 {
			released = true
			change, err = endManagement(ctx, tx, managedID)
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	if released {
		accesschange.Publish(s.accessSink, change)
	}
	s.emit(ctx, EventManagerRemoved, "remove_manager", actorID, managedID,
		map[string]any{"manager_principal_id": m.PrincipalID.String(), "role": m.Role})
	if released {
		s.emit(ctx, EventReleased, "release", actorID, managedID,
			map[string]any{"managers": managerDetails([]ManagerInput{m})})
	}
	return s.sync(ctx, "remove manager", managedID, s.syncer.RemovePrincipalManager(ctx, managedID, m.PrincipalID, m.Role))
}

// IssueLoginToken issues a login token for a managed principal on behalf
// of one of its active managers. The plain token is returned once.
func (s *Service) IssueLoginToken(ctx context.Context, in IssueLoginTokenInput) (*credential.GeneratedLoginToken, error) {
	allowed, err := s.gate.ManagedPrincipalsAllowed(ctx, in.ClientID)
	if err != nil {
		return nil, fmt.Errorf("managedprincipal: check client: %w", err)
	}
	if !allowed {
		return nil, ErrNotAllowed
	}
	if err := s.checkIssuer(ctx, in.ManagedID, in.IssuedBy); err != nil {
		return nil, err
	}
	policy, err := s.gate.LoginTokenPolicy(ctx, in.ClientID)
	if err != nil {
		return nil, fmt.Errorf("managedprincipal: login token policy: %w", err)
	}
	expiresAt, clamped, err := policy.ExpiresAt(s.now(), in.ExpiresAt, in.SingleUse)
	if err != nil {
		return nil, err
	}
	if clamped {
		s.logger.Info("managedprincipal: login token lifetime clamped to the platform ceiling",
			"principal_id", in.ManagedID, "client_id", in.ClientID, "expires_at", expiresAt)
	}

	tok, err := s.creds.IssueLoginToken(ctx, credential.IssueLoginTokenInput{
		PrincipalID: in.ManagedID,
		IssuedBy:    in.IssuedBy,
		ExpiresAt:   expiresAt,
		SingleUse:   in.SingleUse,
		Name:        in.Name,
	})
	if err != nil {
		return nil, fmt.Errorf("managedprincipal: %w", err)
	}
	s.emit(ctx, EventTokenIssued, "issue_login_token", in.IssuedBy, in.ManagedID, map[string]any{
		"client_id":     in.ClientID,
		"credential_id": tok.Credential.ID.String(),
		"prefix":        tok.Prefix,
		"expires_at":    expiresAt,
		"single_use":    in.SingleUse,
		"clamped":       clamped,
	})
	return tok, nil
}

// checkIssuer requires an active managed principal and an issuer that is
// one of its active managers and still a valid manager.
func (s *Service) checkIssuer(ctx context.Context, managedID, issuerID uuid.UUID) error {
	ok, err := s.client.Human.Query().
		Where(
			human.PrincipalID(managedID),
			hasActiveManager(),
			human.HasPrincipalWith(entprincipal.Active(true)),
		).
		Exist(ctx)
	if err != nil {
		return fmt.Errorf("managedprincipal: check principal: %w", err)
	}
	if !ok {
		return ErrNotManaged
	}
	ok, err = s.client.ManagerRelationship.Query().
		Where(
			managerrelationship.ManagedPrincipalID(managedID),
			managerrelationship.ManagerPrincipalID(issuerID),
			managerrelationship.Active(true),
			managerrelationship.HasManagerWith(
				entprincipal.Active(true),
				entprincipal.HasHumanWith(human.EmailNotNil()),
			),
		).
		Exist(ctx)
	if err != nil {
		return fmt.Errorf("managedprincipal: check manager: %w", err)
	}
	if !ok {
		return ErrNotManager
	}
	return nil
}

// ListManagersFor returns the active manager relationships of a managed
// principal to an actor that holds view_profile on it, which guardians and
// educators do.
func (s *Service) ListManagersFor(ctx context.Context, actorID, managedID uuid.UUID) ([]Relationship, error) {
	if err := s.authorizeProfile(ctx, actorID, managedID); err != nil {
		return nil, err
	}
	return s.ListManagers(ctx, managedID)
}

// ListManagers returns the active manager relationships of a principal.
func (s *Service) ListManagers(ctx context.Context, managedID uuid.UUID) ([]Relationship, error) {
	rows, err := s.client.ManagerRelationship.Query().
		Where(
			managerrelationship.ManagedPrincipalID(managedID),
			managerrelationship.Active(true),
		).
		Order(ent.Asc(managerrelationship.FieldCreatedAt)).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("managedprincipal: list managers: %w", err)
	}
	out := make([]Relationship, 0, len(rows))
	for _, r := range rows {
		out = append(out, Relationship{
			ManagedPrincipalID: r.ManagedPrincipalID,
			ManagerPrincipalID: r.ManagerPrincipalID,
			Role:               r.Role,
			Active:             r.Active,
		})
	}
	return out, nil
}

// ManagerRoles returns the roles managerID actively holds over managedID.
// It matches authz.ManagerRoleGetter, so it can back the simple provider:
// rbac.WithManagerRoleGetter(svc.ManagerRoles).
func (s *Service) ManagerRoles(ctx context.Context, managerID, managedID uuid.UUID) ([]string, error) {
	rels := s.client.ManagerRelationship
	if tx, ok := ctx.Value(txContextKey{}).(*ent.Tx); ok {
		// An authorization check made under a row lock reads in that
		// transaction (lockAndAuthorize).
		rels = tx.ManagerRelationship
	}
	roles, err := rels.Query().
		Where(
			managerrelationship.ManagedPrincipalID(managedID),
			managerrelationship.ManagerPrincipalID(managerID),
			managerrelationship.Active(true),
			managerrelationship.HasManagerWith(entprincipal.Active(true)),
		).
		Select(managerrelationship.FieldRole).
		Strings(ctx)
	if err != nil {
		return nil, fmt.Errorf("managedprincipal: manager roles: %w", err)
	}
	return roles, nil
}

// IsManaged reports whether the principal is a human with at least one
// active manager relationship. An email, verified or not, does not change
// the answer (ADR-009).
func (s *Service) IsManaged(ctx context.Context, principalID uuid.UUID) (bool, error) {
	return s.client.Human.Query().
		Where(human.PrincipalID(principalID), hasActiveManager()).
		Exist(ctx)
}

// hasActiveManager matches humans whose principal has an active manager
// relationship: the definition of a managed principal.
func hasActiveManager() predicate.Human {
	return human.HasPrincipalWith(entprincipal.HasManagersWith(managerrelationship.Active(true)))
}

// emailVerified reports whether the human has an email it has proven to
// control, the condition for management to end.
func emailVerified(h *ent.Human) bool {
	return h.Email != nil && h.EmailVerifiedAt != nil
}

// requireManaged returns ErrNotManaged unless the principal has an active
// manager relationship.
func requireManaged(ctx context.Context, tx *ent.Tx, id uuid.UUID) error {
	ok, err := tx.ManagerRelationship.Query().
		Where(managerrelationship.ManagedPrincipalID(id), managerrelationship.Active(true)).
		Exist(ctx)
	if err != nil {
		return fmt.Errorf("managedprincipal: check managed: %w", err)
	}
	if !ok {
		return ErrNotManaged
	}
	return nil
}

func (s *Service) checkRole(role string) error {
	if !slices.Contains(s.roles, role) {
		return fmt.Errorf("%w: %q", ErrInvalidRole, role)
	}
	return nil
}

// validateManager checks that the principal is an active human with an
// email that is not itself managed (ADR-009).
func validateManager(ctx context.Context, tx *ent.Tx, id uuid.UUID) error {
	ok, err := tx.Human.Query().
		Where(
			human.PrincipalID(id),
			human.EmailNotNil(),
			human.HasPrincipalWith(entprincipal.Active(true), entprincipal.TypeEQ(entprincipal.TypeHuman)),
			// A managed principal cannot manage, with or without an email.
			human.Not(hasActiveManager()),
		).
		Exist(ctx)
	if err != nil {
		return fmt.Errorf("managedprincipal: check manager: %w", err)
	}
	if !ok {
		return fmt.Errorf("%w: %s", ErrInvalidManager, id)
	}
	return nil
}

// txContextKey carries the transaction of an authorization check made
// under a row lock, for the built-in role lookup.
type txContextKey struct{}

// lockAndAuthorize takes the managed principal's row lock and then
// requires that principal to be an active managed principal and actorID to
// hold manage_managers on it, returning the principal's human extension.
// Checking after the lock closes the window between check and write: a
// concurrent change to the managers of the same principal has committed, or
// has not started, by the time the authority is read, so two managers
// cannot each act on authority the other's removal withdraws.
//
// The authorizer is called with a context carrying tx, which ManagerRoles
// reads through, so the built-in role lookup runs in the locked
// transaction (a second connection would block on the held lock under
// SQLite). Authorizers backed by another store read committed state, which
// already includes any change whose lock this one waited for.
func (s *Service) lockAndAuthorize(ctx context.Context, tx *ent.Tx, actorID, managedID uuid.UUID) (*ent.Human, error) {
	h, err := lockHuman(ctx, tx, managedID)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrNotManaged
	}
	if err != nil {
		return nil, err
	}
	active, err := tx.Principal.Query().Where(entprincipal.ID(managedID), entprincipal.Active(true)).Exist(ctx)
	if err != nil {
		return nil, fmt.Errorf("managedprincipal: check principal: %w", err)
	}
	if !active {
		return nil, ErrNotManaged
	}
	if err := requireManaged(ctx, tx, managedID); err != nil {
		return nil, err
	}
	ok, err := s.authz.Can(context.WithValue(ctx, txContextKey{}, tx), authz.NewUserPrincipal(actorID), authz.PermManageManagers, authz.NewPrincipalResource(managedID))
	if err != nil {
		return nil, fmt.Errorf("managedprincipal: authorize: %w", err)
	}
	if !ok {
		return nil, ErrForbidden
	}
	return h, nil
}

// lockHuman returns the human extension of the principal after updating
// the principal row, which holds a row lock for the rest of the
// transaction so concurrent manager changes to the same principal
// serialize and cannot together remove the last manager.
func lockHuman(ctx context.Context, tx *ent.Tx, id uuid.UUID) (*ent.Human, error) {
	err := tx.Principal.UpdateOneID(id).Exec(ctx)
	if ent.IsNotFound(err) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("managedprincipal: lock principal: %w", err)
	}
	h, err := tx.Human.Query().Where(human.PrincipalID(id)).Only(ctx)
	if ent.IsNotFound(err) {
		return nil, ErrNotManaged
	}
	if err != nil {
		return nil, fmt.Errorf("managedprincipal: load human: %w", err)
	}
	return h, nil
}

func upsertRelationship(ctx context.Context, tx *ent.Tx, managedID uuid.UUID, m ManagerInput, actorID uuid.UUID) error {
	rel, err := tx.ManagerRelationship.Query().
		Where(
			managerrelationship.ManagedPrincipalID(managedID),
			managerrelationship.ManagerPrincipalID(m.PrincipalID),
			managerrelationship.Role(m.Role),
		).
		Only(ctx)
	switch {
	case ent.IsNotFound(err):
		c := tx.ManagerRelationship.Create().
			SetManagedPrincipalID(managedID).
			SetManagerPrincipalID(m.PrincipalID).
			SetRole(m.Role)
		if actorID != uuid.Nil {
			c.SetCreatedBy(actorID)
		}
		if err := c.Exec(ctx); err != nil {
			return fmt.Errorf("managedprincipal: create relationship: %w", err)
		}
		return nil
	case err != nil:
		return fmt.Errorf("managedprincipal: find relationship: %w", err)
	case rel.Active:
		return nil
	default:
		if err := tx.ManagerRelationship.UpdateOne(rel).SetActive(true).Exec(ctx); err != nil {
			return fmt.Errorf("managedprincipal: reactivate relationship: %w", err)
		}
		return nil
	}
}

func (s *Service) withTx(ctx context.Context, fn func(*ent.Tx) error) error {
	tx, err := s.client.Tx(ctx)
	if err != nil {
		return fmt.Errorf("managedprincipal: begin transaction: %w", err)
	}
	if err := fn(tx); err != nil {
		if rerr := tx.Rollback(); rerr != nil {
			return errors.Join(err, fmt.Errorf("managedprincipal: rollback: %w", rerr))
		}
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("managedprincipal: commit: %w", err)
	}
	return nil
}

// sync applies the sync mode to the result of an authorization backend
// write made after the database change committed.
func (s *Service) sync(ctx context.Context, op string, managedID uuid.UUID, err error) error {
	if err == nil {
		return nil
	}
	if s.syncMode == authz.SyncModeStrict {
		return fmt.Errorf("managedprincipal: sync %s to authz: %w", op, err)
	}
	s.logger.WarnContext(ctx, "managedprincipal: failed to sync to authz", "op", op, "principal_id", managedID, "error", err)
	return nil
}

// emit records an audit event. The change has already committed, so a
// failure is logged rather than returned.
func (s *Service) emit(ctx context.Context, eventType, action string, actorID, managedID uuid.UUID, details map[string]any) {
	if s.audit == nil {
		return
	}
	ev := &audit.Event{
		EventType: eventType,
		Action:    action,
		Actor:     audit.Actor{ID: actorID, Type: "human"},
		Resource:  audit.Resource{Type: "principal", ID: managedID},
		Outcome:   "success",
		Details:   details,
	}
	if err := s.audit.Emit(ctx, ev); err != nil {
		s.logger.Error("managedprincipal: emit audit event", "event_type", eventType, "principal_id", managedID, "error", err)
	}
}

func managerDetails(ms []ManagerInput) []map[string]string {
	out := make([]map[string]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, map[string]string{"principal_id": m.PrincipalID.String(), "role": m.Role})
	}
	return out
}

// authorizeCreate requires the actor to be one of the principal's managers,
// or a platform administrator. There is no principal yet to check a
// permission against: the creating manager is the authority, as it is for
// the first guardian or educator of a classroom.
func (s *Service) authorizeCreate(ctx context.Context, actorID uuid.UUID, managers []ManagerInput) error {
	if actorID == uuid.Nil {
		return fmt.Errorf("%w: an acting principal is required", ErrForbidden)
	}
	for _, m := range managers {
		if m.PrincipalID == actorID {
			return nil
		}
	}
	pa, ok := s.authz.(authz.PlatformAuthorizer)
	if !ok {
		return ErrForbidden
	}
	admin, err := pa.IsPlatformAdmin(ctx, authz.NewUserPrincipal(actorID))
	if err != nil {
		return fmt.Errorf("managedprincipal: authorize: %w", err)
	}
	if !admin {
		return ErrForbidden
	}
	return nil
}
