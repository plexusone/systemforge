package managedprincipal

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/authz/noop"
	"github.com/plexusone/systemforge/authz/simple"
	"github.com/plexusone/systemforge/contract/audit"
	"github.com/plexusone/systemforge/identity/credential"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/human"
	"github.com/plexusone/systemforge/identity/ent/managerrelationship"
	entprincipal "github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/principal"
)

// Audit event types emitted by the service.
const (
	EventCreated        = "managed_principal.created"
	EventManagerAdded   = "managed_principal.manager_added"
	EventManagerRemoved = "managed_principal.manager_removed"
	EventTokenIssued    = "managed_principal.login_token_issued"
)

// Service creates managed principals and maintains their managers.
type Service struct {
	client   *ent.Client
	creds    credential.Service
	now      func() time.Time
	gate     Gate
	audit    audit.Emitter
	syncer   authz.RelationshipSyncer
	syncMode authz.SyncMode
	authz    authz.Authorizer
	claimTTL time.Duration
	logger   *slog.Logger
	roles    []string
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
		client:   client,
		creds:    credential.NewService(client),
		now:      time.Now,
		claimTTL: DefaultClaimTTL,
		gate:     gate,
		syncer:   noop.NewSyncer(),
		syncMode: authz.SyncModeEventual,
		logger:   slog.Default(),
		roles:    []string{RoleGuardian, RoleEducator},
	}
	for _, opt := range opts {
		opt(s)
	}
	if s.authz == nil {
		s.authz = simple.New(simple.WithManagerRoleGetter(s.ManagerRoles))
	}
	return s
}

// Roles returns the registered manager roles.
func (s *Service) Roles() []string {
	return slices.Clone(s.roles)
}

// Create creates a managed principal with its managers in one transaction.
// It returns the new principal's ID.
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
	allowed, err := s.gate.ManagedPrincipalsAllowed(ctx, in.ClientID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("managedprincipal: check client: %w", err)
	}
	if !allowed {
		return uuid.Nil, ErrNotAllowed
	}

	id := uuid.New()
	err = s.withTx(ctx, func(tx *ent.Tx) error {
		for _, m := range in.Managers {
			if err := validateManager(ctx, tx, m.PrincipalID); err != nil {
				return err
			}
		}
		if _, err := tx.Principal.Create().
			SetID(id).
			SetType(entprincipal.TypeHuman).
			SetIdentifier("human:" + id.String()).
			SetDisplayName(in.DisplayName).
			SetActive(true).
			SetCapabilities(principal.ManagedHumanCapabilities().ToMap()).
			Save(ctx); err != nil {
			return fmt.Errorf("managedprincipal: create principal: %w", err)
		}
		if _, err := tx.Human.Create().SetPrincipalID(id).Save(ctx); err != nil {
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

	details := map[string]any{"client_id": in.ClientID, "managers": managerDetails(in.Managers)}
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
// inactive.
func (s *Service) AddManager(ctx context.Context, managedID uuid.UUID, m ManagerInput, actorID uuid.UUID) error {
	if err := s.checkRole(m.Role); err != nil {
		return err
	}
	err := s.withTx(ctx, func(tx *ent.Tx) error {
		if _, err := lockHuman(ctx, tx, managedID); err != nil {
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
// ErrLastManager when the managed principal has no email and this is its
// last active manager; deactivate or delete the principal instead.
func (s *Service) RemoveManager(ctx context.Context, managedID uuid.UUID, m ManagerInput, actorID uuid.UUID) error {
	err := s.withTx(ctx, func(tx *ent.Tx) error {
		h, err := lockHuman(ctx, tx, managedID)
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
		if h.Email == nil {
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
		return nil
	})
	if err != nil {
		return err
	}
	s.emit(ctx, EventManagerRemoved, "remove_manager", actorID, managedID,
		map[string]any{"manager_principal_id": m.PrincipalID.String(), "role": m.Role})
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
			human.EmailIsNil(),
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
// simple.WithManagerRoleGetter(svc.ManagerRoles).
func (s *Service) ManagerRoles(ctx context.Context, managerID, managedID uuid.UUID) ([]string, error) {
	roles, err := s.client.ManagerRelationship.Query().
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

// IsManaged reports whether the principal is a human without an email.
func (s *Service) IsManaged(ctx context.Context, principalID uuid.UUID) (bool, error) {
	return s.client.Human.Query().
		Where(human.PrincipalID(principalID), human.EmailIsNil()).
		Exist(ctx)
}

func (s *Service) checkRole(role string) error {
	if !slices.Contains(s.roles, role) {
		return fmt.Errorf("%w: %q", ErrInvalidRole, role)
	}
	return nil
}

// validateManager checks that the principal is an active human with an
// email; a managed principal has no email, so it cannot be a manager.
func validateManager(ctx context.Context, tx *ent.Tx, id uuid.UUID) error {
	ok, err := tx.Human.Query().
		Where(
			human.PrincipalID(id),
			human.EmailNotNil(),
			human.HasPrincipalWith(entprincipal.Active(true), entprincipal.TypeEQ(entprincipal.TypeHuman)),
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
