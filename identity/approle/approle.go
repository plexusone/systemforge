// Package approle stores and resolves the roles principals hold in the
// applications of an organization (ADR-007).
//
// An application role is one of the roles the application declares in its
// authz.AppVocabulary, assigned to a principal for one organization. The
// rules:
//
//   - Owners hold the application's top role (admin on the standard
//     ladder) in every entitled application, implicitly, without a stored
//     row. Admins and members hold only what is assigned to them.
//   - Nobody holds an application role by default, and an organization is
//     entitled to no application unless the Service is given an
//     entitlement source (WithEntitlementGrants, normally built from the
//     marketplace by marketplace.ApproleOptions). A seat-licensed
//     application caps how many principals may hold a role in it.
//   - Only active owners, admins and members can hold a role;
//     collaborators and non-members cannot.
//   - Removing a member deletes their roles (organization.Service
//     RemoveMember does this in its transaction). Deactivating a
//     membership leaves the rows in place but EffectiveRoles ignores them
//     until the membership is active again.
package approle

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/approle"
	"github.com/plexusone/systemforge/identity/ent/predicate"
	"github.com/plexusone/systemforge/identity/ent/principalmembership"
)

// Errors returned by the service.
var (
	// ErrUnknownApplication means the application is not registered.
	ErrUnknownApplication = errors.New("approle: unknown application")
	// ErrUnknownRole means the role is not one the application declares.
	ErrUnknownRole = errors.New("approle: role not declared by the application")
	// ErrNotEntitled means the organization is not entitled to the
	// application.
	ErrNotEntitled = errors.New("approle: organization is not entitled to the application")
	// ErrNotMember means the principal has no active owner, admin or
	// member membership in the organization.
	ErrNotMember = errors.New("approle: principal is not an active owner, admin or member")
	// ErrNoSeats means every seat licensed for the application is already
	// held by a principal with a role in it.
	ErrNoSeats = errors.New("approle: no seats available for the application")
	// ErrAlreadyAssigned means the principal already has a role in the
	// application; use Change.
	ErrAlreadyAssigned = errors.New("approle: role already assigned")
	// ErrNotAssigned means the principal has no stored role in the
	// application.
	ErrNotAssigned = errors.New("approle: role not assigned")
)

// Membership roles that may hold application roles.
var eligibleMembershipRoles = []string{"owner", "admin", "member"}

// AppRole is a principal's stored role in one application of an
// organization.
type AppRole struct {
	ID             uuid.UUID
	PrincipalID    uuid.UUID
	OrganizationID uuid.UUID
	Application    string
	Role           string
	AssignedBy     *uuid.UUID
}

// EntitlementFunc reports whether an organization is entitled to an
// application.
type EntitlementFunc func(ctx context.Context, organizationID uuid.UUID, application string) (bool, error)

// Grant describes an organization's entitlement to one application.
type Grant struct {
	// SeatLimit caps the number of principals holding a role in the
	// application. Nil means unlimited.
	SeatLimit *int
}

// GrantsFunc returns the applications an organization is entitled to,
// keyed by application identifier. One call answers for every
// application, so it is cheaper than an EntitlementFunc per application.
type GrantsFunc func(ctx context.Context, organizationID uuid.UUID) (map[string]Grant, error)

// Service manages application roles.
type Service struct {
	client   *ent.Client
	registry *authz.VocabularyRegistry
	entitled EntitlementFunc
	grants   GrantsFunc
	syncer   authz.AppRoleSyncer
	syncMode authz.SyncMode
	logger   *slog.Logger

	// seatMu serializes seat-limited assignments in this process;
	// PostgreSQL additionally takes an advisory lock so that other
	// processes are serialized too. dialectMu guards the cached probe.
	seatMu    sync.Mutex
	dialectMu sync.Mutex
	dialect   string // "", "sqlite" or "postgres"
}

// Option configures a Service.
type Option func(*Service)

// WithEntitlements restricts roles to the applications f reports the
// organization is entitled to. It carries no seat limits; prefer
// WithEntitlementGrants, which takes precedence when both are set.
func WithEntitlements(f EntitlementFunc) Option {
	return func(s *Service) { s.entitled = f }
}

// WithEntitlementGrants sets the source of an organization's entitled
// applications and their seat limits. marketplace.ApproleOptions builds
// one from active subscriptions, licenses and the deployment's default
// entitlements.
func WithEntitlementGrants(f GrantsFunc) Option {
	return func(s *Service) { s.grants = f }
}

// EntitleAll treats every registered application as entitled to every
// organization, with unlimited seats. It is for development and tests;
// without any entitlement option no organization is entitled to anything.
func EntitleAll(registry *authz.VocabularyRegistry) Option {
	return WithEntitlementGrants(func(context.Context, uuid.UUID) (map[string]Grant, error) {
		out := map[string]Grant{}
		for _, app := range registry.Apps() {
			out[app] = Grant{}
		}
		return out, nil
	})
}

// WithAuthzSyncer writes application roles to the authorization graph when
// syncer also implements authz.AppRoleSyncer; a syncer that does not is
// ignored, so any existing authz.RelationshipSyncer can be passed. In
// authz.SyncModeStrict a failed write is returned to the caller after the
// role was stored; in SyncModeEventual (the default) it is logged.
func WithAuthzSyncer(syncer authz.RelationshipSyncer, mode authz.SyncMode) Option {
	return func(s *Service) {
		s.syncer, _ = syncer.(authz.AppRoleSyncer)
		s.syncMode = mode
	}
}

// WithLogger sets the logger that records assignments.
func WithLogger(l *slog.Logger) Option {
	return func(s *Service) { s.logger = l }
}

// NewService returns a Service that validates roles against the
// vocabularies in registry.
func NewService(client *ent.Client, registry *authz.VocabularyRegistry, opts ...Option) *Service {
	s := &Service{client: client, registry: registry, logger: slog.Default()}
	for _, o := range opts {
		o(s)
	}
	return s
}

// AssignInput identifies a role to assign or change.
type AssignInput struct {
	OrganizationID uuid.UUID
	PrincipalID    uuid.UUID
	Application    string
	Role           string
	// AssignedBy is the principal making the change. It may equal
	// PrincipalID: assigning a role to oneself is allowed and logged.
	AssignedBy uuid.UUID
}

func (s *Service) vocabulary(application string) (authz.AppVocabulary, error) {
	v, ok := s.registry.Get(application)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownApplication, application)
	}
	return v, nil
}

// validate checks the application, role, entitlement and membership of in
// and returns the organization's grant for the application.
func (s *Service) validate(ctx context.Context, in AssignInput) (Grant, error) {
	v, err := s.vocabulary(in.Application)
	if err != nil {
		return Grant{}, err
	}
	if _, ok := v.Roles()[in.Role]; !ok {
		return Grant{}, fmt.Errorf("%w: %q in %q", ErrUnknownRole, in.Role, in.Application)
	}
	g, ok, err := s.grantFor(ctx, in.OrganizationID, in.Application)
	if err != nil {
		return Grant{}, err
	}
	if !ok {
		return Grant{}, fmt.Errorf("%w: %q", ErrNotEntitled, in.Application)
	}
	if _, err = s.membershipRole(ctx, in.OrganizationID, in.PrincipalID); err != nil {
		return Grant{}, err
	}
	return g, nil
}

// checkSeat refuses an assignment that would exceed the application's
// seat limit. Each stored role holds one seat; owners' implicit roles
// hold none.
func (s *Service) checkSeat(ctx context.Context, roles *ent.AppRoleClient, in AssignInput, g Grant) error {
	if g.SeatLimit == nil {
		return nil
	}
	held, err := roles.Query().
		Where(approle.OrganizationID(in.OrganizationID), approle.PrincipalID(in.PrincipalID), approle.Application(in.Application)).
		Exist(ctx)
	if err != nil {
		return fmt.Errorf("approle: reading role: %w", err)
	}
	if held {
		return nil // Assign reports ErrAlreadyAssigned
	}
	used, err := roles.Query().
		Where(approle.OrganizationID(in.OrganizationID), approle.Application(in.Application)).
		Count(ctx)
	if err != nil {
		return fmt.Errorf("approle: counting seats: %w", err)
	}
	if used >= *g.SeatLimit {
		return fmt.Errorf("%w: %q has %d of %d", ErrNoSeats, in.Application, used, *g.SeatLimit)
	}
	return nil
}

// grantFor returns the organization's grant for one application.
func (s *Service) grantFor(ctx context.Context, organizationID uuid.UUID, application string) (Grant, bool, error) {
	grants, err := s.entitledGrants(ctx, organizationID)
	if err != nil {
		return Grant{}, false, err
	}
	g, ok := grants[application]
	return g, ok, nil
}

// entitledGrants returns the registered applications the organization is
// entitled to. Applications a source reports that are not registered are
// ignored.
func (s *Service) entitledGrants(ctx context.Context, organizationID uuid.UUID) (map[string]Grant, error) {
	switch {
	case s.grants != nil:
		all, err := s.grants(ctx, organizationID)
		if err != nil {
			return nil, fmt.Errorf("approle: reading entitlements: %w", err)
		}
		out := make(map[string]Grant, len(all))
		for app, g := range all {
			if _, ok := s.registry.Get(app); ok {
				out[app] = g
			}
		}
		return out, nil
	case s.entitled != nil:
		out := map[string]Grant{}
		for _, app := range s.registry.Apps() {
			ok, err := s.entitled(ctx, organizationID, app)
			if err != nil {
				return nil, fmt.Errorf("approle: reading entitlements: %w", err)
			}
			if ok {
				out[app] = Grant{}
			}
		}
		return out, nil
	}
	return map[string]Grant{}, nil
}

// membershipRole returns the principal's role from an active membership
// that may hold application roles, or ErrNotMember.
func (s *Service) membershipRole(ctx context.Context, organizationID, principalID uuid.UUID) (string, error) {
	m, err := s.client.PrincipalMembership.Query().
		Where(
			principalmembership.OrganizationID(organizationID),
			principalmembership.PrincipalID(principalID),
			principalmembership.Active(true),
			principalmembership.RoleIn(eligibleMembershipRoles...),
		).
		Only(ctx)
	if ent.IsNotFound(err) {
		return "", ErrNotMember
	}
	if err != nil {
		return "", fmt.Errorf("approle: reading membership: %w", err)
	}
	return m.Role, nil
}

// Assign gives the principal a role in an application. It fails with
// ErrAlreadyAssigned if the principal already has one. When the
// application has a seat limit, counting the seats and inserting the role
// happen under a lock, so concurrent assignments cannot exceed the limit.
func (s *Service) Assign(ctx context.Context, in AssignInput) (*AppRole, error) {
	g, err := s.validate(ctx, in)
	if err != nil {
		return nil, err
	}
	var row *ent.AppRole
	if g.SeatLimit == nil {
		row, err = s.insert(ctx, s.client.AppRole, in)
	} else {
		row, err = s.assignSeated(ctx, in, g)
	}
	if err != nil {
		return nil, err
	}
	s.audit(ctx, "assigned", in, "")
	if err := s.syncAdd(ctx, in.PrincipalID, in.OrganizationID, in.Application, in.Role); err != nil {
		return nil, err
	}
	return toAppRole(row), nil
}

func (s *Service) insert(ctx context.Context, roles *ent.AppRoleClient, in AssignInput) (*ent.AppRole, error) {
	row, err := roles.Create().
		SetPrincipalID(in.PrincipalID).
		SetOrganizationID(in.OrganizationID).
		SetApplication(in.Application).
		SetRole(in.Role).
		SetNillableAssignedBy(nilIfZero(in.AssignedBy)).
		Save(ctx)
	if ent.IsConstraintError(err) {
		return nil, ErrAlreadyAssigned
	}
	if err != nil {
		return nil, fmt.Errorf("approle: assigning: %w", err)
	}
	return row, nil
}

// assignSeated checks the seat limit and inserts the role in one
// transaction holding the seat lock for the organization and application.
func (s *Service) assignSeated(ctx context.Context, in AssignInput, g Grant) (*ent.AppRole, error) {
	postgres, err := s.isPostgres(ctx)
	if err != nil {
		return nil, err
	}
	// The process-wide mutex serializes SQLite, whose single writer needs
	// it, and saves PostgreSQL round trips between local callers.
	s.seatMu.Lock()
	defer s.seatMu.Unlock()
	tx, err := s.client.Tx(ctx)
	if err != nil {
		return nil, fmt.Errorf("approle: starting transaction: %w", err)
	}
	if postgres {
		// Released when the transaction ends.
		key := in.OrganizationID.String() + ":" + in.Application
		if _, err = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", key); err != nil {
			_ = tx.Rollback()
			return nil, fmt.Errorf("approle: locking seats: %w", err)
		}
	}
	if err = s.checkSeat(ctx, tx.AppRole, in, g); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	row, err := s.insert(ctx, tx.AppRole, in)
	if err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("approle: committing assignment: %w", err)
	}
	return row, nil
}

// isPostgres reports whether the client talks to PostgreSQL, probing once
// with a function only SQLite defines.
func (s *Service) isPostgres(ctx context.Context) (bool, error) {
	s.dialectMu.Lock()
	defer s.dialectMu.Unlock()
	if s.dialect == "" {
		_, err := s.client.ExecContext(ctx, "SELECT sqlite_version()")
		switch {
		case err == nil:
			s.dialect = "sqlite"
		case strings.Contains(err.Error(), "does not exist"):
			s.dialect = "postgres"
		default:
			return false, fmt.Errorf("approle: detecting database dialect: %w", err)
		}
	}
	return s.dialect == "postgres", nil
}

// Change sets a different role for a principal who already has one. It
// fails with ErrNotAssigned if there is none.
func (s *Service) Change(ctx context.Context, in AssignInput) (*AppRole, error) {
	if _, err := s.validate(ctx, in); err != nil {
		return nil, err
	}
	row, err := s.find(ctx, in.OrganizationID, in.PrincipalID, in.Application)
	if err != nil {
		return nil, err
	}
	previous := row.Role
	row, err = row.Update().
		SetRole(in.Role).
		SetNillableAssignedBy(nilIfZero(in.AssignedBy)).
		Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("approle: changing: %w", err)
	}
	s.audit(ctx, "changed", in, previous)
	if previous != in.Role {
		// Add the new relation before removing the old one so the
		// principal never has no role in the graph mid-change.
		if err := s.syncAdd(ctx, in.PrincipalID, in.OrganizationID, in.Application, in.Role); err != nil {
			return nil, err
		}
		if err := s.syncRemove(ctx, in.PrincipalID, in.OrganizationID, in.Application, previous); err != nil {
			return nil, err
		}
	}
	return toAppRole(row), nil
}

// Remove deletes the principal's role in an application. It fails with
// ErrNotAssigned if there is none.
func (s *Service) Remove(ctx context.Context, organizationID, principalID uuid.UUID, application string, removedBy uuid.UUID) error {
	row, err := s.find(ctx, organizationID, principalID, application)
	if err != nil {
		return err
	}
	if err := s.client.AppRole.DeleteOne(row).Exec(ctx); err != nil {
		return fmt.Errorf("approle: removing: %w", err)
	}
	s.audit(ctx, "removed", AssignInput{
		OrganizationID: organizationID, PrincipalID: principalID,
		Application: application, Role: row.Role, AssignedBy: removedBy,
	}, row.Role)
	return s.syncRemove(ctx, principalID, organizationID, application, row.Role)
}

// RemoveForMember deletes every role the principal holds in the
// organization and reports how many it deleted. organization.Service
// does the same inside its RemoveMember transaction; this is for callers
// that remove access another way.
func (s *Service) RemoveForMember(ctx context.Context, organizationID, principalID uuid.UUID) (int, error) {
	held, err := s.ListForPrincipal(ctx, organizationID, principalID)
	if err != nil {
		return 0, err
	}
	n, err := s.client.AppRole.Delete().
		Where(approle.OrganizationID(organizationID), approle.PrincipalID(principalID)).
		Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("approle: removing member roles: %w", err)
	}
	var errs []error
	for _, r := range held {
		if err := s.syncRemove(ctx, principalID, organizationID, r.Application, r.Role); err != nil {
			errs = append(errs, err)
		}
	}
	return n, errors.Join(errs...)
}

// syncAdd writes a role to the authorization graph, honoring the sync mode.
func (s *Service) syncAdd(ctx context.Context, principalID, organizationID uuid.UUID, application, role string) error {
	if s.syncer == nil {
		return nil
	}
	return s.handleSync(ctx, "add", principalID, organizationID, application, role,
		s.syncer.AddAppRole(ctx, principalID, organizationID, application, role))
}

// syncRemove deletes a role from the authorization graph, honoring the
// sync mode.
func (s *Service) syncRemove(ctx context.Context, principalID, organizationID uuid.UUID, application, role string) error {
	if s.syncer == nil {
		return nil
	}
	return s.handleSync(ctx, "remove", principalID, organizationID, application, role,
		s.syncer.RemoveAppRole(ctx, principalID, organizationID, application, role))
}

func (s *Service) handleSync(ctx context.Context, op string, principalID, organizationID uuid.UUID, application, role string, err error) error {
	if err == nil {
		return nil
	}
	if s.syncMode == authz.SyncModeStrict {
		return fmt.Errorf("approle: syncing %s of application role to authz: %w", op, err)
	}
	s.logger.WarnContext(ctx, "failed to sync application role to authz",
		"op", op, "principal_id", principalID, "organization_id", organizationID,
		"application", application, "role", role, "error", err)
	return nil
}

func (s *Service) find(ctx context.Context, organizationID, principalID uuid.UUID, application string) (*ent.AppRole, error) {
	row, err := s.client.AppRole.Query().
		Where(
			approle.OrganizationID(organizationID),
			approle.PrincipalID(principalID),
			approle.Application(application),
		).
		Only(ctx)
	if ent.IsNotFound(err) {
		return nil, ErrNotAssigned
	}
	if err != nil {
		return nil, fmt.Errorf("approle: reading role: %w", err)
	}
	return row, nil
}

// ListForPrincipal lists the stored roles a principal holds in an
// organization, ordered by application. Implicit owner roles are not
// included; see EffectiveRoles.
func (s *Service) ListForPrincipal(ctx context.Context, organizationID, principalID uuid.UUID) ([]*AppRole, error) {
	return s.list(ctx, approle.OrganizationID(organizationID), approle.PrincipalID(principalID))
}

// ListForOrganization lists the stored roles in an organization, ordered
// by application. A non-empty application limits the list to it.
func (s *Service) ListForOrganization(ctx context.Context, organizationID uuid.UUID, application string) ([]*AppRole, error) {
	if application == "" {
		return s.list(ctx, approle.OrganizationID(organizationID))
	}
	return s.list(ctx, approle.OrganizationID(organizationID), approle.Application(application))
}

func (s *Service) list(ctx context.Context, preds ...predicate.AppRole) ([]*AppRole, error) {
	rows, err := s.client.AppRole.Query().
		Where(preds...).
		Order(ent.Asc(approle.FieldApplication), ent.Asc(approle.FieldCreatedAt)).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("approle: listing: %w", err)
	}
	out := make([]*AppRole, len(rows))
	for i, r := range rows {
		out[i] = toAppRole(r)
	}
	return out, nil
}

// EffectiveRoles returns the principal's role in each application of the
// organization, keyed by application. An application absent from the map
// is one the principal may not open. A non-member, an inactive member and
// a collaborator get an empty map. An owner holds the top role of every
// entitled registered application; anyone else holds their stored roles
// for entitled applications. If both apply, the higher role wins.
func (s *Service) EffectiveRoles(ctx context.Context, principalID, organizationID uuid.UUID) (map[string]string, error) {
	out := map[string]string{}
	membership, err := s.membershipRole(ctx, organizationID, principalID)
	if errors.Is(err, ErrNotMember) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	stored, err := s.ListForPrincipal(ctx, organizationID, principalID)
	if err != nil {
		return nil, err
	}
	byApp := map[string]string{}
	for _, r := range stored {
		byApp[r.Application] = r.Role
	}
	grants, err := s.entitledGrants(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	for _, app := range s.registry.Apps() {
		if _, ok := grants[app]; !ok {
			continue
		}
		v, _ := s.registry.Get(app)
		role := byApp[app]
		if membership == "owner" {
			if top := TopRole(v); top != "" && (role == "" || v.Hierarchy().Level(top) > v.Hierarchy().Level(role)) {
				role = top
			}
		}
		if role != "" {
			out[app] = role
		}
	}
	return out, nil
}

// TopRole returns the highest role of a vocabulary: "admin" if it
// declares one, otherwise the role with the highest hierarchy level
// (ties broken by name for determinism).
func TopRole(v authz.AppVocabulary) string {
	roles := v.Roles()
	if _, ok := roles["admin"]; ok {
		return "admin"
	}
	names := make([]string, 0, len(roles))
	for r := range roles {
		names = append(names, r)
	}
	sort.Strings(names)
	h := v.Hierarchy()
	top := ""
	for _, r := range names {
		if top == "" || h.Level(r) > h.Level(top) {
			top = r
		}
	}
	return top
}

// Roles returns the roles an application declares, lowest first, for
// role pickers.
func (s *Service) Roles(application string) ([]string, error) {
	v, err := s.vocabulary(application)
	if err != nil {
		return nil, err
	}
	h := v.Hierarchy()
	names := make([]string, 0, len(v.Roles()))
	for r := range v.Roles() {
		names = append(names, r)
	}
	sort.Slice(names, func(i, j int) bool {
		if h.Level(names[i]) != h.Level(names[j]) {
			return h.Level(names[i]) < h.Level(names[j])
		}
		return names[i] < names[j]
	})
	return names, nil
}

func (s *Service) audit(ctx context.Context, action string, in AssignInput, previous string) {
	attrs := []any{
		"action", action,
		"organization_id", in.OrganizationID,
		"principal_id", in.PrincipalID,
		"application", in.Application,
		"role", in.Role,
		"by", in.AssignedBy,
		"self", in.AssignedBy == in.PrincipalID,
	}
	if previous != "" {
		attrs = append(attrs, "previous_role", previous)
	}
	s.logger.InfoContext(ctx, "application role "+action, attrs...)
}

func nilIfZero(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}

func toAppRole(r *ent.AppRole) *AppRole {
	return &AppRole{
		ID: r.ID, PrincipalID: r.PrincipalID, OrganizationID: r.OrganizationID,
		Application: r.Application, Role: r.Role, AssignedBy: r.AssignedBy,
	}
}
