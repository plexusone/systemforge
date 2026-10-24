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
	"github.com/plexusone/systemforge/identity/accesschange"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/approle"
	"github.com/plexusone/systemforge/identity/ent/predicate"
	"github.com/plexusone/systemforge/identity/ent/principalmembership"
	"github.com/plexusone/systemforge/identity/graphlock"
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

	accessSink accesschange.Sink

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
// ignored, so any existing authz.RelationshipSyncer can be passed.
//
// A removed or changed role is deleted from the graph inside the
// transaction that removes or changes it, before the commit: if the graph
// refuses, the role is left as it was and the error is returned, whatever
// the mode. An assigned role is written after the commit; in
// authz.SyncModeStrict a failed write is returned to the caller, in
// SyncModeEventual (the default) it is logged.
func WithAuthzSyncer(syncer authz.RelationshipSyncer, mode authz.SyncMode) Option {
	return func(s *Service) {
		s.syncer, _ = syncer.(authz.AppRoleSyncer)
		s.syncMode = mode
	}
}

// WithAccessChangeSink announces the access changes the service records,
// a changed or removed application role, to sink after the transaction
// that recorded them commits (ADR-010). The records are written whether or
// not a sink is set.
func WithAccessChangeSink(sink accesschange.Sink) Option {
	return func(s *Service) { s.accessSink = sink }
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
func (s *Service) validate(ctx context.Context, members *ent.PrincipalMembershipClient, in AssignInput) (Grant, error) {
	g, err := s.validateRole(ctx, in.OrganizationID, in.Application, in.Role)
	if err != nil {
		return Grant{}, err
	}
	if _, err = s.membershipRole(ctx, members, in.OrganizationID, in.PrincipalID); err != nil {
		return Grant{}, err
	}
	return g, nil
}

// validateRole checks that the application is registered, declares the
// role, and that the organization is entitled to it.
func (s *Service) validateRole(ctx context.Context, organizationID uuid.UUID, application, role string) (Grant, error) {
	v, err := s.vocabulary(application)
	if err != nil {
		return Grant{}, err
	}
	if _, ok := v.Roles()[role]; !ok {
		return Grant{}, fmt.Errorf("%w: %q in %q", ErrUnknownRole, role, application)
	}
	g, ok, err := s.grantFor(ctx, organizationID, application)
	if err != nil {
		return Grant{}, err
	}
	if !ok {
		return Grant{}, fmt.Errorf("%w: %q", ErrNotEntitled, application)
	}
	return g, nil
}

// ValidateRoles checks roles, a map from application identifier to role,
// against the organization: each application must be registered, declare
// the role, and be one the organization is entitled to. It does not check
// membership or seats, so it can validate the roles of an invitation
// before the invitee is a member.
func (s *Service) ValidateRoles(ctx context.Context, organizationID uuid.UUID, roles map[string]string) error {
	for _, app := range sortedKeys(roles) {
		if _, err := s.validateRole(ctx, organizationID, app, roles[app]); err != nil {
			return err
		}
	}
	return nil
}

// EntitledApplications lists the registered applications the organization
// is entitled to, sorted. A role picker offers these.
func (s *Service) EntitledApplications(ctx context.Context, organizationID uuid.UUID) ([]string, error) {
	grants, err := s.entitledGrants(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	return sortedKeys(grants), nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
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
func (s *Service) membershipRole(ctx context.Context, members *ent.PrincipalMembershipClient, organizationID, principalID uuid.UUID) (string, error) {
	m, err := members.Query().
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
	g, err := s.validate(ctx, s.client.PrincipalMembership, in)
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

// AssignInTx gives the principal a role inside the caller's transaction,
// for flows that create the membership and its roles together, such as
// accepting an invitation. The principal's membership may be created in
// tx, uncommitted. Seat limits are enforced under the same lock Assign
// takes. It returns a function to call after tx commits, which audits the
// assignment and writes it to the authorization graph; its error is the
// sync error Assign would return.
func (s *Service) AssignInTx(ctx context.Context, tx *ent.Tx, in AssignInput) (*AppRole, func(context.Context) error, error) {
	g, err := s.validate(ctx, tx.PrincipalMembership, in)
	if err != nil {
		return nil, nil, err
	}
	if g.SeatLimit != nil {
		postgres, perr := s.isPostgres(ctx)
		if perr != nil {
			return nil, nil, perr
		}
		if postgres {
			key := in.OrganizationID.String() + ":" + in.Application
			if _, err = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", key); err != nil {
				return nil, nil, fmt.Errorf("approle: locking seats: %w", err)
			}
		}
		if err = s.checkSeat(ctx, tx.AppRole, in, g); err != nil {
			return nil, nil, err
		}
	}
	row, err := s.insert(ctx, tx.AppRole, in)
	if err != nil {
		return nil, nil, err
	}
	after := func(ctx context.Context) error {
		s.audit(ctx, "assigned", in, "")
		return s.syncAdd(ctx, in.PrincipalID, in.OrganizationID, in.Application, in.Role)
	}
	return toAppRole(row), after, nil
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
// fails with ErrNotAssigned if there is none. The previous role leaves the
// authorization graph before the change commits and the new one is
// written after, so a failure never leaves the principal with more access
// than the database records.
func (s *Service) Change(ctx context.Context, in AssignInput) (*AppRole, error) {
	if _, err := s.validate(ctx, s.client.PrincipalMembership, in); err != nil {
		return nil, err
	}
	row, err := s.find(ctx, in.OrganizationID, in.PrincipalID, in.Application)
	if err != nil {
		return nil, err
	}
	previous := row.Role
	row, err = s.writeRecorded(ctx, func(tx *ent.Tx) (*ent.AppRole, []accesschange.Change, error) {
		updated, err := tx.AppRole.UpdateOne(row).
			SetRole(in.Role).
			SetNillableAssignedBy(nilIfZero(in.AssignedBy)).
			Save(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("approle: changing: %w", err)
		}
		if previous == in.Role {
			return updated, nil, nil
		}
		if err := s.revoke(ctx, tx, in.PrincipalID, in.OrganizationID, in.Application, previous); err != nil {
			return nil, nil, err
		}
		return updated, s.roleChange(in.PrincipalID, in.OrganizationID), nil
	})
	if err != nil {
		return nil, err
	}
	s.audit(ctx, "changed", in, previous)
	if previous != in.Role {
		if err := s.syncAdd(ctx, in.PrincipalID, in.OrganizationID, in.Application, in.Role); err != nil {
			return nil, err
		}
	}
	return toAppRole(row), nil
}

// Remove deletes the principal's role in an application. It fails with
// ErrNotAssigned if there is none. The role leaves the authorization graph
// before the removal commits; if the graph refuses, the role is kept and
// the error is returned.
func (s *Service) Remove(ctx context.Context, organizationID, principalID uuid.UUID, application string, removedBy uuid.UUID) error {
	row, err := s.find(ctx, organizationID, principalID, application)
	if err != nil {
		return err
	}
	if _, err = s.writeRecorded(ctx, func(tx *ent.Tx) (*ent.AppRole, []accesschange.Change, error) {
		if err := tx.AppRole.DeleteOne(row).Exec(ctx); err != nil {
			return nil, nil, fmt.Errorf("approle: removing: %w", err)
		}
		if err := s.revoke(ctx, tx, principalID, organizationID, application, row.Role); err != nil {
			return nil, nil, err
		}
		return row, s.roleChange(principalID, organizationID), nil
	}); err != nil {
		return err
	}
	s.audit(ctx, "removed", AssignInput{
		OrganizationID: organizationID, PrincipalID: principalID,
		Application: application, Role: row.Role, AssignedBy: removedBy,
	}, row.Role)
	return nil
}

// RemoveForMember deletes every role the principal holds in the
// organization and reports how many it deleted. organization.Service
// does the same inside its RemoveMember transaction; this is for callers
// that remove access another way. The roles leave the authorization graph
// before the removal commits; if the graph refuses, none is removed.
func (s *Service) RemoveForMember(ctx context.Context, organizationID, principalID uuid.UUID) (int, error) {
	var n int
	if _, err := s.writeRecorded(ctx, func(tx *ent.Tx) (*ent.AppRole, []accesschange.Change, error) {
		held, err := tx.AppRole.Query().
			Where(approle.OrganizationID(organizationID), approle.PrincipalID(principalID)).
			All(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("approle: reading member roles: %w", err)
		}
		deleted, err := tx.AppRole.Delete().
			Where(approle.OrganizationID(organizationID), approle.PrincipalID(principalID)).
			Exec(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("approle: removing member roles: %w", err)
		}
		n = deleted
		for _, r := range held {
			if err := s.revoke(ctx, tx, principalID, organizationID, r.Application, r.Role); err != nil {
				return nil, nil, err
			}
		}
		if deleted == 0 {
			return nil, nil, nil
		}
		return nil, s.roleChange(principalID, organizationID), nil
	}); err != nil {
		return 0, err
	}
	return n, nil
}

// roleChange is the access change an application role change or removal
// records.
func (s *Service) roleChange(principalID, organizationID uuid.UUID) []accesschange.Change {
	return []accesschange.Change{{PrincipalID: principalID, OrganizationID: &organizationID, Reason: accesschange.AppRoleChanged}}
}

// writeRecorded runs fn in a transaction, records the access changes it
// returns before committing, and announces them after.
func (s *Service) writeRecorded(ctx context.Context, fn func(tx *ent.Tx) (*ent.AppRole, []accesschange.Change, error)) (*ent.AppRole, error) {
	tx, err := s.client.Tx(ctx)
	if err != nil {
		return nil, fmt.Errorf("approle: starting transaction: %w", err)
	}
	row, changes, err := fn(tx)
	if err != nil {
		return nil, errors.Join(err, tx.Rollback())
	}
	recorded := make([]accesschange.Change, len(changes))
	for i, c := range changes {
		if recorded[i], err = accesschange.Record(ctx, tx, c); err != nil {
			return nil, errors.Join(err, tx.Rollback())
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("approle: committing: %w", err)
	}
	accesschange.Publish(s.accessSink, recorded...)
	return row, nil
}

// syncAdd writes a role to the authorization graph, honoring the sync mode.
func (s *Service) syncAdd(ctx context.Context, principalID, organizationID uuid.UUID, application, role string) error {
	if s.syncer == nil {
		return nil
	}
	return s.handleSync(ctx, "add", principalID, organizationID, application, role,
		s.syncer.AddAppRole(ctx, principalID, organizationID, application, role))
}

// revoke deletes a role from the authorization graph inside tx, the
// transaction that removes or changes it, holding the principal's
// graphlock. Its error aborts the transaction whatever the sync mode, so
// the graph never keeps a role the database no longer records.
func (s *Service) revoke(ctx context.Context, tx *ent.Tx, principalID, organizationID uuid.UUID, application, role string) error {
	if s.syncer == nil {
		return nil
	}
	if err := graphlock.Lock(ctx, tx, graphlock.Principal(principalID)); err != nil {
		return err
	}
	if err := s.syncer.RemoveAppRole(ctx, principalID, organizationID, application, role); err != nil {
		return fmt.Errorf("approle: removing application role from authz, change not saved: %w", err)
	}
	return nil
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
	membership, err := s.membershipRole(ctx, s.client.PrincipalMembership, organizationID, principalID)
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
