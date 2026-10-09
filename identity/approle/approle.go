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
//   - Nobody holds an application role by default.
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

// Service manages application roles.
type Service struct {
	client   *ent.Client
	registry *authz.VocabularyRegistry
	entitled EntitlementFunc
	logger   *slog.Logger
}

// Option configures a Service.
type Option func(*Service)

// WithEntitlements restricts roles to the applications the organization
// is entitled to. Without it every registered application counts as
// entitled.
func WithEntitlements(f EntitlementFunc) Option {
	return func(s *Service) { s.entitled = f }
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

// validate checks the application, role, entitlement and membership of in.
func (s *Service) validate(ctx context.Context, in AssignInput) error {
	v, err := s.vocabulary(in.Application)
	if err != nil {
		return err
	}
	if _, ok := v.Roles()[in.Role]; !ok {
		return fmt.Errorf("%w: %q in %q", ErrUnknownRole, in.Role, in.Application)
	}
	ok, err := s.isEntitled(ctx, in.OrganizationID, in.Application)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: %q", ErrNotEntitled, in.Application)
	}
	_, err = s.membershipRole(ctx, in.OrganizationID, in.PrincipalID)
	return err
}

func (s *Service) isEntitled(ctx context.Context, organizationID uuid.UUID, application string) (bool, error) {
	if s.entitled == nil {
		return true, nil
	}
	return s.entitled(ctx, organizationID, application)
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
// ErrAlreadyAssigned if the principal already has one.
func (s *Service) Assign(ctx context.Context, in AssignInput) (*AppRole, error) {
	if err := s.validate(ctx, in); err != nil {
		return nil, err
	}
	row, err := s.client.AppRole.Create().
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
	s.audit(ctx, "assigned", in, "")
	return toAppRole(row), nil
}

// Change sets a different role for a principal who already has one. It
// fails with ErrNotAssigned if there is none.
func (s *Service) Change(ctx context.Context, in AssignInput) (*AppRole, error) {
	if err := s.validate(ctx, in); err != nil {
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
	return nil
}

// RemoveForMember deletes every role the principal holds in the
// organization and reports how many it deleted. organization.Service
// does the same inside its RemoveMember transaction; this is for callers
// that remove access another way.
func (s *Service) RemoveForMember(ctx context.Context, organizationID, principalID uuid.UUID) (int, error) {
	n, err := s.client.AppRole.Delete().
		Where(approle.OrganizationID(organizationID), approle.PrincipalID(principalID)).
		Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("approle: removing member roles: %w", err)
	}
	return n, nil
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
	for _, app := range s.registry.Apps() {
		ok, err := s.isEntitled(ctx, organizationID, app)
		if err != nil {
			return nil, err
		}
		if !ok {
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
