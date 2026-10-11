// Package resourcegrant stores resource grants (ADR-008): a principal's
// role (viewer, contributor or maintainer) on one resource of an
// organization, without organization-wide access.
//
// The grants table, sf_resource_grants, is the record in both
// authorization modes. The role-based provider reads it at check time
// (rbac.WithResourceGrants); the relationship-based provider reads the
// relationships this service mirrors into the graph through an
// authz.ResourceGrantSyncer, so a deployment that switches modes rebuilds
// its graph from the table.
//
// A grant to a principal with no membership in the resource's organization
// creates a collaborator membership in the same transaction, and revoking
// the principal's last grant there removes it. Reducing or removing a grant
// records an access change (accesschange.GrantReduced), and removing the
// membership records another (accesschange.MembershipRemoved), so relying
// parties refuse tokens issued before either.
package resourcegrant

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/identity/accesschange"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/principalmembership"
	"github.com/plexusone/systemforge/identity/ent/resourcegrant"
)

// roleCollaborator is the membership role a grant creates. It is the same
// value as organization.RoleCollaborator; the package does not import the
// organization service, which removes a member's grants itself.
const roleCollaborator = "collaborator"

// ErrInactiveMembership means the principal has a deactivated membership
// in the resource's organization that is not a collaborator's. Reactivate
// the membership, or remove it, before granting.
var ErrInactiveMembership = errors.New("resourcegrant: the principal's membership in the organization is inactive")

// Service stores resource grants. It implements authz.ResourceGranter and
// authz.ResourceGrantReader.
type Service struct {
	client      *ent.Client
	registry    *authz.VocabularyRegistry
	syncer      authz.RelationshipSyncer
	grantSyncer authz.ResourceGrantSyncer
	syncMode    authz.SyncMode
	logger      *slog.Logger
	accessSink  accesschange.Sink

	// dialectMu guards the cached dialect probe.
	dialectMu sync.Mutex
	dialect   string // "", "sqlite" or "postgres"
}

// Option configures a Service.
type Option func(*Service)

// WithVocabularies restricts grants to resource types of the registered
// applications: the type's "{app}_" prefix must name a vocabulary.
func WithVocabularies(registry *authz.VocabularyRegistry) Option {
	return func(s *Service) { s.registry = registry }
}

// WithAuthzSyncer mirrors collaborator memberships and grants to the
// authorization graph. The syncer writes memberships through
// authz.RelationshipSyncer; grants are written only when it also
// implements authz.ResourceGrantSyncer. In authz.SyncModeStrict a failed
// write is returned after the rows were stored; in SyncModeEventual (the
// default) it is logged.
func WithAuthzSyncer(syncer authz.RelationshipSyncer, mode authz.SyncMode) Option {
	return func(s *Service) {
		s.syncer = syncer
		s.grantSyncer, _ = syncer.(authz.ResourceGrantSyncer)
		s.syncMode = mode
	}
}

// WithAccessChangeSink announces the access changes the service records to
// sink after the transaction that recorded them commits (ADR-010). The
// records are written whether or not a sink is set.
func WithAccessChangeSink(sink accesschange.Sink) Option {
	return func(s *Service) { s.accessSink = sink }
}

// WithLogger sets the logger that records sync failures.
func WithLogger(l *slog.Logger) Option {
	return func(s *Service) { s.logger = l }
}

// NewService returns a Service over client.
func NewService(client *ent.Client, opts ...Option) *Service {
	s := &Service{client: client, logger: slog.Default()}
	for _, o := range opts {
		o(s)
	}
	return s
}

var (
	_ authz.ResourceGranter     = (*Service)(nil)
	_ authz.ResourceGrantReader = (*Service)(nil)
)

// validate checks a grant's role and reference.
func (s *Service) validate(ref authz.ResourceRef, role string) error {
	if !authz.ValidResourceRole(role) {
		return fmt.Errorf("%w: %q (want viewer, contributor or maintainer)", authz.ErrInvalidResourceRole, role)
	}
	if err := authz.ValidateResourceRef(ref); err != nil {
		return err
	}
	if s.registry != nil {
		return s.registry.ValidateResourceType(ref.Type)
	}
	return nil
}

// GrantResourceRole gives the principal a role on the resource, replacing
// any role it held there. It creates a collaborator membership when the
// principal has none in the resource's organization.
func (s *Service) GrantResourceRole(ctx context.Context, principalID uuid.UUID, resource authz.ResourceRef, role string, grantedBy uuid.UUID) error {
	// Two first grants to the same principal in one organization race to
	// create the collaborator membership; the loser's insert violates the
	// membership's unique key and the transaction is retried, when it finds
	// the membership.
	const attempts = 3
	for attempt := 1; ; attempt++ {
		after, err := s.grantOnce(ctx, principalID, resource, role, grantedBy)
		if err != nil && attempt < attempts && ent.IsConstraintError(err) {
			continue
		}
		if err != nil {
			return err
		}
		return after(ctx)
	}
}

func (s *Service) grantOnce(ctx context.Context, principalID uuid.UUID, resource authz.ResourceRef, role string, grantedBy uuid.UUID) (func(context.Context) error, error) {
	tx, err := s.client.Tx(ctx)
	if err != nil {
		return nil, fmt.Errorf("resourcegrant: starting transaction: %w", err)
	}
	after, err := s.GrantInTx(ctx, tx, principalID, resource, role, grantedBy)
	if err != nil {
		return nil, errors.Join(err, tx.Rollback())
	}
	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("resourcegrant: committing grant: %w", err)
	}
	return after, nil
}

// GrantInTx gives the principal a role on the resource inside the caller's
// transaction, for flows that create a membership and a grant together,
// such as accepting an invitation. The principal's membership may have
// been created in tx, uncommitted. It records any access change in tx and
// returns a function to call after tx commits, which announces the changes
// and writes the membership and grant to the authorization graph; its
// error is the sync error GrantResourceRole would return.
func (s *Service) GrantInTx(ctx context.Context, tx *ent.Tx, principalID uuid.UUID, resource authz.ResourceRef, role string, grantedBy uuid.UUID) (func(context.Context) error, error) {
	if err := s.validate(resource, role); err != nil {
		return nil, err
	}
	if principalID == uuid.Nil {
		return nil, errors.New("resourcegrant: principal is required")
	}

	// A resource belongs to one organization.
	elsewhere, err := tx.ResourceGrant.Query().
		Where(
			resourcegrant.ResourceType(resource.Type),
			resourcegrant.ResourceID(resource.ID),
			resourcegrant.OrganizationIDNEQ(resource.OrganizationID),
		).
		Exist(ctx)
	if err != nil {
		return nil, fmt.Errorf("resourcegrant: reading grants: %w", err)
	}
	if elsewhere {
		return nil, fmt.Errorf("%w: %s %s", authz.ErrResourceOrganizationMismatch, resource.Type, resource.ID)
	}

	membershipAdded, err := s.ensureMembership(ctx, tx, principalID, resource.OrganizationID)
	if err != nil {
		return nil, err
	}

	var changes []accesschange.Change
	existing, err := tx.ResourceGrant.Query().
		Where(
			resourcegrant.PrincipalID(principalID),
			resourcegrant.ResourceType(resource.Type),
			resourcegrant.ResourceID(resource.ID),
		).
		Only(ctx)
	switch {
	case ent.IsNotFound(err):
		create := tx.ResourceGrant.Create().
			SetPrincipalID(principalID).
			SetOrganizationID(resource.OrganizationID).
			SetResourceType(resource.Type).
			SetResourceID(resource.ID).
			SetRole(role)
		if grantedBy != uuid.Nil {
			create.SetGrantedBy(grantedBy)
		}
		if _, err = create.Save(ctx); err != nil {
			return nil, fmt.Errorf("resourcegrant: granting: %w", err)
		}
	case err != nil:
		return nil, fmt.Errorf("resourcegrant: reading grant: %w", err)
	case existing.Role != role:
		update := tx.ResourceGrant.UpdateOne(existing).SetRole(role)
		if grantedBy != uuid.Nil {
			update.SetGrantedBy(grantedBy)
		}
		if err = update.Exec(ctx); err != nil {
			return nil, fmt.Errorf("resourcegrant: changing grant: %w", err)
		}
		if authz.ResourceRoleRank(role) < authz.ResourceRoleRank(existing.Role) {
			changes = append(changes, s.reduction(principalID, resource.OrganizationID))
		}
	}

	recorded, err := record(ctx, tx, changes)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context) error {
		accesschange.Publish(s.accessSink, recorded...)
		var errs []error
		if membershipAdded {
			errs = append(errs, s.syncMembershipAdd(ctx, principalID, resource.OrganizationID))
		}
		errs = append(errs, s.syncGrant(ctx, principalID, resource, role))
		return errors.Join(errs...)
	}, nil
}

// ensureMembership gives the principal a collaborator membership in the
// organization when it has none, and reactivates a deactivated
// collaborator's. It reports whether a membership was created or
// reactivated, which the graph must learn of.
func (s *Service) ensureMembership(ctx context.Context, tx *ent.Tx, principalID, organizationID uuid.UUID) (bool, error) {
	// The lock serializes this principal's grants and revocations in the
	// organization, so the last-grant test of RevokeResourceRole cannot
	// miss a concurrent grant.
	if err := s.lock(ctx, tx, principalID, organizationID); err != nil {
		return false, err
	}
	m, err := tx.PrincipalMembership.Query().
		Where(principalmembership.PrincipalID(principalID), principalmembership.OrganizationID(organizationID)).
		Only(ctx)
	switch {
	case ent.IsNotFound(err):
		if _, err = tx.PrincipalMembership.Create().
			SetPrincipalID(principalID).
			SetOrganizationID(organizationID).
			SetRole(roleCollaborator).
			SetActive(true).
			Save(ctx); err != nil {
			return false, fmt.Errorf("resourcegrant: creating collaborator membership: %w", err)
		}
		return true, nil
	case err != nil:
		return false, fmt.Errorf("resourcegrant: reading membership: %w", err)
	case m.Active:
		return false, nil
	case m.Role == roleCollaborator:
		if err = tx.PrincipalMembership.UpdateOne(m).SetActive(true).Exec(ctx); err != nil {
			return false, fmt.Errorf("resourcegrant: reactivating collaborator membership: %w", err)
		}
		return true, nil
	}
	return false, ErrInactiveMembership
}

// lock takes a transaction-scoped lock on one principal's grants in one
// organization. PostgreSQL gets an advisory lock, released when the
// transaction ends; SQLite has one writer and needs none.
func (s *Service) lock(ctx context.Context, tx *ent.Tx, principalID, organizationID uuid.UUID) error {
	postgres, err := s.isPostgres(ctx)
	if err != nil {
		return err
	}
	if !postgres {
		return nil
	}
	key := "resourcegrant:" + principalID.String() + ":" + organizationID.String()
	if _, err = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", key); err != nil {
		return fmt.Errorf("resourcegrant: locking grants: %w", err)
	}
	return nil
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
			return false, fmt.Errorf("resourcegrant: detecting database dialect: %w", err)
		}
	}
	return s.dialect == "postgres", nil
}

// RevokeResourceRole removes the principal's grant on the resource, and
// the principal's collaborator membership when it was their last grant in
// the organization.
func (s *Service) RevokeResourceRole(ctx context.Context, principalID uuid.UUID, resource authz.ResourceRef) error {
	if resource.Type == "" || resource.ID == "" {
		return fmt.Errorf("%w: type and id are required", authz.ErrInvalidResource)
	}
	tx, err := s.client.Tx(ctx)
	if err != nil {
		return fmt.Errorf("resourcegrant: starting transaction: %w", err)
	}
	row, err := tx.ResourceGrant.Query().
		Where(
			resourcegrant.PrincipalID(principalID),
			resourcegrant.ResourceType(resource.Type),
			resourcegrant.ResourceID(resource.ID),
		).
		Only(ctx)
	if ent.IsNotFound(err) {
		return errors.Join(authz.ErrGrantNotFound, tx.Rollback())
	}
	if err != nil {
		return errors.Join(fmt.Errorf("resourcegrant: reading grant: %w", err), tx.Rollback())
	}
	if resource.OrganizationID != uuid.Nil && resource.OrganizationID != row.OrganizationID {
		return errors.Join(authz.ErrResourceOrganizationMismatch, tx.Rollback())
	}
	orgID := row.OrganizationID

	// Serialize with this principal's other grants and revocations in the
	// organization (see ensureMembership).
	if err = s.lock(ctx, tx, principalID, orgID); err != nil {
		return errors.Join(err, tx.Rollback())
	}

	if err = tx.ResourceGrant.DeleteOne(row).Exec(ctx); err != nil {
		return errors.Join(fmt.Errorf("resourcegrant: revoking: %w", err), tx.Rollback())
	}
	changes := []accesschange.Change{s.reduction(principalID, orgID)}

	removedMembership := false
	remaining, err := tx.ResourceGrant.Query().
		Where(resourcegrant.PrincipalID(principalID), resourcegrant.OrganizationID(orgID)).
		Exist(ctx)
	if err != nil {
		return errors.Join(fmt.Errorf("resourcegrant: reading remaining grants: %w", err), tx.Rollback())
	}
	if !remaining {
		n, err := tx.PrincipalMembership.Delete().
			Where(
				principalmembership.PrincipalID(principalID),
				principalmembership.OrganizationID(orgID),
				principalmembership.Role(roleCollaborator),
			).
			Exec(ctx)
		if err != nil {
			return errors.Join(fmt.Errorf("resourcegrant: removing collaborator membership: %w", err), tx.Rollback())
		}
		if n > 0 {
			removedMembership = true
			changes = append(changes, accesschange.Change{PrincipalID: principalID, OrganizationID: &orgID, Reason: accesschange.MembershipRemoved})
		}
	}
	recorded, err := record(ctx, tx, changes)
	if err != nil {
		return errors.Join(err, tx.Rollback())
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("resourcegrant: committing revoke: %w", err)
	}
	accesschange.Publish(s.accessSink, recorded...)

	ref := authz.ResourceRef{Type: row.ResourceType, ID: row.ResourceID, OrganizationID: orgID}
	errs := []error{s.syncGrantRemove(ctx, principalID, ref)}
	if removedMembership {
		errs = append(errs, s.syncMembershipRemove(ctx, principalID, orgID))
	}
	return errors.Join(errs...)
}

// reduction is the access change a reduced or removed grant records.
func (s *Service) reduction(principalID, organizationID uuid.UUID) accesschange.Change {
	return accesschange.Change{PrincipalID: principalID, OrganizationID: &organizationID, Reason: accesschange.GrantReduced}
}

func record(ctx context.Context, tx *ent.Tx, changes []accesschange.Change) ([]accesschange.Change, error) {
	out := make([]accesschange.Change, len(changes))
	for i, c := range changes {
		rec, err := accesschange.Record(ctx, tx, c)
		if err != nil {
			return nil, err
		}
		out[i] = rec
	}
	return out, nil
}

// ListResourceGrants lists the grants on one resource, highest role first.
func (s *Service) ListResourceGrants(ctx context.Context, resource authz.ResourceRef) ([]authz.Grant, error) {
	q := s.client.ResourceGrant.Query().
		Where(resourcegrant.ResourceType(resource.Type), resourcegrant.ResourceID(resource.ID))
	if resource.OrganizationID != uuid.Nil {
		q = q.Where(resourcegrant.OrganizationID(resource.OrganizationID))
	}
	rows, err := q.Order(ent.Asc(resourcegrant.FieldCreatedAt), ent.Asc(resourcegrant.FieldID)).All(ctx)
	if err != nil {
		return nil, fmt.Errorf("resourcegrant: listing grants: %w", err)
	}
	out := make([]authz.Grant, len(rows))
	for i, r := range rows {
		out[i] = authz.Grant{
			PrincipalID: r.PrincipalID,
			Resource:    authz.ResourceRef{Type: r.ResourceType, ID: r.ResourceID, OrganizationID: r.OrganizationID},
			Role:        r.Role,
			GrantedBy:   r.GrantedBy,
		}
	}
	slices.SortStableFunc(out, func(a, b authz.Grant) int {
		return authz.ResourceRoleRank(b.Role) - authz.ResourceRoleRank(a.Role)
	})
	return out, nil
}

// ListResources returns the resources of resourceType on which the
// principal holds permission through a grant, in organizations where its
// membership is active. Organization-wide access is the role-based
// provider's to add (OrganizationIDs): it depends on its permission map.
func (s *Service) ListResources(ctx context.Context, principalID uuid.UUID, resourceType string, permission authz.Action) (authz.ResourceSet, error) {
	if !authz.IsResourcePermission(permission) {
		return authz.ResourceSet{}, fmt.Errorf("%w: %q is not view, edit or manage", authz.ErrInvalidResource, permission)
	}
	active, err := s.OrganizationRoles(ctx, principalID)
	if err != nil {
		return authz.ResourceSet{}, err
	}
	rows, err := s.client.ResourceGrant.Query().
		Where(
			resourcegrant.PrincipalID(principalID),
			resourcegrant.ResourceType(resourceType),
			resourcegrant.RoleIn(authz.ResourceRolesGranting(permission)...),
		).
		Order(ent.Asc(resourcegrant.FieldResourceID)).
		All(ctx)
	if err != nil {
		return authz.ResourceSet{}, fmt.Errorf("resourcegrant: listing resources: %w", err)
	}
	set := authz.ResourceSet{IDs: []string{}}
	for _, r := range rows {
		if _, ok := active[r.OrganizationID]; ok {
			set.IDs = append(set.IDs, r.ResourceID)
		}
	}
	return set, nil
}

// ResourceRole returns the principal's role on the resource through a
// grant, or "" when it has none or its membership in the resource's
// organization is not active.
func (s *Service) ResourceRole(ctx context.Context, principalID uuid.UUID, resource authz.ResourceRef) (string, error) {
	row, err := s.client.ResourceGrant.Query().
		Where(
			resourcegrant.PrincipalID(principalID),
			resourcegrant.ResourceType(resource.Type),
			resourcegrant.ResourceID(resource.ID),
		).
		Only(ctx)
	if ent.IsNotFound(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("resourcegrant: reading grant: %w", err)
	}
	if resource.OrganizationID != uuid.Nil && resource.OrganizationID != row.OrganizationID {
		return "", nil
	}
	active, err := s.client.PrincipalMembership.Query().
		Where(
			principalmembership.PrincipalID(principalID),
			principalmembership.OrganizationID(row.OrganizationID),
			principalmembership.Active(true),
		).
		Exist(ctx)
	if err != nil {
		return "", fmt.Errorf("resourcegrant: reading membership: %w", err)
	}
	if !active {
		return "", nil
	}
	return row.Role, nil
}

// OrganizationRoles returns the principal's role in each organization
// where its membership is active.
func (s *Service) OrganizationRoles(ctx context.Context, principalID uuid.UUID) (map[uuid.UUID]string, error) {
	rows, err := s.client.PrincipalMembership.Query().
		Where(principalmembership.PrincipalID(principalID), principalmembership.Active(true)).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("resourcegrant: reading memberships: %w", err)
	}
	out := make(map[uuid.UUID]string, len(rows))
	for _, m := range rows {
		out[m.OrganizationID] = m.Role
	}
	return out, nil
}

// syncMembershipAdd writes the collaborator membership to the graph.
func (s *Service) syncMembershipAdd(ctx context.Context, principalID, organizationID uuid.UUID) error {
	if s.syncer == nil {
		return nil
	}
	return s.handleSync(ctx, "add collaborator membership", principalID, organizationID,
		s.syncer.AddOrgMembership(ctx, principalID, organizationID, roleCollaborator))
}

// syncMembershipRemove deletes the collaborator membership from the graph.
func (s *Service) syncMembershipRemove(ctx context.Context, principalID, organizationID uuid.UUID) error {
	if s.syncer == nil {
		return nil
	}
	return s.handleSync(ctx, "remove collaborator membership", principalID, organizationID,
		s.syncer.RemoveOrgMembership(ctx, principalID, organizationID, roleCollaborator))
}

func (s *Service) syncGrant(ctx context.Context, principalID uuid.UUID, ref authz.ResourceRef, role string) error {
	if s.grantSyncer == nil {
		return nil
	}
	return s.handleSync(ctx, "set resource grant", principalID, ref.OrganizationID,
		s.grantSyncer.SetResourceGrant(ctx, principalID, ref, role))
}

func (s *Service) syncGrantRemove(ctx context.Context, principalID uuid.UUID, ref authz.ResourceRef) error {
	if s.grantSyncer == nil {
		return nil
	}
	return s.handleSync(ctx, "remove resource grant", principalID, ref.OrganizationID,
		s.grantSyncer.RemoveResourceGrant(ctx, principalID, ref))
}

func (s *Service) handleSync(ctx context.Context, op string, principalID, organizationID uuid.UUID, err error) error {
	if err == nil {
		return nil
	}
	if s.syncMode == authz.SyncModeStrict {
		return fmt.Errorf("resourcegrant: syncing %s to authz: %w", op, err)
	}
	s.logger.WarnContext(ctx, "failed to sync resource grant to authz",
		"op", op, "principal_id", principalID, "organization_id", organizationID, "error", err)
	return nil
}
