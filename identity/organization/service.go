package organization

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/authz/noop"
	"github.com/plexusone/systemforge/identity/accesschange"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/approle"
	entinvite "github.com/plexusone/systemforge/identity/ent/invite"
	"github.com/plexusone/systemforge/identity/ent/organization"
	"github.com/plexusone/systemforge/identity/ent/principalmembership"
	"github.com/plexusone/systemforge/identity/ent/resourcegrant"
	"github.com/plexusone/systemforge/identity/ent/slugreservation"
	"github.com/plexusone/systemforge/identity/graphlock"
)

// Service defines the organization service interface.
type Service interface {
	// Create creates a new organization.
	Create(ctx context.Context, input CreateOrganizationInput) (*Organization, error)

	// CreatePersonalOrg creates a personal organization for a user.
	CreatePersonalOrg(ctx context.Context, input CreatePersonalOrgInput) (*Organization, error)

	// GetByID retrieves an organization by ID.
	GetByID(ctx context.Context, id uuid.UUID) (*Organization, error)

	// GetBySlug retrieves an organization by slug.
	GetBySlug(ctx context.Context, slug string) (*Organization, error)

	// GetPersonalOrg retrieves a principal's personal organization.
	GetPersonalOrg(ctx context.Context, principalID uuid.UUID) (*Organization, error)

	// Update updates an organization.
	Update(ctx context.Context, id uuid.UUID, input UpdateOrganizationInput) (*Organization, error)

	// Delete soft-deletes an organization.
	Delete(ctx context.Context, id uuid.UUID) error

	// List lists organizations with optional filters.
	List(ctx context.Context, input ListOrganizationsInput) ([]*Organization, error)

	// AddMember adds a principal as a member of an organization.
	AddMember(ctx context.Context, input AddMemberInput) (*Membership, error)

	// UpdateMember updates a membership.
	UpdateMember(ctx context.Context, membershipID uuid.UUID, input UpdateMemberInput) (*Membership, error)

	// RemoveMember removes a principal from an organization.
	RemoveMember(ctx context.Context, organizationID, principalID uuid.UUID) error

	// GetMembership retrieves a specific membership.
	GetMembership(ctx context.Context, organizationID, principalID uuid.UUID) (*Membership, error)

	// ListMembers lists the active members of an organization. Pass
	// IncludeInactive to also list deactivated memberships.
	ListMembers(ctx context.Context, organizationID uuid.UUID, opts ...ListOption) ([]*Membership, error)

	// ListMemberships lists the organizations a principal is an active
	// member of. Pass IncludeInactive to also list deactivated memberships.
	ListMemberships(ctx context.Context, principalID uuid.UUID, opts ...ListOption) ([]*Membership, error)

	// ResolveSlug returns the organization using slug or, within the
	// cooling-off period after a rename, the organization that released it
	// (alias true).
	ResolveSlug(ctx context.Context, slug string) (*Organization, bool, error)

	// Rename changes an organization's slug on behalf of actor, who must
	// own it. The old slug is held for actor for the cooling-off period.
	Rename(ctx context.Context, orgID uuid.UUID, slug string, actor uuid.UUID) error

	// ConvertToTeam turns a personal organization into a team organization
	// under teamSlug and gives its owner a new personal organization with
	// the old handle, in one transaction.
	ConvertToTeam(ctx context.Context, orgID uuid.UUID, teamSlug string, actor uuid.UUID) (*ConvertResult, error)

	// SlugAvailable checks if a slug is available. A reserved slug is
	// refused with ErrSlugReserved, and one in its cooling-off period with
	// ErrSlugCoolingOff (both with false).
	SlugAvailable(ctx context.Context, slug string) (bool, error)

	// GenerateSlug generates a unique slug from a name.
	GenerateSlug(ctx context.Context, name string) (string, error)

	// TransferOwnership transfers ownership of an organization to another principal.
	TransferOwnership(ctx context.Context, input TransferOwnershipInput) error
}

// DefaultService implements the Service interface.
type DefaultService struct {
	client   *ent.Client
	syncer   authz.RelationshipSyncer
	syncMode authz.SyncMode
	logger   *slog.Logger
	reserved map[string]struct{} // deployment-configured reserved slugs

	coolingOff time.Duration // slug cooling-off period (default SlugCoolingOff)

	accessSink accesschange.Sink // announces access changes after commit
}

// ServiceOption configures a DefaultService.
type ServiceOption func(*DefaultService)

// WithAuthzSyncer sets the authorization syncer for keeping authz in sync with identity changes.
func WithAuthzSyncer(syncer authz.RelationshipSyncer) ServiceOption {
	return func(s *DefaultService) {
		s.syncer = syncer
	}
}

// WithSyncMode sets the sync mode (strict or eventual).
func WithSyncMode(mode authz.SyncMode) ServiceOption {
	return func(s *DefaultService) {
		s.syncMode = mode
	}
}

// WithAccessChangeSink announces the access changes the service records
// (member removal, role change, ownership transfer) to sink after their
// transaction commits (ADR-010). The records are written whether or not a
// sink is set.
func WithAccessChangeSink(sink accesschange.Sink) ServiceOption {
	return func(s *DefaultService) { s.accessSink = sink }
}

// WithLogger sets the logger for the service.
func WithLogger(logger *slog.Logger) ServiceOption {
	return func(s *DefaultService) {
		s.logger = logger
	}
}

// NewService creates a new organization service.
func NewService(client *ent.Client, opts ...ServiceOption) Service {
	s := &DefaultService{
		client:   client,
		syncer:   noop.NewSyncer(),
		syncMode: authz.SyncModeEventual,
		logger:   slog.Default(),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Create creates a new organization.
func (s *DefaultService) Create(ctx context.Context, input CreateOrganizationInput) (*Organization, error) {
	if err := s.validateCreate(ctx, s.client, input); err != nil {
		return nil, err
	}

	// Start transaction
	tx, err := s.client.Tx(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to start transaction: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	org, _, err := s.insertOrganization(ctx, tx, input)
	if err != nil {
		return nil, err
	}

	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	if err = s.syncCreated(ctx, org.ID, input.OwnerPrincipalID); err != nil {
		return nil, err
	}

	return entOrgToModel(org), nil
}

// validateCreate checks a create input against the data visible through c.
func (s *DefaultService) validateCreate(ctx context.Context, c *ent.Client, input CreateOrganizationInput) error {
	// Validate slug
	if !isValidSlug(input.Slug) {
		return fmt.Errorf("invalid slug format: must be lowercase alphanumeric with hyphens")
	}

	// Check slug availability
	// A slug in its cooling-off period is open to the owner who released it.
	if err := s.slugCheck(ctx, c, input.Slug, input.OwnerPrincipalID); err != nil {
		return fmt.Errorf("failed to check slug availability: %w", err)
	}

	// Validate personal org has owner
	if input.OrgType == OrgTypePersonal && input.OwnerPrincipalID == nil {
		return fmt.Errorf("personal organizations require an owner principal ID")
	}
	return nil
}

// insertOrganization writes the organization and, when an owner is given,
// the owner membership in tx.
func (s *DefaultService) insertOrganization(ctx context.Context, tx *ent.Tx, input CreateOrganizationInput) (*ent.Organization, *ent.PrincipalMembership, error) {
	// Create organization
	create := tx.Organization.Create().
		SetName(input.Name).
		SetSlug(input.Slug).
		SetActive(true)
	// An empty type takes the schema default (team).
	if input.OrgType != "" {
		create.SetOrgType(organization.OrgType(input.OrgType))
	}

	if input.OwnerPrincipalID != nil {
		create.SetOwnerPrincipalID(*input.OwnerPrincipalID)
	}
	if input.LogoURL != nil {
		create.SetLogoURL(*input.LogoURL)
	}
	if input.Description != nil {
		create.SetDescription(*input.Description)
	}
	if input.WebsiteURL != nil {
		create.SetWebsiteURL(*input.WebsiteURL)
	}
	if input.Settings != nil {
		create.SetSettings(input.Settings)
	}

	org, err := create.Save(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create organization: %w", err)
	}
	// The slug is now in use; a reservation for it (held by the owner,
	// checked above) is spent.
	if _, err = tx.SlugReservation.Delete().Where(slugreservation.SlugEQ(input.Slug)).Exec(ctx); err != nil {
		return nil, nil, fmt.Errorf("failed to clear slug reservation: %w", err)
	}

	// The owner is a member with the owner role, so membership-based
	// authorization recognizes it.
	var membership *ent.PrincipalMembership
	if input.OwnerPrincipalID != nil {
		membership, err = tx.PrincipalMembership.Create().
			SetPrincipalID(*input.OwnerPrincipalID).
			SetOrganizationID(org.ID).
			SetRole(RoleOwner).
			SetActive(true).
			Save(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create owner membership: %w", err)
		}
	}

	return org, membership, nil
}

// syncCreated registers a committed organization with the authorization
// syncer, honoring the sync mode.
func (s *DefaultService) syncCreated(ctx context.Context, orgID uuid.UUID, owner *uuid.UUID) error {
	if owner == nil {
		return nil
	}
	if syncErr := s.syncer.RegisterOrganization(ctx, orgID, *owner); syncErr != nil {
		if s.syncMode == authz.SyncModeStrict {
			return fmt.Errorf("failed to sync organization to authz: %w", syncErr)
		}
		s.logger.Warn("failed to sync organization to authz", "org_id", orgID, "error", syncErr)
	}
	return nil
}

// AfterCommit registers a created entity with the authorization backend. It
// must be called only after the transaction that created the entity
// committed, and never when it rolled back.
type AfterCommit func(ctx context.Context) error

// PersonalOrgTxCreator is implemented by services that can create a
// personal organization inside a caller's transaction, so a larger
// operation such as signup is atomic.
type PersonalOrgTxCreator interface {
	// CreatePersonalOrgInTx writes the personal organization and its owner
	// membership in tx and leaves committing to the caller. The owner
	// principal may be a row created earlier in the same transaction. The
	// returned AfterCommit registers the organization with the
	// authorization syncer; call it after a successful commit.
	CreatePersonalOrgInTx(ctx context.Context, tx *ent.Tx, input CreatePersonalOrgInput) (*Organization, *Membership, AfterCommit, error)
}

var _ PersonalOrgTxCreator = (*DefaultService)(nil)

// CreatePersonalOrgInTx implements PersonalOrgTxCreator.
func (s *DefaultService) CreatePersonalOrgInTx(ctx context.Context, tx *ent.Tx, input CreatePersonalOrgInput) (*Organization, *Membership, AfterCommit, error) {
	in := CreateOrganizationInput{
		Name:             input.Name,
		Slug:             input.Slug,
		OrgType:          OrgTypePersonal,
		OwnerPrincipalID: &input.OwnerPrincipalID,
		LogoURL:          input.LogoURL,
	}
	if err := s.validateCreate(ctx, tx.Client(), in); err != nil {
		return nil, nil, nil, err
	}
	org, m, err := s.insertOrganization(ctx, tx, in)
	if err != nil {
		return nil, nil, nil, err
	}
	return entOrgToModel(org), entMembershipToModel(m), func(ctx context.Context) error {
		return s.syncCreated(ctx, org.ID, in.OwnerPrincipalID)
	}, nil
}

// CreatePersonalOrg creates a personal organization for a user.
func (s *DefaultService) CreatePersonalOrg(ctx context.Context, input CreatePersonalOrgInput) (*Organization, error) {
	return s.Create(ctx, CreateOrganizationInput{
		Name:             input.Name,
		Slug:             input.Slug,
		OrgType:          OrgTypePersonal,
		OwnerPrincipalID: &input.OwnerPrincipalID,
		LogoURL:          input.LogoURL,
	})
}

// GetByID retrieves an organization by ID.
func (s *DefaultService) GetByID(ctx context.Context, id uuid.UUID) (*Organization, error) {
	org, err := s.client.Organization.Get(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, fmt.Errorf("%w: %s", ErrOrganizationNotFound, id)
		}
		return nil, fmt.Errorf("failed to get organization: %w", err)
	}
	return entOrgToModel(org), nil
}

// GetBySlug retrieves an organization by slug.
func (s *DefaultService) GetBySlug(ctx context.Context, slug string) (*Organization, error) {
	org, err := s.client.Organization.Query().
		Where(organization.Slug(slug)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, fmt.Errorf("organization not found: %s", slug)
		}
		return nil, fmt.Errorf("failed to get organization: %w", err)
	}
	return entOrgToModel(org), nil
}

// GetPersonalOrg retrieves a principal's personal organization.
func (s *DefaultService) GetPersonalOrg(ctx context.Context, principalID uuid.UUID) (*Organization, error) {
	org, err := s.client.Organization.Query().
		Where(
			organization.OrgTypeEQ(organization.OrgTypePersonal),
			organization.OwnerPrincipalID(principalID),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, fmt.Errorf("personal organization not found for principal: %s", principalID)
		}
		return nil, fmt.Errorf("failed to get personal organization: %w", err)
	}
	return entOrgToModel(org), nil
}

// Update updates an organization.
func (s *DefaultService) Update(ctx context.Context, id uuid.UUID, input UpdateOrganizationInput) (*Organization, error) {
	update := s.client.Organization.UpdateOneID(id)

	if input.Name != nil {
		update.SetName(*input.Name)
	}
	if input.LogoURL != nil {
		update.SetLogoURL(*input.LogoURL)
	}
	if input.Description != nil {
		update.SetDescription(*input.Description)
	}
	if input.WebsiteURL != nil {
		update.SetWebsiteURL(*input.WebsiteURL)
	}
	if input.Settings != nil {
		update.SetSettings(input.Settings)
	}

	org, err := update.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, fmt.Errorf("organization not found: %s", id)
		}
		return nil, fmt.Errorf("failed to update organization: %w", err)
	}

	return entOrgToModel(org), nil
}

// Delete soft-deletes an organization. Its relationships, and its
// members' application roles and resource grants in it, are removed from
// the authorization graph before the deletion commits; if the graph
// refuses, the organization is not deleted and the error is returned, so
// the call can be retried.
func (s *DefaultService) Delete(ctx context.Context, id uuid.UUID) error {
	tx, err := s.client.Tx(ctx)
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	if _, err = tx.Organization.UpdateOneID(id).SetActive(false).Save(ctx); err != nil {
		if ent.IsNotFound(err) {
			return errors.Join(fmt.Errorf("organization not found: %s", id), tx.Rollback())
		}
		return errors.Join(fmt.Errorf("failed to delete organization: %w", err), tx.Rollback())
	}
	roles, err := tx.AppRole.Query().Where(approle.OrganizationID(id)).All(ctx)
	if err != nil {
		return errors.Join(fmt.Errorf("failed to read application roles: %w", err), tx.Rollback())
	}
	grants, err := tx.ResourceGrant.Query().Where(resourcegrant.OrganizationID(id)).All(ctx)
	if err != nil {
		return errors.Join(fmt.Errorf("failed to read resource grants: %w", err), tx.Rollback())
	}
	if err = graphlock.Lock(ctx, tx, graphlock.Organization(id)); err != nil {
		return errors.Join(err, tx.Rollback())
	}
	if err = s.revokeOrganization(ctx, id, roles, grants); err != nil {
		return errors.Join(err, tx.Rollback())
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to delete organization: %w", err)
	}
	return nil
}

// revokeOrganization removes an organization's relationships from the
// authorization graph: its memberships, and the application roles and
// resource grants held in it.
func (s *DefaultService) revokeOrganization(ctx context.Context, orgID uuid.UUID, appRoles []*ent.AppRole, grants []*ent.ResourceGrant) error {
	if err := s.syncer.UnregisterOrganization(ctx, orgID); err != nil {
		return revokeErr("organization", err)
	}
	if appSyncer, ok := s.syncer.(authz.AppRoleSyncer); ok {
		for _, r := range appRoles {
			if err := appSyncer.RemoveAppRole(ctx, r.PrincipalID, orgID, r.Application, r.Role); err != nil {
				return revokeErr("application role", err)
			}
		}
	}
	if grantSyncer, ok := s.syncer.(authz.ResourceGrantSyncer); ok {
		for _, g := range grants {
			ref := authz.ResourceRef{Type: g.ResourceType, ID: g.ResourceID, OrganizationID: orgID}
			if err := grantSyncer.RemoveResourceGrant(ctx, g.PrincipalID, ref); err != nil {
				return revokeErr("resource grant", err)
			}
		}
	}
	return nil
}

// revokeErr reports a relationship the authorization graph did not remove,
// which aborts the revocation.
func revokeErr(what string, err error) error {
	return fmt.Errorf("failed to remove %s from authz, change not saved: %w", what, err)
}

// List lists organizations with optional filters.
func (s *DefaultService) List(ctx context.Context, input ListOrganizationsInput) ([]*Organization, error) {
	query := s.client.Organization.Query()

	if input.OrgType != nil {
		query.Where(organization.OrgTypeEQ(organization.OrgType(*input.OrgType)))
	}
	if input.Active != nil {
		query.Where(organization.Active(*input.Active))
	}
	if input.MemberPrincipalID != nil {
		query.Where(organization.HasPrincipalMembershipsWith(
			principalmembership.PrincipalIDEQ(*input.MemberPrincipalID),
			principalmembership.ActiveEQ(true),
		))
	}

	if input.Limit > 0 {
		query.Limit(input.Limit)
	}
	if input.Offset > 0 {
		query.Offset(input.Offset)
	}

	orgs, err := query.All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list organizations: %w", err)
	}

	result := make([]*Organization, len(orgs))
	for i, org := range orgs {
		result[i] = entOrgToModel(org)
	}

	return result, nil
}

// AddMember adds a principal as a member of an organization.
func (s *DefaultService) AddMember(ctx context.Context, input AddMemberInput) (*Membership, error) {
	if err := RequireMembersAllowed(ctx, s.client, input.OrganizationID, input.Role); err != nil {
		return nil, err
	}

	// Check if membership already exists
	existing, err := s.GetMembership(ctx, input.OrganizationID, input.PrincipalID)
	if err == nil && existing != nil {
		return nil, fmt.Errorf("principal is already a member of this organization")
	}

	membership, err := s.client.PrincipalMembership.Create().
		SetPrincipalID(input.PrincipalID).
		SetOrganizationID(input.OrganizationID).
		SetRole(input.Role).
		SetPermissions(input.Permissions).
		SetActive(true).
		Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create membership: %w", err)
	}

	// Sync to authorization backend
	if syncErr := s.syncer.AddOrgMembership(ctx, input.PrincipalID, input.OrganizationID, input.Role); syncErr != nil {
		if s.syncMode == authz.SyncModeStrict {
			return nil, fmt.Errorf("failed to sync membership to authz: %w", syncErr)
		}
		s.logger.Warn("failed to sync membership to authz",
			"principal_id", input.PrincipalID,
			"org_id", input.OrganizationID,
			"role", input.Role,
			"error", syncErr)
	}

	return entMembershipToModel(membership), nil
}

// UpdateMember updates a membership.
//
// A change that reduces access (a deactivation, or a role change) removes
// the relationships it ends from the authorization graph before it
// commits; if the graph refuses, the membership is left unchanged and the
// error is returned. Relationships the change grants are written after it
// commits, as WithSyncMode decides.
func (s *DefaultService) UpdateMember(ctx context.Context, membershipID uuid.UUID, input UpdateMemberInput) (*Membership, error) {
	// Get current membership for role change detection and the type check
	current, err := s.client.PrincipalMembership.Get(ctx, membershipID)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, fmt.Errorf("membership not found: %s", membershipID)
		}
		return nil, fmt.Errorf("failed to get membership: %w", err)
	}
	oldRole := current.Role
	newRole := oldRole
	if input.Role != nil {
		newRole = *input.Role
	}
	if err := RequireMembersAllowed(ctx, s.client, current.OrganizationID, newRole); err != nil {
		return nil, err
	}

	tx, err := s.client.Tx(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to start transaction: %w", err)
	}
	update := tx.PrincipalMembership.UpdateOneID(membershipID)

	if input.Role != nil {
		update.SetRole(*input.Role)
	}
	if input.Permissions != nil {
		update.SetPermissions(input.Permissions)
	}
	if input.Active != nil {
		update.SetActive(*input.Active)
	}

	membership, err := update.Save(ctx)
	if err != nil {
		if rerr := tx.Rollback(); rerr != nil {
			err = errors.Join(err, rerr)
		}
		if ent.IsNotFound(err) {
			return nil, fmt.Errorf("membership not found: %s", membershipID)
		}
		return nil, fmt.Errorf("failed to update membership: %w", err)
	}

	// A role change or a deactivation reduces what existing tokens may
	// claim; record it with the change (ADR-010).
	var changes []accesschange.Change
	orgID := membership.OrganizationID
	roleChanged := oldRole != membership.Role
	if roleChanged {
		changes = append(changes, accesschange.Change{PrincipalID: membership.PrincipalID, OrganizationID: &orgID, Reason: accesschange.OrgRoleChanged})
	}
	if input.Active != nil && !*input.Active && current.Active {
		changes = append(changes, accesschange.Change{PrincipalID: membership.PrincipalID, OrganizationID: &orgID, Reason: accesschange.MembershipRemoved})
	}
	changes, err = recordChanges(ctx, tx, changes)
	if err != nil {
		return nil, errors.Join(err, tx.Rollback())
	}
	// Invitations the member sent and may no longer send are revoked.
	if err = revokeInvitesBeyond(ctx, tx, orgID, membership.PrincipalID, membership.Role, membership.Active); err != nil {
		return nil, errors.Join(err, tx.Rollback())
	}

	// An inactive membership holds no relations in the graph (its rows are
	// kept), so deactivation removes the member's organization role,
	// application roles and resource grants, and reactivation writes them
	// back. Removals happen here, before the commit.
	switch {
	case current.Active && !membership.Active:
		roles, grants, err := memberAccess(ctx, tx.Client(), membership.PrincipalID, orgID)
		if err != nil {
			return nil, errors.Join(err, tx.Rollback())
		}
		if err = graphlock.Lock(ctx, tx, graphlock.Principal(membership.PrincipalID)); err != nil {
			return nil, errors.Join(err, tx.Rollback())
		}
		if err = s.revokeAccess(ctx, membership.PrincipalID, orgID, oldRole, roles, grants); err != nil {
			return nil, errors.Join(err, tx.Rollback())
		}
	case current.Active && membership.Active && roleChanged:
		if err = graphlock.Lock(ctx, tx, graphlock.Principal(membership.PrincipalID)); err != nil {
			return nil, errors.Join(err, tx.Rollback())
		}
		if err = s.syncer.RemoveOrgMembership(ctx, membership.PrincipalID, orgID, oldRole); err != nil {
			return nil, errors.Join(revokeErr("previous role", err), tx.Rollback())
		}
	}

	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to update membership: %w", err)
	}
	accesschange.Publish(s.accessSink, changes...)

	switch {
	case !current.Active && membership.Active:
		roles, grants, err := memberAccess(ctx, s.client, membership.PrincipalID, orgID)
		if err != nil {
			return nil, err
		}
		if err := s.grantAccess(ctx, membership.PrincipalID, orgID, membership.Role, roles, grants); err != nil {
			return nil, err
		}
	case current.Active && membership.Active && roleChanged:
		if err := s.reportGrant("role change", s.syncer.AddOrgMembership(ctx, membership.PrincipalID, orgID, membership.Role),
			"principal_id", membership.PrincipalID, "org_id", orgID, "old_role", oldRole, "new_role", membership.Role); err != nil {
			return nil, err
		}
	}
	return entMembershipToModel(membership), nil
}

// RemoveMember removes a principal from an organization, with its
// application roles, resource grants and the invitations it sent. The
// member's relationships are removed from the authorization graph before
// the removal commits; if the graph refuses, nothing is removed and the
// error is returned, so the call can be retried.
func (s *DefaultService) RemoveMember(ctx context.Context, organizationID, principalID uuid.UUID) error {
	// Get membership to know the role for authz sync
	membership, err := s.GetMembership(ctx, organizationID, principalID)
	if err != nil {
		return fmt.Errorf("membership not found: %w", err)
	}

	tx, err := s.client.Tx(ctx)
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	// The member's application roles and resource grants (ADR-008) go
	// with the membership.
	heldRoles, heldGrants, err := memberAccess(ctx, tx.Client(), principalID, organizationID)
	if err != nil {
		return errors.Join(err, tx.Rollback())
	}
	if _, err = tx.ResourceGrant.Delete().
		Where(
			resourcegrant.OrganizationID(organizationID),
			resourcegrant.PrincipalID(principalID),
		).
		Exec(ctx); err != nil {
		return errors.Join(fmt.Errorf("failed to remove resource grants: %w", err), tx.Rollback())
	}
	if _, err = tx.AppRole.Delete().
		Where(
			approle.OrganizationID(organizationID),
			approle.PrincipalID(principalID),
		).
		Exec(ctx); err != nil {
		return errors.Join(fmt.Errorf("failed to remove application roles: %w", err), tx.Rollback())
	}
	if _, err = tx.PrincipalMembership.Delete().
		Where(
			principalmembership.OrganizationID(organizationID),
			principalmembership.PrincipalID(principalID),
		).
		Exec(ctx); err != nil {
		return errors.Join(fmt.Errorf("failed to remove membership: %w", err), tx.Rollback())
	}
	changes, err := recordChanges(ctx, tx, []accesschange.Change{{PrincipalID: principalID, OrganizationID: &organizationID, Reason: accesschange.MembershipRemoved}})
	if err != nil {
		return errors.Join(err, tx.Rollback())
	}
	// So do the invitations the member sent and has not seen accepted.
	if err = revokeInvitesBeyond(ctx, tx, organizationID, principalID, "", false); err != nil {
		return errors.Join(err, tx.Rollback())
	}
	// An inactive membership has nothing in the graph, but removing what
	// is absent succeeds, so the removal is attempted either way.
	if err = graphlock.Lock(ctx, tx, graphlock.Principal(principalID)); err != nil {
		return errors.Join(err, tx.Rollback())
	}
	if err = s.revokeAccess(ctx, principalID, organizationID, membership.Role, heldRoles, heldGrants); err != nil {
		return errors.Join(err, tx.Rollback())
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to remove membership: %w", err)
	}
	accesschange.Publish(s.accessSink, changes...)
	return nil
}

// revokeInvitesBeyond revokes, in tx, the pending invitations inviterID
// sent to the organization that its membership (role, active) no longer
// allows it to send: all of them when it may not invite at all (removed,
// deactivated, or demoted below invite_member), and owner invitations
// when it is no longer an owner. An invitation does not outlive its
// inviter's authority.
func revokeInvitesBeyond(ctx context.Context, tx *ent.Tx, orgID, inviterID uuid.UUID, role string, active bool) error {
	q := tx.Invite.Update().Where(
		entinvite.OrganizationID(orgID),
		entinvite.InviterPrincipalID(inviterID),
		entinvite.StatusEQ(entinvite.StatusPending),
	)
	switch {
	case !active || !authz.OrgRoleAllows(role, authz.PermOrgInviteMember):
	case !authz.OrgRoleAllows(role, authz.PermOrgDelete):
		q = q.Where(entinvite.Role(RoleOwner))
	default:
		return nil
	}
	if _, err := q.SetStatus(entinvite.StatusRevoked).Save(ctx); err != nil {
		return fmt.Errorf("failed to revoke the member's invitations: %w", err)
	}
	return nil
}

// revokeAccess removes a member's organization role, application roles and
// resource grants from the authorization graph. It is called inside the
// transaction that ends them, holding the member's graphlock, and its
// error aborts that transaction whatever the sync mode.
func (s *DefaultService) revokeAccess(ctx context.Context, principalID, organizationID uuid.UUID, role string, appRoles []*ent.AppRole, grants []*ent.ResourceGrant) error {
	if err := s.syncer.RemoveOrgMembership(ctx, principalID, organizationID, role); err != nil {
		return revokeErr("membership", err)
	}
	if appSyncer, ok := s.syncer.(authz.AppRoleSyncer); ok {
		for _, r := range appRoles {
			if err := appSyncer.RemoveAppRole(ctx, principalID, organizationID, r.Application, r.Role); err != nil {
				return revokeErr("application role", err)
			}
		}
	}
	if grantSyncer, ok := s.syncer.(authz.ResourceGrantSyncer); ok {
		for _, g := range grants {
			ref := authz.ResourceRef{Type: g.ResourceType, ID: g.ResourceID, OrganizationID: organizationID}
			if err := grantSyncer.RemoveResourceGrant(ctx, principalID, ref); err != nil {
				return revokeErr("resource grant", err)
			}
		}
	}
	return nil
}

// grantAccess writes a member's organization role, application roles and
// resource grants to the authorization graph after the change that grants
// them committed. Failures are returned in SyncModeStrict and logged
// otherwise.
func (s *DefaultService) grantAccess(ctx context.Context, principalID, organizationID uuid.UUID, role string, appRoles []*ent.AppRole, grants []*ent.ResourceGrant) error {
	attrs := []any{"principal_id", principalID, "org_id", organizationID}
	if err := s.reportGrant("membership addition", s.syncer.AddOrgMembership(ctx, principalID, organizationID, role), append(attrs, "role", role)...); err != nil {
		return err
	}
	if appSyncer, ok := s.syncer.(authz.AppRoleSyncer); ok {
		for _, r := range appRoles {
			if err := s.reportGrant("application role addition", appSyncer.AddAppRole(ctx, principalID, organizationID, r.Application, r.Role),
				append(attrs, "application", r.Application)...); err != nil {
				return err
			}
		}
	}
	if grantSyncer, ok := s.syncer.(authz.ResourceGrantSyncer); ok {
		for _, g := range grants {
			ref := authz.ResourceRef{Type: g.ResourceType, ID: g.ResourceID, OrganizationID: organizationID}
			if err := s.reportGrant("resource grant addition", grantSyncer.SetResourceGrant(ctx, principalID, ref, g.Role),
				append(attrs, "resource_type", g.ResourceType, "resource_id", g.ResourceID)...); err != nil {
				return err
			}
		}
	}
	return nil
}

// reportGrant handles a failed write of granted access after its change
// committed: returned in SyncModeStrict, logged otherwise.
func (s *DefaultService) reportGrant(what string, syncErr error, attrs ...any) error {
	if syncErr == nil {
		return nil
	}
	if s.syncMode == authz.SyncModeStrict {
		return fmt.Errorf("failed to sync %s to authz: %w", what, syncErr)
	}
	s.logger.Warn("failed to sync "+what+" to authz", append(attrs, "error", syncErr)...)
	return nil
}

// memberAccess returns the application roles and resource grants a
// principal holds in an organization.
func memberAccess(ctx context.Context, c *ent.Client, principalID, organizationID uuid.UUID) ([]*ent.AppRole, []*ent.ResourceGrant, error) {
	roles, err := c.AppRole.Query().
		Where(approle.OrganizationID(organizationID), approle.PrincipalID(principalID)).
		All(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read application roles: %w", err)
	}
	grants, err := c.ResourceGrant.Query().
		Where(resourcegrant.OrganizationID(organizationID), resourcegrant.PrincipalID(principalID)).
		All(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read resource grants: %w", err)
	}
	return roles, grants, nil
}

// GetMembership retrieves a specific membership.
func (s *DefaultService) GetMembership(ctx context.Context, organizationID, principalID uuid.UUID) (*Membership, error) {
	membership, err := s.client.PrincipalMembership.Query().
		Where(
			principalmembership.OrganizationID(organizationID),
			principalmembership.PrincipalID(principalID),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrMembershipNotFound
		}
		return nil, fmt.Errorf("failed to get membership: %w", err)
	}

	return entMembershipToModel(membership), nil
}

// ListOption adjusts membership listing.
type ListOption func(*listOptions)

type listOptions struct {
	includeInactive bool
}

// IncludeInactive makes a membership listing include deactivated
// memberships, which are excluded by default.
func IncludeInactive() ListOption {
	return func(o *listOptions) { o.includeInactive = true }
}

// membershipQuery applies the list options to a membership query.
func membershipQuery(q *ent.PrincipalMembershipQuery, opts []ListOption) *ent.PrincipalMembershipQuery {
	var o listOptions
	for _, opt := range opts {
		opt(&o)
	}
	if !o.includeInactive {
		q = q.Where(principalmembership.ActiveEQ(true))
	}
	return q
}

// ListMembers lists the active members of an organization.
func (s *DefaultService) ListMembers(ctx context.Context, organizationID uuid.UUID, opts ...ListOption) ([]*Membership, error) {
	memberships, err := membershipQuery(s.client.PrincipalMembership.Query().
		Where(principalmembership.OrganizationID(organizationID)), opts).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list members: %w", err)
	}

	result := make([]*Membership, len(memberships))
	for i, m := range memberships {
		result[i] = entMembershipToModel(m)
	}

	return result, nil
}

// ListMemberships lists the organizations a principal is an active member of.
func (s *DefaultService) ListMemberships(ctx context.Context, principalID uuid.UUID, opts ...ListOption) ([]*Membership, error) {
	memberships, err := membershipQuery(s.client.PrincipalMembership.Query().
		Where(principalmembership.PrincipalID(principalID)), opts).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list memberships: %w", err)
	}

	result := make([]*Membership, len(memberships))
	for i, m := range memberships {
		result[i] = entMembershipToModel(m)
	}

	return result, nil
}

// SlugAvailable checks if a slug is available.
func (s *DefaultService) SlugAvailable(ctx context.Context, slug string) (bool, error) {
	err := s.slugCheck(ctx, s.client, slug, nil)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, ErrSlugTaken):
		return false, nil
	default:
		return false, err
	}
}

// TransferOwnership transfers ownership of an organization to another principal.
func (s *DefaultService) TransferOwnership(ctx context.Context, input TransferOwnershipInput) error {
	personal, err := isPersonal(ctx, s.client, input.OrganizationID)
	if err != nil {
		return err
	}
	if personal {
		return fmt.Errorf("%w: it belongs to its owner", ErrPersonalOrganization)
	}

	// Validate the current owner
	currentMembership, err := s.GetMembership(ctx, input.OrganizationID, input.FromPrincipal)
	if err != nil {
		return fmt.Errorf("current owner membership not found: %w", err)
	}
	if currentMembership.Role != RoleOwner {
		return fmt.Errorf("principal is not the current owner")
	}

	// Validate the new owner is a member
	newMembership, err := s.GetMembership(ctx, input.OrganizationID, input.ToPrincipal)
	if err != nil {
		return fmt.Errorf("new owner must be an existing member: %w", err)
	}

	// Default new role for old owner is admin
	newRoleForOld := input.NewRoleForOld
	if newRoleForOld == "" {
		newRoleForOld = RoleAdmin
	}
	if newRoleForOld != RoleAdmin && newRoleForOld != RoleMember {
		return fmt.Errorf("new role for previous owner must be 'admin' or 'member'")
	}

	// Start transaction
	tx, err := s.client.Tx(ctx)
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	// Update old owner's role
	_, err = tx.PrincipalMembership.UpdateOneID(currentMembership.ID).
		SetRole(newRoleForOld).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("failed to update old owner's role: %w", err)
	}

	// Update new owner's role
	_, err = tx.PrincipalMembership.UpdateOneID(newMembership.ID).
		SetRole(RoleOwner).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("failed to update new owner's role: %w", err)
	}

	// Update organization's owner principal ID
	_, err = tx.Organization.UpdateOneID(input.OrganizationID).
		SetOwnerPrincipalID(input.ToPrincipal).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("failed to update organization owner: %w", err)
	}

	changes, err := recordChanges(ctx, tx, []accesschange.Change{
		{PrincipalID: input.FromPrincipal, OrganizationID: &input.OrganizationID, Reason: accesschange.OrgRoleChanged},
		{PrincipalID: input.ToPrincipal, OrganizationID: &input.OrganizationID, Reason: accesschange.OrgRoleChanged},
	})
	if err != nil {
		return err
	}

	// The previous owner loses the owner role in the graph before the
	// transfer commits; if the graph refuses, the transfer is not made.
	if err = graphlock.Lock(ctx, tx, graphlock.Principal(input.FromPrincipal), graphlock.Principal(input.ToPrincipal)); err != nil {
		return err
	}
	if err = s.syncer.RemoveOrgMembership(ctx, input.FromPrincipal, input.OrganizationID, RoleOwner); err != nil {
		return revokeErr("previous owner's role", err)
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	accesschange.Publish(s.accessSink, changes...)

	// The roles the transfer grants are written after it commits.
	if err := s.reportGrant("old owner role change", s.syncer.AddOrgMembership(ctx, input.FromPrincipal, input.OrganizationID, newRoleForOld),
		"principal_id", input.FromPrincipal, "org_id", input.OrganizationID); err != nil {
		return err
	}
	// The new owner's previous role is contained in the owner role, so it
	// is replaced after the commit.
	return s.reportGrant("new owner role change", s.syncer.UpdateOrgMembership(ctx, input.ToPrincipal, input.OrganizationID, newMembership.Role, RoleOwner),
		"principal_id", input.ToPrincipal, "org_id", input.OrganizationID)
}

// GenerateSlug generates a unique slug from a name. A reserved slug and
// one in its cooling-off period are skipped like a taken one.
func (s *DefaultService) GenerateSlug(ctx context.Context, name string) (string, error) {
	base := slugify(name)
	slug := base

	// Try base slug first
	available, err := s.SlugAvailable(ctx, slug)
	if err != nil && !unavailableSlug(err) {
		return "", err
	}
	if available {
		return slug, nil
	}

	// Try with numeric suffix
	for i := 1; i <= 100; i++ {
		slug = fmt.Sprintf("%s-%d", base, i)
		available, err := s.SlugAvailable(ctx, slug)
		if err != nil && !unavailableSlug(err) {
			return "", err
		}
		if available {
			return slug, nil
		}
	}

	// Use UUID suffix as fallback
	slug = fmt.Sprintf("%s-%s", base, uuid.New().String()[:8])
	return slug, nil
}

// Helper functions

// unavailableSlug reports whether err from SlugAvailable means only that the
// slug cannot be used, rather than that the check failed.
func unavailableSlug(err error) bool {
	return errors.Is(err, ErrSlugReserved) || errors.Is(err, ErrSlugCoolingOff)
}

var slugRegex = regexp.MustCompile(`^[a-z][a-z0-9-]*[a-z0-9]$`)
var slugMinLen = 3
var slugMaxLen = 63

// IsValidSlug reports whether slug satisfies the organization slug rules:
// 3 to 63 characters matching ^[a-z][a-z0-9-]*[a-z0-9]$.
func IsValidSlug(slug string) bool { return isValidSlug(slug) }

// Slugify converts a name to slug form (lowercase, spaces and underscores
// to hyphens, other characters dropped, "-org" appended below three
// characters, truncated to 63). The result is not guaranteed to be valid:
// a name starting with a digit yields a slug that IsValidSlug refuses.
func Slugify(name string) string { return slugify(name) }

func isValidSlug(slug string) bool {
	if len(slug) < slugMinLen || len(slug) > slugMaxLen {
		return false
	}
	return slugRegex.MatchString(slug)
}

func slugify(name string) string {
	// Convert to lowercase
	slug := strings.ToLower(name)

	// Replace spaces and underscores with hyphens
	slug = strings.ReplaceAll(slug, " ", "-")
	slug = strings.ReplaceAll(slug, "_", "-")

	// Remove non-alphanumeric characters except hyphens
	var result strings.Builder
	for _, r := range slug {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			result.WriteRune(r)
		}
	}
	slug = result.String()

	// Remove consecutive hyphens
	for strings.Contains(slug, "--") {
		slug = strings.ReplaceAll(slug, "--", "-")
	}

	// Trim hyphens from start and end
	slug = strings.Trim(slug, "-")

	// Ensure minimum length
	if len(slug) < slugMinLen {
		slug = slug + "-org"
	}

	// Truncate to max length
	if len(slug) > slugMaxLen {
		slug = slug[:slugMaxLen]
		// Ensure we don't end with a hyphen after truncation
		slug = strings.TrimRight(slug, "-")
	}

	return slug
}

func entOrgToModel(org *ent.Organization) *Organization {
	model := &Organization{
		ID:        org.ID,
		Name:      org.Name,
		Slug:      org.Slug,
		OrgType:   OrgType(org.OrgType),
		LogoURL:   org.LogoURL,
		Settings:  org.Settings,
		Active:    org.Active,
		CreatedAt: org.CreatedAt,
		UpdatedAt: org.UpdatedAt,
	}

	if org.OwnerPrincipalID != nil {
		model.OwnerPrincipalID = org.OwnerPrincipalID
	}
	if org.Description != nil {
		model.Description = org.Description
	}
	if org.WebsiteURL != nil {
		model.WebsiteURL = org.WebsiteURL
	}

	return model
}

func entMembershipToModel(m *ent.PrincipalMembership) *Membership {
	return &Membership{
		ID:             m.ID,
		PrincipalID:    m.PrincipalID,
		OrganizationID: m.OrganizationID,
		Role:           m.Role,
		Permissions:    m.Permissions,
		Active:         m.Active,
		CreatedAt:      m.CreatedAt,
		UpdatedAt:      m.UpdatedAt,
	}
}

// recordChanges writes changes in tx and returns them with their times.
func recordChanges(ctx context.Context, tx *ent.Tx, changes []accesschange.Change) ([]accesschange.Change, error) {
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
