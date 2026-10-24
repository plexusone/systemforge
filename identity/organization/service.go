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

// Delete soft-deletes an organization.
func (s *DefaultService) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := s.client.Organization.UpdateOneID(id).
		SetActive(false).
		Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return fmt.Errorf("organization not found: %s", id)
		}
		return fmt.Errorf("failed to delete organization: %w", err)
	}

	// Sync to authorization backend
	if syncErr := s.syncer.UnregisterOrganization(ctx, id); syncErr != nil {
		if s.syncMode == authz.SyncModeStrict {
			return fmt.Errorf("failed to sync organization deletion to authz: %w", syncErr)
		}
		s.logger.Warn("failed to sync organization deletion to authz", "org_id", id, "error", syncErr)
	}

	return nil
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
	if input.Role != nil && oldRole != *input.Role {
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
	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to update membership: %w", err)
	}
	accesschange.Publish(s.accessSink, changes...)

	// Sync to the authorization backend. An inactive membership holds no
	// relations in the graph (its rows are kept), so deactivation removes
	// the member's organization role, application roles and resource
	// grants, and reactivation writes them back.
	switch {
	case current.Active && !membership.Active:
		roles, grants, err := s.memberAccess(ctx, membership.PrincipalID, orgID)
		if err != nil {
			return nil, err
		}
		if err := s.syncAccess(ctx, false, membership.PrincipalID, orgID, oldRole, roles, grants); err != nil {
			return nil, err
		}
		return entMembershipToModel(membership), nil
	case !current.Active && membership.Active:
		roles, grants, err := s.memberAccess(ctx, membership.PrincipalID, orgID)
		if err != nil {
			return nil, err
		}
		if err := s.syncAccess(ctx, true, membership.PrincipalID, orgID, membership.Role, roles, grants); err != nil {
			return nil, err
		}
		return entMembershipToModel(membership), nil
	case !membership.Active:
		// Still inactive: nothing is in the graph to change.
		return entMembershipToModel(membership), nil
	}

	// Sync role change to authorization backend
	if input.Role != nil && oldRole != *input.Role {
		if syncErr := s.syncer.UpdateOrgMembership(ctx, membership.PrincipalID, membership.OrganizationID, oldRole, *input.Role); syncErr != nil {
			if s.syncMode == authz.SyncModeStrict {
				return nil, fmt.Errorf("failed to sync role change to authz: %w", syncErr)
			}
			s.logger.Warn("failed to sync role change to authz",
				"principal_id", membership.PrincipalID,
				"org_id", membership.OrganizationID,
				"old_role", oldRole,
				"new_role", *input.Role,
				"error", syncErr)
		}
	}

	return entMembershipToModel(membership), nil
}

// RemoveMember removes a principal from an organization.
func (s *DefaultService) RemoveMember(ctx context.Context, organizationID, principalID uuid.UUID) error {
	// Get membership to know the role for authz sync
	membership, err := s.GetMembership(ctx, organizationID, principalID)
	if err != nil {
		return fmt.Errorf("membership not found: %w", err)
	}

	// The member's application roles go with the membership.
	heldRoles, err := s.client.AppRole.Query().
		Where(approle.OrganizationID(organizationID), approle.PrincipalID(principalID)).
		All(ctx)
	if err != nil {
		return fmt.Errorf("failed to read application roles: %w", err)
	}
	// So do the member's resource grants (ADR-008).
	heldGrants, err := s.client.ResourceGrant.Query().
		Where(resourcegrant.OrganizationID(organizationID), resourcegrant.PrincipalID(principalID)).
		All(ctx)
	if err != nil {
		return fmt.Errorf("failed to read resource grants: %w", err)
	}
	tx, err := s.client.Tx(ctx)
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
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
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to remove membership: %w", err)
	}
	accesschange.Publish(s.accessSink, changes...)

	// Sync to authorization backend: the membership, and the deleted
	// application roles and resource grants.
	return s.syncAccess(ctx, false, principalID, organizationID, membership.Role, heldRoles, heldGrants)
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

// syncAccess adds (add true) or removes a member's organization role,
// application roles and resource grants in the authorization graph. Failures
// are returned in SyncModeStrict and logged otherwise.
func (s *DefaultService) syncAccess(ctx context.Context, add bool, principalID, organizationID uuid.UUID, role string, appRoles []*ent.AppRole, grants []*ent.ResourceGrant) error {
	verb := "removal"
	if add {
		verb = "addition"
	}
	report := func(what string, syncErr error, attrs ...any) error {
		if syncErr == nil {
			return nil
		}
		if s.syncMode == authz.SyncModeStrict {
			return fmt.Errorf("failed to sync %s %s to authz: %w", what, verb, syncErr)
		}
		s.logger.Warn("failed to sync "+what+" "+verb+" to authz",
			append([]any{"principal_id", principalID, "org_id", organizationID, "error", syncErr}, attrs...)...)
		return nil
	}

	var syncErr error
	if add {
		syncErr = s.syncer.AddOrgMembership(ctx, principalID, organizationID, role)
	} else {
		syncErr = s.syncer.RemoveOrgMembership(ctx, principalID, organizationID, role)
	}
	if err := report("membership", syncErr, "role", role); err != nil {
		return err
	}

	// Application roles, when the syncer carries them.
	if appSyncer, ok := s.syncer.(authz.AppRoleSyncer); ok {
		for _, r := range appRoles {
			if add {
				syncErr = appSyncer.AddAppRole(ctx, principalID, organizationID, r.Application, r.Role)
			} else {
				syncErr = appSyncer.RemoveAppRole(ctx, principalID, organizationID, r.Application, r.Role)
			}
			if err := report("application role", syncErr, "application", r.Application); err != nil {
				return err
			}
		}
	}

	// Resource grants, when the syncer carries them.
	if grantSyncer, ok := s.syncer.(authz.ResourceGrantSyncer); ok {
		for _, g := range grants {
			ref := authz.ResourceRef{Type: g.ResourceType, ID: g.ResourceID, OrganizationID: organizationID}
			if add {
				syncErr = grantSyncer.SetResourceGrant(ctx, principalID, ref, g.Role)
			} else {
				syncErr = grantSyncer.RemoveResourceGrant(ctx, principalID, ref)
			}
			if err := report("resource grant", syncErr, "resource_type", g.ResourceType, "resource_id", g.ResourceID); err != nil {
				return err
			}
		}
	}
	return nil
}

// memberAccess returns the application roles and resource grants a
// principal holds in an organization.
func (s *DefaultService) memberAccess(ctx context.Context, principalID, organizationID uuid.UUID) ([]*ent.AppRole, []*ent.ResourceGrant, error) {
	roles, err := s.client.AppRole.Query().
		Where(approle.OrganizationID(organizationID), approle.PrincipalID(principalID)).
		All(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read application roles: %w", err)
	}
	grants, err := s.client.ResourceGrant.Query().
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

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	accesschange.Publish(s.accessSink, changes...)

	// Sync role changes to authorization backend
	// Update old owner's role
	if syncErr := s.syncer.UpdateOrgMembership(ctx, input.FromPrincipal, input.OrganizationID, RoleOwner, newRoleForOld); syncErr != nil {
		if s.syncMode == authz.SyncModeStrict {
			return fmt.Errorf("failed to sync old owner role change to authz: %w", syncErr)
		}
		s.logger.Warn("failed to sync old owner role change to authz",
			"principal_id", input.FromPrincipal,
			"org_id", input.OrganizationID,
			"error", syncErr)
	}

	// Update new owner's role
	if syncErr := s.syncer.UpdateOrgMembership(ctx, input.ToPrincipal, input.OrganizationID, newMembership.Role, RoleOwner); syncErr != nil {
		if s.syncMode == authz.SyncModeStrict {
			return fmt.Errorf("failed to sync new owner role change to authz: %w", syncErr)
		}
		s.logger.Warn("failed to sync new owner role change to authz",
			"principal_id", input.ToPrincipal,
			"org_id", input.OrganizationID,
			"error", syncErr)
	}

	return nil
}

// GenerateSlug generates a unique slug from a name.
func (s *DefaultService) GenerateSlug(ctx context.Context, name string) (string, error) {
	base := slugify(name)
	slug := base

	// Try base slug first
	available, err := s.SlugAvailable(ctx, slug)
	if err != nil && !errors.Is(err, ErrSlugReserved) {
		return "", err
	}
	if available {
		return slug, nil
	}

	// Try with numeric suffix
	for i := 1; i <= 100; i++ {
		slug = fmt.Sprintf("%s-%d", base, i)
		available, err := s.SlugAvailable(ctx, slug)
		if err != nil && !errors.Is(err, ErrSlugReserved) {
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
