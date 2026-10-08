package organization

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/authz/noop"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/organization"
	"github.com/plexusone/systemforge/identity/ent/principalmembership"
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

	// SlugAvailable checks if a slug is available.
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
	// Validate slug
	if !isValidSlug(input.Slug) {
		return nil, fmt.Errorf("invalid slug format: must be lowercase alphanumeric with hyphens")
	}

	// Check slug availability
	available, err := s.SlugAvailable(ctx, input.Slug)
	if err != nil {
		return nil, fmt.Errorf("failed to check slug availability: %w", err)
	}
	if !available {
		return nil, fmt.Errorf("slug already taken: %s", input.Slug)
	}

	// Validate personal org has owner
	if input.OrgType == OrgTypePersonal && input.OwnerPrincipalID == nil {
		return nil, fmt.Errorf("personal organizations require an owner principal ID")
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

	// Create organization
	create := tx.Organization.Create().
		SetName(input.Name).
		SetSlug(input.Slug).
		SetOrgType(organization.OrgType(input.OrgType)).
		SetPlan(organization.Plan(input.Plan)).
		SetActive(true)

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
		return nil, fmt.Errorf("failed to create organization: %w", err)
	}

	// If personal org, create owner membership automatically
	if input.OrgType == OrgTypePersonal && input.OwnerPrincipalID != nil {
		_, err = tx.PrincipalMembership.Create().
			SetPrincipalID(*input.OwnerPrincipalID).
			SetOrganizationID(org.ID).
			SetRole(RoleOwner).
			SetActive(true).
			Save(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create owner membership: %w", err)
		}
	}

	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Sync to authorization backend
	if input.OwnerPrincipalID != nil {
		if syncErr := s.syncer.RegisterOrganization(ctx, org.ID, *input.OwnerPrincipalID); syncErr != nil {
			if s.syncMode == authz.SyncModeStrict {
				return nil, fmt.Errorf("failed to sync organization to authz: %w", syncErr)
			}
			s.logger.Warn("failed to sync organization to authz", "org_id", org.ID, "error", syncErr)
		}
	}

	return entOrgToModel(org), nil
}

// CreatePersonalOrg creates a personal organization for a user.
func (s *DefaultService) CreatePersonalOrg(ctx context.Context, input CreatePersonalOrgInput) (*Organization, error) {
	return s.Create(ctx, CreateOrganizationInput{
		Name:             input.Name,
		Slug:             input.Slug,
		OrgType:          OrgTypePersonal,
		OwnerPrincipalID: &input.OwnerPrincipalID,
		LogoURL:          input.LogoURL,
		Plan:             PlanFree,
	})
}

// GetByID retrieves an organization by ID.
func (s *DefaultService) GetByID(ctx context.Context, id uuid.UUID) (*Organization, error) {
	org, err := s.client.Organization.Get(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, fmt.Errorf("organization not found: %s", id)
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
	if input.Plan != nil {
		update.SetPlan(organization.Plan(*input.Plan))
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
	if input.Plan != nil {
		query.Where(organization.PlanEQ(organization.Plan(*input.Plan)))
	}
	if input.Active != nil {
		query.Where(organization.Active(*input.Active))
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
	// Get current membership for role change detection
	var oldRole string
	if input.Role != nil {
		current, err := s.client.PrincipalMembership.Get(ctx, membershipID)
		if err != nil {
			if ent.IsNotFound(err) {
				return nil, fmt.Errorf("membership not found: %s", membershipID)
			}
			return nil, fmt.Errorf("failed to get membership: %w", err)
		}
		oldRole = current.Role
	}

	update := s.client.PrincipalMembership.UpdateOneID(membershipID)

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
		if ent.IsNotFound(err) {
			return nil, fmt.Errorf("membership not found: %s", membershipID)
		}
		return nil, fmt.Errorf("failed to update membership: %w", err)
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

	_, err = s.client.PrincipalMembership.Delete().
		Where(
			principalmembership.OrganizationID(organizationID),
			principalmembership.PrincipalID(principalID),
		).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to remove membership: %w", err)
	}

	// Sync to authorization backend
	if syncErr := s.syncer.RemoveOrgMembership(ctx, principalID, organizationID, membership.Role); syncErr != nil {
		if s.syncMode == authz.SyncModeStrict {
			return fmt.Errorf("failed to sync membership removal to authz: %w", syncErr)
		}
		s.logger.Warn("failed to sync membership removal to authz",
			"principal_id", principalID,
			"org_id", organizationID,
			"role", membership.Role,
			"error", syncErr)
	}

	return nil
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
			return nil, fmt.Errorf("membership not found")
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
	exists, err := s.client.Organization.Query().
		Where(organization.Slug(slug)).
		Exist(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to check slug: %w", err)
	}
	return !exists, nil
}

// TransferOwnership transfers ownership of an organization to another principal.
func (s *DefaultService) TransferOwnership(ctx context.Context, input TransferOwnershipInput) error {
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

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

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
	if err != nil {
		return "", err
	}
	if available {
		return slug, nil
	}

	// Try with numeric suffix
	for i := 1; i <= 100; i++ {
		slug = fmt.Sprintf("%s-%d", base, i)
		available, err := s.SlugAvailable(ctx, slug)
		if err != nil {
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
		Plan:      Plan(org.Plan),
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
