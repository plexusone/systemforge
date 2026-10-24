// Package store provides SCIM Store implementations.
package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/approle"
	"github.com/plexusone/systemforge/identity/ent/credential"
	"github.com/plexusone/systemforge/identity/ent/externalidentity"
	"github.com/plexusone/systemforge/identity/ent/human"
	"github.com/plexusone/systemforge/identity/ent/organization"
	"github.com/plexusone/systemforge/identity/ent/predicate"
	"github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/ent/principalmembership"
	orgsvc "github.com/plexusone/systemforge/identity/organization"
	"github.com/plexusone/systemforge/identity/scim"
	"github.com/plexusone/systemforge/identity/scim/filter"
)

// EntStore implements the scim.Store interface using Ent ORM.
type EntStore struct {
	client *ent.Client
	config *Config
}

// Config holds configuration for the Ent store.
type Config struct {
	// BaseURL is the base URL for SCIM resources.
	BaseURL string

	// DefaultRole is the default role for new group members.
	DefaultRole string

	// TrustProvisionedEmail marks emails written through SCIM as verified.
	// Enable it only when the identity provider is trusted to assert email
	// ownership: a verified email lets a later social login with the same
	// address link to the provisioned user automatically. When false (the
	// default), provisioned and changed emails are unverified, and social
	// login refuses to link rather than creating a second identity.
	TrustProvisionedEmail bool
}

// DefaultConfig returns the default store configuration.
func DefaultConfig() *Config {
	return &Config{
		BaseURL:     "/scim/v2",
		DefaultRole: "member",
	}
}

// NewEntStore creates a new Ent-backed SCIM store.
func NewEntStore(client *ent.Client, config *Config) *EntStore {
	if config == nil {
		config = DefaultConfig()
	}
	return &EntStore{
		client: client,
		config: config,
	}
}

// User Operations

// Tenant scoping
//
// Every operation runs in the request's provisioning scope
// (scim.ScopeFromContext). A tenant credential sees only its organization:
// users who are members of it, and that organization as the only group.
// Identity fields (email, name, photo) of a user change only when the
// tenant owns the user: it provisioned the user and the user belongs to no
// other organization. For other users the tenant manages only their
// membership, so a tenant cannot take over an account used elsewhere.
// A platform operator credential sees every user and organization.

// errNoScope is returned for requests without a provisioning scope.
func errNoScope() error {
	return scim.ErrForbidden("SCIM credential is not bound to an organization")
}

// scopeOf returns the request's provisioning scope.
func scopeOf(ctx context.Context) (scim.Scope, error) {
	sc, ok := scim.ScopeFromContext(ctx)
	if !ok {
		return scim.Scope{}, errNoScope()
	}
	return sc, nil
}

// provisionedBy is the ExternalIdentity provider that records an
// organization's SCIM directory provisioned a principal.
func provisionedBy(orgID uuid.UUID) string {
	return "scim:" + orgID.String()
}

// memberOf selects principals with a membership, active or not, in orgID.
func memberOf(orgID uuid.UUID) predicate.Principal {
	return principal.HasPrincipalMembershipsWith(principalmembership.OrganizationIDEQ(orgID))
}

// humanQuery returns a query over the human principals SCIM manages in
// scope, with the Human edge loaded and, for a tenant, the membership in
// the tenant's organization.
func (s *EntStore) humanQuery(sc scim.Scope) *ent.PrincipalQuery {
	q := s.client.Principal.Query().
		Where(scimHuman()...).
		WithHuman()
	if !sc.Platform {
		q = q.Where(memberOf(sc.OrganizationID)).
			WithPrincipalMemberships(func(mq *ent.PrincipalMembershipQuery) {
				mq.Where(principalmembership.OrganizationIDEQ(sc.OrganizationID))
			})
	}
	return q
}

// ownedBy reports whether orgID's directory owns principal id: it
// provisioned the principal and the principal belongs to no other
// organization.
func ownedBy(ctx context.Context, client *ent.Client, id, orgID uuid.UUID) (bool, error) {
	provisioned, err := client.ExternalIdentity.Query().
		Where(externalidentity.PrincipalIDEQ(id), externalidentity.ProviderEQ(provisionedBy(orgID))).
		Exist(ctx)
	if err != nil || !provisioned {
		return false, err
	}
	elsewhere, err := client.PrincipalMembership.Query().
		Where(principalmembership.PrincipalIDEQ(id), principalmembership.OrganizationIDNEQ(orgID)).
		Exist(ctx)
	return !elsewhere, err
}

// scimHuman selects the humans SCIM manages: those with an email. Managed
// principals (no email, ADR-005) are created and controlled by their
// managers inside an application, not by an enterprise identity provider,
// so SCIM neither lists nor changes them.
func scimHuman() []predicate.Principal {
	return []predicate.Principal{
		principal.TypeEQ(principal.TypeHuman),
		principal.HasHumanWith(human.EmailNotNil()),
	}
}

func (s *EntStore) onlyUser(ctx context.Context, q *ent.PrincipalQuery) (*scim.User, error) {
	p, err := q.Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, scim.ErrNotFound("user not found")
		}
		return nil, scim.ErrInternal(err.Error())
	}
	return s.principalToSCIMUser(p), nil
}

// GetUserByID retrieves a user by SCIM ID.
func (s *EntStore) GetUserByID(ctx context.Context, id string) (*scim.User, error) {
	sc, err := scopeOf(ctx)
	if err != nil {
		return nil, err
	}
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, scim.ErrNotFound("invalid user ID")
	}
	return s.onlyUser(ctx, s.humanQuery(sc).Where(principal.IDEQ(uid)))
}

// GetUserByUserName retrieves a user by userName (email). userName is not
// case-exact (RFC 7643 section 4.1.1), so the match ignores case.
func (s *EntStore) GetUserByUserName(ctx context.Context, userName string) (*scim.User, error) {
	sc, err := scopeOf(ctx)
	if err != nil {
		return nil, err
	}
	return s.onlyUser(ctx, s.humanQuery(sc).Where(principal.HasHumanWith(human.EmailEqualFold(userName))))
}

// GetUserByExternalID retrieves a user by externalId.
// SystemForge does not store externalId, so this always reports not found.
func (s *EntStore) GetUserByExternalID(ctx context.Context, externalID string) (*scim.User, error) {
	return nil, scim.ErrNotFound("user not found")
}

// ListUsers lists users with filtering and pagination.
//
//nolint:dupl // Mirrors ListGroups - same query pattern for different entity types
func (s *EntStore) ListUsers(ctx context.Context, opts scim.ListOptions) ([]*scim.User, int, error) {
	sc, err := scopeOf(ctx)
	if err != nil {
		return nil, 0, err
	}
	query := s.humanQuery(sc)

	// Apply filter if provided
	if opts.Filter != "" {
		predicates, err := s.buildUserPredicates(opts.Filter)
		if err != nil {
			return nil, 0, err
		}
		if len(predicates) > 0 {
			query = query.Where(predicates...)
		}
	}

	// Get total count
	total, err := query.Clone().Count(ctx)
	if err != nil {
		return nil, 0, scim.ErrInternal(err.Error())
	}

	// Apply sorting
	query = s.applySortUser(query, opts.SortBy, opts.SortOrder)

	// Apply pagination (startIndex is 1-based)
	offset := opts.StartIndex - 1
	if offset < 0 {
		offset = 0
	}
	query = query.Offset(offset).Limit(opts.Count)

	principals, err := query.All(ctx)
	if err != nil {
		return nil, 0, scim.ErrInternal(err.Error())
	}

	result := make([]*scim.User, len(principals))
	for i, p := range principals {
		result[i] = s.principalToSCIMUser(p)
	}

	return result, total, nil
}

// emailTaken reports whether a human other than exceptID uses email,
// ignoring case.
func emailTaken(ctx context.Context, tx *ent.Tx, email string, exceptID uuid.UUID) (bool, error) {
	return tx.Human.Query().
		Where(human.EmailEqualFold(email), human.PrincipalIDNEQ(exceptID)).
		Exist(ctx)
}

// primaryPhoto returns the primary or "photo"-typed photo URL, if any.
func primaryPhoto(photos []scim.MultiValue) (string, bool) {
	for _, photo := range photos {
		if photo.Primary || photo.Type == "photo" {
			return photo.Value, true
		}
	}
	return "", false
}

// withTx runs fn in a transaction, rolling back on error.
func (s *EntStore) withTx(ctx context.Context, fn func(tx *ent.Tx) error) error {
	tx, err := s.client.Tx(ctx)
	if err != nil {
		return scim.ErrInternal(err.Error())
	}
	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return scim.ErrInternal(errors.Join(err, rbErr).Error())
		}
		return err
	}
	if err := tx.Commit(); err != nil {
		return scim.ErrInternal(err.Error())
	}
	return nil
}

// asSCIMError passes SCIM errors through and wraps anything else as internal.
func asSCIMError(err error) error {
	var se *scim.Error
	if errors.As(err, &se) {
		return se
	}
	if ent.IsConstraintError(err) {
		return scim.ErrConflict("user already exists")
	}
	return scim.ErrInternal(err.Error())
}

// CreateUser creates a new user as a human principal. For a tenant, the
// user also becomes a member of the tenant's organization, and the tenant
// is recorded as having provisioned it. A user who already exists
// elsewhere is linked by adding the membership; their identity is not
// changed.
func (s *EntStore) CreateUser(ctx context.Context, scimUser *scim.User) (*scim.User, error) {
	sc, err := scopeOf(ctx)
	if err != nil {
		return nil, err
	}
	email := userEmail(scimUser)
	if email == "" {
		return nil, scim.ErrInvalidValue("userName or email is required")
	}

	// Extract name
	name := scimUser.DisplayName
	if name == "" && scimUser.Name != nil {
		name = scimUser.Name.Formatted
	}
	if name == "" {
		name = email // fallback
	}

	// Determine active status
	active := true
	if scimUser.Active != nil {
		active = *scimUser.Active
	}

	id := uuid.New()
	err = s.withTx(ctx, func(tx *ent.Tx) error {
		existing, err := tx.Principal.Query().
			Where(append(scimHuman(), principal.HasHumanWith(human.EmailEqualFold(email)))...).
			Only(ctx)
		switch {
		case err == nil:
			if sc.Platform {
				return scim.ErrConflict("user with this email already exists")
			}
			id = existing.ID
			return s.linkMember(ctx, tx, sc.OrganizationID, existing.ID, active)
		case !ent.IsNotFound(err):
			return err
		}
		taken, err := emailTaken(ctx, tx, email, uuid.Nil)
		if err != nil {
			return err
		}
		if taken {
			return scim.ErrConflict("user with this email already exists")
		}
		principalActive := active
		if !sc.Platform {
			// For a tenant, active is the membership's state.
			principalActive = true
		}
		if _, err := tx.Principal.Create().
			SetID(id).
			SetType(principal.TypeHuman).
			SetIdentifier(email).
			SetDisplayName(name).
			SetActive(principalActive).
			Save(ctx); err != nil {
			return err
		}
		hc := tx.Human.Create().
			SetPrincipalID(id).
			SetEmail(email)
		if s.config.TrustProvisionedEmail {
			hc.SetEmailVerifiedAt(time.Now())
		}
		if url, ok := primaryPhoto(scimUser.Photos); ok {
			hc.SetAvatarURL(url)
		}
		if _, err := hc.Save(ctx); err != nil {
			return err
		}
		if sc.Platform {
			return nil
		}
		if _, err := tx.ExternalIdentity.Create().
			SetPrincipalID(id).
			SetProvider(provisionedBy(sc.OrganizationID)).
			SetSubject(id.String()).
			SetEmail(email).
			SetEmailVerified(s.config.TrustProvisionedEmail).
			Save(ctx); err != nil {
			return err
		}
		return s.linkMember(ctx, tx, sc.OrganizationID, id, active)
	})
	if err != nil {
		return nil, asSCIMError(err)
	}
	return s.GetUserByID(ctx, id.String())
}

// userEmail returns the email a SCIM user is created with: userName, else
// the primary or work email, else the first email.
func userEmail(u *scim.User) string {
	if u.UserName != "" {
		return u.UserName
	}
	for _, e := range u.Emails {
		if e.Primary || e.Type == "work" {
			return e.Value
		}
	}
	if len(u.Emails) > 0 {
		return u.Emails[0].Value
	}
	return ""
}

// linkMember adds principal id to organization orgID with the default role.
// A user who is already a member is a conflict, as SCIM requires for a
// duplicate create.
func (s *EntStore) linkMember(ctx context.Context, tx *ent.Tx, orgID, id uuid.UUID, active bool) error {
	exists, err := tx.PrincipalMembership.Query().
		Where(principalmembership.PrincipalIDEQ(id), principalmembership.OrganizationIDEQ(orgID)).
		Exist(ctx)
	if err != nil {
		return err
	}
	if exists {
		return scim.ErrConflict("user already exists in this organization")
	}
	if err := orgsvc.RequireMembersAllowed(ctx, tx.Client(), orgID, s.config.DefaultRole); err != nil {
		if errors.Is(err, orgsvc.ErrPersonalOrganization) {
			return scim.ErrInvalidValue("a personal organization cannot have members")
		}
		return err
	}
	_, err = tx.PrincipalMembership.Create().
		SetPrincipalID(id).
		SetOrganizationID(orgID).
		SetRole(s.config.DefaultRole).
		SetActive(active).
		Save(ctx)
	return err
}

// UpdateUser updates an existing user. For a tenant, active sets the
// membership in the tenant's organization, and identity fields change only
// for users the tenant owns; for other users they are left as they are.
func (s *EntStore) UpdateUser(ctx context.Context, id string, scimUser *scim.User) (*scim.User, error) {
	sc, err := scopeOf(ctx)
	if err != nil {
		return nil, err
	}
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, scim.ErrNotFound("invalid user ID")
	}

	err = s.withTx(ctx, func(tx *ent.Tx) error {
		q := tx.Principal.Query().
			Where(append(scimHuman(), principal.IDEQ(uid))...).
			WithHuman()
		if !sc.Platform {
			q = q.Where(memberOf(sc.OrganizationID))
		}
		p, err := q.Only(ctx)
		if err != nil {
			if ent.IsNotFound(err) {
				return scim.ErrNotFound("user not found")
			}
			return err
		}
		if p.Edges.Human == nil {
			return scim.ErrInternal("user has no human record")
		}

		if sc.Platform {
			if scimUser.Active != nil {
				if err := tx.Principal.UpdateOne(p).SetActive(*scimUser.Active).Exec(ctx); err != nil {
					return err
				}
			}
			return s.updateIdentity(ctx, tx, p, scimUser)
		}

		if scimUser.Active != nil {
			if _, err := tx.PrincipalMembership.Update().
				Where(principalmembership.PrincipalIDEQ(uid), principalmembership.OrganizationIDEQ(sc.OrganizationID)).
				SetActive(*scimUser.Active).
				Save(ctx); err != nil {
				return err
			}
		}
		owned, err := ownedBy(ctx, tx.Client(), uid, sc.OrganizationID)
		if err != nil || !owned {
			return err
		}
		return s.updateIdentity(ctx, tx, p, scimUser)
	})
	if err != nil {
		return nil, asSCIMError(err)
	}
	return s.GetUserByID(ctx, id)
}

// updateIdentity applies the email, name and photo of scimUser to p.
func (s *EntStore) updateIdentity(ctx context.Context, tx *ent.Tx, p *ent.Principal, scimUser *scim.User) error {
	pu := tx.Principal.UpdateOne(p)
	hu := tx.Human.UpdateOne(p.Edges.Human)

	if scimUser.UserName != "" {
		taken, err := emailTaken(ctx, tx, scimUser.UserName, p.ID)
		if err != nil {
			return err
		}
		if taken {
			return scim.ErrConflict("email already in use")
		}
		pu.SetIdentifier(scimUser.UserName)
		hu.SetEmail(scimUser.UserName)
		// Verification belongs to an address, so a changed email does
		// not inherit the previous address's verification.
		if p.Edges.Human.Email == nil || !strings.EqualFold(scimUser.UserName, *p.Edges.Human.Email) {
			if s.config.TrustProvisionedEmail {
				hu.SetEmailVerifiedAt(time.Now())
			} else {
				hu.ClearEmailVerifiedAt()
			}
		}
	}
	if scimUser.DisplayName != "" {
		pu.SetDisplayName(scimUser.DisplayName)
	} else if scimUser.Name != nil && scimUser.Name.Formatted != "" {
		pu.SetDisplayName(scimUser.Name.Formatted)
	}
	if url, ok := primaryPhoto(scimUser.Photos); ok {
		hu.SetAvatarURL(url)
	}

	if _, err := pu.Save(ctx); err != nil {
		return err
	}
	_, err := hu.Save(ctx)
	return err
}

// DeleteUser deletes a user together with its group memberships and the
// records that belong only to it. For a tenant, a user the tenant does not
// own only loses the membership in the tenant's organization.
func (s *EntStore) DeleteUser(ctx context.Context, id string) error {
	sc, err := scopeOf(ctx)
	if err != nil {
		return err
	}
	uid, err := uuid.Parse(id)
	if err != nil {
		return scim.ErrNotFound("invalid user ID")
	}

	err = s.withTx(ctx, func(tx *ent.Tx) error {
		where := append(scimHuman(), principal.IDEQ(uid))
		if !sc.Platform {
			where = append(where, memberOf(sc.OrganizationID))
		}
		exists, err := tx.Principal.Query().Where(where...).Exist(ctx)
		if err != nil {
			return err
		}
		if !exists {
			return scim.ErrNotFound("user not found")
		}
		if !sc.Platform {
			owned, err := ownedBy(ctx, tx.Client(), uid, sc.OrganizationID)
			if err != nil {
				return err
			}
			if !owned {
				return removeMember(ctx, tx, sc.OrganizationID, uid)
			}
		}
		if _, err := tx.PrincipalMembership.Delete().Where(principalmembership.PrincipalIDEQ(uid)).Exec(ctx); err != nil {
			return err
		}
		if _, err := tx.Human.Delete().Where(human.PrincipalIDEQ(uid)).Exec(ctx); err != nil {
			return err
		}
		if _, err := tx.ExternalIdentity.Delete().Where(externalidentity.PrincipalIDEQ(uid)).Exec(ctx); err != nil {
			return err
		}
		if _, err := tx.Credential.Delete().Where(credential.PrincipalIDEQ(uid)).Exec(ctx); err != nil {
			return err
		}
		return tx.Principal.DeleteOneID(uid).Exec(ctx)
	})
	if err != nil {
		var se *scim.Error
		if errors.As(err, &se) {
			return se
		}
		return scim.ErrInternal(err.Error())
	}
	return nil
}

// removeMember removes principal id from organization orgID, with its
// application roles there.
func removeMember(ctx context.Context, tx *ent.Tx, orgID, id uuid.UUID) error {
	if _, err := tx.AppRole.Delete().
		Where(approle.PrincipalID(id), approle.OrganizationID(orgID)).
		Exec(ctx); err != nil {
		return err
	}
	_, err := tx.PrincipalMembership.Delete().
		Where(
			principalmembership.PrincipalIDEQ(id),
			principalmembership.OrganizationIDEQ(orgID),
		).
		Exec(ctx)
	return err
}

// Group Operations

// tenantGroup reports whether a tenant may address group gid: only its own
// organization. A platform scope may address any group.
func tenantGroup(sc scim.Scope, gid uuid.UUID) bool {
	return sc.Platform || gid == sc.OrganizationID
}

// orgQuery returns a query over the organizations visible in scope.
func (s *EntStore) orgQuery(sc scim.Scope) *ent.OrganizationQuery {
	q := s.client.Organization.Query()
	if !sc.Platform {
		q = q.Where(organization.IDEQ(sc.OrganizationID))
	}
	return q
}

func onlyGroup(ctx context.Context, s *EntStore, q *ent.OrganizationQuery) (*scim.Group, error) {
	org, err := q.Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, scim.ErrNotFound("group not found")
		}
		return nil, scim.ErrInternal(err.Error())
	}
	return s.entOrgToSCIM(org), nil
}

// GetGroupByID retrieves a group by SCIM ID.
func (s *EntStore) GetGroupByID(ctx context.Context, id string) (*scim.Group, error) {
	sc, err := scopeOf(ctx)
	if err != nil {
		return nil, err
	}
	gid, err := uuid.Parse(id)
	if err != nil {
		return nil, scim.ErrNotFound("invalid group ID")
	}
	return onlyGroup(ctx, s, s.orgQuery(sc).Where(organization.IDEQ(gid)))
}

// GetGroupByDisplayName retrieves a group by displayName.
func (s *EntStore) GetGroupByDisplayName(ctx context.Context, displayName string) (*scim.Group, error) {
	sc, err := scopeOf(ctx)
	if err != nil {
		return nil, err
	}
	return onlyGroup(ctx, s, s.orgQuery(sc).Where(organization.NameEQ(displayName)))
}

// GetGroupByExternalID retrieves a group by externalId (the organization
// slug).
func (s *EntStore) GetGroupByExternalID(ctx context.Context, externalID string) (*scim.Group, error) {
	sc, err := scopeOf(ctx)
	if err != nil {
		return nil, err
	}
	return onlyGroup(ctx, s, s.orgQuery(sc).Where(organization.SlugEQ(externalID)))
}

// ListGroups lists groups with filtering and pagination.
//
//nolint:dupl // Mirrors ListUsers - same query pattern for different entity types
func (s *EntStore) ListGroups(ctx context.Context, opts scim.ListOptions) ([]*scim.Group, int, error) {
	sc, err := scopeOf(ctx)
	if err != nil {
		return nil, 0, err
	}
	query := s.orgQuery(sc)

	// Apply filter if provided
	if opts.Filter != "" {
		predicates, err := s.buildGroupPredicates(opts.Filter)
		if err != nil {
			return nil, 0, err
		}
		if len(predicates) > 0 {
			query = query.Where(predicates...)
		}
	}

	// Get total count
	total, err := query.Clone().Count(ctx)
	if err != nil {
		return nil, 0, scim.ErrInternal(err.Error())
	}

	// Apply sorting
	query = s.applySortGroup(query, opts.SortBy, opts.SortOrder)

	// Apply pagination (startIndex is 1-based)
	offset := opts.StartIndex - 1
	if offset < 0 {
		offset = 0
	}
	query = query.Offset(offset).Limit(opts.Count)

	orgs, err := query.All(ctx)
	if err != nil {
		return nil, 0, scim.ErrInternal(err.Error())
	}

	result := make([]*scim.Group, len(orgs))
	for i, org := range orgs {
		result[i] = s.entOrgToSCIM(org)
	}

	return result, total, nil
}

// errTenantGroups is returned when a tenant tries to create, rename or
// delete a group: its only group is its own organization, which the
// platform manages.
func errTenantGroups() error {
	return scim.ErrForbidden("a tenant SCIM credential manages members of its organization, not groups")
}

// CreateGroup creates a new group. Only a platform scope may create groups.
func (s *EntStore) CreateGroup(ctx context.Context, scimGroup *scim.Group) (*scim.Group, error) {
	sc, err := scopeOf(ctx)
	if err != nil {
		return nil, err
	}
	if !sc.Platform {
		return nil, errTenantGroups()
	}
	if scimGroup.DisplayName == "" {
		return nil, scim.ErrInvalidValue("displayName is required")
	}

	// Generate slug from displayName
	slug := generateSlug(scimGroup.DisplayName)
	if scimGroup.ExternalID != "" {
		slug = scimGroup.ExternalID
	}

	if orgsvc.IsReservedSlug(slug) {
		return nil, scim.ErrInvalidValue("group slug is reserved")
	}

	// Check for existing organization with same slug
	exists, err := s.client.Organization.Query().Where(organization.SlugEQ(slug)).Exist(ctx)
	if err != nil {
		return nil, scim.ErrInternal(err.Error())
	}
	if exists {
		return nil, scim.ErrConflict("group with this slug already exists")
	}

	org, err := s.client.Organization.Create().
		SetName(scimGroup.DisplayName).
		SetSlug(slug).
		SetActive(true).
		Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, scim.ErrConflict("group already exists")
		}
		return nil, scim.ErrInternal(err.Error())
	}

	return s.entOrgToSCIM(org), nil
}

// UpdateGroup updates an existing group. A tenant may not rename its
// organization; an update that keeps the name is accepted so that member
// changes in the same request apply.
func (s *EntStore) UpdateGroup(ctx context.Context, id string, scimGroup *scim.Group) (*scim.Group, error) {
	sc, err := scopeOf(ctx)
	if err != nil {
		return nil, err
	}
	gid, err := uuid.Parse(id)
	if err != nil || !tenantGroup(sc, gid) {
		return nil, scim.ErrNotFound("group not found")
	}

	if !sc.Platform {
		current, err := s.GetGroupByID(ctx, id)
		if err != nil {
			return nil, err
		}
		if scimGroup.DisplayName != "" && scimGroup.DisplayName != current.DisplayName {
			return nil, errTenantGroups()
		}
		return current, nil
	}

	update := s.client.Organization.UpdateOneID(gid)

	if scimGroup.DisplayName != "" {
		update = update.SetName(scimGroup.DisplayName)
	}

	org, err := update.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, scim.ErrNotFound("group not found")
		}
		return nil, scim.ErrInternal(err.Error())
	}

	return s.entOrgToSCIM(org), nil
}

// DeleteGroup deletes a group. Only a platform scope may delete groups.
func (s *EntStore) DeleteGroup(ctx context.Context, id string) error {
	sc, err := scopeOf(ctx)
	if err != nil {
		return err
	}
	if !sc.Platform {
		return errTenantGroups()
	}
	gid, err := uuid.Parse(id)
	if err != nil {
		return scim.ErrNotFound("invalid group ID")
	}

	err = s.client.Organization.DeleteOneID(gid).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return scim.ErrNotFound("group not found")
		}
		return scim.ErrInternal(err.Error())
	}

	return nil
}

// Membership Operations

// GetGroupsForUser returns all groups a user belongs to. A tenant sees only
// its own organization.
//
//nolint:dupl // Mirrors GetMembersForGroup - intentional symmetry for membership queries
func (s *EntStore) GetGroupsForUser(ctx context.Context, userID string) ([]scim.GroupRef, error) {
	sc, err := scopeOf(ctx)
	if err != nil {
		return nil, err
	}
	uid, err := uuid.Parse(userID)
	if err != nil {
		return nil, scim.ErrNotFound("invalid user ID")
	}

	q := s.client.PrincipalMembership.Query().
		Where(
			principalmembership.PrincipalIDEQ(uid),
			principalmembership.ActiveEQ(true),
		)
	if !sc.Platform {
		q = q.Where(principalmembership.OrganizationIDEQ(sc.OrganizationID))
	}
	memberships, err := q.WithOrganization().All(ctx)
	if err != nil {
		return nil, scim.ErrInternal(err.Error())
	}

	groups := make([]scim.GroupRef, 0, len(memberships))
	for _, m := range memberships {
		if m.Edges.Organization != nil {
			groups = append(groups, scim.GroupRef{
				Value:   m.OrganizationID.String(),
				Ref:     s.config.BaseURL + "/Groups/" + m.OrganizationID.String(),
				Display: m.Edges.Organization.Name,
				Type:    "direct",
			})
		}
	}

	return groups, nil
}

// GetMembersForGroup returns all human members of a group.
//
//nolint:dupl // Mirrors GetGroupsForUser - intentional symmetry for membership queries
func (s *EntStore) GetMembersForGroup(ctx context.Context, groupID string) ([]scim.MemberRef, error) {
	sc, err := scopeOf(ctx)
	if err != nil {
		return nil, err
	}
	gid, err := uuid.Parse(groupID)
	if err != nil || !tenantGroup(sc, gid) {
		return nil, scim.ErrNotFound("group not found")
	}

	memberships, err := s.client.PrincipalMembership.Query().
		Where(
			principalmembership.OrganizationIDEQ(gid),
			principalmembership.ActiveEQ(true),
			principalmembership.HasPrincipalWith(scimHuman()...),
		).
		WithPrincipal().
		All(ctx)
	if err != nil {
		return nil, scim.ErrInternal(err.Error())
	}

	members := make([]scim.MemberRef, 0, len(memberships))
	for _, m := range memberships {
		if m.Edges.Principal != nil {
			members = append(members, scim.MemberRef{
				Value:   m.PrincipalID.String(),
				Ref:     s.config.BaseURL + "/Users/" + m.PrincipalID.String(),
				Display: m.Edges.Principal.DisplayName,
				Type:    "User",
			})
		}
	}

	return members, nil
}

// AddMemberToGroup adds a user to a group. Adding an existing member is a
// no-op; re-adding a deactivated member reactivates the membership. A
// tenant may add only users it already sees: members of its organization,
// active or not.
func (s *EntStore) AddMemberToGroup(ctx context.Context, groupID, userID string) error {
	sc, err := scopeOf(ctx)
	if err != nil {
		return err
	}
	gid, err := uuid.Parse(groupID)
	if err != nil || !tenantGroup(sc, gid) {
		return scim.ErrNotFound("group not found")
	}
	uid, err := uuid.Parse(userID)
	if err != nil {
		return scim.ErrNotFound("invalid user ID")
	}
	where := append(scimHuman(), principal.IDEQ(uid))
	if !sc.Platform {
		where = append(where, memberOf(sc.OrganizationID))
	}
	known, err := s.client.Principal.Query().Where(where...).Exist(ctx)
	if err != nil {
		return scim.ErrInternal(err.Error())
	}
	if !known {
		return scim.ErrNotFound("user not found")
	}

	if err := orgsvc.RequireMembersAllowed(ctx, s.client, gid, s.config.DefaultRole); err != nil {
		if errors.Is(err, orgsvc.ErrPersonalOrganization) {
			return scim.ErrInvalidValue("a personal organization cannot have group members")
		}
		return scim.ErrInternal(err.Error())
	}

	existing, err := s.client.PrincipalMembership.Query().
		Where(
			principalmembership.PrincipalIDEQ(uid),
			principalmembership.OrganizationIDEQ(gid),
		).
		Only(ctx)
	switch {
	case err == nil:
		if existing.Active {
			return nil
		}
		if _, err := s.client.PrincipalMembership.UpdateOne(existing).SetActive(true).Save(ctx); err != nil {
			return scim.ErrInternal(err.Error())
		}
		return nil
	case !ent.IsNotFound(err):
		return scim.ErrInternal(err.Error())
	}

	_, err = s.client.PrincipalMembership.Create().
		SetPrincipalID(uid).
		SetOrganizationID(gid).
		SetRole(s.config.DefaultRole).
		Save(ctx)
	if err != nil {
		return scim.ErrInternal(err.Error())
	}

	return nil
}

// RemoveMemberFromGroup removes a user from a group.
func (s *EntStore) RemoveMemberFromGroup(ctx context.Context, groupID, userID string) error {
	sc, err := scopeOf(ctx)
	if err != nil {
		return err
	}
	gid, err := uuid.Parse(groupID)
	if err != nil || !tenantGroup(sc, gid) {
		return scim.ErrNotFound("group not found")
	}
	uid, err := uuid.Parse(userID)
	if err != nil {
		return scim.ErrNotFound("invalid user ID")
	}

	// The member's application roles go with the membership.
	if err := s.withTx(ctx, func(tx *ent.Tx) error {
		return removeMember(ctx, tx, gid, uid)
	}); err != nil {
		return scim.ErrInternal(err.Error())
	}

	return nil
}

// Helper methods

// principalToSCIMUser converts a human Principal, loaded with its Human edge,
// to a SCIM User.
func (s *EntStore) principalToSCIMUser(p *ent.Principal) *scim.User {
	// For a tenant, the membership edge is loaded and active means the
	// membership in the tenant's organization.
	active := p.Active
	for _, m := range p.Edges.PrincipalMemberships {
		active = active && m.Active
	}
	var email string
	var avatar *string
	if h := p.Edges.Human; h != nil {
		if h.Email != nil {
			email = *h.Email
		}
		avatar = h.AvatarURL
	}
	scimUser := &scim.User{
		Resource: scim.Resource{
			Schemas: []string{scim.SchemaUser},
			ID:      p.ID.String(),
			Meta: &scim.Meta{
				ResourceType: scim.ResourceTypeUser,
				Created:      &p.CreatedAt,
				LastModified: &p.UpdatedAt,
				Location:     s.config.BaseURL + "/Users/" + p.ID.String(),
				Version:      p.UpdatedAt.Format("20060102150405"),
			},
		},
		UserName:    email,
		DisplayName: p.DisplayName,
		Active:      &active,
		Name: &scim.Name{
			Formatted: p.DisplayName,
		},
		Emails: []scim.MultiValue{
			{
				Value:   email,
				Type:    "work",
				Primary: true,
			},
		},
	}

	if avatar != nil && *avatar != "" {
		scimUser.Photos = []scim.MultiValue{
			{
				Value:   *avatar,
				Type:    "photo",
				Primary: true,
			},
		}
	}

	return scimUser
}

// entOrgToSCIM converts an Ent Organization to a SCIM Group.
func (s *EntStore) entOrgToSCIM(org *ent.Organization) *scim.Group {
	return &scim.Group{
		Resource: scim.Resource{
			Schemas:    []string{scim.SchemaGroup},
			ID:         org.ID.String(),
			ExternalID: org.Slug,
			Meta: &scim.Meta{
				ResourceType: scim.ResourceTypeGroup,
				Created:      &org.CreatedAt,
				LastModified: &org.UpdatedAt,
				Location:     s.config.BaseURL + "/Groups/" + org.ID.String(),
				Version:      org.UpdatedAt.Format("20060102150405"),
			},
		},
		DisplayName: org.Name,
	}
}

// buildUserPredicates builds Ent predicates from a SCIM filter.
func (s *EntStore) buildUserPredicates(filterExpr string) ([]predicate.Principal, error) {
	node, err := filter.ParseFilter(filterExpr)
	if err != nil {
		return nil, scim.ErrInvalidFilter(err.Error())
	}
	if node == nil {
		return nil, nil
	}

	return s.collectUserPredicates(node), nil
}

// collectUserPredicates recursively collects predicates from a filter node.
//
//nolint:dupl // Mirrors collectGroupPredicates - same traversal logic for different predicate types
func (s *EntStore) collectUserPredicates(node filter.Node) []predicate.Principal {
	var predicates []predicate.Principal

	switch n := node.(type) {
	case *filter.ComparisonNode:
		if p := s.userComparisonToPredicate(n); p != nil {
			predicates = append(predicates, p)
		}
	case *filter.LogicalAndNode:
		predicates = append(predicates, s.collectUserPredicates(n.Left)...)
		predicates = append(predicates, s.collectUserPredicates(n.Right)...)
	case *filter.LogicalOrNode:
		left := s.collectUserPredicates(n.Left)
		right := s.collectUserPredicates(n.Right)
		if len(left) > 0 && len(right) > 0 {
			predicates = append(predicates, principal.Or(append(left, right...)...))
		}
	case *filter.LogicalNotNode:
		inner := s.collectUserPredicates(n.Operand)
		if len(inner) > 0 {
			predicates = append(predicates, principal.Not(principal.And(inner...)))
		}
	}

	return predicates
}

// hasEmail wraps a Human email predicate as a Principal predicate.
func hasEmail(p predicate.Human) predicate.Principal {
	return principal.HasHumanWith(p)
}

// userComparisonToPredicate converts a comparison node to a principal
// predicate. userName and emails.value are not case-exact (RFC 7643), so
// equality and containment ignore case.
func (s *EntStore) userComparisonToPredicate(node *filter.ComparisonNode) predicate.Principal {
	attr := strings.ToLower(node.AttributePath)
	value, _ := node.Value.(string)

	switch attr {
	case "id":
		id, err := uuid.Parse(value)
		if err != nil {
			return nil
		}
		switch node.Operator {
		case filter.OpEqual:
			return principal.IDEQ(id)
		case filter.OpNotEqual:
			return principal.IDNEQ(id)
		}
	case "username", "emails.value":
		switch node.Operator {
		case filter.OpEqual:
			return hasEmail(human.EmailEqualFold(value))
		case filter.OpNotEqual:
			return principal.Not(hasEmail(human.EmailEqualFold(value)))
		case filter.OpContains:
			return hasEmail(human.EmailContainsFold(value))
		case filter.OpStartsWith:
			return hasEmail(human.EmailHasPrefix(value))
		case filter.OpEndsWith:
			return hasEmail(human.EmailHasSuffix(value))
		case filter.OpPresent:
			return hasEmail(human.EmailNEQ(""))
		}
	case "displayname", "name.formatted":
		switch node.Operator {
		case filter.OpEqual:
			return principal.DisplayNameEQ(value)
		case filter.OpNotEqual:
			return principal.DisplayNameNEQ(value)
		case filter.OpContains:
			return principal.DisplayNameContains(value)
		case filter.OpStartsWith:
			return principal.DisplayNameHasPrefix(value)
		case filter.OpEndsWith:
			return principal.DisplayNameHasSuffix(value)
		case filter.OpPresent:
			return principal.DisplayNameNEQ("")
		}
	case "active":
		boolValue, ok := node.Value.(bool)
		if ok && node.Operator == filter.OpEqual {
			return principal.ActiveEQ(boolValue)
		}
	case "meta.created":
		if t, err := time.Parse(time.RFC3339, value); err == nil {
			switch node.Operator {
			case filter.OpGreaterThan:
				return principal.CreatedAtGT(t)
			case filter.OpGreaterThanOrEqual:
				return principal.CreatedAtGTE(t)
			case filter.OpLessThan:
				return principal.CreatedAtLT(t)
			case filter.OpLessThanOrEqual:
				return principal.CreatedAtLTE(t)
			}
		}
	case "meta.lastmodified":
		if t, err := time.Parse(time.RFC3339, value); err == nil {
			switch node.Operator {
			case filter.OpGreaterThan:
				return principal.UpdatedAtGT(t)
			case filter.OpGreaterThanOrEqual:
				return principal.UpdatedAtGTE(t)
			case filter.OpLessThan:
				return principal.UpdatedAtLT(t)
			case filter.OpLessThanOrEqual:
				return principal.UpdatedAtLTE(t)
			}
		}
	}

	return nil
}

// applySortUser applies sorting to a user query.
func (s *EntStore) applySortUser(q *ent.PrincipalQuery, sortBy, sortOrder string) *ent.PrincipalQuery {
	desc := strings.EqualFold(sortOrder, "descending")
	field := strings.ToLower(sortBy)

	// A nil OrderTermOption panics when Ent applies it, so pass the
	// descending option only when it is requested.
	var orderOpts []sql.OrderTermOption
	if desc {
		orderOpts = append(orderOpts, sql.OrderDesc())
	}

	switch field {
	case "username", "emails.value":
		return q.Order(principal.ByHumanField(human.FieldEmail, orderOpts...))
	case "displayname", "name.formatted":
		return q.Order(principal.ByDisplayName(orderOpts...))
	case "meta.created":
		return q.Order(principal.ByCreatedAt(orderOpts...))
	case "meta.lastmodified":
		return q.Order(principal.ByUpdatedAt(orderOpts...))
	default:
		return q.Order(principal.ByCreatedAt(orderOpts...))
	}
}

// buildGroupPredicates builds Ent predicates from a SCIM filter.
func (s *EntStore) buildGroupPredicates(filterExpr string) ([]predicate.Organization, error) {
	node, err := filter.ParseFilter(filterExpr)
	if err != nil {
		return nil, scim.ErrInvalidFilter(err.Error())
	}
	if node == nil {
		return nil, nil
	}

	return s.collectGroupPredicates(node), nil
}

// collectGroupPredicates recursively collects predicates from a filter node.
//
//nolint:dupl // Mirrors collectUserPredicates - same traversal logic for different predicate types
func (s *EntStore) collectGroupPredicates(node filter.Node) []predicate.Organization {
	var predicates []predicate.Organization

	switch n := node.(type) {
	case *filter.ComparisonNode:
		if p := s.groupComparisonToPredicate(n); p != nil {
			predicates = append(predicates, p)
		}
	case *filter.LogicalAndNode:
		predicates = append(predicates, s.collectGroupPredicates(n.Left)...)
		predicates = append(predicates, s.collectGroupPredicates(n.Right)...)
	case *filter.LogicalOrNode:
		left := s.collectGroupPredicates(n.Left)
		right := s.collectGroupPredicates(n.Right)
		if len(left) > 0 && len(right) > 0 {
			predicates = append(predicates, organization.Or(append(left, right...)...))
		}
	case *filter.LogicalNotNode:
		inner := s.collectGroupPredicates(n.Operand)
		if len(inner) > 0 {
			predicates = append(predicates, organization.Not(organization.And(inner...)))
		}
	}

	return predicates
}

// groupComparisonToPredicate converts a comparison node to an organization predicate.
func (s *EntStore) groupComparisonToPredicate(node *filter.ComparisonNode) predicate.Organization {
	attr := strings.ToLower(node.AttributePath)
	value, _ := node.Value.(string)

	switch attr {
	case "id":
		id, err := uuid.Parse(value)
		if err != nil {
			return nil
		}
		switch node.Operator {
		case filter.OpEqual:
			return organization.IDEQ(id)
		case filter.OpNotEqual:
			return organization.IDNEQ(id)
		}
	case "displayname":
		switch node.Operator {
		case filter.OpEqual:
			return organization.NameEQ(value)
		case filter.OpNotEqual:
			return organization.NameNEQ(value)
		case filter.OpContains:
			return organization.NameContains(value)
		case filter.OpStartsWith:
			return organization.NameHasPrefix(value)
		case filter.OpEndsWith:
			return organization.NameHasSuffix(value)
		case filter.OpPresent:
			return organization.NameNEQ("")
		}
	case "externalid":
		switch node.Operator {
		case filter.OpEqual:
			return organization.SlugEQ(value)
		case filter.OpNotEqual:
			return organization.SlugNEQ(value)
		}
	case "meta.created":
		if t, err := time.Parse(time.RFC3339, value); err == nil {
			switch node.Operator {
			case filter.OpGreaterThan:
				return organization.CreatedAtGT(t)
			case filter.OpGreaterThanOrEqual:
				return organization.CreatedAtGTE(t)
			case filter.OpLessThan:
				return organization.CreatedAtLT(t)
			case filter.OpLessThanOrEqual:
				return organization.CreatedAtLTE(t)
			}
		}
	case "meta.lastmodified":
		if t, err := time.Parse(time.RFC3339, value); err == nil {
			switch node.Operator {
			case filter.OpGreaterThan:
				return organization.UpdatedAtGT(t)
			case filter.OpGreaterThanOrEqual:
				return organization.UpdatedAtGTE(t)
			case filter.OpLessThan:
				return organization.UpdatedAtLT(t)
			case filter.OpLessThanOrEqual:
				return organization.UpdatedAtLTE(t)
			}
		}
	}

	return nil
}

// applySortGroup applies sorting to a group query.
func (s *EntStore) applySortGroup(q *ent.OrganizationQuery, sortBy, sortOrder string) *ent.OrganizationQuery {
	desc := strings.EqualFold(sortOrder, "descending")
	field := strings.ToLower(sortBy)

	// A nil OrderTermOption panics when Ent applies it, so pass the
	// descending option only when it is requested.
	var orderOpts []sql.OrderTermOption
	if desc {
		orderOpts = append(orderOpts, sql.OrderDesc())
	}

	switch field {
	case "displayname":
		return q.Order(organization.ByName(orderOpts...))
	case "externalid":
		return q.Order(organization.BySlug(orderOpts...))
	case "meta.created":
		return q.Order(organization.ByCreatedAt(orderOpts...))
	case "meta.lastmodified":
		return q.Order(organization.ByUpdatedAt(orderOpts...))
	default:
		return q.Order(organization.ByCreatedAt(orderOpts...))
	}
}

// generateSlug generates a URL-safe slug from a name.
func generateSlug(name string) string {
	var sb strings.Builder
	for _, r := range name {
		if r >= 'a' && r <= 'z' {
			sb.WriteRune(r)
		} else if r >= 'A' && r <= 'Z' {
			sb.WriteRune(r + 32) // lowercase
		} else if r >= '0' && r <= '9' {
			sb.WriteRune(r)
		} else if r == ' ' || r == '-' || r == '_' {
			sb.WriteByte('-')
		}
	}
	return sb.String()
}

// Ensure EntStore implements scim.Store
var _ scim.Store = (*EntStore)(nil)
