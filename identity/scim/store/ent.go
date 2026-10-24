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
	"github.com/plexusone/systemforge/identity/ent/credential"
	"github.com/plexusone/systemforge/identity/ent/externalidentity"
	"github.com/plexusone/systemforge/identity/ent/human"
	"github.com/plexusone/systemforge/identity/ent/organization"
	"github.com/plexusone/systemforge/identity/ent/predicate"
	"github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/ent/principalmembership"
	orgsvc "github.com/plexusone/systemforge/identity/organization"
	principalsvc "github.com/plexusone/systemforge/identity/principal"
	"github.com/plexusone/systemforge/identity/scim"
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

	// Memberships adds, changes and removes organization memberships for
	// SCIM, with their side effects: authorization-graph sync, access-change
	// records, and cleanup of application roles and resource grants. Pass
	// the application's organization service so the graph sync uses its
	// syncer. Default: organization.NewService on the store's client, which
	// records access changes but syncs no authorization graph.
	Memberships Memberships

	// Principals deactivates and reactivates accounts, recording the access
	// change that stops existing tokens being honored. Default:
	// principal.NewService on the store's client.
	Principals Principals

	// Organizations creates, renames and deletes the organizations a
	// platform-scoped credential manages as groups, with the organization
	// service's slug rules and authorization-graph sync. Default: Memberships
	// when it also implements Organizations (as organization.Service does),
	// otherwise organization.NewService on the store's client.
	Organizations Organizations
}

// Organizations is the part of organization.Service the SCIM store uses to
// manage groups.
type Organizations interface {
	Create(ctx context.Context, input orgsvc.CreateOrganizationInput) (*orgsvc.Organization, error)
	Update(ctx context.Context, id uuid.UUID, input orgsvc.UpdateOrganizationInput) (*orgsvc.Organization, error)
	Delete(ctx context.Context, id uuid.UUID) error
	GenerateSlug(ctx context.Context, name string) (string, error)
}

// Memberships is the part of organization.Service the SCIM store uses.
type Memberships interface {
	AddMember(ctx context.Context, input orgsvc.AddMemberInput) (*orgsvc.Membership, error)
	UpdateMember(ctx context.Context, membershipID uuid.UUID, input orgsvc.UpdateMemberInput) (*orgsvc.Membership, error)
	RemoveMember(ctx context.Context, organizationID, principalID uuid.UUID) error
}

// Principals is the part of principal.Service the SCIM store uses.
type Principals interface {
	Deactivate(ctx context.Context, id uuid.UUID) error
	Reactivate(ctx context.Context, id uuid.UUID) error
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
	cfg := DefaultConfig()
	if config != nil {
		c := *config
		cfg = &c
	}
	if cfg.Memberships == nil {
		cfg.Memberships = orgsvc.NewService(client)
	}
	if cfg.Principals == nil {
		cfg.Principals = principalsvc.NewService(client)
	}
	if cfg.Organizations == nil {
		if o, ok := cfg.Memberships.(Organizations); ok {
			cfg.Organizations = o
		} else {
			cfg.Organizations = orgsvc.NewService(client)
		}
	}
	return &EntStore{
		client: client,
		config: cfg,
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
		return nil, internalError(ctx, err)
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
		return nil, 0, internalError(ctx, err)
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
		return nil, 0, internalError(ctx, err)
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
		return internalError(ctx, err)
	}
	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return internalError(ctx, errors.Join(err, rbErr))
		}
		return err
	}
	if err := tx.Commit(); err != nil {
		return internalError(ctx, err)
	}
	return nil
}

// internalError logs err and returns a 500 SCIM error without its text.
func internalError(ctx context.Context, err error) error {
	return scim.InternalError(ctx, err)
}

// asSCIMError passes SCIM errors through and wraps anything else as internal.
func asSCIMError(ctx context.Context, err error) error {
	var se *scim.Error
	if errors.As(err, &se) {
		return se
	}
	if ent.IsConstraintError(err) {
		return scim.ErrConflict("user already exists")
	}
	return internalError(ctx, err)
}

// CreateUser creates a new user as a human principal. For a tenant, the
// user also becomes a member of the tenant's organization, and the tenant
// is recorded as having provisioned it. A user who already exists
// elsewhere is linked by adding the membership; their identity is not
// changed.
//
// The account is created first and the membership is added after through
// the membership service. If adding it fails, the request fails and the
// identity provider's retry finds the account by email and links it.
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

	var id uuid.UUID
	err = s.withTx(ctx, func(tx *ent.Tx) error {
		existing, err := tx.Principal.Query().
			Where(append(scimHuman(), principal.HasHumanWith(human.EmailEqualFold(email)))...).
			Only(ctx)
		switch {
		case err == nil:
			if sc.Platform {
				return scim.ErrConflict("user with this email already exists")
			}
			member, err := tx.PrincipalMembership.Query().
				Where(principalmembership.PrincipalIDEQ(existing.ID), principalmembership.OrganizationIDEQ(sc.OrganizationID)).
				Exist(ctx)
			if err != nil {
				return err
			}
			if member {
				return scim.ErrConflict("user already exists in this organization")
			}
			id = existing.ID
			return nil
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
		id = uuid.New()
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
		_, err = tx.ExternalIdentity.Create().
			SetPrincipalID(id).
			SetProvider(provisionedBy(sc.OrganizationID)).
			SetSubject(id.String()).
			SetEmail(email).
			SetEmailVerified(s.config.TrustProvisionedEmail).
			Save(ctx)
		return err
	})
	if err != nil {
		return nil, asSCIMError(ctx, err)
	}
	if !sc.Platform {
		if err := s.addMember(ctx, sc.OrganizationID, id); err != nil {
			return nil, err
		}
		if !active {
			if err := s.setMemberActive(ctx, sc.OrganizationID, id, false); err != nil {
				return nil, err
			}
		}
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

// UpdateUser updates an existing user. For a platform scope, active
// deactivates or reactivates the account. For a tenant, active suspends or
// restores the membership in the tenant's organization, and identity
// fields change only for users the tenant owns; for other users they are
// left as they are.
func (s *EntStore) UpdateUser(ctx context.Context, id string, scimUser *scim.User) (*scim.User, error) {
	sc, err := scopeOf(ctx)
	if err != nil {
		return nil, err
	}
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, scim.ErrNotFound("invalid user ID")
	}

	var wasActive bool
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
		wasActive = p.Active
		if !sc.Platform {
			owned, err := ownedBy(ctx, tx.Client(), uid, sc.OrganizationID)
			if err != nil || !owned {
				return err
			}
		}
		return s.updateIdentity(ctx, tx, p, scimUser)
	})
	if err != nil {
		return nil, asSCIMError(ctx, err)
	}

	if scimUser.Active != nil {
		switch {
		case !sc.Platform:
			err = s.setMemberActive(ctx, sc.OrganizationID, uid, *scimUser.Active)
		case *scimUser.Active && !wasActive:
			err = s.config.Principals.Reactivate(ctx, uid)
		case !*scimUser.Active && wasActive:
			err = s.config.Principals.Deactivate(ctx, uid)
		}
		if err != nil {
			return nil, asSCIMError(ctx, err)
		}
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

// DeleteUser deletes a user. For a tenant, a user the tenant does not own
// only loses the membership in the tenant's organization. Otherwise every
// membership is removed through the membership service, the account is
// deactivated so existing tokens stop being honored, and the account and
// the records that belong only to it are deleted. An organization owner
// is never deleted through SCIM.
func (s *EntStore) DeleteUser(ctx context.Context, id string) error {
	sc, err := scopeOf(ctx)
	if err != nil {
		return err
	}
	uid, err := uuid.Parse(id)
	if err != nil {
		return scim.ErrNotFound("invalid user ID")
	}

	where := append(scimHuman(), principal.IDEQ(uid))
	if !sc.Platform {
		where = append(where, memberOf(sc.OrganizationID))
	}
	exists, err := s.client.Principal.Query().Where(where...).Exist(ctx)
	if err != nil {
		return asSCIMError(ctx, err)
	}
	if !exists {
		return scim.ErrNotFound("user not found")
	}
	if !sc.Platform {
		owned, err := ownedBy(ctx, s.client, uid, sc.OrganizationID)
		if err != nil {
			return asSCIMError(ctx, err)
		}
		if !owned {
			return s.removeMember(ctx, sc.OrganizationID, uid)
		}
	}

	memberships, err := s.client.PrincipalMembership.Query().
		Where(principalmembership.PrincipalIDEQ(uid)).
		All(ctx)
	if err != nil {
		return asSCIMError(ctx, err)
	}
	for _, m := range memberships {
		if m.Role == orgsvc.RoleOwner {
			return errOwnerDeprovision()
		}
	}
	for _, m := range memberships {
		if err := s.removeMember(ctx, m.OrganizationID, uid); err != nil {
			return err
		}
	}
	if err := s.config.Principals.Deactivate(ctx, uid); err != nil {
		return asSCIMError(ctx, err)
	}

	err = s.withTx(ctx, func(tx *ent.Tx) error {
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
		return asSCIMError(ctx, err)
	}
	return nil
}

// Memberships
//
// SCIM changes memberships only through Config.Memberships, so they carry
// the same side effects as any other membership change. Two rules apply
// on top: an organization owner is never suspended or removed through
// SCIM, so an identity provider cannot lock a customer out of its own
// organization; and a restored membership gets the default role rather
// than the role it had before, since the identity provider does not manage
// roles.

// errOwnerDeprovision refuses to suspend or remove an organization owner.
func errOwnerDeprovision() error {
	return scim.ErrForbidden("an organization owner cannot be deprovisioned through SCIM; transfer ownership first")
}

// membership returns principal id's membership in orgID, or nil.
func (s *EntStore) membership(ctx context.Context, orgID, id uuid.UUID) (*ent.PrincipalMembership, error) {
	m, err := s.client.PrincipalMembership.Query().
		Where(principalmembership.PrincipalIDEQ(id), principalmembership.OrganizationIDEQ(orgID)).
		Only(ctx)
	if ent.IsNotFound(err) {
		return nil, nil
	}
	return m, err
}

// addMember makes principal id an active member of orgID: a new membership
// with the default role, or a restored one (see setMemberActive).
func (s *EntStore) addMember(ctx context.Context, orgID, id uuid.UUID) error {
	m, err := s.membership(ctx, orgID, id)
	if err != nil {
		return asSCIMError(ctx, err)
	}
	if m != nil {
		return s.setMemberActive(ctx, orgID, id, true)
	}
	_, err = s.config.Memberships.AddMember(ctx, orgsvc.AddMemberInput{
		OrganizationID: orgID,
		PrincipalID:    id,
		Role:           s.config.DefaultRole,
	})
	return membershipError(ctx, err)
}

// setMemberActive suspends or restores principal id's membership in orgID.
// A restored membership gets the default role.
func (s *EntStore) setMemberActive(ctx context.Context, orgID, id uuid.UUID, active bool) error {
	m, err := s.membership(ctx, orgID, id)
	if err != nil {
		return asSCIMError(ctx, err)
	}
	if m == nil {
		return scim.ErrNotFound("user not found")
	}
	if m.Active == active {
		return nil
	}
	in := orgsvc.UpdateMemberInput{Active: &active}
	if active {
		role := s.config.DefaultRole
		in.Role = &role
	} else if m.Role == orgsvc.RoleOwner {
		return errOwnerDeprovision()
	}
	_, err = s.config.Memberships.UpdateMember(ctx, m.ID, in)
	return membershipError(ctx, err)
}

// removeMember removes principal id from orgID; removing a non-member is a
// no-op.
func (s *EntStore) removeMember(ctx context.Context, orgID, id uuid.UUID) error {
	m, err := s.membership(ctx, orgID, id)
	if err != nil {
		return asSCIMError(ctx, err)
	}
	if m == nil {
		return nil
	}
	if m.Role == orgsvc.RoleOwner {
		return errOwnerDeprovision()
	}
	err = s.config.Memberships.RemoveMember(ctx, orgID, id)
	if errors.Is(err, orgsvc.ErrMembershipNotFound) {
		return nil
	}
	return membershipError(ctx, err)
}

// membershipError maps a membership service error to a SCIM error.
func membershipError(ctx context.Context, err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, orgsvc.ErrPersonalOrganization):
		return scim.ErrInvalidValue("a personal organization cannot have members")
	default:
		return asSCIMError(ctx, err)
	}
}

// Group Operations

// tenantGroup reports whether a tenant may address group gid: only its own
// organization. A platform scope may address any group.
func tenantGroup(sc scim.Scope, gid uuid.UUID) bool {
	return sc.Platform || gid == sc.OrganizationID
}

// orgQuery returns a query over the organizations visible in scope. A
// deleted (inactive) organization is not a group.
func (s *EntStore) orgQuery(sc scim.Scope) *ent.OrganizationQuery {
	q := s.client.Organization.Query().Where(organization.Active(true))
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
		return nil, internalError(ctx, err)
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
		return nil, 0, internalError(ctx, err)
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
		return nil, 0, internalError(ctx, err)
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
// The organization is created through the organization service, so its
// slug obeys the same rules as any other: a valid format, not reserved, not
// taken and not in another organization's cooling-off period.
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

	// The slug is the group's externalId when one is given, held to the
	// organization slug rules; otherwise it is generated from displayName.
	slug := scimGroup.ExternalID
	if slug == "" {
		generated, err := s.config.Organizations.GenerateSlug(ctx, scimGroup.DisplayName)
		if err != nil {
			return nil, internalError(ctx, err)
		}
		slug = generated
	}
	if !orgsvc.IsValidSlug(slug) {
		if scimGroup.ExternalID == "" {
			return nil, scim.ErrInvalidValue("displayName does not yield a valid organization slug; supply externalId")
		}
		return nil, scim.ErrInvalidValue("externalId is not a valid organization slug: 3 to 63 lowercase letters, digits and hyphens, starting with a letter")
	}

	org, err := s.config.Organizations.Create(ctx, orgsvc.CreateOrganizationInput{
		Name:    scimGroup.DisplayName,
		Slug:    slug,
		OrgType: orgsvc.OrgTypeTeam,
	})
	if err != nil {
		return nil, groupError(ctx, err)
	}
	return s.GetGroupByID(ctx, org.ID.String())
}

// groupError maps an organization service error on a group write to a SCIM
// error.
func groupError(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, orgsvc.ErrSlugReserved):
		return scim.ErrInvalidValue("group slug is reserved")
	case errors.Is(err, orgsvc.ErrSlugTaken), errors.Is(err, orgsvc.ErrSlugCoolingOff):
		return scim.ErrConflict("group slug is not available")
	case errors.Is(err, orgsvc.ErrPersonalOrganization):
		return errPersonalGroup()
	}
	return internalError(ctx, err)
}

// errPersonalGroup is returned when a platform credential tries to rename or
// delete a personal organization, which belongs to its owner.
func errPersonalGroup() error {
	return scim.ErrForbidden("a personal organization belongs to its owner and cannot be renamed or deleted through SCIM")
}

// platformGroup returns the active, non-personal organization gid for a
// platform-scoped rename or delete.
func (s *EntStore) platformGroup(ctx context.Context, sc scim.Scope, gid uuid.UUID) (*ent.Organization, error) {
	org, err := s.orgQuery(sc).Where(organization.IDEQ(gid)).Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, scim.ErrNotFound("group not found")
		}
		return nil, internalError(ctx, err)
	}
	if org.OrgType == organization.OrgTypePersonal {
		return nil, errPersonalGroup()
	}
	return org, nil
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

	org, err := s.platformGroup(ctx, sc, gid)
	if err != nil {
		return nil, err
	}
	if scimGroup.DisplayName == "" || scimGroup.DisplayName == org.Name {
		return s.entOrgToSCIM(org), nil
	}
	name := scimGroup.DisplayName
	if _, err := s.config.Organizations.Update(ctx, gid, orgsvc.UpdateOrganizationInput{Name: &name}); err != nil {
		return nil, groupError(ctx, err)
	}
	return s.GetGroupByID(ctx, id)
}

// DeleteGroup deletes a group. Only a platform scope may delete groups, and
// never a personal organization. The organization is soft-deleted through
// the organization service, as an administrator's delete is.
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

	if _, err := s.platformGroup(ctx, sc, gid); err != nil {
		return err
	}
	// The organization service soft-deletes the organization and removes it
	// from the authorization graph; its memberships, roles and history stay.
	if err := s.config.Organizations.Delete(ctx, gid); err != nil {
		return groupError(ctx, err)
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
		return nil, internalError(ctx, err)
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
		return nil, internalError(ctx, err)
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
// no-op; re-adding a deactivated member restores the membership with the
// default role. A tenant may add only users it already sees: members of
// its organization, active or not.
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
		return internalError(ctx, err)
	}
	if !known {
		return scim.ErrNotFound("user not found")
	}

	return s.addMember(ctx, gid, uid)
}

// RemoveMemberFromGroup removes a user from a group. An organization owner
// cannot be removed through SCIM.
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

	return s.removeMember(ctx, gid, uid)
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

// Ensure EntStore implements scim.Store
var _ scim.Store = (*EntStore)(nil)
