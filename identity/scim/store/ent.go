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

// humanQuery returns a query over human principals with the Human edge loaded.
func (s *EntStore) humanQuery() *ent.PrincipalQuery {
	return s.client.Principal.Query().
		Where(principal.TypeEQ(principal.TypeHuman)).
		WithHuman()
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
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, scim.ErrNotFound("invalid user ID")
	}
	return s.onlyUser(ctx, s.humanQuery().Where(principal.IDEQ(uid)))
}

// GetUserByUserName retrieves a user by userName (email). userName is not
// case-exact (RFC 7643 section 4.1.1), so the match ignores case.
func (s *EntStore) GetUserByUserName(ctx context.Context, userName string) (*scim.User, error) {
	return s.onlyUser(ctx, s.humanQuery().Where(principal.HasHumanWith(human.EmailEqualFold(userName))))
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
	query := s.humanQuery()

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

// CreateUser creates a new user as a human principal.
func (s *EntStore) CreateUser(ctx context.Context, scimUser *scim.User) (*scim.User, error) {
	// Extract email from userName or emails
	email := scimUser.UserName
	if email == "" {
		for _, e := range scimUser.Emails {
			if e.Primary || e.Type == "work" {
				email = e.Value
				break
			}
		}
	}
	if email == "" && len(scimUser.Emails) > 0 {
		email = scimUser.Emails[0].Value
	}
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
	err := s.withTx(ctx, func(tx *ent.Tx) error {
		taken, err := emailTaken(ctx, tx, email, uuid.Nil)
		if err != nil {
			return err
		}
		if taken {
			return scim.ErrConflict("user with this email already exists")
		}
		if _, err := tx.Principal.Create().
			SetID(id).
			SetType(principal.TypeHuman).
			SetIdentifier(email).
			SetDisplayName(name).
			SetActive(active).
			Save(ctx); err != nil {
			return err
		}
		hc := tx.Human.Create().
			SetPrincipalID(id).
			SetEmail(email)
		if url, ok := primaryPhoto(scimUser.Photos); ok {
			hc.SetAvatarURL(url)
		}
		_, err = hc.Save(ctx)
		return err
	})
	if err != nil {
		return nil, asSCIMError(err)
	}
	return s.GetUserByID(ctx, id.String())
}

// UpdateUser updates an existing user.
func (s *EntStore) UpdateUser(ctx context.Context, id string, scimUser *scim.User) (*scim.User, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, scim.ErrNotFound("invalid user ID")
	}

	err = s.withTx(ctx, func(tx *ent.Tx) error {
		p, err := tx.Principal.Query().
			Where(principal.IDEQ(uid), principal.TypeEQ(principal.TypeHuman)).
			WithHuman().
			Only(ctx)
		if err != nil {
			if ent.IsNotFound(err) {
				return scim.ErrNotFound("user not found")
			}
			return err
		}
		if p.Edges.Human == nil {
			return scim.ErrInternal("user has no human record")
		}

		pu := tx.Principal.UpdateOne(p)
		hu := tx.Human.UpdateOne(p.Edges.Human)

		// Update fields if provided
		if scimUser.UserName != "" {
			taken, err := emailTaken(ctx, tx, scimUser.UserName, uid)
			if err != nil {
				return err
			}
			if taken {
				return scim.ErrConflict("email already in use")
			}
			pu.SetIdentifier(scimUser.UserName)
			hu.SetEmail(scimUser.UserName)
		}
		if scimUser.DisplayName != "" {
			pu.SetDisplayName(scimUser.DisplayName)
		} else if scimUser.Name != nil && scimUser.Name.Formatted != "" {
			pu.SetDisplayName(scimUser.Name.Formatted)
		}
		if scimUser.Active != nil {
			pu.SetActive(*scimUser.Active)
		}
		if url, ok := primaryPhoto(scimUser.Photos); ok {
			hu.SetAvatarURL(url)
		}

		if _, err := pu.Save(ctx); err != nil {
			return err
		}
		_, err = hu.Save(ctx)
		return err
	})
	if err != nil {
		return nil, asSCIMError(err)
	}
	return s.GetUserByID(ctx, id)
}

// DeleteUser deletes a user together with its group memberships and the
// records that belong only to it.
func (s *EntStore) DeleteUser(ctx context.Context, id string) error {
	uid, err := uuid.Parse(id)
	if err != nil {
		return scim.ErrNotFound("invalid user ID")
	}

	err = s.withTx(ctx, func(tx *ent.Tx) error {
		exists, err := tx.Principal.Query().
			Where(principal.IDEQ(uid), principal.TypeEQ(principal.TypeHuman)).
			Exist(ctx)
		if err != nil {
			return err
		}
		if !exists {
			return scim.ErrNotFound("user not found")
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

// Group Operations

// GetGroupByID retrieves a group by SCIM ID.
func (s *EntStore) GetGroupByID(ctx context.Context, id string) (*scim.Group, error) {
	gid, err := uuid.Parse(id)
	if err != nil {
		return nil, scim.ErrNotFound("invalid group ID")
	}

	org, err := s.client.Organization.Get(ctx, gid)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, scim.ErrNotFound("group not found")
		}
		return nil, scim.ErrInternal(err.Error())
	}

	return s.entOrgToSCIM(org), nil
}

// GetGroupByDisplayName retrieves a group by displayName.
func (s *EntStore) GetGroupByDisplayName(ctx context.Context, displayName string) (*scim.Group, error) {
	org, err := s.client.Organization.Query().
		Where(organization.NameEQ(displayName)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, scim.ErrNotFound("group not found")
		}
		return nil, scim.ErrInternal(err.Error())
	}

	return s.entOrgToSCIM(org), nil
}

// GetGroupByExternalID retrieves a group by externalId.
func (s *EntStore) GetGroupByExternalID(ctx context.Context, externalID string) (*scim.Group, error) {
	// Use slug as externalId
	org, err := s.client.Organization.Query().
		Where(organization.SlugEQ(externalID)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, scim.ErrNotFound("group not found")
		}
		return nil, scim.ErrInternal(err.Error())
	}

	return s.entOrgToSCIM(org), nil
}

// ListGroups lists groups with filtering and pagination.
//
//nolint:dupl // Mirrors ListUsers - same query pattern for different entity types
func (s *EntStore) ListGroups(ctx context.Context, opts scim.ListOptions) ([]*scim.Group, int, error) {
	query := s.client.Organization.Query()

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

// CreateGroup creates a new group.
func (s *EntStore) CreateGroup(ctx context.Context, scimGroup *scim.Group) (*scim.Group, error) {
	if scimGroup.DisplayName == "" {
		return nil, scim.ErrInvalidValue("displayName is required")
	}

	// Generate slug from displayName
	slug := generateSlug(scimGroup.DisplayName)
	if scimGroup.ExternalID != "" {
		slug = scimGroup.ExternalID
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
		SetPlan(organization.PlanFree).
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

// UpdateGroup updates an existing group.
func (s *EntStore) UpdateGroup(ctx context.Context, id string, scimGroup *scim.Group) (*scim.Group, error) {
	gid, err := uuid.Parse(id)
	if err != nil {
		return nil, scim.ErrNotFound("invalid group ID")
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

// DeleteGroup deletes a group.
func (s *EntStore) DeleteGroup(ctx context.Context, id string) error {
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

// GetGroupsForUser returns all groups a user belongs to.
//
//nolint:dupl // Mirrors GetMembersForGroup - intentional symmetry for membership queries
func (s *EntStore) GetGroupsForUser(ctx context.Context, userID string) ([]scim.GroupRef, error) {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return nil, scim.ErrNotFound("invalid user ID")
	}

	memberships, err := s.client.PrincipalMembership.Query().
		Where(
			principalmembership.PrincipalIDEQ(uid),
			principalmembership.ActiveEQ(true),
		).
		WithOrganization().
		All(ctx)
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
	gid, err := uuid.Parse(groupID)
	if err != nil {
		return nil, scim.ErrNotFound("invalid group ID")
	}

	memberships, err := s.client.PrincipalMembership.Query().
		Where(
			principalmembership.OrganizationIDEQ(gid),
			principalmembership.ActiveEQ(true),
			principalmembership.HasPrincipalWith(principal.TypeEQ(principal.TypeHuman)),
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
// no-op; re-adding a deactivated member reactivates the membership.
func (s *EntStore) AddMemberToGroup(ctx context.Context, groupID, userID string) error {
	gid, err := uuid.Parse(groupID)
	if err != nil {
		return scim.ErrNotFound("invalid group ID")
	}
	uid, err := uuid.Parse(userID)
	if err != nil {
		return scim.ErrNotFound("invalid user ID")
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
	gid, err := uuid.Parse(groupID)
	if err != nil {
		return scim.ErrNotFound("invalid group ID")
	}
	uid, err := uuid.Parse(userID)
	if err != nil {
		return scim.ErrNotFound("invalid user ID")
	}

	_, err = s.client.PrincipalMembership.Delete().
		Where(
			principalmembership.PrincipalIDEQ(uid),
			principalmembership.OrganizationIDEQ(gid),
		).
		Exec(ctx)
	if err != nil {
		return scim.ErrInternal(err.Error())
	}

	return nil
}

// Helper methods

// principalToSCIMUser converts a human Principal, loaded with its Human edge,
// to a SCIM User.
func (s *EntStore) principalToSCIMUser(p *ent.Principal) *scim.User {
	active := p.Active
	var email string
	var avatar *string
	if h := p.Edges.Human; h != nil {
		email = h.Email
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
