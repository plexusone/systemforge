// Package store provides SCIM Store implementations.
package store

import (
	"context"
	"strings"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/membership"
	"github.com/plexusone/systemforge/identity/ent/organization"
	"github.com/plexusone/systemforge/identity/ent/predicate"
	"github.com/plexusone/systemforge/identity/ent/user"
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

// GetUserByID retrieves a user by SCIM ID.
func (s *EntStore) GetUserByID(ctx context.Context, id string) (*scim.User, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, scim.ErrNotFound("invalid user ID")
	}

	u, err := s.client.User.Get(ctx, uid)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, scim.ErrNotFound("user not found")
		}
		return nil, scim.ErrInternal(err.Error())
	}

	return s.entUserToSCIM(u), nil
}

// GetUserByUserName retrieves a user by userName (email).
func (s *EntStore) GetUserByUserName(ctx context.Context, userName string) (*scim.User, error) {
	u, err := s.client.User.Query().
		Where(user.EmailEQ(userName)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, scim.ErrNotFound("user not found")
		}
		return nil, scim.ErrInternal(err.Error())
	}

	return s.entUserToSCIM(u), nil
}

// GetUserByExternalID retrieves a user by externalId.
// Since SystemForge doesn't have an externalId field, we return not found.
func (s *EntStore) GetUserByExternalID(ctx context.Context, externalID string) (*scim.User, error) {
	// SystemForge doesn't store externalId - could be added as metadata
	return nil, scim.ErrNotFound("user not found")
}

// ListUsers lists users with filtering and pagination.
//
//nolint:dupl // Mirrors ListGroups - same query pattern for different entity types
func (s *EntStore) ListUsers(ctx context.Context, opts scim.ListOptions) ([]*scim.User, int, error) {
	query := s.client.User.Query()

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

	users, err := query.All(ctx)
	if err != nil {
		return nil, 0, scim.ErrInternal(err.Error())
	}

	result := make([]*scim.User, len(users))
	for i, u := range users {
		result[i] = s.entUserToSCIM(u)
	}

	return result, total, nil
}

// CreateUser creates a new user.
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

	// Check for existing user
	exists, err := s.client.User.Query().Where(user.EmailEQ(email)).Exist(ctx)
	if err != nil {
		return nil, scim.ErrInternal(err.Error())
	}
	if exists {
		return nil, scim.ErrConflict("user with this email already exists")
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

	// Create user
	create := s.client.User.Create().
		SetEmail(email).
		SetName(name).
		SetActive(active)

	// Set optional fields
	for _, photo := range scimUser.Photos {
		if photo.Primary || photo.Type == "photo" {
			create = create.SetAvatarURL(photo.Value)
			break
		}
	}

	u, err := create.Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, scim.ErrConflict("user already exists")
		}
		return nil, scim.ErrInternal(err.Error())
	}

	return s.entUserToSCIM(u), nil
}

// UpdateUser updates an existing user.
func (s *EntStore) UpdateUser(ctx context.Context, id string, scimUser *scim.User) (*scim.User, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, scim.ErrNotFound("invalid user ID")
	}

	update := s.client.User.UpdateOneID(uid)

	// Update fields if provided
	if scimUser.UserName != "" {
		update = update.SetEmail(scimUser.UserName)
	}
	if scimUser.DisplayName != "" {
		update = update.SetName(scimUser.DisplayName)
	} else if scimUser.Name != nil && scimUser.Name.Formatted != "" {
		update = update.SetName(scimUser.Name.Formatted)
	}
	if scimUser.Active != nil {
		update = update.SetActive(*scimUser.Active)
	}

	// Update avatar from photos
	for _, photo := range scimUser.Photos {
		if photo.Primary || photo.Type == "photo" {
			update = update.SetAvatarURL(photo.Value)
			break
		}
	}

	u, err := update.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, scim.ErrNotFound("user not found")
		}
		if ent.IsConstraintError(err) {
			return nil, scim.ErrConflict("email already in use")
		}
		return nil, scim.ErrInternal(err.Error())
	}

	return s.entUserToSCIM(u), nil
}

// DeleteUser deletes a user.
func (s *EntStore) DeleteUser(ctx context.Context, id string) error {
	uid, err := uuid.Parse(id)
	if err != nil {
		return scim.ErrNotFound("invalid user ID")
	}

	err = s.client.User.DeleteOneID(uid).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return scim.ErrNotFound("user not found")
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

	memberships, err := s.client.Membership.Query().
		Where(membership.UserIDEQ(uid)).
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

// GetMembersForGroup returns all members of a group.
//
//nolint:dupl // Mirrors GetGroupsForUser - intentional symmetry for membership queries
func (s *EntStore) GetMembersForGroup(ctx context.Context, groupID string) ([]scim.MemberRef, error) {
	gid, err := uuid.Parse(groupID)
	if err != nil {
		return nil, scim.ErrNotFound("invalid group ID")
	}

	memberships, err := s.client.Membership.Query().
		Where(membership.OrganizationIDEQ(gid)).
		WithUser().
		All(ctx)
	if err != nil {
		return nil, scim.ErrInternal(err.Error())
	}

	members := make([]scim.MemberRef, 0, len(memberships))
	for _, m := range memberships {
		if m.Edges.User != nil {
			members = append(members, scim.MemberRef{
				Value:   m.UserID.String(),
				Ref:     s.config.BaseURL + "/Users/" + m.UserID.String(),
				Display: m.Edges.User.Name,
				Type:    "User",
			})
		}
	}

	return members, nil
}

// AddMemberToGroup adds a user to a group.
func (s *EntStore) AddMemberToGroup(ctx context.Context, groupID, userID string) error {
	gid, err := uuid.Parse(groupID)
	if err != nil {
		return scim.ErrNotFound("invalid group ID")
	}
	uid, err := uuid.Parse(userID)
	if err != nil {
		return scim.ErrNotFound("invalid user ID")
	}

	// Check if membership already exists
	exists, err := s.client.Membership.Query().
		Where(
			membership.UserIDEQ(uid),
			membership.OrganizationIDEQ(gid),
		).
		Exist(ctx)
	if err != nil {
		return scim.ErrInternal(err.Error())
	}
	if exists {
		return nil // Already a member, no-op
	}

	// Create membership
	_, err = s.client.Membership.Create().
		SetUserID(uid).
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

	_, err = s.client.Membership.Delete().
		Where(
			membership.UserIDEQ(uid),
			membership.OrganizationIDEQ(gid),
		).
		Exec(ctx)
	if err != nil {
		return scim.ErrInternal(err.Error())
	}

	return nil
}

// Helper methods

// entUserToSCIM converts an Ent User to a SCIM User.
func (s *EntStore) entUserToSCIM(u *ent.User) *scim.User {
	active := u.Active
	scimUser := &scim.User{
		Resource: scim.Resource{
			Schemas: []string{scim.SchemaUser},
			ID:      u.ID.String(),
			Meta: &scim.Meta{
				ResourceType: scim.ResourceTypeUser,
				Created:      &u.CreatedAt,
				LastModified: &u.UpdatedAt,
				Location:     s.config.BaseURL + "/Users/" + u.ID.String(),
				Version:      u.UpdatedAt.Format("20060102150405"),
			},
		},
		UserName:    u.Email,
		DisplayName: u.Name,
		Active:      &active,
		Name: &scim.Name{
			Formatted: u.Name,
		},
		Emails: []scim.MultiValue{
			{
				Value:   u.Email,
				Type:    "work",
				Primary: true,
			},
		},
	}

	if u.AvatarURL != nil && *u.AvatarURL != "" {
		scimUser.Photos = []scim.MultiValue{
			{
				Value:   *u.AvatarURL,
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
func (s *EntStore) buildUserPredicates(filterExpr string) ([]predicate.User, error) {
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
func (s *EntStore) collectUserPredicates(node filter.Node) []predicate.User {
	var predicates []predicate.User

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
			predicates = append(predicates, user.Or(append(left, right...)...))
		}
	case *filter.LogicalNotNode:
		inner := s.collectUserPredicates(n.Operand)
		if len(inner) > 0 {
			predicates = append(predicates, user.Not(user.And(inner...)))
		}
	}

	return predicates
}

// userComparisonToPredicate converts a comparison node to a user predicate.
func (s *EntStore) userComparisonToPredicate(node *filter.ComparisonNode) predicate.User {
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
			return user.IDEQ(id)
		case filter.OpNotEqual:
			return user.IDNEQ(id)
		}
	case "username", "emails.value":
		switch node.Operator {
		case filter.OpEqual:
			return user.EmailEQ(value)
		case filter.OpNotEqual:
			return user.EmailNEQ(value)
		case filter.OpContains:
			return user.EmailContains(value)
		case filter.OpStartsWith:
			return user.EmailHasPrefix(value)
		case filter.OpEndsWith:
			return user.EmailHasSuffix(value)
		case filter.OpPresent:
			return user.EmailNEQ("")
		}
	case "displayname", "name.formatted":
		switch node.Operator {
		case filter.OpEqual:
			return user.NameEQ(value)
		case filter.OpNotEqual:
			return user.NameNEQ(value)
		case filter.OpContains:
			return user.NameContains(value)
		case filter.OpStartsWith:
			return user.NameHasPrefix(value)
		case filter.OpEndsWith:
			return user.NameHasSuffix(value)
		case filter.OpPresent:
			return user.NameNEQ("")
		}
	case "active":
		boolValue, ok := node.Value.(bool)
		if ok && node.Operator == filter.OpEqual {
			return user.ActiveEQ(boolValue)
		}
	case "meta.created":
		if t, err := time.Parse(time.RFC3339, value); err == nil {
			switch node.Operator {
			case filter.OpGreaterThan:
				return user.CreatedAtGT(t)
			case filter.OpGreaterThanOrEqual:
				return user.CreatedAtGTE(t)
			case filter.OpLessThan:
				return user.CreatedAtLT(t)
			case filter.OpLessThanOrEqual:
				return user.CreatedAtLTE(t)
			}
		}
	case "meta.lastmodified":
		if t, err := time.Parse(time.RFC3339, value); err == nil {
			switch node.Operator {
			case filter.OpGreaterThan:
				return user.UpdatedAtGT(t)
			case filter.OpGreaterThanOrEqual:
				return user.UpdatedAtGTE(t)
			case filter.OpLessThan:
				return user.UpdatedAtLT(t)
			case filter.OpLessThanOrEqual:
				return user.UpdatedAtLTE(t)
			}
		}
	}

	return nil
}

// applySortUser applies sorting to a user query.
func (s *EntStore) applySortUser(q *ent.UserQuery, sortBy, sortOrder string) *ent.UserQuery {
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
		return q.Order(user.ByEmail(orderOpts...))
	case "displayname", "name.formatted":
		return q.Order(user.ByName(orderOpts...))
	case "meta.created":
		return q.Order(user.ByCreatedAt(orderOpts...))
	case "meta.lastmodified":
		return q.Order(user.ByUpdatedAt(orderOpts...))
	default:
		return q.Order(user.ByCreatedAt(orderOpts...))
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
