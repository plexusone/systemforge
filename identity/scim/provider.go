package scim

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/plexusone/systemforge/identity/scim/schema"
)

// Provider is the main entry point for SCIM operations.
// It wraps a Store implementation and provides the Service interface.
type Provider struct {
	config         *Config
	store          Store
	auth           AuthorizationHook
	passwordHasher PasswordHasher
}

// ProviderOption configures a Provider.
type ProviderOption func(*Provider)

// WithAuthorizationHook sets a custom authorization hook.
func WithAuthorizationHook(hook AuthorizationHook) ProviderOption {
	return func(p *Provider) {
		p.auth = hook
	}
}

// WithPasswordHasher sets a custom password hasher.
func WithPasswordHasher(hasher PasswordHasher) ProviderOption {
	return func(p *Provider) {
		p.passwordHasher = hasher
	}
}

// NewProvider creates a new SCIM provider.
func NewProvider(config *Config, store Store, opts ...ProviderOption) (*Provider, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	p := &Provider{
		config:         config,
		store:          store,
		auth:           DenyAllAuthorizationHook{},
		passwordHasher: DefaultPasswordHasher(),
	}

	for _, opt := range opts {
		opt(p)
	}

	return p, nil
}

// PasswordHasher returns the configured password hasher.
func (p *Provider) PasswordHasher() PasswordHasher {
	return p.passwordHasher
}

// Config returns the SCIM configuration.
func (p *Provider) Config() *Config {
	return p.config
}

// Service returns the SCIM service interface.
func (p *Provider) Service() Service {
	return &providerService{p: p}
}

// ServiceProviderConfig returns the SCIM service provider configuration.
func (p *Provider) ServiceProviderConfig() schema.ServiceProviderConfig {
	authSchemes := make([]schema.AuthenticationScheme, len(p.config.AuthenticationSchemes))
	for i, s := range p.config.AuthenticationSchemes {
		authSchemes[i] = schema.AuthenticationScheme{
			Type:             s.Type,
			Name:             s.Name,
			Description:      s.Description,
			SpecURI:          s.SpecURI,
			DocumentationURI: s.DocumentationURI,
			Primary:          s.Primary,
		}
	}

	return schema.ServiceProviderConfig{
		Schemas:          []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		DocumentationURI: p.config.DocumentationURI,
		Patch: schema.SupportedFeature{
			Supported: p.config.SupportPatch,
		},
		Bulk: schema.BulkConfig{
			Supported:      p.config.SupportBulk,
			MaxOperations:  p.config.BulkMaxOperations,
			MaxPayloadSize: p.config.BulkMaxPayloadSize,
		},
		Filter: schema.FilterConfig{
			Supported:  p.config.SupportFiltering,
			MaxResults: p.config.MaxResults,
		},
		ChangePassword: schema.SupportedFeature{
			Supported: p.config.SupportChangePassword,
		},
		Sort: schema.SupportedFeature{
			Supported: p.config.SupportSorting,
		},
		Etag: schema.SupportedFeature{
			Supported: p.config.SupportETag,
		},
		AuthenticationSchemes: authSchemes,
		Meta: &schema.SPConfigMeta{
			ResourceType: "ServiceProviderConfig",
			Location:     p.config.BaseURL + "/ServiceProviderConfig",
		},
	}
}

// Schemas returns all supported SCIM schemas.
func (p *Provider) Schemas() []schema.Schema {
	schemas := []schema.Schema{
		schema.UserSchema(),
		schema.GroupSchema(),
		schema.EnterpriseUserSchema(),
	}

	// Set locations
	for i := range schemas {
		if schemas[i].Meta != nil {
			schemas[i].Meta.Location = p.config.BaseURL + "/Schemas/" + schemas[i].ID
		}
	}

	return schemas
}

// ResourceTypes returns all supported resource types.
func (p *Provider) ResourceTypes() []schema.ResourceType {
	return []schema.ResourceType{
		schema.UserResourceType(p.config.BaseURL),
		schema.GroupResourceType(p.config.BaseURL),
	}
}

// providerService implements the Service interface using a Provider.
type providerService struct {
	p *Provider
}

// GetUser retrieves a user by ID.
func (s *providerService) GetUser(ctx context.Context, id string) (*User, error) {
	if err := s.p.auth.CanRead(ctx, ResourceTypeUser, id); err != nil {
		return nil, err
	}

	user, err := s.p.store.GetUserByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Populate groups
	groups, err := s.p.store.GetGroupsForUser(ctx, id)
	if err != nil {
		return nil, err
	}
	user.Groups = groups

	// Set metadata
	s.populateUserMeta(user)

	return user, nil
}

// ListUsers lists users with optional filtering and pagination.
//
//nolint:dupl // Mirrors ListGroups - same pagination/filtering logic for different resource types
func (s *providerService) ListUsers(ctx context.Context, opts ListOptions) (*ListResponse, error) {
	if err := s.p.auth.CanRead(ctx, ResourceTypeUser, ""); err != nil {
		return nil, err
	}
	// Apply config limits
	if opts.Count > s.p.config.MaxResults {
		opts.Count = s.p.config.MaxResults
	}
	if opts.Count == 0 {
		opts.Count = s.p.config.DefaultPageSize
	}

	users, total, err := s.p.store.ListUsers(ctx, opts)
	if err != nil {
		return nil, err
	}

	// Convert to interface slice and populate metadata
	resources := make([]any, len(users))
	for i, user := range users {
		// Populate groups for each user
		groups, err := s.p.store.GetGroupsForUser(ctx, user.ID)
		if err != nil {
			return nil, err
		}
		user.Groups = groups
		s.populateUserMeta(user)
		resources[i] = user
	}

	return NewListResponse(resources, total, opts.StartIndex, len(users)), nil
}

// CreateUser creates a new user.
func (s *providerService) CreateUser(ctx context.Context, user *User) (*User, error) {
	if err := s.p.auth.CanCreate(ctx, ResourceTypeUser); err != nil {
		return nil, err
	}

	// Validate required fields
	if user.UserName == "" {
		return nil, ErrInvalidValue("userName is required")
	}

	// Hash password if provided
	if err := s.hashPassword(user); err != nil {
		return nil, err
	}

	// Set schemas if not present
	if len(user.Schemas) == 0 {
		user.Schemas = []string{SchemaUser}
		if user.EnterpriseUser != nil {
			user.Schemas = append(user.Schemas, SchemaEnterpriseUser)
		}
	}

	created, err := s.p.store.CreateUser(ctx, user)
	if err != nil {
		return nil, err
	}

	// Clear password from response (never return password hashes)
	created.Password = ""

	s.populateUserMeta(created)
	return created, nil
}

// hashPassword replaces a password supplied in a write with its hash, so a
// store never receives a plaintext password.
func (s *providerService) hashPassword(user *User) error {
	if user.Password == "" {
		return nil
	}
	hashed, err := s.p.passwordHasher.Hash(user.Password)
	if err != nil {
		return ErrInternal("failed to hash password: " + err.Error())
	}
	user.Password = hashed
	return nil
}

// UpdateUser replaces a user (PUT semantics).
func (s *providerService) UpdateUser(ctx context.Context, id string, user *User, etag string) (*User, error) {
	if err := s.p.auth.CanUpdate(ctx, ResourceTypeUser, id); err != nil {
		return nil, err
	}

	// Check ETag if provided and supported
	if etag != "" && s.p.config.SupportETag {
		existing, err := s.p.store.GetUserByID(ctx, id)
		if err != nil {
			return nil, err
		}
		if existing.Meta != nil && existing.Meta.Version != "" {
			if ParseETag(etag) != existing.Meta.Version {
				return nil, ErrPreconditionFailed("ETag mismatch")
			}
		}
	}

	user.ID = id
	// A password in the replacement is hashed before the store sees it,
	// as on create.
	if err := s.hashPassword(user); err != nil {
		return nil, err
	}
	updated, err := s.p.store.UpdateUser(ctx, id, user)
	if err != nil {
		return nil, err
	}

	// Populate groups
	groups, err := s.p.store.GetGroupsForUser(ctx, id)
	if err != nil {
		return nil, err
	}
	updated.Groups = groups

	s.populateUserMeta(updated)
	return updated, nil
}

// PatchUser applies partial modifications to a user.
func (s *providerService) PatchUser(ctx context.Context, id string, patch *PatchRequest, etag string) (*User, error) {
	if err := s.p.auth.CanUpdate(ctx, ResourceTypeUser, id); err != nil {
		return nil, err
	}

	if !s.p.config.SupportPatch {
		return nil, ErrNotImplemented("PATCH is not supported")
	}

	// Get existing user
	existing, err := s.p.store.GetUserByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Check ETag if provided
	if etag != "" && s.p.config.SupportETag {
		if existing.Meta != nil && existing.Meta.Version != "" {
			if ParseETag(etag) != existing.Meta.Version {
				return nil, ErrPreconditionFailed("ETag mismatch")
			}
		}
	}

	// Apply patch operations. The patch is applied to existing in place,
	// so the stored password is set aside first: a password present after
	// the patch came from the request and is hashed; otherwise the stored
	// value is passed back unchanged.
	stored := existing.Password
	existing.Password = ""
	patched, err := applyUserPatch(existing, patch.Operations)
	if err != nil {
		return nil, err
	}
	if patched.Password != "" {
		if err := s.hashPassword(patched); err != nil {
			return nil, err
		}
	} else {
		patched.Password = stored
	}

	// Update in store
	updated, err := s.p.store.UpdateUser(ctx, id, patched)
	if err != nil {
		return nil, err
	}

	// Clear password from response
	updated.Password = ""

	// Populate groups
	groups, err := s.p.store.GetGroupsForUser(ctx, id)
	if err != nil {
		return nil, err
	}
	updated.Groups = groups

	s.populateUserMeta(updated)
	return updated, nil
}

// DeleteUser removes a user.
func (s *providerService) DeleteUser(ctx context.Context, id string) error {
	if err := s.p.auth.CanDelete(ctx, ResourceTypeUser, id); err != nil {
		return err
	}
	return s.p.store.DeleteUser(ctx, id)
}

// GetGroup retrieves a group by ID.
func (s *providerService) GetGroup(ctx context.Context, id string) (*Group, error) {
	if err := s.p.auth.CanRead(ctx, ResourceTypeGroup, id); err != nil {
		return nil, err
	}

	group, err := s.p.store.GetGroupByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Populate members
	members, err := s.p.store.GetMembersForGroup(ctx, id)
	if err != nil {
		return nil, err
	}
	group.Members = members

	s.populateGroupMeta(group)
	return group, nil
}

// ListGroups lists groups with optional filtering and pagination.
//
//nolint:dupl // Mirrors ListUsers - same pagination/filtering logic for different resource types
func (s *providerService) ListGroups(ctx context.Context, opts ListOptions) (*ListResponse, error) {
	if err := s.p.auth.CanRead(ctx, ResourceTypeGroup, ""); err != nil {
		return nil, err
	}
	// Apply config limits
	if opts.Count > s.p.config.MaxResults {
		opts.Count = s.p.config.MaxResults
	}
	if opts.Count == 0 {
		opts.Count = s.p.config.DefaultPageSize
	}

	groups, total, err := s.p.store.ListGroups(ctx, opts)
	if err != nil {
		return nil, err
	}

	// Convert to interface slice and populate metadata
	resources := make([]any, len(groups))
	for i, group := range groups {
		// Populate members for each group
		members, err := s.p.store.GetMembersForGroup(ctx, group.ID)
		if err != nil {
			return nil, err
		}
		group.Members = members
		s.populateGroupMeta(group)
		resources[i] = group
	}

	return NewListResponse(resources, total, opts.StartIndex, len(groups)), nil
}

// CreateGroup creates a new group.
func (s *providerService) CreateGroup(ctx context.Context, group *Group) (*Group, error) {
	if err := s.p.auth.CanCreate(ctx, ResourceTypeGroup); err != nil {
		return nil, err
	}

	// Validate required fields
	if group.DisplayName == "" {
		return nil, ErrInvalidValue("displayName is required")
	}

	// Set schemas if not present
	if len(group.Schemas) == 0 {
		group.Schemas = []string{SchemaGroup}
	}

	created, err := s.p.store.CreateGroup(ctx, group)
	if err != nil {
		return nil, err
	}

	// Add members if specified
	for _, member := range group.Members {
		if member.Value != "" {
			if err := s.p.store.AddMemberToGroup(ctx, created.ID, member.Value); err != nil {
				return nil, err
			}
		}
	}

	// Re-fetch members to get populated data
	members, err := s.p.store.GetMembersForGroup(ctx, created.ID)
	if err != nil {
		return nil, err
	}
	created.Members = members

	s.populateGroupMeta(created)
	return created, nil
}

// UpdateGroup replaces a group (PUT semantics).
func (s *providerService) UpdateGroup(ctx context.Context, id string, group *Group, etag string) (*Group, error) {
	if err := s.p.auth.CanUpdate(ctx, ResourceTypeGroup, id); err != nil {
		return nil, err
	}

	// Check ETag if provided and supported
	if etag != "" && s.p.config.SupportETag {
		existing, err := s.p.store.GetGroupByID(ctx, id)
		if err != nil {
			return nil, err
		}
		if existing.Meta != nil && existing.Meta.Version != "" {
			if ParseETag(etag) != existing.Meta.Version {
				return nil, ErrPreconditionFailed("ETag mismatch")
			}
		}
	}

	group.ID = id
	updated, err := s.p.store.UpdateGroup(ctx, id, group)
	if err != nil {
		return nil, err
	}

	// Sync members: get current members, compute diff
	currentMembers, err := s.p.store.GetMembersForGroup(ctx, id)
	if err != nil {
		return nil, err
	}

	currentMemberIDs := make(map[string]bool)
	for _, m := range currentMembers {
		currentMemberIDs[m.Value] = true
	}

	newMemberIDs := make(map[string]bool)
	for _, m := range group.Members {
		if m.Value != "" {
			newMemberIDs[m.Value] = true
		}
	}

	// Remove members not in new list
	for _, m := range currentMembers {
		if !newMemberIDs[m.Value] {
			if err := s.p.store.RemoveMemberFromGroup(ctx, id, m.Value); err != nil {
				return nil, err
			}
		}
	}

	// Add new members
	for _, m := range group.Members {
		if m.Value != "" && !currentMemberIDs[m.Value] {
			if err := s.p.store.AddMemberToGroup(ctx, id, m.Value); err != nil {
				return nil, err
			}
		}
	}

	// Re-fetch members
	members, err := s.p.store.GetMembersForGroup(ctx, id)
	if err != nil {
		return nil, err
	}
	updated.Members = members

	s.populateGroupMeta(updated)
	return updated, nil
}

// PatchGroup applies partial modifications to a group.
func (s *providerService) PatchGroup(ctx context.Context, id string, patch *PatchRequest, etag string) (*Group, error) {
	if err := s.p.auth.CanUpdate(ctx, ResourceTypeGroup, id); err != nil {
		return nil, err
	}

	if !s.p.config.SupportPatch {
		return nil, ErrNotImplemented("PATCH is not supported")
	}

	// Get existing group
	existing, err := s.p.store.GetGroupByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Populate current members
	members, err := s.p.store.GetMembersForGroup(ctx, id)
	if err != nil {
		return nil, err
	}
	existing.Members = members

	// Check ETag if provided
	if etag != "" && s.p.config.SupportETag {
		if existing.Meta != nil && existing.Meta.Version != "" {
			if ParseETag(etag) != existing.Meta.Version {
				return nil, ErrPreconditionFailed("ETag mismatch")
			}
		}
	}

	// Apply patch operations
	patched, memberOps, err := applyGroupPatch(existing, patch.Operations)
	if err != nil {
		return nil, err
	}

	// Update group in store
	updated, err := s.p.store.UpdateGroup(ctx, id, patched)
	if err != nil {
		return nil, err
	}

	// Apply member operations
	for _, op := range memberOps {
		switch op.Op {
		case "add":
			if err := s.p.store.AddMemberToGroup(ctx, id, op.Value); err != nil {
				return nil, err
			}
		case "remove":
			if err := s.p.store.RemoveMemberFromGroup(ctx, id, op.Value); err != nil {
				return nil, err
			}
		}
	}

	// Re-fetch members
	updatedMembers, err := s.p.store.GetMembersForGroup(ctx, id)
	if err != nil {
		return nil, err
	}
	updated.Members = updatedMembers

	s.populateGroupMeta(updated)
	return updated, nil
}

// DeleteGroup removes a group.
func (s *providerService) DeleteGroup(ctx context.Context, id string) error {
	if err := s.p.auth.CanDelete(ctx, ResourceTypeGroup, id); err != nil {
		return err
	}
	return s.p.store.DeleteGroup(ctx, id)
}

// ProcessBulk processes a bulk request.
func (s *providerService) ProcessBulk(ctx context.Context, req *BulkRequest) (*BulkResponse, error) {
	if !s.p.config.SupportBulk {
		return nil, ErrNotImplemented("Bulk operations are not supported")
	}

	if len(req.Operations) > s.p.config.BulkMaxOperations {
		return nil, ErrTooMany(fmt.Sprintf("bulk request exceeds maximum of %d operations", s.p.config.BulkMaxOperations))
	}

	response := &BulkResponse{
		Schemas:    []string{SchemaBulkResponse},
		Operations: make([]BulkResponseOperation, 0, len(req.Operations)),
	}

	// Track bulkId → resourceID mappings for cross-references
	bulkIdMap := make(map[string]string)

	failCount := 0
	for _, op := range req.Operations {
		// Resolve bulkId references in the operation data
		op = s.resolveBulkIdReferences(op, bulkIdMap)

		result := s.processBulkOperation(ctx, op)
		response.Operations = append(response.Operations, result)

		// Track created resource IDs for bulkId resolution
		if result.Status == "201" && op.BulkID != "" {
			// Extract the created resource ID from the response
			if createdID := extractResourceID(result.Response); createdID != "" {
				bulkIdMap[op.BulkID] = createdID
			}
		}

		if result.Status[0] != '2' { // Not a 2xx status
			failCount++
			if req.FailOnErrors > 0 && failCount >= req.FailOnErrors {
				break
			}
		}
	}

	return response, nil
}

// resolveBulkIdReferences replaces bulkId:xxx references with actual resource IDs.
func (s *providerService) resolveBulkIdReferences(op BulkOperation, bulkIdMap map[string]string) BulkOperation {
	// Resolve references in the path (e.g., /Groups/bulkId:group1)
	if strings.Contains(op.Path, "bulkId:") {
		for bulkId, resourceID := range bulkIdMap {
			op.Path = strings.ReplaceAll(op.Path, "bulkId:"+bulkId, resourceID)
		}
	}

	// Resolve references in the data
	if op.Data != nil {
		op.Data = s.resolveBulkIdInData(op.Data, bulkIdMap)
	}

	return op
}

// resolveBulkIdInData recursively resolves bulkId references in operation data.
func (s *providerService) resolveBulkIdInData(data any, bulkIdMap map[string]string) any {
	switch v := data.(type) {
	case map[string]any:
		result := make(map[string]any)
		for key, val := range v {
			result[key] = s.resolveBulkIdInData(val, bulkIdMap)
		}
		return result
	case []any:
		result := make([]any, len(v))
		for i, item := range v {
			result[i] = s.resolveBulkIdInData(item, bulkIdMap)
		}
		return result
	case string:
		// Check if this is a bulkId reference
		if strings.HasPrefix(v, "bulkId:") {
			bulkId := strings.TrimPrefix(v, "bulkId:")
			if resourceID, ok := bulkIdMap[bulkId]; ok {
				return resourceID
			}
		}
		return v
	default:
		return data
	}
}

// extractResourceID extracts the resource ID from a created resource response.
func extractResourceID(response any) string {
	switch r := response.(type) {
	case *User:
		return r.ID
	case *Group:
		return r.ID
	case map[string]any:
		if id, ok := r["id"].(string); ok {
			return id
		}
	}
	return ""
}

// processBulkOperation processes a single bulk operation.
func (s *providerService) processBulkOperation(ctx context.Context, op BulkOperation) BulkResponseOperation {
	result := BulkResponseOperation{
		Method: op.Method,
		BulkID: op.BulkID,
	}

	// Parse the path to determine resource type
	path := strings.TrimPrefix(op.Path, "/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) == 0 {
		result.Status = "400"
		result.Response = ErrInvalidPath("invalid path")
		return result
	}

	resourceType := parts[0]
	var resourceID string
	if len(parts) > 1 {
		resourceID = parts[1]
	}

	switch strings.ToUpper(op.Method) {
	case "POST":
		result = s.processBulkCreate(ctx, resourceType, op.Data, result)
	case "PUT":
		result = s.processBulkUpdate(ctx, resourceType, resourceID, op.Data, result)
	case "PATCH":
		result = s.processBulkPatch(ctx, resourceType, resourceID, op.Data, result)
	case "DELETE":
		result = s.processBulkDelete(ctx, resourceType, resourceID, result)
	default:
		result.Status = "400"
		result.Response = ErrInvalidValue("unsupported method: " + op.Method)
	}

	return result
}

func (s *providerService) processBulkCreate(ctx context.Context, resourceType string, data any, result BulkResponseOperation) BulkResponseOperation {
	switch resourceType {
	case "Users":
		user, err := convertToUser(data)
		if err != nil {
			result.Status = "400"
			result.Response = ErrInvalidSyntax("invalid user data: " + err.Error())
			return result
		}
		created, err := s.CreateUser(ctx, user)
		if err != nil {
			result.Status = fmt.Sprintf("%d", ToSCIMError(err).Status)
			result.Response = ToSCIMError(err)
			return result
		}
		result.Status = "201"
		result.Location = s.p.config.UserLocation(created.ID)
		result.Response = created
	case "Groups":
		group, err := convertToGroup(data)
		if err != nil {
			result.Status = "400"
			result.Response = ErrInvalidSyntax("invalid group data: " + err.Error())
			return result
		}
		created, err := s.CreateGroup(ctx, group)
		if err != nil {
			result.Status = fmt.Sprintf("%d", ToSCIMError(err).Status)
			result.Response = ToSCIMError(err)
			return result
		}
		result.Status = "201"
		result.Location = s.p.config.GroupLocation(created.ID)
		result.Response = created
	default:
		result.Status = "400"
		result.Response = ErrInvalidValue("unsupported resource type: " + resourceType)
	}
	return result
}

func (s *providerService) processBulkUpdate(ctx context.Context, resourceType, id string, data any, result BulkResponseOperation) BulkResponseOperation {
	if id == "" {
		result.Status = "400"
		result.Response = ErrInvalidPath("resource ID required for PUT")
		return result
	}

	switch resourceType {
	case "Users":
		user, err := convertToUser(data)
		if err != nil {
			result.Status = "400"
			result.Response = ErrInvalidSyntax("invalid user data: " + err.Error())
			return result
		}
		updated, err := s.UpdateUser(ctx, id, user, "")
		if err != nil {
			result.Status = fmt.Sprintf("%d", ToSCIMError(err).Status)
			result.Response = ToSCIMError(err)
			return result
		}
		result.Status = "200"
		result.Location = s.p.config.UserLocation(id)
		result.Response = updated
	case "Groups":
		group, err := convertToGroup(data)
		if err != nil {
			result.Status = "400"
			result.Response = ErrInvalidSyntax("invalid group data: " + err.Error())
			return result
		}
		updated, err := s.UpdateGroup(ctx, id, group, "")
		if err != nil {
			result.Status = fmt.Sprintf("%d", ToSCIMError(err).Status)
			result.Response = ToSCIMError(err)
			return result
		}
		result.Status = "200"
		result.Location = s.p.config.GroupLocation(id)
		result.Response = updated
	default:
		result.Status = "400"
		result.Response = ErrInvalidValue("unsupported resource type: " + resourceType)
	}
	return result
}

func (s *providerService) processBulkPatch(ctx context.Context, resourceType, id string, data any, result BulkResponseOperation) BulkResponseOperation {
	if id == "" {
		result.Status = "400"
		result.Response = ErrInvalidPath("resource ID required for PATCH")
		return result
	}

	patch, err := convertToPatchRequest(data)
	if err != nil {
		result.Status = "400"
		result.Response = ErrInvalidSyntax("invalid patch data: " + err.Error())
		return result
	}

	switch resourceType {
	case "Users":
		updated, err := s.PatchUser(ctx, id, patch, "")
		if err != nil {
			result.Status = fmt.Sprintf("%d", ToSCIMError(err).Status)
			result.Response = ToSCIMError(err)
			return result
		}
		result.Status = "200"
		result.Location = s.p.config.UserLocation(id)
		result.Response = updated
	case "Groups":
		updated, err := s.PatchGroup(ctx, id, patch, "")
		if err != nil {
			result.Status = fmt.Sprintf("%d", ToSCIMError(err).Status)
			result.Response = ToSCIMError(err)
			return result
		}
		result.Status = "200"
		result.Location = s.p.config.GroupLocation(id)
		result.Response = updated
	default:
		result.Status = "400"
		result.Response = ErrInvalidValue("unsupported resource type: " + resourceType)
	}
	return result
}

func (s *providerService) processBulkDelete(ctx context.Context, resourceType, id string, result BulkResponseOperation) BulkResponseOperation {
	if id == "" {
		result.Status = "400"
		result.Response = ErrInvalidPath("resource ID required for DELETE")
		return result
	}

	switch resourceType {
	case "Users":
		if err := s.DeleteUser(ctx, id); err != nil {
			result.Status = fmt.Sprintf("%d", ToSCIMError(err).Status)
			result.Response = ToSCIMError(err)
			return result
		}
		result.Status = "204"
	case "Groups":
		if err := s.DeleteGroup(ctx, id); err != nil {
			result.Status = fmt.Sprintf("%d", ToSCIMError(err).Status)
			result.Response = ToSCIMError(err)
			return result
		}
		result.Status = "204"
	default:
		result.Status = "400"
		result.Response = ErrInvalidValue("unsupported resource type: " + resourceType)
	}
	return result
}

// GetMe retrieves the current user based on context.
func (s *providerService) GetMe(ctx context.Context) (*User, error) {
	subject := AuthSubjectFromContext(ctx)
	if subject == "" {
		return nil, ErrUnauthorized("no authenticated user")
	}
	return s.GetUser(ctx, subject)
}

// PatchMe applies partial modifications to the current user.
func (s *providerService) PatchMe(ctx context.Context, patch *PatchRequest, etag string) (*User, error) {
	subject := AuthSubjectFromContext(ctx)
	if subject == "" {
		return nil, ErrUnauthorized("no authenticated user")
	}
	return s.PatchUser(ctx, subject, patch, etag)
}

// populateUserMeta sets metadata fields on a user.
//
// It also clears the password: every user the service returns passes
// through here, and a password, or its hash, is never returned.
func (s *providerService) populateUserMeta(user *User) {
	user.Password = ""
	if user.Meta == nil {
		user.Meta = &Meta{}
	}
	user.Meta.ResourceType = ResourceTypeUser
	user.Meta.Location = s.p.config.UserLocation(user.ID)
	if user.Meta.Version == "" && user.Meta.LastModified != nil {
		user.Meta.Version = GenerateETag(user.Meta.LastModified.Format("20060102150405"))
	}
}

// populateGroupMeta sets metadata fields on a group.
func (s *providerService) populateGroupMeta(group *Group) {
	if group.Meta == nil {
		group.Meta = &Meta{}
	}
	group.Meta.ResourceType = ResourceTypeGroup
	group.Meta.Location = s.p.config.GroupLocation(group.ID)
	if group.Meta.Version == "" && group.Meta.LastModified != nil {
		group.Meta.Version = GenerateETag(group.Meta.LastModified.Format("20060102150405"))
	}
}

// memberOp represents a member add/remove operation.
type memberOp struct {
	Op    string
	Value string
}

// applyUserPatch applies PATCH operations to a user.
func applyUserPatch(user *User, ops []PatchOperation) (*User, error) {
	for _, op := range ops {
		if err := applyUserPatchOp(user, op); err != nil {
			return nil, err
		}
	}
	return user, nil
}

// applyUserPatchOp applies a single PATCH operation to a user.
func applyUserPatchOp(user *User, op PatchOperation) error {
	opType := strings.ToLower(op.Op)
	path := strings.ToLower(op.Path)

	switch opType {
	case "add", "replace":
		return applyUserAddReplace(user, path, op.Value)
	case "remove":
		return applyUserRemove(user, path)
	default:
		return ErrInvalidValue("unsupported operation: " + op.Op)
	}
}

func applyUserAddReplace(user *User, path string, value any) error {
	switch path {
	case "", "username":
		if v, ok := value.(string); ok {
			user.UserName = v
		}
	case "displayname":
		if v, ok := value.(string); ok {
			user.DisplayName = v
		}
	case "password":
		if v, ok := value.(string); ok {
			// The provider hashes a password set by PATCH before the store sees it.
			user.Password = v
		}
	case "active":
		if v, ok := value.(bool); ok {
			user.Active = &v
		}
	case "name.formatted", "name":
		if user.Name == nil {
			user.Name = &Name{}
		}
		if v, ok := value.(string); ok {
			user.Name.Formatted = v
		}
	case "name.givenname":
		if user.Name == nil {
			user.Name = &Name{}
		}
		if v, ok := value.(string); ok {
			user.Name.GivenName = v
		}
	case "name.familyname":
		if user.Name == nil {
			user.Name = &Name{}
		}
		if v, ok := value.(string); ok {
			user.Name.FamilyName = v
		}
	case "emails":
		if emails, ok := value.([]any); ok {
			user.Emails = parseMultiValues(emails)
		}
	default:
		// For paths we don't recognize, check if it's setting a top-level attribute via no path
		if path == "" && value != nil {
			if attrs, ok := value.(map[string]any); ok {
				return applyUserAttributes(user, attrs)
			}
		}
	}
	return nil
}

func applyUserRemove(user *User, path string) error {
	switch path {
	case "displayname":
		user.DisplayName = ""
	case "nickname":
		user.NickName = ""
	case "profileurl":
		user.ProfileURL = ""
	case "title":
		user.Title = ""
	case "name":
		user.Name = nil
	case "emails":
		user.Emails = nil
	case "phonenumbers":
		user.PhoneNumbers = nil
	}
	return nil
}

func applyUserAttributes(user *User, attrs map[string]any) error {
	for k, v := range attrs {
		if err := applyUserAddReplace(user, strings.ToLower(k), v); err != nil {
			return err
		}
	}
	return nil
}

// applyGroupPatch applies PATCH operations to a group.
// Returns the patched group and any member operations to perform.
func applyGroupPatch(group *Group, ops []PatchOperation) (*Group, []memberOp, error) {
	var memberOps []memberOp

	for _, op := range ops {
		opMemberOps, err := applyGroupPatchOp(group, op)
		if err != nil {
			return nil, nil, err
		}
		memberOps = append(memberOps, opMemberOps...)
	}

	return group, memberOps, nil
}

// applyGroupPatchOp applies a single PATCH operation to a group.
func applyGroupPatchOp(group *Group, op PatchOperation) ([]memberOp, error) {
	opType := strings.ToLower(op.Op)
	path := strings.ToLower(op.Path)

	switch opType {
	case "add":
		return applyGroupAdd(group, path, op.Value)
	case "replace":
		return applyGroupReplace(group, path, op.Value)
	case "remove":
		return applyGroupRemove(group, path, op.Value)
	default:
		return nil, ErrInvalidValue("unsupported operation: " + op.Op)
	}
}

func applyGroupAdd(group *Group, path string, value any) ([]memberOp, error) {
	switch path {
	case "displayname":
		if v, ok := value.(string); ok {
			group.DisplayName = v
		}
	case "members":
		return parseMemberOps("add", value)
	}
	return nil, nil
}

func applyGroupReplace(group *Group, path string, value any) ([]memberOp, error) {
	switch path {
	case "displayname":
		if v, ok := value.(string); ok {
			group.DisplayName = v
		}
	case "members":
		// Replace means remove all then add new
		var ops []memberOp
		for _, m := range group.Members {
			ops = append(ops, memberOp{Op: "remove", Value: m.Value})
		}
		addOps, err := parseMemberOps("add", value)
		if err != nil {
			return nil, err
		}
		ops = append(ops, addOps...)
		return ops, nil
	}
	return nil, nil
}

func applyGroupRemove(group *Group, path string, value any) ([]memberOp, error) {
	switch path {
	case "displayname":
		group.DisplayName = ""
	case "members":
		if value != nil {
			return parseMemberOps("remove", value)
		}
		// Remove all members
		var ops []memberOp
		for _, m := range group.Members {
			ops = append(ops, memberOp{Op: "remove", Value: m.Value})
		}
		return ops, nil
	default:
		// Check for filter-based remove like members[value eq "xxx"]
		if strings.HasPrefix(path, "members[") {
			memberID := extractMemberIDFromFilter(path)
			if memberID != "" {
				return []memberOp{{Op: "remove", Value: memberID}}, nil
			}
		}
	}
	return nil, nil
}

func parseMemberOps(opType string, value any) ([]memberOp, error) {
	var ops []memberOp

	switch v := value.(type) {
	case []any:
		for _, item := range v {
			if m, ok := item.(map[string]any); ok {
				if val, ok := m["value"].(string); ok && val != "" {
					ops = append(ops, memberOp{Op: opType, Value: val})
				}
			}
		}
	case map[string]any:
		if val, ok := v["value"].(string); ok && val != "" {
			ops = append(ops, memberOp{Op: opType, Value: val})
		}
	}

	return ops, nil
}

func extractMemberIDFromFilter(path string) string {
	// Parse members[value eq "xxx"] pattern
	start := strings.Index(path, `"`)
	end := strings.LastIndex(path, `"`)
	if start >= 0 && end > start {
		return path[start+1 : end]
	}
	return ""
}

func parseMultiValues(values []any) []MultiValue {
	var result []MultiValue
	for _, v := range values {
		if m, ok := v.(map[string]any); ok {
			mv := MultiValue{}
			if val, ok := m["value"].(string); ok {
				mv.Value = val
			}
			if val, ok := m["display"].(string); ok {
				mv.Display = val
			}
			if val, ok := m["type"].(string); ok {
				mv.Type = val
			}
			if val, ok := m["primary"].(bool); ok {
				mv.Primary = val
			}
			result = append(result, mv)
		}
	}
	return result
}

// convertToUser converts a map[string]any or *User to *User.
// This handles the case where JSON unmarshaling produces a map instead of a typed struct.
func convertToUser(data any) (*User, error) {
	switch v := data.(type) {
	case *User:
		return v, nil
	case User:
		return &v, nil
	case map[string]any:
		// Marshal back to JSON then unmarshal to User
		jsonBytes, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal user data: %w", err)
		}
		var user User
		if err := json.Unmarshal(jsonBytes, &user); err != nil {
			return nil, fmt.Errorf("failed to unmarshal user data: %w", err)
		}
		return &user, nil
	default:
		return nil, fmt.Errorf("unexpected data type: %T", data)
	}
}

// convertToGroup converts a map[string]any or *Group to *Group.
// This handles the case where JSON unmarshaling produces a map instead of a typed struct.
func convertToGroup(data any) (*Group, error) {
	switch v := data.(type) {
	case *Group:
		return v, nil
	case Group:
		return &v, nil
	case map[string]any:
		// Marshal back to JSON then unmarshal to Group
		jsonBytes, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal group data: %w", err)
		}
		var group Group
		if err := json.Unmarshal(jsonBytes, &group); err != nil {
			return nil, fmt.Errorf("failed to unmarshal group data: %w", err)
		}
		return &group, nil
	default:
		return nil, fmt.Errorf("unexpected data type: %T", data)
	}
}

// convertToPatchRequest converts a map[string]any or *PatchRequest to *PatchRequest.
// This handles the case where JSON unmarshaling produces a map instead of a typed struct.
func convertToPatchRequest(data any) (*PatchRequest, error) {
	switch v := data.(type) {
	case *PatchRequest:
		return v, nil
	case PatchRequest:
		return &v, nil
	case map[string]any:
		// Marshal back to JSON then unmarshal to PatchRequest
		jsonBytes, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal patch data: %w", err)
		}
		var patch PatchRequest
		if err := json.Unmarshal(jsonBytes, &patch); err != nil {
			return nil, fmt.Errorf("failed to unmarshal patch data: %w", err)
		}
		return &patch, nil
	default:
		return nil, fmt.Errorf("unexpected data type: %T", data)
	}
}
