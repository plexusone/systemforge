package mapper

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity"
	"github.com/plexusone/systemforge/identity/scim"
	"github.com/plexusone/systemforge/identity/scim/patch"
)

// GroupMapper maps between SCIM Group resources and SystemForge Organization entities.
type GroupMapper struct {
	config *Config
}

// NewGroupMapper creates a new group mapper.
func NewGroupMapper(config *Config) *GroupMapper {
	if config == nil {
		config = DefaultConfig()
	}
	return &GroupMapper{config: config}
}

// ToSCIM converts a SystemForge OrganizationInfo to a SCIM Group.
func (m *GroupMapper) ToSCIM(ctx context.Context, org *identity.OrganizationInfo) (*scim.Group, error) {
	if org == nil {
		return nil, nil
	}

	scimGroup := &scim.Group{
		Resource: scim.Resource{
			Schemas: []string{scim.SchemaGroup},
			ID:      org.ID.String(),
			Meta: &scim.Meta{
				ResourceType: scim.ResourceTypeGroup,
				Location:     m.config.BaseURL + "/Groups/" + org.ID.String(),
			},
		},
		DisplayName: org.Name,
	}

	return scimGroup, nil
}

// ToSCIMWithMeta converts a SystemForge OrganizationInfo to a SCIM Group with metadata timestamps.
func (m *GroupMapper) ToSCIMWithMeta(ctx context.Context, org *identity.OrganizationInfo, createdAt, updatedAt time.Time) (*scim.Group, error) {
	scimGroup, err := m.ToSCIM(ctx, org)
	if err != nil {
		return nil, err
	}

	if scimGroup.Meta != nil {
		scimGroup.Meta.Created = &createdAt
		scimGroup.Meta.LastModified = &updatedAt
		scimGroup.Meta.Version = updatedAt.Format("20060102150405")
	}

	return scimGroup, nil
}

// ToSCIMWithMembers converts a SystemForge OrganizationInfo to a SCIM Group with members.
func (m *GroupMapper) ToSCIMWithMembers(ctx context.Context, org *identity.OrganizationInfo, members []*identity.MembershipInfo, memberNames map[uuid.UUID]string) (*scim.Group, error) {
	scimGroup, err := m.ToSCIM(ctx, org)
	if err != nil {
		return nil, err
	}

	// Add members
	for _, member := range members {
		memberRef := scim.MemberRef{
			Value: member.UserID.String(),
			Ref:   m.config.BaseURL + "/Users/" + member.UserID.String(),
			Type:  "User",
		}
		if name, ok := memberNames[member.UserID]; ok {
			memberRef.Display = name
		}
		scimGroup.Members = append(scimGroup.Members, memberRef)
	}

	return scimGroup, nil
}

// FromSCIM converts a SCIM Group to a SystemForge CreateOrganizationInput.
func (m *GroupMapper) FromSCIM(ctx context.Context, scimGroup *scim.Group) (*identity.CreateOrganizationInput, error) {
	if scimGroup == nil {
		return nil, nil
	}

	input := &identity.CreateOrganizationInput{
		Name: scimGroup.DisplayName,
		Slug: generateSlug(scimGroup.DisplayName),
		Plan: "free", // Default plan
	}

	// Use externalId as slug if provided
	if scimGroup.ExternalID != "" {
		input.Slug = scimGroup.ExternalID
	}

	return input, nil
}

// ToUpdateInput converts a SCIM Group to a SystemForge UpdateOrganizationInput.
func (m *GroupMapper) ToUpdateInput(ctx context.Context, scimGroup *scim.Group) (*identity.UpdateOrganizationInput, error) {
	if scimGroup == nil {
		return nil, nil
	}

	input := &identity.UpdateOrganizationInput{}

	if scimGroup.DisplayName != "" {
		input.Name = &scimGroup.DisplayName
	}

	return input, nil
}

// ApplyPatch applies PATCH operations to an OrganizationInfo.
func (m *GroupMapper) ApplyPatch(ctx context.Context, org *identity.OrganizationInfo, ops []patch.Operation) (*identity.UpdateOrganizationInput, []MemberOperation, error) {
	input := &identity.UpdateOrganizationInput{}
	var memberOps []MemberOperation

	for _, op := range ops {
		parsedPath, err := patch.ParsePath(op.Path)
		if err != nil {
			return nil, nil, err
		}

		// Handle member operations separately
		if parsedPath != nil && (parsedPath.Attribute == "members" || op.Path == "" && containsMembersOp(op.Value)) {
			memberOp, err := m.parseMemberOperation(op)
			if err != nil {
				return nil, nil, err
			}
			memberOps = append(memberOps, memberOp...)
			continue
		}

		// Handle other operations
		if err := m.applyPatchOp(input, op); err != nil {
			return nil, nil, err
		}
	}

	return input, memberOps, nil
}

// MemberOperation represents a member add/remove operation.
type MemberOperation struct {
	Op     patch.OperationType
	UserID uuid.UUID
}

// parseMemberOperation parses member operations from a patch operation.
func (m *GroupMapper) parseMemberOperation(op patch.Operation) ([]MemberOperation, error) {
	var result []MemberOperation

	// Handle remove with filter path like "members[value eq 'xxx']"
	if op.Op == patch.OpRemove {
		parsedPath, _ := patch.ParsePath(op.Path)
		if parsedPath != nil && parsedPath.Filter != "" {
			selector, err := patch.ParseFilter(parsedPath.Filter)
			if err != nil {
				return nil, err
			}
			if idStr, ok := selector.FilterValue.(string); ok {
				userID, err := uuid.Parse(idStr)
				if err != nil {
					return nil, err
				}
				result = append(result, MemberOperation{
					Op:     patch.OpRemove,
					UserID: userID,
				})
			}
		}
		return result, nil
	}

	// Handle add/replace with value
	members := extractMembers(op.Value)
	for _, memberID := range members {
		userID, err := uuid.Parse(memberID)
		if err != nil {
			continue
		}
		result = append(result, MemberOperation{
			Op:     op.Op,
			UserID: userID,
		})
	}

	return result, nil
}

// extractMembers extracts member IDs from a patch value.
func extractMembers(value any) []string {
	var result []string

	switch v := value.(type) {
	case []any:
		for _, item := range v {
			if m, ok := item.(map[string]any); ok {
				if val, ok := m["value"].(string); ok && val != "" {
					result = append(result, val)
				}
			}
		}
	case map[string]any:
		if val, ok := v["value"].(string); ok && val != "" {
			result = append(result, val)
		}
	}

	return result
}

// containsMembersOp checks if a value contains members operations.
func containsMembersOp(value any) bool {
	if m, ok := value.(map[string]any); ok {
		_, hasMembers := m["members"]
		return hasMembers
	}
	return false
}

// applyPatchOp applies a single patch operation to an update input.
func (m *GroupMapper) applyPatchOp(input *identity.UpdateOrganizationInput, op patch.Operation) error {
	applier := patch.NewApplier()

	// Create a temporary struct that mirrors the SCIM Group structure
	temp := &tempGroupPatch{}
	if err := applier.Apply(temp, []patch.Operation{op}); err != nil {
		return err
	}

	// Map the patched values to the update input
	if temp.DisplayName != "" {
		input.Name = &temp.DisplayName
	}

	return nil
}

// tempGroupPatch is a temporary struct for applying patches.
type tempGroupPatch struct {
	DisplayName string `json:"displayName"`
}

// ParseGroupID parses a SCIM group ID to a UUID.
func ParseGroupID(id string) (uuid.UUID, error) {
	return uuid.Parse(id)
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
