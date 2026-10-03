package mapper

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity"
	"github.com/plexusone/systemforge/identity/scim"
	"github.com/plexusone/systemforge/identity/scim/patch"
)

// UserMapper maps between SCIM User resources and SystemForge User entities.
type UserMapper struct {
	config *Config
}

// NewUserMapper creates a new user mapper.
func NewUserMapper(config *Config) *UserMapper {
	if config == nil {
		config = DefaultConfig()
	}
	return &UserMapper{config: config}
}

// ToSCIM converts a SystemForge UserInfo to a SCIM User.
func (m *UserMapper) ToSCIM(ctx context.Context, user *identity.UserInfo) (*scim.User, error) {
	if user == nil {
		return nil, nil
	}

	active := user.Active
	scimUser := &scim.User{
		Resource: scim.Resource{
			Schemas: []string{scim.SchemaUser},
			ID:      user.ID.String(),
			Meta: &scim.Meta{
				ResourceType: scim.ResourceTypeUser,
				Location:     m.config.BaseURL + "/Users/" + user.ID.String(),
			},
		},
		UserName:    user.Email,
		DisplayName: user.Name,
		Active:      &active,
	}

	// Set name components
	if user.Name != "" {
		scimUser.Name = &scim.Name{
			Formatted: user.Name,
		}
	}

	// Set primary email
	scimUser.Emails = []scim.MultiValue{
		{
			Value:   user.Email,
			Type:    "work",
			Primary: true,
		},
	}

	// Set avatar URL as photo
	if user.AvatarURL != nil && *user.AvatarURL != "" {
		scimUser.Photos = []scim.MultiValue{
			{
				Value:   *user.AvatarURL,
				Type:    "photo",
				Primary: true,
			},
		}
	}

	return scimUser, nil
}

// ToSCIMWithMeta converts a SystemForge UserInfo to a SCIM User with metadata timestamps.
func (m *UserMapper) ToSCIMWithMeta(ctx context.Context, user *identity.UserInfo, createdAt, updatedAt time.Time) (*scim.User, error) {
	scimUser, err := m.ToSCIM(ctx, user)
	if err != nil {
		return nil, err
	}

	if scimUser.Meta != nil {
		scimUser.Meta.Created = &createdAt
		scimUser.Meta.LastModified = &updatedAt
		scimUser.Meta.Version = updatedAt.Format("20060102150405")
	}

	return scimUser, nil
}

// FromSCIM converts a SCIM User to a SystemForge CreateUserInput.
func (m *UserMapper) FromSCIM(ctx context.Context, scimUser *scim.User) (*identity.CreateUserInput, error) {
	if scimUser == nil {
		return nil, nil
	}

	input := &identity.CreateUserInput{
		Email: scimUser.UserName,
		Name:  scimUser.DisplayName,
	}

	// Use formatted name if displayName is empty
	if input.Name == "" && scimUser.Name != nil {
		if scimUser.Name.Formatted != "" {
			input.Name = scimUser.Name.Formatted
		} else {
			// Construct from components
			parts := []string{}
			if scimUser.Name.GivenName != "" {
				parts = append(parts, scimUser.Name.GivenName)
			}
			if scimUser.Name.MiddleName != "" {
				parts = append(parts, scimUser.Name.MiddleName)
			}
			if scimUser.Name.FamilyName != "" {
				parts = append(parts, scimUser.Name.FamilyName)
			}
			if len(parts) > 0 {
				input.Name = joinStrings(parts, " ")
			}
		}
	}

	// Extract primary email if userName is not set
	if input.Email == "" {
		for _, email := range scimUser.Emails {
			if email.Primary || email.Type == "work" {
				input.Email = email.Value
				break
			}
		}
		if input.Email == "" && len(scimUser.Emails) > 0 {
			input.Email = scimUser.Emails[0].Value
		}
	}

	// Extract avatar URL from photos
	for _, photo := range scimUser.Photos {
		if photo.Primary || photo.Type == "photo" {
			input.AvatarURL = &photo.Value
			break
		}
	}

	// Set password if provided
	if scimUser.Password != "" {
		input.Password = &scimUser.Password
	}

	return input, nil
}

// ToUpdateInput converts a SCIM User to a SystemForge UpdateUserInput.
func (m *UserMapper) ToUpdateInput(ctx context.Context, scimUser *scim.User) (*identity.UpdateUserInput, error) {
	if scimUser == nil {
		return nil, nil
	}

	input := &identity.UpdateUserInput{}

	if scimUser.UserName != "" {
		input.Email = &scimUser.UserName
	}

	if scimUser.DisplayName != "" {
		input.Name = &scimUser.DisplayName
	} else if scimUser.Name != nil && scimUser.Name.Formatted != "" {
		input.Name = &scimUser.Name.Formatted
	}

	if scimUser.Active != nil {
		input.Active = scimUser.Active
	}

	// Extract avatar URL from photos
	for _, photo := range scimUser.Photos {
		if photo.Primary || photo.Type == "photo" {
			input.AvatarURL = &photo.Value
			break
		}
	}

	return input, nil
}

// ApplyPatch applies PATCH operations to a UserInfo.
func (m *UserMapper) ApplyPatch(ctx context.Context, user *identity.UserInfo, ops []patch.Operation) (*identity.UpdateUserInput, error) {
	// Convert patch operations to update input
	input := &identity.UpdateUserInput{}

	for _, op := range ops {
		if err := m.applyPatchOp(input, op); err != nil {
			return nil, err
		}
	}

	return input, nil
}

// applyPatchOp applies a single patch operation to an update input.
func (m *UserMapper) applyPatchOp(input *identity.UpdateUserInput, op patch.Operation) error {
	applier := patch.NewApplier()

	// Create a temporary struct that mirrors the SCIM User structure
	temp := &tempUserPatch{}
	if err := applier.Apply(temp, []patch.Operation{op}); err != nil {
		return err
	}

	// Map the patched values to the update input
	if temp.UserName != "" {
		input.Email = &temp.UserName
	}
	if temp.DisplayName != "" {
		input.Name = &temp.DisplayName
	}
	if temp.Active != nil {
		input.Active = temp.Active
	}
	if temp.Name != nil && temp.Name.Formatted != "" {
		input.Name = &temp.Name.Formatted
	}

	return nil
}

// tempUserPatch is a temporary struct for applying patches.
type tempUserPatch struct {
	UserName    string    `json:"userName"`
	DisplayName string    `json:"displayName"`
	Active      *bool     `json:"active"`
	Name        *tempName `json:"name"`
}

type tempName struct {
	Formatted  string `json:"formatted"`
	GivenName  string `json:"givenName"`
	FamilyName string `json:"familyName"`
}

// ParseUserID parses a SCIM user ID to a UUID.
func ParseUserID(id string) (uuid.UUID, error) {
	return uuid.Parse(id)
}

// joinStrings joins non-empty strings with a separator.
func joinStrings(parts []string, sep string) string {
	result := ""
	for i, part := range parts {
		if part != "" {
			if result != "" {
				result += sep
			}
			result += part
		} else if i == 0 {
			continue
		}
	}
	return result
}
