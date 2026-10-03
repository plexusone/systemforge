package mapper

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/principal"
	"github.com/plexusone/systemforge/identity/scim"
	"github.com/plexusone/systemforge/identity/scim/patch"
)

// ErrInvalidPrincipalType is returned when attempting to map a non-human principal to SCIM User.
var ErrInvalidPrincipalType = errors.New("principal must be of type human for SCIM User mapping")

// PrincipalUserMapper maps between SCIM User resources and SystemForge Principal+Human entities.
// This mapper wraps the Principal-centric identity model where SCIM Users map to
// Principal(type=human) with an associated Human extension.
type PrincipalUserMapper struct {
	config *Config
}

// NewPrincipalUserMapper creates a new principal user mapper.
func NewPrincipalUserMapper(config *Config) *PrincipalUserMapper {
	if config == nil {
		config = DefaultConfig()
	}
	return &PrincipalUserMapper{config: config}
}

// ToSCIM converts a SystemForge Principal (with Human extension) to a SCIM User.
func (m *PrincipalUserMapper) ToSCIM(ctx context.Context, p *principal.Principal) (*scim.User, error) {
	if p == nil {
		return nil, nil
	}

	// Verify this is a human principal
	if p.Type != principal.TypeHuman {
		return nil, ErrInvalidPrincipalType
	}

	active := p.Active
	scimUser := &scim.User{
		Resource: scim.Resource{
			Schemas: []string{scim.SchemaUser},
			ID:      p.ID.String(),
			Meta: &scim.Meta{
				ResourceType: scim.ResourceTypeUser,
				Location:     m.config.BaseURL + "/Users/" + p.ID.String(),
			},
		},
		UserName:    p.Identifier,
		DisplayName: p.DisplayName,
		Active:      &active,
	}

	// Set name components from Human extension
	if p.Human != nil {
		scimUser.Name = &scim.Name{
			GivenName:  p.Human.GivenName,
			FamilyName: p.Human.FamilyName,
			Formatted:  p.DisplayName,
		}

		// Set primary email
		scimUser.Emails = []scim.MultiValue{
			{
				Value:   p.Human.Email,
				Type:    "work",
				Primary: true,
			},
		}

		// Set avatar URL as photo
		if p.Human.AvatarURL != nil && *p.Human.AvatarURL != "" {
			scimUser.Photos = []scim.MultiValue{
				{
					Value:   *p.Human.AvatarURL,
					Type:    "photo",
					Primary: true,
				},
			}
		}

		// Set locale and timezone
		if p.Human.Locale != "" {
			scimUser.Locale = p.Human.Locale
		}
		if p.Human.Timezone != "" {
			scimUser.Timezone = p.Human.Timezone
		}
	}

	return scimUser, nil
}

// ToSCIMWithMeta converts a SystemForge Principal to a SCIM User with metadata timestamps.
func (m *PrincipalUserMapper) ToSCIMWithMeta(ctx context.Context, p *principal.Principal, createdAt, updatedAt time.Time) (*scim.User, error) {
	scimUser, err := m.ToSCIM(ctx, p)
	if err != nil {
		return nil, err
	}

	if scimUser != nil && scimUser.Meta != nil {
		scimUser.Meta.Created = &createdAt
		scimUser.Meta.LastModified = &updatedAt
		scimUser.Meta.Version = updatedAt.Format("20060102150405")
	}

	return scimUser, nil
}

// FromSCIM converts a SCIM User to a SystemForge CreateHumanInput.
func (m *PrincipalUserMapper) FromSCIM(ctx context.Context, scimUser *scim.User) (*principal.CreateHumanInput, error) {
	if scimUser == nil {
		return nil, nil
	}

	input := &principal.CreateHumanInput{
		Email:       scimUser.UserName,
		DisplayName: scimUser.DisplayName,
	}

	// Extract name components
	if scimUser.Name != nil {
		input.GivenName = scimUser.Name.GivenName
		input.FamilyName = scimUser.Name.FamilyName

		// Use formatted name if displayName is empty
		if input.DisplayName == "" {
			if scimUser.Name.Formatted != "" {
				input.DisplayName = scimUser.Name.Formatted
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
					input.DisplayName = joinStrings(parts, " ")
				}
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
			input.AvatarURL = strPtr(photo.Value)
			break
		}
	}

	// Extract locale and timezone
	if scimUser.Locale != "" {
		input.Locale = scimUser.Locale
	}
	if scimUser.Timezone != "" {
		input.Timezone = scimUser.Timezone
	}

	// Note: Password is handled separately via CredentialService.CreatePassword()
	// The SCIM handler should extract scimUser.Password and call CredentialService

	return input, nil
}

// ToUpdateInput converts a SCIM User to a SystemForge UpdateHumanInput.
func (m *PrincipalUserMapper) ToUpdateInput(ctx context.Context, scimUser *scim.User) (*principal.UpdateHumanInput, error) {
	if scimUser == nil {
		return nil, nil
	}

	input := &principal.UpdateHumanInput{}

	// Note: UserName (email) changes require updating the Principal's Identifier,
	// which should be handled at the SCIM handler level using PrincipalService.Update()

	if scimUser.DisplayName != "" {
		input.DisplayName = strPtr(scimUser.DisplayName)
	} else if scimUser.Name != nil && scimUser.Name.Formatted != "" {
		input.DisplayName = strPtr(scimUser.Name.Formatted)
	}

	if scimUser.Name != nil {
		if scimUser.Name.GivenName != "" {
			input.GivenName = strPtr(scimUser.Name.GivenName)
		}
		if scimUser.Name.FamilyName != "" {
			input.FamilyName = strPtr(scimUser.Name.FamilyName)
		}
	}

	if scimUser.Active != nil {
		input.Active = scimUser.Active
	}

	// Extract avatar URL from photos
	for _, photo := range scimUser.Photos {
		if photo.Primary || photo.Type == "photo" {
			input.AvatarURL = strPtr(photo.Value)
			break
		}
	}

	// Extract locale and timezone
	if scimUser.Locale != "" {
		input.Locale = strPtr(scimUser.Locale)
	}
	if scimUser.Timezone != "" {
		input.Timezone = strPtr(scimUser.Timezone)
	}

	return input, nil
}

// ApplyPatch applies PATCH operations to a Principal and returns an UpdateHumanInput.
func (m *PrincipalUserMapper) ApplyPatch(ctx context.Context, p *principal.Principal, ops []patch.Operation) (*principal.UpdateHumanInput, error) {
	// Convert patch operations to update input
	input := &principal.UpdateHumanInput{}

	for _, op := range ops {
		if err := m.applyPatchOp(input, op); err != nil {
			return nil, err
		}
	}

	return input, nil
}

// applyPatchOp applies a single patch operation to an update input.
func (m *PrincipalUserMapper) applyPatchOp(input *principal.UpdateHumanInput, op patch.Operation) error {
	applier := patch.NewApplier()

	// Create a temporary struct that mirrors the SCIM User structure
	temp := &tempPrincipalUserPatch{}
	if err := applier.Apply(temp, []patch.Operation{op}); err != nil {
		return err
	}

	// Map the patched values to the update input
	// Note: UserName (email) changes require updating the Principal's Identifier,
	// which should be handled at the SCIM handler level using PrincipalService.Update()
	if temp.DisplayName != "" {
		input.DisplayName = strPtr(temp.DisplayName)
	}
	if temp.Active != nil {
		input.Active = temp.Active
	}
	if temp.Name != nil {
		if temp.Name.Formatted != "" {
			input.DisplayName = strPtr(temp.Name.Formatted)
		}
		if temp.Name.GivenName != "" {
			input.GivenName = strPtr(temp.Name.GivenName)
		}
		if temp.Name.FamilyName != "" {
			input.FamilyName = strPtr(temp.Name.FamilyName)
		}
	}
	if temp.Locale != "" {
		input.Locale = strPtr(temp.Locale)
	}
	if temp.Timezone != "" {
		input.Timezone = strPtr(temp.Timezone)
	}

	return nil
}

// tempPrincipalUserPatch is a temporary struct for applying patches.
type tempPrincipalUserPatch struct {
	UserName    string             `json:"userName"`
	DisplayName string             `json:"displayName"`
	Active      *bool              `json:"active"`
	Name        *tempPrincipalName `json:"name"`
	Locale      string             `json:"locale"`
	Timezone    string             `json:"timezone"`
}

type tempPrincipalName struct {
	Formatted  string `json:"formatted"`
	GivenName  string `json:"givenName"`
	FamilyName string `json:"familyName"`
}

// ParsePrincipalID parses a SCIM user ID to a UUID.
func ParsePrincipalID(id string) (uuid.UUID, error) {
	return uuid.Parse(id)
}

// strPtr returns a pointer to the given string, or nil if empty.
func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
