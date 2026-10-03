package mapper

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity"
	"github.com/plexusone/systemforge/identity/scim"
	"github.com/plexusone/systemforge/identity/scim/patch"
)

func TestUserMapperToSCIM(t *testing.T) {
	mapper := NewUserMapper(&Config{BaseURL: "https://example.com/scim/v2"})
	ctx := context.Background()

	avatarURL := "https://example.com/avatar.png"
	userID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")

	user := &identity.UserInfo{
		ID:        userID,
		Email:     "john.doe@example.com",
		Name:      "John Doe",
		AvatarURL: &avatarURL,
		Active:    true,
	}

	scimUser, err := mapper.ToSCIM(ctx, user)
	if err != nil {
		t.Fatalf("ToSCIM() error = %v", err)
	}

	if scimUser.ID != userID.String() {
		t.Errorf("ID = %q, want %q", scimUser.ID, userID.String())
	}

	if scimUser.UserName != "john.doe@example.com" {
		t.Errorf("UserName = %q, want %q", scimUser.UserName, "john.doe@example.com")
	}

	if scimUser.DisplayName != "John Doe" {
		t.Errorf("DisplayName = %q, want %q", scimUser.DisplayName, "John Doe")
	}

	if scimUser.Active == nil || !*scimUser.Active {
		t.Error("Active should be true")
	}

	if len(scimUser.Emails) != 1 {
		t.Fatalf("Emails length = %d, want 1", len(scimUser.Emails))
	}

	if scimUser.Emails[0].Value != "john.doe@example.com" {
		t.Errorf("Emails[0].Value = %q, want %q", scimUser.Emails[0].Value, "john.doe@example.com")
	}

	if !scimUser.Emails[0].Primary {
		t.Error("Emails[0].Primary should be true")
	}

	if len(scimUser.Photos) != 1 {
		t.Fatalf("Photos length = %d, want 1", len(scimUser.Photos))
	}

	if scimUser.Photos[0].Value != avatarURL {
		t.Errorf("Photos[0].Value = %q, want %q", scimUser.Photos[0].Value, avatarURL)
	}

	if scimUser.Meta == nil {
		t.Fatal("Meta should not be nil")
	}

	if scimUser.Meta.ResourceType != scim.ResourceTypeUser {
		t.Errorf("Meta.ResourceType = %q, want %q", scimUser.Meta.ResourceType, scim.ResourceTypeUser)
	}

	expectedLocation := "https://example.com/scim/v2/Users/" + userID.String()
	if scimUser.Meta.Location != expectedLocation {
		t.Errorf("Meta.Location = %q, want %q", scimUser.Meta.Location, expectedLocation)
	}
}

func TestUserMapperToSCIMNil(t *testing.T) {
	mapper := NewUserMapper(nil)
	ctx := context.Background()

	scimUser, err := mapper.ToSCIM(ctx, nil)
	if err != nil {
		t.Fatalf("ToSCIM(nil) error = %v", err)
	}
	if scimUser != nil {
		t.Error("ToSCIM(nil) should return nil")
	}
}

func TestUserMapperToSCIMWithMeta(t *testing.T) {
	mapper := NewUserMapper(&Config{BaseURL: "https://example.com/scim/v2"})
	ctx := context.Background()

	userID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	user := &identity.UserInfo{
		ID:     userID,
		Email:  "test@example.com",
		Name:   "Test User",
		Active: true,
	}

	createdAt := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	updatedAt := time.Date(2024, 6, 20, 14, 45, 0, 0, time.UTC)

	scimUser, err := mapper.ToSCIMWithMeta(ctx, user, createdAt, updatedAt)
	if err != nil {
		t.Fatalf("ToSCIMWithMeta() error = %v", err)
	}

	if scimUser.Meta.Created == nil {
		t.Fatal("Meta.Created should not be nil")
	}
	if !scimUser.Meta.Created.Equal(createdAt) {
		t.Errorf("Meta.Created = %v, want %v", scimUser.Meta.Created, createdAt)
	}

	if scimUser.Meta.LastModified == nil {
		t.Fatal("Meta.LastModified should not be nil")
	}
	if !scimUser.Meta.LastModified.Equal(updatedAt) {
		t.Errorf("Meta.LastModified = %v, want %v", scimUser.Meta.LastModified, updatedAt)
	}

	expectedVersion := updatedAt.Format("20060102150405")
	if scimUser.Meta.Version != expectedVersion {
		t.Errorf("Meta.Version = %q, want %q", scimUser.Meta.Version, expectedVersion)
	}
}

func TestUserMapperFromSCIM(t *testing.T) {
	mapper := NewUserMapper(nil)
	ctx := context.Background()

	scimUser := &scim.User{
		Resource: scim.Resource{
			ID:      "550e8400-e29b-41d4-a716-446655440000",
			Schemas: []string{scim.SchemaUser},
		},
		UserName:    "jane.doe@example.com",
		DisplayName: "Jane Doe",
		Emails: []scim.MultiValue{
			{Value: "jane.doe@example.com", Type: "work", Primary: true},
		},
		Photos: []scim.MultiValue{
			{Value: "https://example.com/photo.jpg", Type: "photo", Primary: true},
		},
		Password: "secretpassword",
	}

	input, err := mapper.FromSCIM(ctx, scimUser)
	if err != nil {
		t.Fatalf("FromSCIM() error = %v", err)
	}

	if input.Email != "jane.doe@example.com" {
		t.Errorf("Email = %q, want %q", input.Email, "jane.doe@example.com")
	}

	if input.Name != "Jane Doe" {
		t.Errorf("Name = %q, want %q", input.Name, "Jane Doe")
	}

	if input.AvatarURL == nil {
		t.Fatal("AvatarURL should not be nil")
	}
	if *input.AvatarURL != "https://example.com/photo.jpg" {
		t.Errorf("AvatarURL = %q, want %q", *input.AvatarURL, "https://example.com/photo.jpg")
	}

	if input.Password == nil {
		t.Fatal("Password should not be nil")
	}
	if *input.Password != "secretpassword" {
		t.Errorf("Password = %q, want %q", *input.Password, "secretpassword")
	}
}

func TestUserMapperFromSCIMNil(t *testing.T) {
	mapper := NewUserMapper(nil)
	ctx := context.Background()

	input, err := mapper.FromSCIM(ctx, nil)
	if err != nil {
		t.Fatalf("FromSCIM(nil) error = %v", err)
	}
	if input != nil {
		t.Error("FromSCIM(nil) should return nil")
	}
}

func TestUserMapperFromSCIMNameComponents(t *testing.T) {
	mapper := NewUserMapper(nil)
	ctx := context.Background()

	// Test with name components instead of displayName
	scimUser := &scim.User{
		Resource: scim.Resource{
			ID: "550e8400-e29b-41d4-a716-446655440000",
		},
		UserName: "user@example.com",
		Name: &scim.Name{
			GivenName:  "John",
			MiddleName: "Q",
			FamilyName: "Public",
		},
	}

	input, err := mapper.FromSCIM(ctx, scimUser)
	if err != nil {
		t.Fatalf("FromSCIM() error = %v", err)
	}

	if input.Name != "John Q Public" {
		t.Errorf("Name = %q, want %q", input.Name, "John Q Public")
	}
}

func TestUserMapperFromSCIMFormattedName(t *testing.T) {
	mapper := NewUserMapper(nil)
	ctx := context.Background()

	// Test with formatted name
	scimUser := &scim.User{
		Resource: scim.Resource{
			ID: "550e8400-e29b-41d4-a716-446655440000",
		},
		UserName: "user@example.com",
		Name: &scim.Name{
			Formatted: "Dr. Jane Smith, PhD",
		},
	}

	input, err := mapper.FromSCIM(ctx, scimUser)
	if err != nil {
		t.Fatalf("FromSCIM() error = %v", err)
	}

	if input.Name != "Dr. Jane Smith, PhD" {
		t.Errorf("Name = %q, want %q", input.Name, "Dr. Jane Smith, PhD")
	}
}

func TestUserMapperFromSCIMEmailFallback(t *testing.T) {
	mapper := NewUserMapper(nil)
	ctx := context.Background()

	// Test email extraction when userName is empty
	scimUser := &scim.User{
		Resource: scim.Resource{
			ID: "550e8400-e29b-41d4-a716-446655440000",
		},
		DisplayName: "Test User",
		Emails: []scim.MultiValue{
			{Value: "fallback@example.com", Type: "work", Primary: true},
		},
	}

	input, err := mapper.FromSCIM(ctx, scimUser)
	if err != nil {
		t.Fatalf("FromSCIM() error = %v", err)
	}

	if input.Email != "fallback@example.com" {
		t.Errorf("Email = %q, want %q", input.Email, "fallback@example.com")
	}
}

func TestUserMapperToUpdateInput(t *testing.T) {
	mapper := NewUserMapper(nil)
	ctx := context.Background()

	active := false
	scimUser := &scim.User{
		UserName:    "new.email@example.com",
		DisplayName: "New Name",
		Active:      &active,
		Photos: []scim.MultiValue{
			{Value: "https://example.com/new-photo.jpg", Type: "photo", Primary: true},
		},
	}

	input, err := mapper.ToUpdateInput(ctx, scimUser)
	if err != nil {
		t.Fatalf("ToUpdateInput() error = %v", err)
	}

	if input.Email == nil || *input.Email != "new.email@example.com" {
		t.Errorf("Email = %v, want %q", input.Email, "new.email@example.com")
	}

	if input.Name == nil || *input.Name != "New Name" {
		t.Errorf("Name = %v, want %q", input.Name, "New Name")
	}

	if input.Active == nil || *input.Active != false {
		t.Errorf("Active = %v, want false", input.Active)
	}

	if input.AvatarURL == nil || *input.AvatarURL != "https://example.com/new-photo.jpg" {
		t.Errorf("AvatarURL = %v, want %q", input.AvatarURL, "https://example.com/new-photo.jpg")
	}
}

func TestUserMapperToUpdateInputNil(t *testing.T) {
	mapper := NewUserMapper(nil)
	ctx := context.Background()

	input, err := mapper.ToUpdateInput(ctx, nil)
	if err != nil {
		t.Fatalf("ToUpdateInput(nil) error = %v", err)
	}
	if input != nil {
		t.Error("ToUpdateInput(nil) should return nil")
	}
}

func TestUserMapperApplyPatch(t *testing.T) {
	mapper := NewUserMapper(nil)
	ctx := context.Background()

	user := &identity.UserInfo{
		ID:     uuid.MustParse("550e8400-e29b-41d4-a716-446655440000"),
		Email:  "old@example.com",
		Name:   "Old Name",
		Active: true,
	}

	ops := []patch.Operation{
		{Op: patch.OpReplace, Path: "userName", Value: "new@example.com"},
		{Op: patch.OpReplace, Path: "displayName", Value: "New Name"},
	}

	input, err := mapper.ApplyPatch(ctx, user, ops)
	if err != nil {
		t.Fatalf("ApplyPatch() error = %v", err)
	}

	if input.Email == nil || *input.Email != "new@example.com" {
		t.Errorf("Email = %v, want %q", input.Email, "new@example.com")
	}

	if input.Name == nil || *input.Name != "New Name" {
		t.Errorf("Name = %v, want %q", input.Name, "New Name")
	}
}

func TestParseUserID(t *testing.T) {
	tests := []struct {
		name      string
		id        string
		wantError bool
	}{
		{
			name:      "valid UUID",
			id:        "550e8400-e29b-41d4-a716-446655440000",
			wantError: false,
		},
		{
			name:      "invalid UUID",
			id:        "not-a-uuid",
			wantError: true,
		},
		{
			name:      "empty string",
			id:        "",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseUserID(tt.id)
			if (err != nil) != tt.wantError {
				t.Errorf("ParseUserID() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestJoinStrings(t *testing.T) {
	tests := []struct {
		name  string
		parts []string
		sep   string
		want  string
	}{
		{
			name:  "normal join",
			parts: []string{"a", "b", "c"},
			sep:   " ",
			want:  "a b c",
		},
		{
			name:  "with empty parts",
			parts: []string{"a", "", "c"},
			sep:   " ",
			want:  "a c",
		},
		{
			name:  "all empty",
			parts: []string{"", "", ""},
			sep:   " ",
			want:  "",
		},
		{
			name:  "single item",
			parts: []string{"hello"},
			sep:   " ",
			want:  "hello",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := joinStrings(tt.parts, tt.sep)
			if got != tt.want {
				t.Errorf("joinStrings() = %q, want %q", got, tt.want)
			}
		})
	}
}
