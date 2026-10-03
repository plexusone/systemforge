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

func TestGroupMapperToSCIM(t *testing.T) {
	mapper := NewGroupMapper(&Config{BaseURL: "https://example.com/scim/v2"})
	ctx := context.Background()

	orgID := uuid.MustParse("660e8400-e29b-41d4-a716-446655440000")
	org := &identity.OrganizationInfo{
		ID:   orgID,
		Name: "Engineering Team",
		Slug: "engineering-team",
	}

	scimGroup, err := mapper.ToSCIM(ctx, org)
	if err != nil {
		t.Fatalf("ToSCIM() error = %v", err)
	}

	if scimGroup.ID != orgID.String() {
		t.Errorf("ID = %q, want %q", scimGroup.ID, orgID.String())
	}

	if scimGroup.DisplayName != "Engineering Team" {
		t.Errorf("DisplayName = %q, want %q", scimGroup.DisplayName, "Engineering Team")
	}

	if len(scimGroup.Schemas) != 1 || scimGroup.Schemas[0] != scim.SchemaGroup {
		t.Errorf("Schemas = %v, want [%q]", scimGroup.Schemas, scim.SchemaGroup)
	}

	if scimGroup.Meta == nil {
		t.Fatal("Meta should not be nil")
	}

	if scimGroup.Meta.ResourceType != scim.ResourceTypeGroup {
		t.Errorf("Meta.ResourceType = %q, want %q", scimGroup.Meta.ResourceType, scim.ResourceTypeGroup)
	}

	expectedLocation := "https://example.com/scim/v2/Groups/" + orgID.String()
	if scimGroup.Meta.Location != expectedLocation {
		t.Errorf("Meta.Location = %q, want %q", scimGroup.Meta.Location, expectedLocation)
	}
}

func TestGroupMapperToSCIMNil(t *testing.T) {
	mapper := NewGroupMapper(nil)
	ctx := context.Background()

	scimGroup, err := mapper.ToSCIM(ctx, nil)
	if err != nil {
		t.Fatalf("ToSCIM(nil) error = %v", err)
	}
	if scimGroup != nil {
		t.Error("ToSCIM(nil) should return nil")
	}
}

func TestGroupMapperToSCIMWithMeta(t *testing.T) {
	mapper := NewGroupMapper(&Config{BaseURL: "https://example.com/scim/v2"})
	ctx := context.Background()

	orgID := uuid.MustParse("660e8400-e29b-41d4-a716-446655440000")
	org := &identity.OrganizationInfo{
		ID:   orgID,
		Name: "Test Org",
		Slug: "test-org",
	}

	createdAt := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	updatedAt := time.Date(2024, 6, 20, 14, 45, 0, 0, time.UTC)

	scimGroup, err := mapper.ToSCIMWithMeta(ctx, org, createdAt, updatedAt)
	if err != nil {
		t.Fatalf("ToSCIMWithMeta() error = %v", err)
	}

	if scimGroup.Meta.Created == nil {
		t.Fatal("Meta.Created should not be nil")
	}
	if !scimGroup.Meta.Created.Equal(createdAt) {
		t.Errorf("Meta.Created = %v, want %v", scimGroup.Meta.Created, createdAt)
	}

	if scimGroup.Meta.LastModified == nil {
		t.Fatal("Meta.LastModified should not be nil")
	}
	if !scimGroup.Meta.LastModified.Equal(updatedAt) {
		t.Errorf("Meta.LastModified = %v, want %v", scimGroup.Meta.LastModified, updatedAt)
	}

	expectedVersion := updatedAt.Format("20060102150405")
	if scimGroup.Meta.Version != expectedVersion {
		t.Errorf("Meta.Version = %q, want %q", scimGroup.Meta.Version, expectedVersion)
	}
}

func TestGroupMapperToSCIMWithMembers(t *testing.T) {
	mapper := NewGroupMapper(&Config{BaseURL: "https://example.com/scim/v2"})
	ctx := context.Background()

	orgID := uuid.MustParse("660e8400-e29b-41d4-a716-446655440000")
	userID1 := uuid.MustParse("550e8400-e29b-41d4-a716-446655440001")
	userID2 := uuid.MustParse("550e8400-e29b-41d4-a716-446655440002")

	org := &identity.OrganizationInfo{
		ID:   orgID,
		Name: "Engineering Team",
		Slug: "engineering-team",
	}

	members := []*identity.MembershipInfo{
		{ID: uuid.New(), UserID: userID1, OrganizationID: orgID, Role: "admin"},
		{ID: uuid.New(), UserID: userID2, OrganizationID: orgID, Role: "member"},
	}

	memberNames := map[uuid.UUID]string{
		userID1: "Alice Smith",
		userID2: "Bob Jones",
	}

	scimGroup, err := mapper.ToSCIMWithMembers(ctx, org, members, memberNames)
	if err != nil {
		t.Fatalf("ToSCIMWithMembers() error = %v", err)
	}

	if len(scimGroup.Members) != 2 {
		t.Fatalf("Members length = %d, want 2", len(scimGroup.Members))
	}

	// Check first member
	if scimGroup.Members[0].Value != userID1.String() {
		t.Errorf("Members[0].Value = %q, want %q", scimGroup.Members[0].Value, userID1.String())
	}
	if scimGroup.Members[0].Display != "Alice Smith" {
		t.Errorf("Members[0].Display = %q, want %q", scimGroup.Members[0].Display, "Alice Smith")
	}
	expectedRef := "https://example.com/scim/v2/Users/" + userID1.String()
	if scimGroup.Members[0].Ref != expectedRef {
		t.Errorf("Members[0].Ref = %q, want %q", scimGroup.Members[0].Ref, expectedRef)
	}

	// Check second member
	if scimGroup.Members[1].Value != userID2.String() {
		t.Errorf("Members[1].Value = %q, want %q", scimGroup.Members[1].Value, userID2.String())
	}
	if scimGroup.Members[1].Display != "Bob Jones" {
		t.Errorf("Members[1].Display = %q, want %q", scimGroup.Members[1].Display, "Bob Jones")
	}
}

func TestGroupMapperFromSCIM(t *testing.T) {
	mapper := NewGroupMapper(nil)
	ctx := context.Background()

	scimGroup := &scim.Group{
		Resource: scim.Resource{
			ID:      "660e8400-e29b-41d4-a716-446655440000",
			Schemas: []string{scim.SchemaGroup},
		},
		DisplayName: "Engineering Team",
	}

	input, err := mapper.FromSCIM(ctx, scimGroup)
	if err != nil {
		t.Fatalf("FromSCIM() error = %v", err)
	}

	if input.Name != "Engineering Team" {
		t.Errorf("Name = %q, want %q", input.Name, "Engineering Team")
	}

	if input.Slug != "engineering-team" {
		t.Errorf("Slug = %q, want %q", input.Slug, "engineering-team")
	}

	if input.Plan != "free" {
		t.Errorf("Plan = %q, want %q", input.Plan, "free")
	}
}

func TestGroupMapperFromSCIMNil(t *testing.T) {
	mapper := NewGroupMapper(nil)
	ctx := context.Background()

	input, err := mapper.FromSCIM(ctx, nil)
	if err != nil {
		t.Fatalf("FromSCIM(nil) error = %v", err)
	}
	if input != nil {
		t.Error("FromSCIM(nil) should return nil")
	}
}

func TestGroupMapperFromSCIMWithExternalID(t *testing.T) {
	mapper := NewGroupMapper(nil)
	ctx := context.Background()

	scimGroup := &scim.Group{
		Resource: scim.Resource{
			ID:         "660e8400-e29b-41d4-a716-446655440000",
			ExternalID: "ext-engineering",
		},
		DisplayName: "Engineering Team",
	}

	input, err := mapper.FromSCIM(ctx, scimGroup)
	if err != nil {
		t.Fatalf("FromSCIM() error = %v", err)
	}

	// Should use externalId as slug
	if input.Slug != "ext-engineering" {
		t.Errorf("Slug = %q, want %q", input.Slug, "ext-engineering")
	}
}

func TestGroupMapperToUpdateInput(t *testing.T) {
	mapper := NewGroupMapper(nil)
	ctx := context.Background()

	scimGroup := &scim.Group{
		DisplayName: "New Team Name",
	}

	input, err := mapper.ToUpdateInput(ctx, scimGroup)
	if err != nil {
		t.Fatalf("ToUpdateInput() error = %v", err)
	}

	if input.Name == nil || *input.Name != "New Team Name" {
		t.Errorf("Name = %v, want %q", input.Name, "New Team Name")
	}
}

func TestGroupMapperToUpdateInputNil(t *testing.T) {
	mapper := NewGroupMapper(nil)
	ctx := context.Background()

	input, err := mapper.ToUpdateInput(ctx, nil)
	if err != nil {
		t.Fatalf("ToUpdateInput(nil) error = %v", err)
	}
	if input != nil {
		t.Error("ToUpdateInput(nil) should return nil")
	}
}

func TestGroupMapperApplyPatch(t *testing.T) {
	mapper := NewGroupMapper(nil)
	ctx := context.Background()

	orgID := uuid.MustParse("660e8400-e29b-41d4-a716-446655440000")
	org := &identity.OrganizationInfo{
		ID:   orgID,
		Name: "Old Name",
		Slug: "old-name",
	}

	ops := []patch.Operation{
		{Op: patch.OpReplace, Path: "displayName", Value: "New Name"},
	}

	input, memberOps, err := mapper.ApplyPatch(ctx, org, ops)
	if err != nil {
		t.Fatalf("ApplyPatch() error = %v", err)
	}

	if input.Name == nil || *input.Name != "New Name" {
		t.Errorf("Name = %v, want %q", input.Name, "New Name")
	}

	if len(memberOps) != 0 {
		t.Errorf("memberOps length = %d, want 0", len(memberOps))
	}
}

func TestGroupMapperApplyPatchAddMembers(t *testing.T) {
	mapper := NewGroupMapper(nil)
	ctx := context.Background()

	orgID := uuid.MustParse("660e8400-e29b-41d4-a716-446655440000")
	org := &identity.OrganizationInfo{
		ID:   orgID,
		Name: "Test Org",
	}

	userID := "550e8400-e29b-41d4-a716-446655440001"
	ops := []patch.Operation{
		{
			Op:   patch.OpAdd,
			Path: "members",
			Value: []any{
				map[string]any{"value": userID},
			},
		},
	}

	_, memberOps, err := mapper.ApplyPatch(ctx, org, ops)
	if err != nil {
		t.Fatalf("ApplyPatch() error = %v", err)
	}

	if len(memberOps) != 1 {
		t.Fatalf("memberOps length = %d, want 1", len(memberOps))
	}

	if memberOps[0].Op != patch.OpAdd {
		t.Errorf("memberOps[0].Op = %v, want %v", memberOps[0].Op, patch.OpAdd)
	}

	if memberOps[0].UserID.String() != userID {
		t.Errorf("memberOps[0].UserID = %v, want %v", memberOps[0].UserID, userID)
	}
}

func TestGroupMapperApplyPatchRemoveMembers(t *testing.T) {
	mapper := NewGroupMapper(nil)
	ctx := context.Background()

	orgID := uuid.MustParse("660e8400-e29b-41d4-a716-446655440000")
	org := &identity.OrganizationInfo{
		ID:   orgID,
		Name: "Test Org",
	}

	userID := "550e8400-e29b-41d4-a716-446655440001"
	ops := []patch.Operation{
		{
			Op:   patch.OpRemove,
			Path: "members[value eq \"" + userID + "\"]",
		},
	}

	_, memberOps, err := mapper.ApplyPatch(ctx, org, ops)
	if err != nil {
		t.Fatalf("ApplyPatch() error = %v", err)
	}

	if len(memberOps) != 1 {
		t.Fatalf("memberOps length = %d, want 1", len(memberOps))
	}

	if memberOps[0].Op != patch.OpRemove {
		t.Errorf("memberOps[0].Op = %v, want %v", memberOps[0].Op, patch.OpRemove)
	}

	if memberOps[0].UserID.String() != userID {
		t.Errorf("memberOps[0].UserID = %v, want %v", memberOps[0].UserID, userID)
	}
}

func TestParseGroupID(t *testing.T) {
	tests := []struct {
		name      string
		id        string
		wantError bool
	}{
		{
			name:      "valid UUID",
			id:        "660e8400-e29b-41d4-a716-446655440000",
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
			_, err := ParseGroupID(tt.id)
			if (err != nil) != tt.wantError {
				t.Errorf("ParseGroupID() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestGenerateSlug(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "simple name",
			input: "Engineering",
			want:  "engineering",
		},
		{
			name:  "name with spaces",
			input: "Engineering Team",
			want:  "engineering-team",
		},
		{
			name:  "name with mixed case",
			input: "DevOps Team",
			want:  "devops-team",
		},
		{
			name:  "name with numbers",
			input: "Team 42",
			want:  "team-42",
		},
		{
			name:  "name with special chars",
			input: "Test & Verification!",
			want:  "test--verification",
		},
		{
			name:  "already lowercase",
			input: "already-slug",
			want:  "already-slug",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := generateSlug(tt.input)
			if got != tt.want {
				t.Errorf("generateSlug(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestExtractMembers(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  []string
	}{
		{
			name: "array of members",
			value: []any{
				map[string]any{"value": "user1"},
				map[string]any{"value": "user2"},
			},
			want: []string{"user1", "user2"},
		},
		{
			name:  "single member map",
			value: map[string]any{"value": "user1"},
			want:  []string{"user1"},
		},
		{
			name:  "nil value",
			value: nil,
			want:  nil,
		},
		{
			name:  "empty array",
			value: []any{},
			want:  nil,
		},
		{
			name: "array with non-map items",
			value: []any{
				"not a map",
				map[string]any{"value": "user1"},
			},
			want: []string{"user1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractMembers(tt.value)
			if len(got) != len(tt.want) {
				t.Errorf("extractMembers() = %v, want %v", got, tt.want)
				return
			}
			for i, v := range got {
				if v != tt.want[i] {
					t.Errorf("extractMembers()[%d] = %q, want %q", i, v, tt.want[i])
				}
			}
		})
	}
}

func TestContainsMembersOp(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  bool
	}{
		{
			name:  "map with members",
			value: map[string]any{"members": []any{}},
			want:  true,
		},
		{
			name:  "map without members",
			value: map[string]any{"displayName": "Test"},
			want:  false,
		},
		{
			name:  "not a map",
			value: []any{},
			want:  false,
		},
		{
			name:  "nil",
			value: nil,
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsMembersOp(tt.value)
			if got != tt.want {
				t.Errorf("containsMembersOp() = %v, want %v", got, tt.want)
			}
		})
	}
}
