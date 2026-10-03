package mapper

import (
	"context"
	"testing"

	"github.com/plexusone/systemforge/identity/scim"
)

func TestExtensionMapperToSCIM(t *testing.T) {
	mapper := NewExtensionMapper(&Config{BaseURL: "https://example.com/scim/v2"})
	ctx := context.Background()

	ext := &EnterpriseExtension{
		EmployeeNumber: "EMP001",
		CostCenter:     "CC-123",
		Organization:   "Acme Corp",
		Division:       "Engineering",
		Department:     "Platform",
		ManagerID:      "550e8400-e29b-41d4-a716-446655440000",
	}

	enterprise := mapper.ToSCIM(ctx, ext)

	if enterprise.EmployeeNumber != "EMP001" {
		t.Errorf("EmployeeNumber = %q, want %q", enterprise.EmployeeNumber, "EMP001")
	}

	if enterprise.CostCenter != "CC-123" {
		t.Errorf("CostCenter = %q, want %q", enterprise.CostCenter, "CC-123")
	}

	if enterprise.Organization != "Acme Corp" {
		t.Errorf("Organization = %q, want %q", enterprise.Organization, "Acme Corp")
	}

	if enterprise.Division != "Engineering" {
		t.Errorf("Division = %q, want %q", enterprise.Division, "Engineering")
	}

	if enterprise.Department != "Platform" {
		t.Errorf("Department = %q, want %q", enterprise.Department, "Platform")
	}

	if enterprise.Manager == nil {
		t.Fatal("Manager should not be nil")
	}

	if enterprise.Manager.Value != "550e8400-e29b-41d4-a716-446655440000" {
		t.Errorf("Manager.Value = %q, want %q", enterprise.Manager.Value, "550e8400-e29b-41d4-a716-446655440000")
	}

	expectedRef := "https://example.com/scim/v2/Users/550e8400-e29b-41d4-a716-446655440000"
	if enterprise.Manager.Ref != expectedRef {
		t.Errorf("Manager.Ref = %q, want %q", enterprise.Manager.Ref, expectedRef)
	}
}

func TestExtensionMapperToSCIMNil(t *testing.T) {
	mapper := NewExtensionMapper(nil)
	ctx := context.Background()

	enterprise := mapper.ToSCIM(ctx, nil)
	if enterprise != nil {
		t.Error("ToSCIM(nil) should return nil")
	}
}

func TestExtensionMapperToSCIMWithoutManager(t *testing.T) {
	mapper := NewExtensionMapper(&Config{BaseURL: "https://example.com/scim/v2"})
	ctx := context.Background()

	ext := &EnterpriseExtension{
		EmployeeNumber: "EMP001",
		Department:     "Engineering",
	}

	enterprise := mapper.ToSCIM(ctx, ext)

	if enterprise.Manager != nil {
		t.Error("Manager should be nil when ManagerID is empty")
	}
}

func TestExtensionMapperFromSCIM(t *testing.T) {
	mapper := NewExtensionMapper(nil)
	ctx := context.Background()

	enterprise := &scim.EnterpriseUser{
		EmployeeNumber: "EMP002",
		CostCenter:     "CC-456",
		Organization:   "Tech Corp",
		Division:       "Product",
		Department:     "Backend",
		Manager: &scim.ManagerRef{
			Value: "660e8400-e29b-41d4-a716-446655440000",
			Ref:   "https://example.com/scim/v2/Users/660e8400-e29b-41d4-a716-446655440000",
		},
	}

	ext := mapper.FromSCIM(ctx, enterprise)

	if ext.EmployeeNumber != "EMP002" {
		t.Errorf("EmployeeNumber = %q, want %q", ext.EmployeeNumber, "EMP002")
	}

	if ext.CostCenter != "CC-456" {
		t.Errorf("CostCenter = %q, want %q", ext.CostCenter, "CC-456")
	}

	if ext.Organization != "Tech Corp" {
		t.Errorf("Organization = %q, want %q", ext.Organization, "Tech Corp")
	}

	if ext.Division != "Product" {
		t.Errorf("Division = %q, want %q", ext.Division, "Product")
	}

	if ext.Department != "Backend" {
		t.Errorf("Department = %q, want %q", ext.Department, "Backend")
	}

	if ext.ManagerID != "660e8400-e29b-41d4-a716-446655440000" {
		t.Errorf("ManagerID = %q, want %q", ext.ManagerID, "660e8400-e29b-41d4-a716-446655440000")
	}
}

func TestExtensionMapperFromSCIMNil(t *testing.T) {
	mapper := NewExtensionMapper(nil)
	ctx := context.Background()

	ext := mapper.FromSCIM(ctx, nil)
	if ext != nil {
		t.Error("FromSCIM(nil) should return nil")
	}
}

func TestExtensionMapperFromSCIMWithoutManager(t *testing.T) {
	mapper := NewExtensionMapper(nil)
	ctx := context.Background()

	enterprise := &scim.EnterpriseUser{
		EmployeeNumber: "EMP003",
	}

	ext := mapper.FromSCIM(ctx, enterprise)

	if ext.ManagerID != "" {
		t.Errorf("ManagerID = %q, want empty", ext.ManagerID)
	}
}

func TestExtensionMapperToMetadata(t *testing.T) {
	mapper := NewExtensionMapper(nil)

	ext := &EnterpriseExtension{
		EmployeeNumber: "EMP001",
		CostCenter:     "CC-123",
		Organization:   "Acme Corp",
		Division:       "Engineering",
		Department:     "Platform",
		ManagerID:      "550e8400-e29b-41d4-a716-446655440000",
	}

	metadata := mapper.ToMetadata(ext)

	if v, ok := metadata["employee_number"].(string); !ok || v != "EMP001" {
		t.Errorf("metadata[employee_number] = %v, want %q", metadata["employee_number"], "EMP001")
	}

	if v, ok := metadata["cost_center"].(string); !ok || v != "CC-123" {
		t.Errorf("metadata[cost_center] = %v, want %q", metadata["cost_center"], "CC-123")
	}

	if v, ok := metadata["organization"].(string); !ok || v != "Acme Corp" {
		t.Errorf("metadata[organization] = %v, want %q", metadata["organization"], "Acme Corp")
	}

	if v, ok := metadata["division"].(string); !ok || v != "Engineering" {
		t.Errorf("metadata[division] = %v, want %q", metadata["division"], "Engineering")
	}

	if v, ok := metadata["department"].(string); !ok || v != "Platform" {
		t.Errorf("metadata[department] = %v, want %q", metadata["department"], "Platform")
	}

	if v, ok := metadata["manager_id"].(string); !ok || v != "550e8400-e29b-41d4-a716-446655440000" {
		t.Errorf("metadata[manager_id] = %v, want %q", metadata["manager_id"], "550e8400-e29b-41d4-a716-446655440000")
	}
}

func TestExtensionMapperToMetadataNil(t *testing.T) {
	mapper := NewExtensionMapper(nil)

	metadata := mapper.ToMetadata(nil)
	if metadata != nil {
		t.Error("ToMetadata(nil) should return nil")
	}
}

func TestExtensionMapperToMetadataPartial(t *testing.T) {
	mapper := NewExtensionMapper(nil)

	ext := &EnterpriseExtension{
		EmployeeNumber: "EMP001",
		Department:     "Engineering",
	}

	metadata := mapper.ToMetadata(ext)

	// Should only contain set fields
	if len(metadata) != 2 {
		t.Errorf("metadata length = %d, want 2", len(metadata))
	}

	if _, ok := metadata["cost_center"]; ok {
		t.Error("metadata should not contain cost_center")
	}

	if _, ok := metadata["organization"]; ok {
		t.Error("metadata should not contain organization")
	}
}

func TestExtensionMapperFromMetadata(t *testing.T) {
	mapper := NewExtensionMapper(nil)

	metadata := map[string]any{
		"employee_number": "EMP001",
		"cost_center":     "CC-123",
		"organization":    "Acme Corp",
		"division":        "Engineering",
		"department":      "Platform",
		"manager_id":      "550e8400-e29b-41d4-a716-446655440000",
	}

	ext := mapper.FromMetadata(metadata)

	if ext.EmployeeNumber != "EMP001" {
		t.Errorf("EmployeeNumber = %q, want %q", ext.EmployeeNumber, "EMP001")
	}

	if ext.CostCenter != "CC-123" {
		t.Errorf("CostCenter = %q, want %q", ext.CostCenter, "CC-123")
	}

	if ext.Organization != "Acme Corp" {
		t.Errorf("Organization = %q, want %q", ext.Organization, "Acme Corp")
	}

	if ext.Division != "Engineering" {
		t.Errorf("Division = %q, want %q", ext.Division, "Engineering")
	}

	if ext.Department != "Platform" {
		t.Errorf("Department = %q, want %q", ext.Department, "Platform")
	}

	if ext.ManagerID != "550e8400-e29b-41d4-a716-446655440000" {
		t.Errorf("ManagerID = %q, want %q", ext.ManagerID, "550e8400-e29b-41d4-a716-446655440000")
	}
}

func TestExtensionMapperFromMetadataNil(t *testing.T) {
	mapper := NewExtensionMapper(nil)

	ext := mapper.FromMetadata(nil)
	if ext != nil {
		t.Error("FromMetadata(nil) should return nil")
	}
}

func TestExtensionMapperFromMetadataWrongTypes(t *testing.T) {
	mapper := NewExtensionMapper(nil)

	// Test with non-string values
	metadata := map[string]any{
		"employee_number": 123, // int instead of string
		"department":      "Engineering",
	}

	ext := mapper.FromMetadata(metadata)

	// employee_number should be empty since it's not a string
	if ext.EmployeeNumber != "" {
		t.Errorf("EmployeeNumber = %q, want empty (type mismatch)", ext.EmployeeNumber)
	}

	// department should still work
	if ext.Department != "Engineering" {
		t.Errorf("Department = %q, want %q", ext.Department, "Engineering")
	}
}

func TestEnterpriseExtensionIsEmpty(t *testing.T) {
	tests := []struct {
		name string
		ext  *EnterpriseExtension
		want bool
	}{
		{
			name: "nil extension",
			ext:  nil,
			want: true,
		},
		{
			name: "empty extension",
			ext:  &EnterpriseExtension{},
			want: true,
		},
		{
			name: "extension with employee number",
			ext:  &EnterpriseExtension{EmployeeNumber: "EMP001"},
			want: false,
		},
		{
			name: "extension with cost center",
			ext:  &EnterpriseExtension{CostCenter: "CC-123"},
			want: false,
		},
		{
			name: "extension with organization",
			ext:  &EnterpriseExtension{Organization: "Acme"},
			want: false,
		},
		{
			name: "extension with division",
			ext:  &EnterpriseExtension{Division: "Engineering"},
			want: false,
		},
		{
			name: "extension with department",
			ext:  &EnterpriseExtension{Department: "Platform"},
			want: false,
		},
		{
			name: "extension with manager",
			ext:  &EnterpriseExtension{ManagerID: "some-id"},
			want: false,
		},
		{
			name: "fully populated extension",
			ext: &EnterpriseExtension{
				EmployeeNumber: "EMP001",
				CostCenter:     "CC-123",
				Organization:   "Acme Corp",
				Division:       "Engineering",
				Department:     "Platform",
				ManagerID:      "some-id",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.ext.IsEmpty()
			if got != tt.want {
				t.Errorf("IsEmpty() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtensionRoundTrip(t *testing.T) {
	mapper := NewExtensionMapper(&Config{BaseURL: "https://example.com/scim/v2"})
	ctx := context.Background()

	original := &EnterpriseExtension{
		EmployeeNumber: "EMP001",
		CostCenter:     "CC-123",
		Organization:   "Acme Corp",
		Division:       "Engineering",
		Department:     "Platform",
		ManagerID:      "550e8400-e29b-41d4-a716-446655440000",
	}

	// Convert to SCIM
	enterprise := mapper.ToSCIM(ctx, original)

	// Convert back
	result := mapper.FromSCIM(ctx, enterprise)

	// Compare
	if result.EmployeeNumber != original.EmployeeNumber {
		t.Errorf("EmployeeNumber = %q, want %q", result.EmployeeNumber, original.EmployeeNumber)
	}
	if result.CostCenter != original.CostCenter {
		t.Errorf("CostCenter = %q, want %q", result.CostCenter, original.CostCenter)
	}
	if result.Organization != original.Organization {
		t.Errorf("Organization = %q, want %q", result.Organization, original.Organization)
	}
	if result.Division != original.Division {
		t.Errorf("Division = %q, want %q", result.Division, original.Division)
	}
	if result.Department != original.Department {
		t.Errorf("Department = %q, want %q", result.Department, original.Department)
	}
	if result.ManagerID != original.ManagerID {
		t.Errorf("ManagerID = %q, want %q", result.ManagerID, original.ManagerID)
	}
}

func TestMetadataRoundTrip(t *testing.T) {
	mapper := NewExtensionMapper(nil)

	original := &EnterpriseExtension{
		EmployeeNumber: "EMP001",
		CostCenter:     "CC-123",
		Organization:   "Acme Corp",
		Division:       "Engineering",
		Department:     "Platform",
		ManagerID:      "550e8400-e29b-41d4-a716-446655440000",
	}

	// Convert to metadata
	metadata := mapper.ToMetadata(original)

	// Convert back
	result := mapper.FromMetadata(metadata)

	// Compare
	if result.EmployeeNumber != original.EmployeeNumber {
		t.Errorf("EmployeeNumber = %q, want %q", result.EmployeeNumber, original.EmployeeNumber)
	}
	if result.CostCenter != original.CostCenter {
		t.Errorf("CostCenter = %q, want %q", result.CostCenter, original.CostCenter)
	}
	if result.Organization != original.Organization {
		t.Errorf("Organization = %q, want %q", result.Organization, original.Organization)
	}
	if result.Division != original.Division {
		t.Errorf("Division = %q, want %q", result.Division, original.Division)
	}
	if result.Department != original.Department {
		t.Errorf("Department = %q, want %q", result.Department, original.Department)
	}
	if result.ManagerID != original.ManagerID {
		t.Errorf("ManagerID = %q, want %q", result.ManagerID, original.ManagerID)
	}
}
