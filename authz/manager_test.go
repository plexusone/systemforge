package authz

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// TestManagerRolePermissionsMatchSchema verifies that the manager role
// permissions the simple provider uses are exactly those the principal
// definition of the base SpiceDB schema grants.
func TestManagerRolePermissionsMatchSchema(t *testing.T) {
	def := regexp.MustCompile(`(?s)definition principal \{(.*?)\n\}`).FindStringSubmatch(BaseSpiceDBSchema)
	if def == nil {
		t.Fatal("principal definition not found")
	}
	fromSchema := map[string][]Action{}
	for _, m := range regexp.MustCompile(`permission (\w+)\s*=\s*([\w +]+)`).FindAllStringSubmatch(def[1], -1) {
		for _, role := range strings.Split(m[2], "+") {
			role = strings.TrimSpace(role)
			fromSchema[role] = append(fromSchema[role], Action(m[1]))
		}
	}
	if len(fromSchema) != len(ManagerRolePermissions) {
		t.Fatalf("schema roles %v, Go roles %v", fromSchema, ManagerRolePermissions)
	}
	for role, perms := range ManagerRolePermissions {
		got := slices.Clone(fromSchema[role])
		want := slices.Clone(perms)
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("role %s: schema %v, Go %v", role, got, want)
		}
	}
}

func TestManagerRoleAllows(t *testing.T) {
	if !ManagerRoleAllows(ManagerRoleGuardian, PermManageAccount) {
		t.Error("guardian should manage the account")
	}
	if ManagerRoleAllows(ManagerRoleEducator, PermManageAccount) || ManagerRoleAllows(ManagerRoleEducator, PermManageManagers) {
		t.Error("educator should not manage the account or managers")
	}
	if ManagerRoleAllows("coach", PermViewProfile) {
		t.Error("unregistered role should grant nothing")
	}
}
