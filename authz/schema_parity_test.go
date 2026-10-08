package authz

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// schemaRoleGrants returns, for each relation of a definition in schema,
// the permissions it grants, resolving permissions defined in terms of
// other permissions. Arrow terms (x->y) are ignored.
func schemaRoleGrants(t *testing.T, schema, definition string) map[string][]Action {
	t.Helper()
	def := regexp.MustCompile(`(?s)definition ` + definition + ` \{(.*?)\n\}`).FindStringSubmatch(schema)
	if def == nil {
		t.Fatalf("definition %s not found", definition)
	}
	var relations []string
	for _, m := range regexp.MustCompile(`relation (\w+):`).FindAllStringSubmatch(def[1], -1) {
		relations = append(relations, m[1])
	}
	perms := map[string][]string{}
	for _, m := range regexp.MustCompile(`permission (\w+)\s*=\s*([\w +\->]+)`).FindAllStringSubmatch(def[1], -1) {
		for _, term := range strings.Split(m[2], "+") {
			if term = strings.TrimSpace(term); !strings.Contains(term, "->") {
				perms[m[1]] = append(perms[m[1]], term)
			}
		}
	}
	var grants func(relation, perm string, seen map[string]bool) bool
	grants = func(relation, perm string, seen map[string]bool) bool {
		if seen[perm] {
			return false
		}
		seen[perm] = true
		for _, term := range perms[perm] {
			if term == relation || grants(relation, term, seen) {
				return true
			}
		}
		return false
	}
	out := map[string][]Action{}
	for _, r := range relations {
		for p := range perms {
			if grants(r, p, map[string]bool{}) {
				out[r] = append(out[r], Action(p))
			}
		}
	}
	return out
}

func assertSameGrants(t *testing.T, fromSchema, fromGo map[string][]Action) {
	t.Helper()
	if len(fromSchema) != len(fromGo) {
		t.Fatalf("schema roles %v, Go roles %v", fromSchema, fromGo)
	}
	for role, perms := range fromGo {
		got, want := slices.Clone(fromSchema[role]), slices.Clone(perms)
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("role %s: schema %v, Go %v", role, got, want)
		}
	}
}

// TestOrgRolePermissionsMatchSchema keeps the simple provider's
// organization grants equal to the base schema's.
func TestOrgRolePermissionsMatchSchema(t *testing.T) {
	assertSameGrants(t, schemaRoleGrants(t, BaseSpiceDBSchema, "organization"), OrgRolePermissions)
}

// TestManagerRolePermissionsMatchSchema keeps the manager grants equal to
// the principal definition of the base schema.
func TestManagerRolePermissionsMatchSchema(t *testing.T) {
	assertSameGrants(t, schemaRoleGrants(t, BaseSpiceDBSchema, "principal"), ManagerRolePermissions)
}

func TestOrgRoleAllows(t *testing.T) {
	if !OrgRoleAllows("editor", PermOrgEdit) || OrgRoleAllows("member", PermOrgEdit) || OrgRoleAllows("admin", PermOrgDelete) {
		t.Error("organization role grants wrong")
	}
	if !IsOrgPermission(PermOrgView) || IsOrgPermission("read") {
		t.Error("IsOrgPermission wrong")
	}
}
