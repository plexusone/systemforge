package authz

import "testing"

type facetVocab struct{ app, schema string }

func (v facetVocab) App() string              { return v.app }
func (v facetVocab) Roles() RolePermissions   { return RolePermissions{"admin": {"x.manage"}} }
func (v facetVocab) Hierarchy() RoleHierarchy { return RoleHierarchy{"admin": 10} }
func (v facetVocab) Scopes() []string         { return nil }
func (v facetVocab) SpiceDBSchema() string    { return v.schema }

func TestHasOrgFacet(t *testing.T) {
	r := NewVocabularyRegistry()
	for _, v := range []facetVocab{
		{"withfacet", "definition withfacet_org {\n    relation org: organization\n    relation admin: principal\n}\n"},
		{"nofacet", ResourceRoleFragment("nofacet_doc")},
		{"noschema", ""},
	} {
		if err := r.Register(v); err != nil {
			t.Fatalf("register %s: %v", v.app, err)
		}
	}
	for app, want := range map[string]bool{"withfacet": true, "nofacet": false, "noschema": false, "unknown": false} {
		if got := r.HasOrgFacet(app); got != want {
			t.Errorf("HasOrgFacet(%q) = %v, want %v", app, got, want)
		}
	}
}
