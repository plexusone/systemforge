package authz

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestValidateResourceRef(t *testing.T) {
	org := uuid.New()
	long := strings.Repeat("a", 1025)
	for name, tc := range map[string]struct {
		ref ResourceRef
		ok  bool
	}{
		"uuid id":          {ResourceRef{Type: "myapp_project", ID: uuid.NewString(), OrganizationID: org}, true},
		"slug id":          {ResourceRef{Type: "myapp_project", ID: "team/alpha-1_x|y=z+1", OrganizationID: org}, true},
		"underscored type": {ResourceRef{Type: "myapp_sub_item", ID: "1", OrganizationID: org}, true},
		"no app":           {ResourceRef{Type: "project", ID: "1", OrganizationID: org}, false},
		"uppercase":        {ResourceRef{Type: "MyApp_project", ID: "1", OrganizationID: org}, false},
		"empty id":         {ResourceRef{Type: "myapp_project", OrganizationID: org}, false},
		"space in id":      {ResourceRef{Type: "myapp_project", ID: "a b", OrganizationID: org}, false},
		"long id":          {ResourceRef{Type: "myapp_project", ID: long, OrganizationID: org}, false},
		"no organization":  {ResourceRef{Type: "myapp_project", ID: "1"}, false},
	} {
		err := ValidateResourceRef(tc.ref)
		if (err == nil) != tc.ok || (err != nil && !errors.Is(err, ErrInvalidResource)) {
			t.Errorf("%s: ValidateResourceRef = %v, want ok=%v", name, err, tc.ok)
		}
	}
}

func TestRegistryValidateResourceType(t *testing.T) {
	r := NewVocabularyRegistry()
	if err := r.Register(testVocab{app: "myapp", roles: RolePermissions{"admin": {"x.y"}}, hier: RoleHierarchy{"admin": 1}}); err != nil {
		t.Fatal(err)
	}
	if err := r.ValidateResourceType("myapp_project"); err != nil {
		t.Errorf("registered application: %v", err)
	}
	for _, typ := range []string{"other_project", "project", "myapp", ""} {
		if err := r.ValidateResourceType(typ); !errors.Is(err, ErrInvalidResource) {
			t.Errorf("ValidateResourceType(%q) = %v, want ErrInvalidResource", typ, err)
		}
	}
	if got := ResourceApp("myapp_sub_item"); got != "myapp" {
		t.Errorf("ResourceApp = %q", got)
	}
}

func TestResourceRefOf(t *testing.T) {
	id, org := uuid.New(), uuid.New()
	ref, ok := ResourceRefOf(Resource{Type: "myapp_project", ID: &id, OrgID: &org})
	if !ok || ref.Type != "myapp_project" || ref.ID != id.String() || ref.OrganizationID != org {
		t.Errorf("ResourceRefOf = %+v, %v", ref, ok)
	}
	if _, ok := ResourceRefOf(Resource{Type: "myapp_project"}); ok {
		t.Error("ResourceRefOf accepted a resource with no ID")
	}
}

func TestValidateAppSchemaResourceRoles(t *testing.T) {
	good := ResourceRoleFragment("myapp_project")
	if err := ValidateAppSchema("myapp", good); err != nil {
		t.Errorf("standard fragment: %v", err)
	}
	for name, tc := range map[string]struct {
		schema string
		want   string
	}{
		"partial ladder": {
			schema: `definition myapp_doc {
    relation org: organization
    relation viewer: principal
    relation editor: principal
}`,
			want: "must be declared together",
		},
		"two of three": {
			schema: `definition myapp_doc { relation org: organization relation viewer: principal relation maintainer: principal }`,
			want:   "contributor",
		},
		"bound to a group": {
			schema: `definition myapp_doc {
    relation org: organization
    relation viewer: principal | myapp_team#member
    relation contributor: principal
    relation maintainer: principal
}`,
			want: "of type principal",
		},
		"no org": {
			schema: `definition myapp_doc {
    relation viewer: principal
    relation contributor: principal
    relation maintainer: principal
}`,
			want: "org: organization",
		},
		"org of the wrong type": {
			schema: `definition myapp_doc {
    relation org: myapp_org
    relation viewer: principal
    relation contributor: principal
    relation maintainer: principal
}`,
			want: "org: organization",
		},
	} {
		err := ValidateAppSchema("myapp", tc.schema)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want it to mention %q", name, err, tc.want)
		}
	}
	// A definition that does not use the reserved names is unaffected, and
	// comments do not count.
	plain := `definition myapp_org {
    relation org: organization
    // relation viewer: principal
    relation approver: principal
}`
	if err := ValidateAppSchema("myapp", plain); err != nil {
		t.Errorf("plain facet: %v", err)
	}
	if got := CollaboratorDefinitions(plain + "\n" + good); len(got) != 1 || got[0] != "myapp_project" {
		t.Errorf("CollaboratorDefinitions = %v", got)
	}
}

func TestRegistryResourceTypesFollowFragment(t *testing.T) {
	r := NewVocabularyRegistry()
	frag := ResourceRoleFragment("myapp_project") + "\ndefinition myapp_org {\n    relation org: organization\n}\n"
	if err := r.Register(testVocab{app: "myapp", roles: RolePermissions{"admin": {"x.y"}}, hier: RoleHierarchy{"admin": 1}, schema: frag}); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(testVocab{app: "plain", roles: RolePermissions{"admin": {"x.y"}}, hier: RoleHierarchy{"admin": 1}}); err != nil {
		t.Fatal(err)
	}
	if err := r.ValidateResourceType("myapp_project"); err != nil {
		t.Errorf("declared type: %v", err)
	}
	if err := r.ValidateResourceType("myapp_org"); !errors.Is(err, ErrInvalidResource) {
		t.Errorf("a definition without the ladder = %v, want ErrInvalidResource", err)
	}
	if err := r.ValidateResourceType("myapp_unknown"); !errors.Is(err, ErrInvalidResource) {
		t.Errorf("an undeclared type = %v, want ErrInvalidResource", err)
	}
	// An application with no fragment supports only the role-based
	// provider, where any of its types is accepted.
	if err := r.ValidateResourceType("plain_thing"); err != nil {
		t.Errorf("fragment-less application: %v", err)
	}
	if got := r.CollaboratorResourceTypes("myapp"); len(got) != 1 || got[0] != "myapp_project" {
		t.Errorf("CollaboratorResourceTypes = %v", got)
	}
	if got := r.CollaboratorResourceTypes("plain"); len(got) != 0 {
		t.Errorf("CollaboratorResourceTypes(plain) = %v", got)
	}
}
