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
