package contract

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plexusone/systemforge/authz"
)

// notesVocab declares a two-role application ladder.
type notesVocab struct{}

func (notesVocab) App() string { return "notes" }
func (notesVocab) Roles() authz.RolePermissions {
	return authz.RolePermissions{"admin": {"note.read", "note.admin"}, "viewer": {"note.read"}}
}
func (notesVocab) Hierarchy() authz.RoleHierarchy {
	return authz.RoleHierarchy{"viewer": 10, "admin": 40}
}
func (notesVocab) Scopes() []string      { return []string{"notes:note:read", "notes:admin"} }
func (notesVocab) SpiceDBSchema() string { return "" }

func newVocabAPI(t *testing.T, opts ...ProviderOption) *API {
	t.Helper()
	provider, err := NewProvider(&Config{
		AppID: "test-app", DisplayName: "Test", Version: "1", BaseURL: "/systemforge",
		Capabilities:                   []Capability{CapabilityRBAC},
		AllowUnauthenticatedStandalone: true,
	}, nil, opts...)
	if err != nil {
		t.Fatal(err)
	}
	api, err := NewAPI(provider)
	if err != nil {
		t.Fatal(err)
	}
	return api
}

func listVocabs(t *testing.T, api *API) (int, []Vocabulary) {
	t.Helper()
	w := httptest.NewRecorder()
	api.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/systemforge/policy/vocabularies", nil))
	var body struct {
		Vocabularies []Vocabulary `json:"vocabularies"`
	}
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("body: %v\n%s", err, w.Body.String())
		}
	}
	return w.Code, body.Vocabularies
}

func TestListVocabularies(t *testing.T) {
	reg := authz.NewVocabularyRegistry()
	if err := reg.Register(notesVocab{}); err != nil {
		t.Fatal(err)
	}
	code, got := listVocabs(t, newVocabAPI(t, WithVocabularies(reg)))
	if code != http.StatusOK || len(got) != 1 {
		t.Fatalf("GET vocabularies: %d %+v", code, got)
	}
	v := got[0]
	if v.App != "notes" || len(v.Roles) != 2 {
		t.Fatalf("vocabulary = %+v", v)
	}
	if v.Roles[0].ID != "viewer" || v.Roles[0].Level != 10 || v.Roles[1].ID != "admin" || v.Roles[1].Level != 40 {
		t.Errorf("roles not ordered by level: %+v", v.Roles)
	}
	if len(v.Roles[1].Permissions) != 2 || v.Roles[1].Permissions[0] != "note.admin" {
		t.Errorf("admin permissions = %v, want sorted [note.admin note.read]", v.Roles[1].Permissions)
	}
	if len(v.Permissions) != 2 || v.Permissions[0] != "note.admin" || v.Permissions[1] != "note.read" {
		t.Errorf("permissions = %v", v.Permissions)
	}
	if len(v.Scopes) != 2 || v.Scopes[0] != "notes:admin" {
		t.Errorf("scopes = %v", v.Scopes)
	}

	// Without vocabularies the list is empty, not null.
	code, got = listVocabs(t, newVocabAPI(t))
	if code != http.StatusOK || got == nil || len(got) != 0 {
		t.Errorf("no registry: %d %v", code, got)
	}
}

func TestListVocabulariesNeedsPolicyRead(t *testing.T) {
	api := newStandaloneTestAPI(t, false)
	if got := get(api, "/systemforge/policy/vocabularies"); got != http.StatusForbidden {
		t.Errorf("GET vocabularies = %d, want %d", got, http.StatusForbidden)
	}
}
