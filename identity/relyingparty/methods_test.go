package relyingparty

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// methodsHarness is a BFF over a fake SystemAuth that publishes published in
// its discovery document, with adjust applied to the BFF's configuration.
func methodsHarness(t *testing.T, published []string, adjust func(*BFFConfig)) *bffHarness {
	t.Helper()
	fake := newFakeSystemAuth(t)
	fake.signInMethods = published
	store := NewMemoryPrincipalStore()
	cfg := BFFConfig{Client: fake.client(t), Principals: store, Memberships: LocalMemberships(store)}
	if adjust != nil {
		adjust(&cfg)
	}
	b, err := NewBFF(cfg)
	if err != nil {
		t.Fatalf("NewBFF: %v", err)
	}
	return &bffHarness{t: t, fake: fake, store: store, bff: b}
}

func getMethods(t *testing.T, h *bffHarness, path string) ([]SignInMethod, *httptest.ResponseRecorder) {
	t.Helper()
	w := h.do(httptest.NewRequest(http.MethodGet, path, nil))
	var body struct {
		Methods []SignInMethod `json:"methods"`
	}
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("decoding %s: %v", w.Body.String(), err)
		}
	}
	return body.Methods, w
}

func TestMethodsComeFromSystemAuthDiscovery(t *testing.T) {
	h := methodsHarness(t, []string{"github", "google", "email"}, nil)
	methods, w := getMethods(t, h, "/bff/auth/methods")
	if w.Code != http.StatusOK || !strings.Contains(w.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("methods: %d %s", w.Code, w.Header().Get("Content-Type"))
	}
	want := []SignInMethod{
		{ID: "github", Name: "GitHub", Path: "/bff/auth/github"},
		{ID: "google", Name: "Google", Path: "/bff/auth/google"},
		{ID: "email", Name: "Email", Path: "/bff/auth/email"},
	}
	if len(methods) != len(want) {
		t.Fatalf("methods = %+v, want %+v", methods, want)
	}
	for i := range want {
		if methods[i] != want[i] {
			t.Errorf("method %d = %+v, want %+v", i, methods[i], want[i])
		}
	}
	// /auth/methods is the list, not a provider called "methods".
	if w.Code == http.StatusNotFound {
		t.Error("/auth/methods was treated as a provider")
	}
	// Every method it lists starts a sign-in with that method's hint.
	for _, m := range methods {
		u, _ := h.start(m.Path + "?return_to=%2F")
		if u.Query().Get("idp_hint") != m.ID {
			t.Errorf("%s starts with idp_hint %q", m.Path, u.Query().Get("idp_hint"))
		}
	}
}

func TestMethodsOnlyWhatTheDeploymentOffers(t *testing.T) {
	// A deployment with email only offers email only.
	h := methodsHarness(t, []string{"email"}, nil)
	methods, _ := getMethods(t, h, "/bff/auth/methods")
	if len(methods) != 1 || methods[0].ID != "email" {
		t.Fatalf("methods = %+v, want email only", methods)
	}
}

func TestMethodsConfigOverridesDiscovery(t *testing.T) {
	h := methodsHarness(t, []string{"github", "google"}, func(c *BFFConfig) { c.SignInMethods = []string{"email", "google"} })
	methods, _ := getMethods(t, h, "/bff/auth/methods")
	if len(methods) != 2 || methods[0].ID != "email" || methods[1].ID != "google" {
		t.Fatalf("methods = %+v, want the configured email, google", methods)
	}
}

func TestMethodsLeaveOutWhatTheBFFCannotStart(t *testing.T) {
	h := methodsHarness(t, []string{"github", "myspace", "github", "email", ""}, nil)
	methods, _ := getMethods(t, h, "/bff/auth/methods")
	var ids []string
	for _, m := range methods {
		ids = append(ids, m.ID)
	}
	if strings.Join(ids, ",") != "github,email" {
		t.Fatalf("methods = %v, want github,email (unknown and repeated ones left out, order kept)", ids)
	}
}

func TestMethodsAreAnEmptyListFromAnOlderSystemAuth(t *testing.T) {
	h := methodsHarness(t, nil, nil)
	w := h.do(httptest.NewRequest(http.MethodGet, "/bff/auth/methods", nil))
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != `{"methods":[]}` {
		t.Fatalf("methods from a SystemAuth that publishes none: %d %s, want {\"methods\":[]}", w.Code, w.Body.String())
	}
}

func TestMethodsFollowTheBasePath(t *testing.T) {
	h := methodsHarness(t, []string{"email"}, func(c *BFFConfig) { c.BasePath = "/api/bff" })
	methods, _ := getMethods(t, h, "/api/bff/auth/methods")
	if len(methods) != 1 || methods[0].Path != "/api/bff/auth/email" {
		t.Fatalf("methods = %+v, want a path under the base path", methods)
	}
}
