package organization_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz/rbac"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	"github.com/plexusone/systemforge/identity/organization"
	"github.com/plexusone/systemforge/identity/requestprincipal"
)

// memberAuthorizer authorizes from real memberships, with optional
// platform administrators.
func memberAuthorizer(svc organization.Service, admins ...uuid.UUID) *rbac.Provider {
	return rbac.New(
		rbac.WithRoleGetter(organization.MembershipRoleGetter(svc)),
		rbac.WithPlatformAdminChecker(func(_ context.Context, pid uuid.UUID) (bool, error) {
			for _, a := range admins {
				if a == pid {
					return true, nil
				}
			}
			return false, nil
		}),
	)
}

type orgAPI struct {
	t   *testing.T
	db  *ent.Client
	svc organization.Service
	h   http.Handler
}

func newOrgAPI(t *testing.T, admins ...uuid.UUID) *orgAPI {
	t.Helper()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	svc := organization.NewService(db)
	cfg := organization.DefaultAPIConfig()
	cfg.Authorizer = memberAuthorizer(svc, admins...)
	return &orgAPI{t: t, db: db, svc: svc, h: organization.NewAPI(svc, cfg)}
}

func (a *orgAPI) do(method, path string, as uuid.UUID, body any) (int, []byte) {
	a.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			a.t.Fatalf("encode: %v", err)
		}
	}
	req := httptest.NewRequest(method, "/api/v1"+path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if as != uuid.Nil {
		req = req.WithContext(requestprincipal.WithPrincipal(req.Context(), &requestprincipal.RequestPrincipal{PrincipalID: as.String()}))
	}
	w := httptest.NewRecorder()
	a.h.ServeHTTP(w, req)
	return w.Code, w.Body.Bytes()
}

func TestOrganizationAPIAuthorization(t *testing.T) {
	ctx := context.Background()
	api := newOrgAPI(t)
	owner := newHuman(t, api.db, "owner@example.com")
	admin := newHuman(t, api.db, "admin@example.com")
	member := newHuman(t, api.db, "member@example.com")
	outsider := newHuman(t, api.db, "outsider@example.com")

	// Creating makes the caller the owner, with an owner membership.
	if code, body := api.do(http.MethodPost, "/organizations", uuid.Nil, map[string]any{"name": "Acme", "slug": "acme"}); code != http.StatusUnauthorized {
		t.Fatalf("anonymous create: %d %s", code, body)
	}
	if code, body := api.do(http.MethodPost, "/organizations", owner, map[string]any{"name": "Acme", "slug": "acme"}); code >= 300 {
		t.Fatalf("create: %d %s", code, body)
	}
	org, err := api.svc.GetBySlug(ctx, "acme")
	if err != nil {
		t.Fatalf("GetBySlug: %v", err)
	}
	if m, err := api.svc.GetMembership(ctx, org.ID, owner); err != nil || m.Role != organization.RoleOwner {
		t.Fatalf("owner membership = %+v, %v", m, err)
	}

	// Members join by invitation; the fixture adds them directly.
	for who, role := range map[uuid.UUID]string{admin: "admin", member: "member"} {
		if _, err := api.svc.AddMember(ctx, organization.AddMemberInput{OrganizationID: org.ID, PrincipalID: who, Role: role}); err != nil {
			t.Fatalf("AddMember: %v", err)
		}
	}

	for _, tc := range []struct {
		name   string
		method string
		path   string
		as     uuid.UUID
		body   any
		want   int
	}{
		{"outsider get", http.MethodGet, "/organizations/acme", outsider, nil, 404},
		{"anonymous get", http.MethodGet, "/organizations/acme", uuid.Nil, nil, 401},
		{"member get", http.MethodGet, "/organizations/acme", member, nil, 200},
		{"member lists members", http.MethodGet, "/organizations/acme/members", member, nil, 200},
		{"outsider lists members", http.MethodGet, "/organizations/acme/members", outsider, nil, 404},
		{"member updates", http.MethodPatch, "/organizations/acme", member, map[string]any{"name": "X"}, 403},
		{"admin updates", http.MethodPatch, "/organizations/acme", admin, map[string]any{"name": "Acme Inc"}, 200},
		{"member adds", http.MethodPost, "/organizations/acme/members", member, map[string]any{"principal_id": outsider.String(), "role": "member"}, 403},
		{"admin adds owner", http.MethodPost, "/organizations/acme/members", admin, map[string]any{"principal_id": outsider.String(), "role": "owner"}, 403},
		{"admin promotes to owner", http.MethodPatch, "/organizations/acme/members/" + member.String(), admin, map[string]any{"role": "owner"}, 403},
		{"admin demotes owner", http.MethodPatch, "/organizations/acme/members/" + owner.String(), admin, map[string]any{"role": "member"}, 403},
		{"admin removes owner", http.MethodDelete, "/organizations/acme/members/" + owner.String(), admin, nil, 403},
		{"member removes admin", http.MethodDelete, "/organizations/acme/members/" + admin.String(), member, nil, 403},
		{"admin transfers ownership", http.MethodPost, "/organizations/acme/transfer-ownership", admin, map[string]any{"new_owner_principal_id": admin.String()}, 403},
		{"admin deletes", http.MethodDelete, "/organizations/acme", admin, nil, 403},
	} {
		if code, body := api.do(tc.method, tc.path, tc.as, tc.body); code != tc.want {
			t.Errorf("%s: %d, want %d (%s)", tc.name, code, tc.want, body)
		}
	}

	// Members may leave.
	if code, body := api.do(http.MethodDelete, "/organizations/acme/members/"+member.String(), member, nil); code >= 300 {
		t.Errorf("member leaves: %d %s", code, body)
	}

	// Listing shows the caller's organizations only.
	if _, err := api.svc.Create(ctx, organization.CreateOrganizationInput{Name: "Other", Slug: "other", OrgType: organization.OrgTypeTeam, OwnerPrincipalID: &outsider}); err != nil {
		t.Fatalf("Create other: %v", err)
	}
	listed := func(as uuid.UUID) []string {
		code, body := api.do(http.MethodGet, "/organizations", as, nil)
		if code != http.StatusOK {
			t.Fatalf("list: %d %s", code, body)
		}
		var out struct {
			Organizations []struct {
				Slug string `json:"slug"`
			} `json:"organizations"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		var slugs []string
		for _, o := range out.Organizations {
			slugs = append(slugs, o.Slug)
		}
		return slugs
	}
	if got := listed(admin); len(got) != 1 || got[0] != "acme" {
		t.Errorf("admin lists %v, want [acme]", got)
	}

	// The owner may transfer ownership and delete.
	if code, body := api.do(http.MethodPost, "/organizations/acme/transfer-ownership", owner, map[string]any{"new_owner_principal_id": admin.String(), "new_role_for_old_owner": "admin"}); code >= 300 {
		t.Errorf("owner transfers: %d %s", code, body)
	}
}

func TestPlatformAdminListsAllOrganizations(t *testing.T) {
	ctx := context.Background()
	admin := uuid.New()
	api := newOrgAPI(t, admin)
	for _, slug := range []string{"one", "two"} {
		if _, err := api.svc.Create(ctx, organization.CreateOrganizationInput{Name: slug, Slug: slug, OrgType: organization.OrgTypeTeam}); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}
	code, body := api.do(http.MethodGet, "/organizations", admin, nil)
	var out struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal(body, &out); err != nil || code != http.StatusOK || out.Total != 2 {
		t.Errorf("platform admin list: %d %s %v", code, body, err)
	}
}

func TestOrganizationAPIFailsClosed(t *testing.T) {
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	api := &orgAPI{t: t, db: db, h: organization.NewAPI(organization.NewService(db), organization.DefaultAPIConfig())}
	if code, _ := api.do(http.MethodGet, "/organizations", uuid.New(), nil); code != http.StatusNotImplemented {
		t.Errorf("list without authorizer: %d", code)
	}
	if code, _ := api.do(http.MethodGet, "/organizations/acme", uuid.New(), nil); code != http.StatusNotImplemented {
		t.Errorf("get without authorizer: %d", code)
	}
}

// TestMembershipRoleGetterIgnoresInactive verifies that a deactivated
// membership grants no role.
func TestMembershipRoleGetterIgnoresInactive(t *testing.T) {
	ctx := context.Background()
	api := newOrgAPI(t)
	owner := newHuman(t, api.db, "o@example.com")
	org, err := api.svc.Create(ctx, organization.CreateOrganizationInput{Name: "A", Slug: "a-org", OrgType: organization.OrgTypeTeam, OwnerPrincipalID: &owner})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	roles := organization.MembershipRoleGetter(api.svc)
	if role, err := roles(ctx, owner, org.ID); err != nil || role != organization.RoleOwner {
		t.Fatalf("role = %q, %v", role, err)
	}
	m, err := api.svc.GetMembership(ctx, org.ID, owner)
	if err != nil {
		t.Fatalf("GetMembership: %v", err)
	}
	inactive := false
	if _, err := api.svc.UpdateMember(ctx, m.ID, organization.UpdateMemberInput{Active: &inactive}); err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	if role, err := roles(ctx, owner, org.ID); err != nil || role != "" {
		t.Errorf("deactivated role = %q, %v; want none", role, err)
	}
	if role, err := roles(ctx, uuid.New(), org.ID); err != nil || role != "" {
		t.Errorf("non-member role = %q, %v", role, err)
	}
}
