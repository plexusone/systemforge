package invite_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"

	"github.com/plexusone/systemforge/authz/rbac"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	entprincipal "github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/invite"
	"github.com/plexusone/systemforge/identity/organization"
	"github.com/plexusone/systemforge/identity/requestprincipal"
)

type inviteAPI struct {
	t      *testing.T
	db     *ent.Client
	orgs   organization.Service
	h      http.Handler
	org    *organization.Organization
	people map[string]uuid.UUID
}

func newInviteAPI(t *testing.T, optFns ...func(*ent.Client) invite.ServiceOption) *inviteAPI {
	t.Helper()
	ctx := context.Background()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	orgs := organization.NewService(db)
	a := &inviteAPI{t: t, db: db, orgs: orgs, people: map[string]uuid.UUID{}}
	for _, name := range []string{"owner", "admin", "member", "invitee", "other"} {
		p, err := db.Principal.Create().SetType(entprincipal.TypeHuman).SetIdentifier(name + "@example.com").SetDisplayName(name).Save(ctx)
		if err != nil {
			t.Fatalf("principal: %v", err)
		}
		if _, err := db.Human.Create().SetPrincipalID(p.ID).SetEmail(name + "@example.com").Save(ctx); err != nil {
			t.Fatalf("human: %v", err)
		}
		a.people[name] = p.ID
	}
	owner := a.people["owner"]
	org, err := orgs.Create(ctx, organization.CreateOrganizationInput{Name: "Acme", Slug: "acme", OrgType: organization.OrgTypeTeam, OwnerPrincipalID: &owner})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	a.org = org
	for name, role := range map[string]string{"admin": "admin", "member": "member"} {
		if _, err := orgs.AddMember(ctx, organization.AddMemberInput{OrganizationID: org.ID, PrincipalID: a.people[name], Role: role}); err != nil {
			t.Fatalf("AddMember: %v", err)
		}
	}
	var opts []invite.ServiceOption
	for _, fn := range optFns {
		opts = append(opts, fn(db))
	}
	cfg := invite.DefaultAPIConfig()
	cfg.Authorizer = rbac.New(rbac.WithRoleGetter(organization.MembershipRoleGetter(orgs)))
	a.h = invite.NewAPI(invite.NewService(db, "https://app.example.com", opts...), orgs, cfg)
	return a
}

func (a *inviteAPI) do(method, path, as string, body any) (int, []byte) {
	a.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			a.t.Fatalf("encode: %v", err)
		}
	}
	req := httptest.NewRequest(method, "/api/v1"+path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if as != "" {
		req = req.WithContext(requestprincipal.WithPrincipal(req.Context(), &requestprincipal.RequestPrincipal{PrincipalID: a.people[as].String()}))
	}
	w := httptest.NewRecorder()
	a.h.ServeHTTP(w, req)
	return w.Code, w.Body.Bytes()
}

// invite creates an invite as admin and returns its ID and token.
func (a *inviteAPI) invite(email string) (string, string) {
	a.t.Helper()
	code, body := a.do(http.MethodPost, "/organizations/acme/invites", "admin", map[string]any{"email": email, "role": "member"})
	if code >= 300 {
		a.t.Fatalf("create invite: %d %s", code, body)
	}
	var out struct {
		Invite struct {
			ID                 string `json:"id"`
			InviterPrincipalID string `json:"inviter_principal_id"`
		} `json:"invite"`
		InviteURL string `json:"invite_url"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		a.t.Fatalf("decode: %v", err)
	}
	if out.Invite.InviterPrincipalID != a.people["admin"].String() {
		a.t.Errorf("inviter = %s, want the caller", out.Invite.InviterPrincipalID)
	}
	// The token reaches the invitee only in the link.
	u, err := url.Parse(out.InviteURL)
	if err != nil {
		a.t.Fatalf("invite URL %q: %v", out.InviteURL, err)
	}
	return out.Invite.ID, path.Base(u.Path)
}

func TestInviteManagementAuthorization(t *testing.T) {
	a := newInviteAPI(t)
	id, _ := a.invite("invitee@example.com")

	for _, tc := range []struct {
		name, method, path, as string
		body                   any
		want                   int
	}{
		{"anonymous create", http.MethodPost, "/organizations/acme/invites", "", map[string]any{"email": "x@example.com", "role": "member"}, 401},
		{"member create", http.MethodPost, "/organizations/acme/invites", "member", map[string]any{"email": "x@example.com", "role": "member"}, 403},
		{"outsider create", http.MethodPost, "/organizations/acme/invites", "other", map[string]any{"email": "x@example.com", "role": "member"}, 404},
		{"admin invites owner", http.MethodPost, "/organizations/acme/invites", "admin", map[string]any{"email": "x@example.com", "role": "owner"}, 403},
		{"spoofed inviter", http.MethodPost, "/organizations/acme/invites", "admin", map[string]any{"email": "x@example.com", "role": "member", "inviter_principal_id": a.people["owner"].String()}, 403},
		{"member lists", http.MethodGet, "/organizations/acme/invites", "member", nil, 403},
		{"admin lists", http.MethodGet, "/organizations/acme/invites", "admin", nil, 200},
		{"member revokes", http.MethodDelete, "/organizations/acme/invites/" + id, "member", nil, 403},
	} {
		if code, body := a.do(tc.method, tc.path, tc.as, tc.body); code != tc.want {
			t.Errorf("%s: %d, want %d (%s)", tc.name, code, tc.want, body)
		}
	}

	// An invite of one organization cannot be managed through another.
	other := a.people["other"]
	if _, err := a.orgs.Create(context.Background(), organization.CreateOrganizationInput{Name: "Other", Slug: "other", OrgType: organization.OrgTypeTeam, OwnerPrincipalID: &other}); err != nil {
		t.Fatalf("Create other: %v", err)
	}
	if code, _ := a.do(http.MethodDelete, "/organizations/other/invites/"+id, "other", nil); code != http.StatusNotFound {
		t.Errorf("revoke through another organization: %d", code)
	}
	if code, body := a.do(http.MethodDelete, "/organizations/acme/invites/"+id, "admin", nil); code >= 300 {
		t.Errorf("admin revokes: %d %s", code, body)
	}
}

func TestAcceptInviteIsBoundToTheInvitee(t *testing.T) {
	ctx := context.Background()
	a := newInviteAPI(t)
	_, token := a.invite("Invitee@Example.com")

	// Someone else holding the link cannot accept or decline it, and may
	// not name the invitee either.
	if code, _ := a.do(http.MethodPost, "/invites/"+token+"/accept", "other", map[string]any{}); code != http.StatusNotFound {
		t.Errorf("accept by another principal: %d", code)
	}
	if code, _ := a.do(http.MethodPost, "/invites/"+token+"/decline", "other", nil); code != http.StatusNotFound {
		t.Errorf("decline by another principal: %d", code)
	}
	if code, _ := a.do(http.MethodPost, "/invites/"+token+"/accept", "invitee", map[string]any{"principal_id": a.people["other"].String()}); code != http.StatusForbidden {
		t.Errorf("accept naming someone else: %d", code)
	}
	if code, _ := a.do(http.MethodPost, "/invites/"+token+"/accept", "", map[string]any{}); code != http.StatusUnauthorized {
		t.Errorf("anonymous accept: %d", code)
	}

	// Pending invites are the caller's own.
	code, body := a.do(http.MethodGet, "/invites", "invitee", nil)
	var pending struct {
		Invites []struct{} `json:"invites"`
	}
	if err := json.Unmarshal(body, &pending); err != nil || code != http.StatusOK || len(pending.Invites) != 1 {
		t.Errorf("invitee pending: %d %s %v", code, body, err)
	}
	if code, _ := a.do(http.MethodGet, "/invites?email=invitee@example.com", "other", nil); code != http.StatusForbidden {
		t.Errorf("listing someone else's invites: %d", code)
	}

	if code, body := a.do(http.MethodPost, "/invites/"+token+"/accept", "invitee", map[string]any{}); code >= 300 {
		t.Fatalf("invitee accepts: %d %s", code, body)
	}
	if m, err := a.orgs.GetMembership(ctx, a.org.ID, a.people["invitee"]); err != nil || m.Role != "member" {
		t.Errorf("membership after accept = %+v, %v", m, err)
	}
}
