package systemauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/identity/approle"
	"github.com/plexusone/systemforge/identity/ent"
	entorg "github.com/plexusone/systemforge/identity/ent/organization"
	"github.com/plexusone/systemforge/identity/ent/principalmembership"
)

// notesVocab declares a two-role application ladder.
type notesVocab struct{}

func (notesVocab) App() string { return "notes" }
func (notesVocab) Roles() authz.RolePermissions {
	return authz.RolePermissions{"viewer": {"note.read"}, "admin": {"note.read", "note.admin"}}
}
func (notesVocab) Hierarchy() authz.RoleHierarchy {
	return authz.RoleHierarchy{"viewer": 10, "admin": 40}
}
func (notesVocab) Scopes() []string      { return []string{"notes:admin"} }
func (notesVocab) SpiceDBSchema() string { return "" }

type orgsFixture struct {
	s         *Server
	db        *ent.Client
	roles     *approle.Service
	sess      *http.Cookie
	principal uuid.UUID
	personal  *ent.Organization
	base      time.Time
}

func newOrgsFixture(t *testing.T) *orgsFixture {
	t.Helper()
	db := openTestEnt(t)
	reg := authz.NewVocabularyRegistry()
	if err := reg.Register(notesVocab{}); err != nil {
		t.Fatal(err)
	}
	roles := approle.NewService(db, reg, approle.EntitleAll(reg))
	f := newFakeGitHub(t)
	s, err := NewEmbedded(Config{
		Issuer: testIssuer,
		Clients: []ClientConfig{{
			ID: "spa", Type: "public", Name: "Example App",
			RedirectURIs:  []string{testRPCB},
			GrantTypes:    []string{"authorization_code", "refresh_token"},
			ResponseTypes: []string{"code"},
			Scopes:        []string{"openid", "profile", "email", "offline_access"},
		}},
		Features:    FeatureConfig{EnableJWTAccessTokens: true, RequirePKCE: true},
		SocialLogin: &SocialLoginConfig{},
	}, WithSocialConnector(f.connector()), WithPrincipalDirectory(NewEntPrincipalDirectory(db)),
		WithStorage(NewEntStorage(db, WithDefaultOwner(createTestOwner(t, db)))),
		WithOrgsSource(NewEntOrgsSource(db, roles)))
	if err != nil {
		t.Fatal(err)
	}
	of := &orgsFixture{s: s, db: db, roles: roles, base: time.Now().Add(-time.Hour)}
	of.sess = socialSession(t, s)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(of.sess)
	ls, err := s.CurrentLoginSession(req)
	if err != nil {
		t.Fatal(err)
	}
	of.principal = ls.PrincipalID
	of.personal = db.Organization.Query().Where(entorg.OrgTypeEQ(entorg.OrgTypePersonal)).OnlyX(context.Background())
	return of
}

// join adds the principal to a new organization, joined at base+offset.
func (f *orgsFixture) join(t *testing.T, slug, role string, offset time.Duration) *ent.Organization {
	t.Helper()
	ctx := context.Background()
	org, err := f.db.Organization.Create().SetName("Org " + slug).SetSlug(slug).SetOrgType(entorg.OrgTypeTeam).Save(ctx)
	if err != nil {
		t.Fatalf("create organization %s: %v", slug, err)
	}
	if _, err := f.db.PrincipalMembership.Create().SetPrincipalID(f.principal).SetOrganizationID(org.ID).
		SetRole(role).SetCreatedAt(f.base.Add(offset)).Save(ctx); err != nil {
		t.Fatalf("create membership %s: %v", slug, err)
	}
	return org
}

func (f *orgsFixture) tokens(t *testing.T, scope string) map[string]any {
	t.Helper()
	return exchangeCode(t, f.s, authorizeCode(t, f.s, scope, withCookie(f.sess)))
}

func orgsOf(t *testing.T, claims map[string]any) []map[string]any {
	t.Helper()
	raw, ok := claims["orgs"].([]any)
	if !ok {
		t.Fatalf("no orgs claim in %v", claims)
	}
	out := make([]map[string]any, len(raw))
	for i, r := range raw {
		out[i], _ = r.(map[string]any)
	}
	return out
}

func memberships(t *testing.T, s *Server, token, query string) (int, MembershipsResponse) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, MembershipsPath+query, nil)
	dpopAuth(t, token)(req)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	var out MembershipsResponse
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("memberships body: %v", err)
		}
	}
	return w.Code, out
}

func TestOrgsClaimShapes(t *testing.T) {
	f := newOrgsFixture(t)
	ctx := context.Background()
	team := f.join(t, "acme", "member", 0)
	f.join(t, "guest-org", "collaborator", time.Minute)
	if _, err := f.roles.Assign(ctx, approle.AssignInput{OrganizationID: team.ID, PrincipalID: f.principal, Application: "notes", Role: "viewer"}); err != nil {
		t.Fatalf("assign: %v", err)
	}

	tokens := f.tokens(t, "openid offline_access")
	access := verifyJWT(t, f.s, tokens["access_token"].(string))
	compact := orgsOf(t, access)
	if len(compact) != 3 || access["orgs_truncated"] != false {
		t.Fatalf("access token orgs = %v truncated=%v", compact, access["orgs_truncated"])
	}
	// Personal first, then newest membership first.
	if compact[0]["id"] != f.personal.ID.String() || compact[1]["role"] != "collaborator" || compact[2]["id"] != team.ID.String() {
		t.Errorf("order = %v", compact)
	}
	if compact[0]["role"] != "owner" || compact[0]["apps"].(map[string]any)["notes"] != "admin" {
		t.Errorf("owner of the personal organization = %v, want implicit admin", compact[0])
	}
	if apps := compact[1]["apps"].(map[string]any); len(apps) != 0 {
		t.Errorf("collaborator apps = %v, want none", apps)
	}
	if compact[2]["role"] != "member" || compact[2]["apps"].(map[string]any)["notes"] != "viewer" {
		t.Errorf("member = %v, want the assigned viewer role", compact[2])
	}
	for _, o := range compact {
		for _, k := range []string{"slug", "name", "type"} {
			if _, ok := o[k]; ok {
				t.Errorf("compact form carries %q: %v", k, o)
			}
		}
	}

	// The ID token and userinfo carry the full form, whatever the scope.
	idc := verifyJWT(t, f.s, tokens["id_token"].(string))
	full := orgsOf(t, idc)
	if len(full) != 3 || full[2]["slug"] != "acme" || full[2]["name"] != "Org acme" || full[2]["type"] != "team" || full[0]["type"] != "personal" {
		t.Errorf("id token orgs = %v", full)
	}
	w, info := userinfo(t, f.s, dpopAuth(t, tokens["access_token"].(string)), http.MethodGet, nil)
	if w.Code != http.StatusOK || len(orgsOf(t, info)) != 3 || orgsOf(t, info)[0]["slug"] == nil || info["orgs_truncated"] != false {
		t.Errorf("userinfo orgs: %d %v", w.Code, info)
	}
}

func TestOrgsClaimSkipsInactiveMemberships(t *testing.T) {
	f := newOrgsFixture(t)
	ctx := context.Background()
	inactive := f.join(t, "left", "member", 0)
	closed := f.join(t, "closed", "member", time.Minute)
	kept := f.join(t, "kept", "member", 2*time.Minute)
	f.db.PrincipalMembership.Update().
		Where(principalmembership.OrganizationID(inactive.ID)).SetActive(false).ExecX(ctx)
	f.db.Organization.UpdateOneID(closed.ID).SetActive(false).ExecX(ctx)

	res, err := NewEntOrgsSource(f.db, nil).OrgsClaim(ctx, f.principal, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Orgs) != 2 || res.Orgs[0].ID != f.personal.ID.String() || res.Orgs[1].ID != kept.ID.String() {
		t.Errorf("orgs = %+v, want the personal and kept organizations only", res.Orgs)
	}
	if res.Orgs[0].Apps == nil {
		t.Error("apps must be an empty map, not null")
	}
}

func TestOrgsClaimTruncationAndMembershipsPaging(t *testing.T) {
	f := newOrgsFixture(t)
	const extra = MaxOrgsInToken + 4 // plus the personal organization
	ids := map[string]bool{f.personal.ID.String(): true}
	for i := 0; i < extra; i++ {
		org := f.join(t, "team-"+uuid.NewString()[:8], "member", time.Duration(i)*time.Second)
		ids[org.ID.String()] = true
	}

	tokens := f.tokens(t, "openid")
	access := verifyJWT(t, f.s, tokens["access_token"].(string))
	if got := orgsOf(t, access); len(got) != MaxOrgsInToken || access["orgs_truncated"] != true {
		t.Errorf("access token carries %d orgs truncated=%v, want %d and true", len(got), access["orgs_truncated"], MaxOrgsInToken)
	}
	if got := orgsOf(t, verifyJWT(t, f.s, tokens["id_token"].(string))); len(got) != MaxOrgsInToken {
		t.Errorf("id token carries %d orgs, want %d", len(got), MaxOrgsInToken)
	}

	at := tokens["access_token"].(string)
	seen := map[string]bool{}
	query, pages := "?limit=20", 0
	for {
		code, page := memberships(t, f.s, at, query)
		if code != http.StatusOK {
			t.Fatalf("memberships%s: %d", query, code)
		}
		pages++
		for _, o := range page.Orgs {
			if seen[o.ID] {
				t.Fatalf("organization %s on two pages", o.ID)
			}
			if o.Slug == "" || o.Type == "" || o.Apps == nil {
				t.Errorf("memberships entry is not the full form: %+v", o)
			}
			seen[o.ID] = true
		}
		if page.NextCursor == "" {
			break
		}
		query = "?limit=20&cursor=" + url.QueryEscape(page.NextCursor)
	}
	if len(seen) != len(ids) || pages != 3 {
		t.Errorf("paged %d organizations in %d pages, want %d in 3", len(seen), pages, len(ids))
	}
	for id := range ids {
		if !seen[id] {
			t.Errorf("organization %s missing from the pages", id)
		}
	}

	if code, _ := memberships(t, f.s, at, "?cursor="+uuid.NewString()); code != http.StatusBadRequest {
		t.Errorf("unknown cursor: %d, want 400", code)
	}
	if code, _ := memberships(t, f.s, at, "?limit=0"); code != http.StatusBadRequest {
		t.Errorf("zero limit: %d, want 400", code)
	}
	if code, _ := memberships(t, f.s, "not-a-token", ""); code != http.StatusUnauthorized {
		t.Errorf("bad token: %d, want 401", code)
	}
	req := httptest.NewRequest(http.MethodGet, MembershipsPath, nil)
	w := httptest.NewRecorder()
	f.s.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("no token: %d, want 401", w.Code)
	}
}

func TestOrgsClaimRefreshCarriesCurrentRoles(t *testing.T) {
	f := newOrgsFixture(t)
	ctx := context.Background()
	team := f.join(t, "acme", "member", 0)
	if _, err := f.roles.Assign(ctx, approle.AssignInput{OrganizationID: team.ID, PrincipalID: f.principal, Application: "notes", Role: "viewer"}); err != nil {
		t.Fatal(err)
	}
	tokens := f.tokens(t, "openid offline_access")

	if _, err := f.roles.Change(ctx, approle.AssignInput{OrganizationID: team.ID, PrincipalID: f.principal, Application: "notes", Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	status, refreshed := refresh(t, f.s, tokens["refresh_token"].(string))
	if status != http.StatusOK {
		t.Fatalf("refresh: %d %v", status, refreshed)
	}
	for name, raw := range map[string]string{"access": refreshed["access_token"].(string), "id": refreshed["id_token"].(string)} {
		var got string
		for _, o := range orgsOf(t, verifyJWT(t, f.s, raw)) {
			if o["id"] == team.ID.String() {
				got, _ = o["apps"].(map[string]any)["notes"].(string)
			}
		}
		if got != "admin" {
			t.Errorf("refreshed %s token has notes role %q, want admin", name, got)
		}
	}

	// Removing the membership drops the organization at the next refresh.
	f.db.PrincipalMembership.Delete().Where(principalmembership.OrganizationID(team.ID)).ExecX(ctx)
	status, again := refresh(t, f.s, refreshed["refresh_token"].(string))
	if status != http.StatusOK {
		t.Fatalf("second refresh: %d %v", status, again)
	}
	for _, o := range orgsOf(t, verifyJWT(t, f.s, again["access_token"].(string))) {
		if o["id"] == team.ID.String() {
			t.Errorf("removed organization still in the access token: %v", o)
		}
	}
}

func TestNoOrgsClaimWithoutSource(t *testing.T) {
	s := newSocialFlowServer(t, PartyFirst)
	sess := socialSession(t, s)
	tokens := exchangeCode(t, s, authorizeCode(t, s, "openid", withCookie(sess)))
	if got := verifyJWTOrOpaque(t, s, tokens); got != nil {
		t.Errorf("orgs claim without a source: %v", got)
	}
	if w, info := userinfo(t, s, dpopAuth(t, tokens["access_token"].(string)), http.MethodGet, nil); w.Code != http.StatusOK || info["orgs"] != nil {
		t.Errorf("userinfo = %d %v", w.Code, info)
	}
	if code, _ := memberships(t, s, tokens["access_token"].(string), ""); code != http.StatusNotImplemented {
		t.Errorf("memberships without a source: %d, want 501", code)
	}
}

func verifyJWTOrOpaque(t *testing.T, s *Server, tokens map[string]any) any {
	t.Helper()
	return verifyJWT(t, s, tokens["id_token"].(string))["orgs"]
}
