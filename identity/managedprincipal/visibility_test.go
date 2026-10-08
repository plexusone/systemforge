package managedprincipal

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz/rbac"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/principaltoken"
	"github.com/plexusone/systemforge/identity/requestprincipal"
)

type visibilityFixture struct {
	db                                  *ent.Client
	svc                                 *Service
	rec                                 *recorder
	learner, teacher, parent, stranger  uuid.UUID
	oauthFamily, tokenFamily, loginSess uuid.UUID
	plain                               string
}

func newVisibilityFixture(t *testing.T) *visibilityFixture {
	t.Helper()
	ctx := context.Background()
	f := &visibilityFixture{db: openSQLite(t)}
	f.svc, f.rec = newService(t, f.db)
	f.teacher = addHuman(t, f.db, "teacher@example.com", true)
	f.parent = addHuman(t, f.db, "parent@example.com", true)
	f.stranger = addHuman(t, f.db, "stranger@example.com", true)
	var err error
	f.learner, err = f.svc.Create(ctx, CreateInput{DisplayName: "Learner", ClientID: client,
		Managers: []ManagerInput{{f.teacher, RoleEducator}, {f.parent, RoleGuardian}}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	tok, err := f.svc.IssueLoginToken(ctx, IssueLoginTokenInput{ManagedID: f.learner, ClientID: client, IssuedBy: f.teacher, Name: "card"})
	if err != nil {
		t.Fatalf("IssueLoginToken: %v", err)
	}
	f.plain = tok.PlainToken

	now := time.Now()
	sess, err := f.db.LoginSession.Create().SetTokenHash(uuid.NewString()).SetPrincipalID(f.learner).
		SetProvider("login_token").SetCreatedAt(now).SetExpiresAt(now.Add(time.Hour)).Save(ctx)
	if err != nil {
		t.Fatalf("login session: %v", err)
	}
	f.loginSess = sess.ID
	if _, err := f.db.LoginSession.Create().SetTokenHash(uuid.NewString()).SetPrincipalID(f.learner).
		SetCreatedAt(now.Add(-2 * time.Hour)).SetExpiresAt(now.Add(-time.Hour)).Save(ctx); err != nil {
		t.Fatalf("expired login session: %v", err)
	}

	app, err := f.db.OAuthApp.Create().SetClientID(client).SetName("Learning").SetOwnerID(f.parent).
		SetRedirectUris([]string{"https://app.example.com/cb"}).SetAllowedScopes([]string{"openid"}).
		SetAllowedGrants([]string{"authorization_code"}).SetAllowedResponseTypes([]string{"code"}).Save(ctx)
	if err != nil {
		t.Fatalf("oauth app: %v", err)
	}
	f.oauthFamily = uuid.New()
	for i := range 2 { // a refresh rotation: two tokens in one family
		if _, err := f.db.OAuthToken.Create().SetAppID(app.ID).SetSubject(f.learner.String()).
			SetAccessTokenSignature(uuid.NewString()).SetFamilyID(f.oauthFamily).
			SetAccessExpiresAt(now.Add(time.Duration(i+1) * time.Minute)).
			SetCreatedAt(now.Add(time.Duration(i) * time.Second)).Save(ctx); err != nil {
			t.Fatalf("oauth token: %v", err)
		}
	}
	f.tokenFamily = uuid.New()
	if _, err := f.db.PrincipalToken.Create().SetPrincipalID(f.learner).SetPrincipalType(principaltoken.PrincipalTypeHuman).
		SetAccessTokenSignature(uuid.NewString()).SetFamilyID(f.tokenFamily).
		SetAccessExpiresAt(now.Add(time.Hour)).SetCreatedAt(now).Save(ctx); err != nil {
		t.Fatalf("principal token: %v", err)
	}
	return f
}

func TestListAndRevoke(t *testing.T) {
	ctx := context.Background()
	f := newVisibilityFixture(t)

	tokens, err := f.svc.ListLoginTokens(ctx, f.teacher, f.learner)
	if err != nil || len(tokens) != 1 || tokens[0].Name != "card" {
		t.Fatalf("ListLoginTokens = %+v, %v", tokens, err)
	}
	sessions, err := f.svc.ListSessions(ctx, f.parent, f.learner)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	kinds := map[SessionKind]uuid.UUID{}
	for _, s := range sessions {
		if _, dup := kinds[s.Kind]; dup {
			t.Errorf("duplicate %s session: %+v", s.Kind, sessions)
		}
		kinds[s.Kind] = s.ID
	}
	want := map[SessionKind]uuid.UUID{SessionKindLogin: f.loginSess, SessionKindOAuth: f.oauthFamily, SessionKindToken: f.tokenFamily}
	if len(kinds) != len(want) {
		t.Fatalf("sessions = %+v", sessions)
	}
	for k, id := range want {
		if kinds[k] != id {
			t.Errorf("%s session = %v, want %v", k, kinds[k], id)
		}
	}
	for _, s := range sessions {
		if s.Kind == SessionKindOAuth && s.ClientID != client {
			t.Errorf("oauth session client = %q", s.ClientID)
		}
	}

	// Revoke one of each.
	if err := f.svc.RevokeLoginToken(ctx, f.teacher, f.learner, tokens[0].ID); err != nil {
		t.Fatalf("RevokeLoginToken: %v", err)
	}
	if err := f.svc.RevokeLoginToken(ctx, f.teacher, f.learner, tokens[0].ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoke twice = %v, want ErrNotFound", err)
	}
	if _, err := f.svc.creds.VerifyLoginToken(ctx, f.plain, ""); err == nil {
		t.Error("revoked login token still verifies")
	}
	for k, id := range want {
		if err := f.svc.RevokeSession(ctx, f.teacher, f.learner, k, id); err != nil {
			t.Errorf("RevokeSession(%s): %v", k, err)
		}
	}
	oauthTokens, err := f.db.OAuthToken.Query().All(ctx)
	if err != nil || len(oauthTokens) != 2 {
		t.Fatalf("oauth tokens = %d, %v", len(oauthTokens), err)
	}
	for _, tok := range oauthTokens {
		if !tok.Revoked {
			t.Error("an OAuth token of the revoked family is still live")
		}
	}
	if err := f.svc.RevokeSession(ctx, f.teacher, f.learner, "bogus", uuid.New()); !errors.Is(err, ErrNotFound) {
		t.Errorf("bogus kind = %v", err)
	}
	if left, err := f.svc.ListSessions(ctx, f.teacher, f.learner); err != nil || len(left) != 0 {
		t.Errorf("sessions after revocation = %+v, %v", left, err)
	}
	if left, err := f.svc.ListLoginTokens(ctx, f.teacher, f.learner); err != nil || len(left) != 0 {
		t.Errorf("tokens after revocation = %+v, %v", left, err)
	}

	revoked := 0
	for _, e := range f.rec.events {
		if e.EventType == EventTokenRevoked || e.EventType == EventSessionRevoked {
			revoked++
		}
	}
	if revoked != 4 {
		t.Errorf("revocation audit events = %d, want 4", revoked)
	}
}

func TestRevokeAll(t *testing.T) {
	ctx := context.Background()
	f := newVisibilityFixture(t)
	if err := f.svc.RevokeAll(ctx, f.parent, f.learner); err != nil {
		t.Fatalf("RevokeAll: %v", err)
	}
	if left, err := f.svc.ListSessions(ctx, f.parent, f.learner); err != nil || len(left) != 0 {
		t.Errorf("sessions = %+v, %v", left, err)
	}
	if left, err := f.svc.ListLoginTokens(ctx, f.parent, f.learner); err != nil || len(left) != 0 {
		t.Errorf("tokens = %+v, %v", left, err)
	}
	if n, err := f.db.LoginSession.Query().Count(ctx); err != nil || n != 0 {
		t.Errorf("login sessions = %d, %v", n, err)
	}
	last := f.rec.events[len(f.rec.events)-1]
	if last.EventType != EventAllRevoked || last.Details["oauth_tokens"] != 2 || last.Details["login_tokens"] != 1 {
		t.Errorf("audit = %+v", last)
	}
}

func TestVisibilityAuthorization(t *testing.T) {
	ctx := context.Background()
	f := newVisibilityFixture(t)
	adult := addHuman(t, f.db, "adult@example.com", true)

	for name, fn := range map[string]func(actor, managed uuid.UUID) error{
		"ListLoginTokens": func(a, m uuid.UUID) error { _, err := f.svc.ListLoginTokens(ctx, a, m); return err },
		"ListSessions":    func(a, m uuid.UUID) error { _, err := f.svc.ListSessions(ctx, a, m); return err },
		"RevokeLoginToken": func(a, m uuid.UUID) error {
			return f.svc.RevokeLoginToken(ctx, a, m, uuid.New())
		},
		"RevokeSession": func(a, m uuid.UUID) error {
			return f.svc.RevokeSession(ctx, a, m, SessionKindLogin, f.loginSess)
		},
		"RevokeAll": func(a, m uuid.UUID) error { return f.svc.RevokeAll(ctx, a, m) },
	} {
		if err := fn(f.stranger, f.learner); !errors.Is(err, ErrForbidden) {
			t.Errorf("%s by stranger = %v, want ErrForbidden", name, err)
		}
		if err := fn(f.learner, f.learner); !errors.Is(err, ErrForbidden) {
			t.Errorf("%s by the managed principal = %v, want ErrForbidden", name, err)
		}
		if err := fn(f.parent, adult); !errors.Is(err, ErrNotManaged) {
			t.Errorf("%s on a principal with an email = %v, want ErrNotManaged", name, err)
		}
	}
	// Nothing was revoked by the refused calls.
	if left, err := f.svc.ListSessions(ctx, f.parent, f.learner); err != nil || len(left) != 3 {
		t.Errorf("sessions = %d, %v; want 3", len(left), err)
	}

	// A configured authorizer replaces the default, here adding a
	// platform administrator.
	admin := addHuman(t, f.db, "admin@example.com", true)
	withAdmin := NewService(f.db, gate{client: true}, WithAuthorizer(rbac.New(
		rbac.WithManagerRoleGetter(f.svc.ManagerRoles),
		rbac.WithPlatformAdminChecker(func(_ context.Context, id uuid.UUID) (bool, error) { return id == admin, nil }),
	)))
	if _, err := withAdmin.ListSessions(ctx, admin, f.learner); err != nil {
		t.Errorf("platform admin ListSessions: %v", err)
	}
}

func TestHandler(t *testing.T) {
	f := newVisibilityFixture(t)
	h := NewHandler(f.svc)
	do := func(method, path string, actor string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		if actor != "" {
			req = req.WithContext(requestprincipal.WithPrincipal(req.Context(), &requestprincipal.RequestPrincipal{PrincipalID: actor}))
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	base := "/" + f.learner.String()

	w := do(http.MethodGet, base+"/login-tokens", f.teacher.String())
	if w.Code != http.StatusOK {
		t.Fatalf("list tokens: %d %s", w.Code, w.Body)
	}
	var tokens struct {
		LoginTokens []LoginTokenView `json:"login_tokens"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &tokens); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(tokens.LoginTokens) != 1 || tokens.LoginTokens[0].IssuedBy != f.teacher || len(tokens.LoginTokens[0].Prefix) != 12 {
		t.Errorf("tokens = %+v", tokens)
	}
	if strings.Contains(w.Body.String(), f.plain) {
		t.Error("response contains the token value")
	}

	w = do(http.MethodGet, base+"/sessions", f.parent.String())
	var sessions struct {
		Sessions []Session `json:"sessions"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &sessions); err != nil || w.Code != http.StatusOK || len(sessions.Sessions) != 3 {
		t.Fatalf("sessions: %d %s %v", w.Code, w.Body, err)
	}

	for _, tc := range []struct {
		name, method, path, actor string
		want                      int
	}{
		{"unauthenticated", http.MethodGet, base + "/sessions", "", http.StatusUnauthorized},
		{"foreign subject", http.MethodGet, base + "/sessions", "https://issuer.example|abc", http.StatusForbidden},
		{"stranger", http.MethodGet, base + "/sessions", f.stranger.String(), http.StatusForbidden},
		{"bad principal", http.MethodGet, "/not-a-uuid/sessions", f.parent.String(), http.StatusNotFound},
		{"unknown token", http.MethodDelete, base + "/login-tokens/" + uuid.NewString(), f.parent.String(), http.StatusNotFound},
		{"revoke session", http.MethodDelete, base + "/sessions/login/" + f.loginSess.String(), f.teacher.String(), http.StatusNoContent},
		{"revoke token", http.MethodDelete, base + "/login-tokens/" + tokens.LoginTokens[0].ID.String(), f.teacher.String(), http.StatusNoContent},
		{"revoke all", http.MethodPost, base + "/revoke-all", f.parent.String(), http.StatusNoContent},
	} {
		if w := do(tc.method, tc.path, tc.actor); w.Code != tc.want {
			t.Errorf("%s: status %d, want %d (%s)", tc.name, w.Code, tc.want, w.Body)
		}
	}
}
