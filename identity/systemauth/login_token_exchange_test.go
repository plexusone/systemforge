package systemauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/credential"
	"github.com/plexusone/systemforge/identity/ent"
	entprincipal "github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/session/ratelimit"
)

type loginTokenFixture struct {
	db    *ent.Client
	srv   *Server
	creds credential.Service
}

func newLoginTokenFixture(t *testing.T, opts ...Option) *loginTokenFixture {
	t.Helper()
	db := openTestEnt(t)
	storage := NewEntStorage(db, WithDefaultOwner(createTestOwner(t, db)))
	opts = append([]Option{
		WithStorage(storage),
		WithLoginTokenRateLimit(ratelimit.NewMemoryStorage(), ratelimit.PerMinute(1000), ratelimit.PerMinute(1000)),
	}, opts...)
	srv, err := NewEmbedded(Config{
		Issuer:            testIssuer,
		Clients:           []ClientConfig{managedClient("learning", true), managedClient("ordinary", false)},
		ManagedPrincipals: &ManagedPrincipalsConfig{Enabled: true},
	}, opts...)
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	return &loginTokenFixture{db: db, srv: srv, creds: credential.NewService(db)}
}

// managedHuman creates a human principal without an email.
func (f *loginTokenFixture) managedHuman(t *testing.T) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	id := uuid.New()
	if _, err := f.db.Principal.Create().SetID(id).SetType(entprincipal.TypeHuman).
		SetIdentifier("human:" + id.String()).SetDisplayName("Learner").Save(ctx); err != nil {
		t.Fatalf("principal: %v", err)
	}
	if _, err := f.db.Human.Create().SetPrincipalID(id).Save(ctx); err != nil {
		t.Fatalf("human: %v", err)
	}
	return id
}

func (f *loginTokenFixture) issue(t *testing.T, principalID uuid.UUID, singleUse bool) string {
	t.Helper()
	tok, err := f.creds.IssueLoginToken(context.Background(), credential.IssueLoginTokenInput{
		PrincipalID: principalID, IssuedBy: uuid.New(), ExpiresAt: time.Now().Add(time.Hour), SingleUse: singleUse,
	})
	if err != nil {
		t.Fatalf("IssueLoginToken: %v", err)
	}
	return tok.PlainToken
}

func postLoginToken(s *Server, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, LoginTokenPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "198.51.100.7:4242"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	return w
}

func TestLoginTokenExchange(t *testing.T) {
	ctx := context.Background()
	f := newLoginTokenFixture(t)
	learner := f.managedHuman(t)
	plain := f.issue(t, learner, false)

	w := postLoginToken(f.srv, url.Values{"token": {plain}, "client_id": {"learning"}, "return_to": {"/play"}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/play" {
		t.Fatalf("status %d location %q body %q", w.Code, w.Header().Get("Location"), w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Error("response is cacheable")
	}
	cookie := findCookie(t, w.Result(), LoginCookieName)
	if cookie == nil || !cookie.HttpOnly || !cookie.Secure {
		t.Fatalf("session cookie = %+v", cookie)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	sess, err := f.srv.CurrentLoginSession(req)
	if err != nil || sess.PrincipalID != learner || sess.Provider != loginTokenProvider {
		t.Fatalf("session = %+v, %v", sess, err)
	}

	// Reusable tokens work again, and default to the default target.
	w = postLoginToken(f.srv, url.Values{"token": {plain}, "client_id": {"learning"}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" {
		t.Errorf("second use: status %d location %q", w.Code, w.Header().Get("Location"))
	}

	// The use is recorded on the credential.
	row, err := f.db.Credential.Query().Only(ctx)
	if err != nil || row.LastUsedAt == nil || row.LastUsedIP != "198.51.100.7" {
		t.Errorf("credential after use = %+v, %v", row, err)
	}

	// Without social providers there is no provider chooser.
	rec := httptest.NewRecorder()
	f.srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, LoginPath, nil))
	if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET %s without providers: status %d", LoginPath, rec.Code)
	}

	// An off-site return_to is refused.
	w = postLoginToken(f.srv, url.Values{"token": {plain}, "client_id": {"learning"}, "return_to": {"https://evil.example/"}})
	if w.Code != http.StatusBadRequest {
		t.Errorf("open redirect: status %d", w.Code)
	}
}

// TestLoginTokenExchangeFailuresAreIdentical verifies that every reason a
// token cannot be used produces the same response.
func TestLoginTokenExchangeFailuresAreIdentical(t *testing.T) {
	ctx := context.Background()
	f := newLoginTokenFixture(t)
	learner := f.managedHuman(t)
	good := f.issue(t, learner, false)

	expired := f.issue(t, learner, false)
	revoked := f.issue(t, learner, false)
	used := f.issue(t, learner, true)
	if w := postLoginToken(f.srv, url.Values{"token": {used}, "client_id": {"learning"}}); w.Code != http.StatusSeeOther {
		t.Fatalf("single use first: %d", w.Code)
	}
	rows, err := f.db.Credential.Query().All(ctx)
	if err != nil {
		t.Fatalf("credentials: %v", err)
	}
	for _, r := range rows {
		switch {
		case strings.HasPrefix(expired, r.Identifier):
			if err := f.db.Credential.UpdateOne(r).SetExpiresAt(time.Now().Add(-time.Minute)).Exec(ctx); err != nil {
				t.Fatalf("expire: %v", err)
			}
		case strings.HasPrefix(revoked, r.Identifier):
			if err := f.creds.Revoke(ctx, r.ID, "lost"); err != nil {
				t.Fatalf("revoke: %v", err)
			}
		}
	}
	inactiveLearner := f.managedHuman(t)
	inactive := f.issue(t, inactiveLearner, false)
	if err := f.db.Principal.UpdateOneID(inactiveLearner).SetActive(false).Exec(ctx); err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	adult := seedHuman(t, f.db, "adult@example.com", true)
	ofAdult := f.issue(t, adult, false)

	cases := map[string]url.Values{
		"unknown token":     {"token": {credential.LoginTokenPrefix + strings.Repeat("A", 52)}, "client_id": {"learning"}},
		"garbage":           {"token": {"hello"}, "client_id": {"learning"}},
		"missing token":     {"client_id": {"learning"}},
		"expired":           {"token": {expired}, "client_id": {"learning"}},
		"revoked":           {"token": {revoked}, "client_id": {"learning"}},
		"used single-use":   {"token": {used}, "client_id": {"learning"}},
		"inactive":          {"token": {inactive}, "client_id": {"learning"}},
		"principal w/email": {"token": {ofAdult}, "client_id": {"learning"}},
		"client not opted":  {"token": {good}, "client_id": {"ordinary"}},
		"unknown client":    {"token": {good}, "client_id": {"nope"}},
		"missing client":    {"token": {good}},
	}
	var want string
	for name, form := range cases {
		w := postLoginToken(f.srv, form)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s: status %d", name, w.Code)
		}
		if findCookie(t, w.Result(), LoginCookieName) != nil {
			t.Errorf("%s: session cookie set", name)
		}
		got := w.Body.String()
		if want == "" {
			want = got
		}
		if got != want {
			t.Errorf("%s: body %q differs from %q", name, got, want)
		}
	}
	// The rejected client check did not consume or touch the good token.
	if w := postLoginToken(f.srv, url.Values{"token": {good}, "client_id": {"learning"}}); w.Code != http.StatusSeeOther {
		t.Errorf("good token after failures: %d", w.Code)
	}
}

func TestLoginTokenExchangeRateLimit(t *testing.T) {
	f := newLoginTokenFixture(t, WithLoginTokenRateLimit(ratelimit.NewMemoryStorage(), ratelimit.PerMinute(2), ratelimit.PerMinute(1000)))
	form := url.Values{"token": {"nope"}, "client_id": {"learning"}}
	for i := range 2 {
		if w := postLoginToken(f.srv, form); w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status %d", i, w.Code)
		}
	}
	w := postLoginToken(f.srv, form)
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Errorf("limited: status %d retry-after %q", w.Code, w.Header().Get("Retry-After"))
	}

	// The per-client limit applies across addresses.
	g := newLoginTokenFixture(t, WithLoginTokenRateLimit(ratelimit.NewMemoryStorage(), ratelimit.PerMinute(1000), ratelimit.PerMinute(1)))
	if w := postLoginToken(g.srv, form); w.Code != http.StatusUnauthorized {
		t.Fatalf("first: %d", w.Code)
	}
	req := httptest.NewRequest(http.MethodPost, LoginTokenPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "203.0.113.9:1"
	rec := httptest.NewRecorder()
	g.srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("per-client limit from another address: %d", rec.Code)
	}
}

// TestLoginTokenEndpointRequiresManagedPrincipals verifies that the
// endpoint does not exist unless the deployment enables managed principals.
func TestLoginTokenEndpointRequiresManagedPrincipals(t *testing.T) {
	srv, err := NewEmbedded(Config{Issuer: testIssuer, Clients: []ClientConfig{managedClient("learning", true)}})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	w := postLoginToken(srv, url.Values{"token": {"x"}, "client_id": {"learning"}})
	if w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status %d, want not found", w.Code)
	}
}

// TestManagedClaims verifies that managed principals get the managed claim
// and no email claims, and everyone else keeps their email claims.
func TestManagedClaims(t *testing.T) {
	ctx := context.Background()
	f := newLoginTokenFixture(t)
	learner := f.managedHuman(t)
	adult := seedHuman(t, f.db, "adult@example.com", true)
	scopes := []string{"openid", "profile", "email"}

	got := f.srv.sessionProvider.GetUserClaims(ctx, learner.String(), scopes)
	if got[ManagedClaim] != true {
		t.Errorf("managed claims = %v, want managed", got)
	}
	if _, ok := got["email"]; ok {
		t.Errorf("managed claims include email: %v", got)
	}
	if _, ok := got["email_verified"]; ok {
		t.Errorf("managed claims include email_verified: %v", got)
	}
	info := UserInfoClaims(learner.String(), got, []string{"openid"})
	if info[ManagedClaim] != true {
		t.Errorf("userinfo without profile scope drops managed: %v", info)
	}

	got = f.srv.sessionProvider.GetUserClaims(ctx, adult.String(), scopes)
	if got["email"] != "adult@example.com" || got["email_verified"] != true {
		t.Errorf("adult claims = %v", got)
	}
	if _, ok := got[ManagedClaim]; ok {
		t.Errorf("adult claims include managed: %v", got)
	}
}
