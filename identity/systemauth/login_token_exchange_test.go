package systemauth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/credential"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/managerrelationship"
	entprincipal "github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/session/clientaddr"
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

// managedHuman creates a human principal without an email and gives it a
// manager.
func (f *loginTokenFixture) managedHuman(t *testing.T) uuid.UUID {
	t.Helper()
	id := f.humanWithEmail(t, "")
	f.manage(t, id)
	return id
}

// humanWithEmail creates a human principal; an empty email creates one
// without.
func (f *loginTokenFixture) humanWithEmail(t *testing.T, email string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	id := uuid.New()
	identifier := "human:" + id.String()
	if email != "" {
		identifier = email
	}
	if _, err := f.db.Principal.Create().SetID(id).SetType(entprincipal.TypeHuman).
		SetIdentifier(identifier).SetDisplayName("Learner").Save(ctx); err != nil {
		t.Fatalf("principal: %v", err)
	}
	hc := f.db.Human.Create().SetPrincipalID(id)
	if email != "" {
		hc.SetEmail(email)
	}
	if _, err := hc.Save(ctx); err != nil {
		t.Fatalf("human: %v", err)
	}
	return id
}

// manage gives the principal an active guardian.
func (f *loginTokenFixture) manage(t *testing.T, id uuid.UUID) {
	t.Helper()
	guardian := f.humanWithEmail(t, uuid.NewString()+"@example.com")
	if err := f.db.ManagerRelationship.Create().SetManagedPrincipalID(id).SetManagerPrincipalID(guardian).SetRole("guardian").Exec(context.Background()); err != nil {
		t.Fatalf("relationship: %v", err)
	}
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
	req.Header.Set("Origin", testIssuer)
	req.RemoteAddr = "198.51.100.7:4242"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	return w
}

// TestLoginTokenExchangeRejectsCrossSiteForms verifies that a form posted
// from another site, or with no Origin or Referer, cannot exchange a token,
// so a hostile page cannot sign a visitor into an account it controls,
// and that the visitor's existing session is kept.
func TestLoginTokenExchangeRejectsCrossSiteForms(t *testing.T) {
	f := newLoginTokenFixture(t)
	learner := f.managedHuman(t)
	plain := f.issue(t, learner, false)
	victim := f.loginSession(t, seedHuman(t, f.db, "adult@example.com", true))

	for name, headers := range map[string]map[string]string{
		"foreign origin":  {"Origin": "https://evil.example"},
		"foreign referer": {"Referer": "https://evil.example/page"},
		"no origin":       {},
		"null origin":     {"Origin": "null"},
	} {
		form := url.Values{"token": {plain}, "client_id": {"learning"}}
		req := httptest.NewRequest(http.MethodPost, LoginTokenPath, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		req.AddCookie(victim)
		w := httptest.NewRecorder()
		f.srv.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403", name, w.Code)
		}
		if len(w.Result().Cookies()) != 0 {
			t.Errorf("%s: response sets cookies %v", name, w.Result().Cookies())
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(victim)
	if _, err := f.srv.CurrentLoginSession(req); err != nil {
		t.Errorf("victim session after rejected exchanges: %v", err)
	}

	// The issuer's own page, identified by its Referer, still works.
	form := url.Values{"token": {plain}, "client_id": {"learning"}}
	req = httptest.NewRequest(http.MethodPost, LoginTokenPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", testIssuer+"/sign-in")
	w := httptest.NewRecorder()
	f.srv.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Errorf("same-origin referer: status %d %s", w.Code, w.Body.String())
	}
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
	req.Header.Set("Origin", testIssuer)
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

// TestManagementIsARelationship verifies that management comes from an
// active manager relationship and not from the email (ADR-009): a managed
// principal with an email carries the managed claim and the email claims,
// signs in with a login token, and stops doing both when management ends.
func TestManagementIsARelationship(t *testing.T) {
	ctx := context.Background()
	f := newLoginTokenFixture(t)
	student := f.humanWithEmail(t, "student@example.com")
	f.manage(t, student)
	scopes := []string{"openid", "profile", "email"}

	got := f.srv.sessionProvider.GetUserClaims(ctx, student.String(), scopes)
	if got[ManagedClaim] != true || got["email"] != "student@example.com" {
		t.Errorf("managed claims with an email = %v", got)
	}
	plain := f.issue(t, student, false)
	if w := postLoginToken(f.srv, url.Values{"token": {plain}, "client_id": {"learning"}}); w.Code != http.StatusSeeOther {
		t.Errorf("managed principal with an email: login token status %d", w.Code)
	}

	// An email-less human with no manager is not managed.
	orphan := f.humanWithEmail(t, "")
	if got := f.srv.sessionProvider.GetUserClaims(ctx, orphan.String(), scopes); got[ManagedClaim] != nil {
		t.Errorf("human without a manager has the managed claim: %v", got)
	}

	// Ending management removes the claim and the token's power.
	if _, err := f.db.ManagerRelationship.Update().Where(managerrelationship.ManagedPrincipalID(student)).SetActive(false).Save(ctx); err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	if got := f.srv.sessionProvider.GetUserClaims(ctx, student.String(), scopes); got[ManagedClaim] != nil {
		t.Errorf("released principal has the managed claim: %v", got)
	}
	if w := postLoginToken(f.srv, url.Values{"token": {plain}, "client_id": {"learning"}}); w.Code != http.StatusUnauthorized {
		t.Errorf("released principal: login token status %d, want 401", w.Code)
	}
}

// TestLoginTokenRateLimitIgnoresForwardingHeaders verifies that rotating
// X-Forwarded-For does not evade the per-address limit, and that made-up
// client IDs do not each get a rate-limit bucket.
func TestLoginTokenRateLimitIgnoresForwardingHeaders(t *testing.T) {
	rates := ratelimit.NewMemoryStorage(ratelimit.WithMaxKeys(50))
	t.Cleanup(func() {
		if err := rates.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	f := newLoginTokenFixture(t, WithLoginTokenRateLimit(rates, ratelimit.PerMinute(3), ratelimit.PerMinute(1000)))

	send := func(forwarded, clientID string) int {
		req := httptest.NewRequest(http.MethodPost, LoginTokenPath, strings.NewReader(url.Values{"token": {"nope"}, "client_id": {clientID}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", testIssuer)
		req.Header.Set("X-Forwarded-For", forwarded)
		req.RemoteAddr = "203.0.113.9:4000"
		w := httptest.NewRecorder()
		f.srv.ServeHTTP(w, req)
		return w.Code
	}
	for i := range 3 {
		if code := send(fmt.Sprintf("198.51.100.%d", i), "learning"); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i, code)
		}
	}
	if code := send("198.51.100.200", "learning"); code != http.StatusTooManyRequests {
		t.Errorf("a fresh X-Forwarded-For evaded the per-address limit: %d", code)
	}

	// Made-up client IDs share one bucket instead of each growing the store.
	g := newLoginTokenFixture(t, WithLoginTokenRateLimit(rates, ratelimit.PerMinute(1000), ratelimit.PerMinute(1000)))
	for i := range 200 {
		req := httptest.NewRequest(http.MethodPost, LoginTokenPath, strings.NewReader(url.Values{"token": {"x"}, "client_id": {fmt.Sprintf("made-up-%d", i)}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", testIssuer)
		req.RemoteAddr = "203.0.113.10:1"
		g.srv.ServeHTTP(httptest.NewRecorder(), req)
	}
	rates2 := ratelimit.NewMemoryStorage(ratelimit.WithMaxKeys(5))
	t.Cleanup(func() {
		if err := rates2.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	h := newLoginTokenFixture(t, WithLoginTokenRateLimit(rates2, ratelimit.PerMinute(1000), ratelimit.PerMinute(1000)))
	for i := range 100 {
		req := httptest.NewRequest(http.MethodPost, LoginTokenPath, strings.NewReader(url.Values{"token": {"x"}, "client_id": {fmt.Sprintf("made-up-%d", i)}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", testIssuer)
		req.RemoteAddr = "203.0.113.11:1"
		w := httptest.NewRecorder()
		h.srv.ServeHTTP(w, req)
		if w.Code == http.StatusTooManyRequests {
			t.Fatalf("made-up client %d used up the limiter's keys: %d", i, w.Code)
		}
	}

	// Behind a configured proxy the forwarded address is believed.
	clientAddr, err := clientaddr.New(clientaddr.Config{TrustedProxies: []string{"203.0.113.0/24"}})
	if err != nil {
		t.Fatalf("clientaddr.New: %v", err)
	}
	p := newLoginTokenFixture(t, WithClientAddressResolver(clientAddr),
		WithLoginTokenRateLimit(ratelimit.NewMemoryStorage(), ratelimit.PerMinute(1), ratelimit.PerMinute(1000)))
	for _, c := range []struct {
		ip   string
		want int
	}{{"198.51.100.1", http.StatusUnauthorized}, {"198.51.100.2", http.StatusUnauthorized}, {"198.51.100.1", http.StatusTooManyRequests}} {
		if got := func() int {
			req := httptest.NewRequest(http.MethodPost, LoginTokenPath, strings.NewReader(url.Values{"token": {"x"}, "client_id": {"learning"}}.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Origin", testIssuer)
			req.Header.Set("X-Forwarded-For", c.ip)
			req.RemoteAddr = "203.0.113.9:1"
			w := httptest.NewRecorder()
			p.srv.ServeHTTP(w, req)
			return w.Code
		}(); got != c.want {
			t.Errorf("client %s behind the proxy: %d, want %d", c.ip, got, c.want)
		}
	}
}

// TestManagedPrincipalAuthorizeRequiresOptedInClient verifies that the
// login session a managed principal gets from a login token, exchanged for
// a client that allows managed principals, cannot authorize a client that
// does not, while an ordinary human's session can.
func TestManagedPrincipalAuthorizeRequiresOptedInClient(t *testing.T) {
	f := newLoginTokenFixture(t)
	learner := f.managedHuman(t)
	w := postLoginToken(f.srv, url.Values{"token": {f.issue(t, learner, false)}, "client_id": {"learning"}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("login token: status %d %s", w.Code, w.Body.String())
	}
	sess := findCookie(t, w.Result(), LoginCookieName)

	authorize := func(clientID string, cookie *http.Cookie) *url.URL {
		t.Helper()
		params := url.Values{
			"response_type":         {"code"},
			"client_id":             {clientID},
			"redirect_uri":          {testRPCB},
			"scope":                 {"openid"},
			"state":                 {"rp-state-12345"},
			"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
			"code_challenge_method": {"S256"},
		}
		req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+params.Encode(), nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		f.srv.ServeHTTP(rec, req)
		loc, err := url.Parse(rec.Header().Get("Location"))
		if err != nil {
			t.Fatalf("location: %v", err)
		}
		return loc
	}

	if loc := authorize("ordinary", sess); loc.Query().Get("error") != "access_denied" {
		t.Errorf("managed principal at a client without managed principals: redirect %s, want access_denied", loc)
	}
	if loc := authorize("learning", sess); loc.Query().Get("error") != "" {
		t.Errorf("managed principal at an opted-in client: redirect %s, want no error", loc)
	}

	// An ordinary human is not affected.
	adult := seedHuman(t, f.db, "adult@example.com", true)
	adultSess := f.loginSession(t, adult)
	if loc := authorize("ordinary", adultSess); loc.Query().Get("error") != "" {
		t.Errorf("ordinary human: redirect %s, want no error", loc)
	}
}

// loginSession establishes a login session for principalID and returns its
// cookie.
func (f *loginTokenFixture) loginSession(t *testing.T, principalID uuid.UUID) *http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := f.srv.social.establishSession(req.Context(), rec, req, principalID, "test"); err != nil {
		t.Fatalf("establishSession: %v", err)
	}
	return findCookie(t, rec.Result(), LoginCookieName)
}
