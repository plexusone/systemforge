package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/ory/fosite"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	"github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/systemauth"
)

const (
	flowRedirect      = "https://app.example.com/callback"
	flowOtherRedirect = "https://app.example.com/other"
	flowSubject       = "user-1"
)

type flow struct {
	t        *testing.T
	p        *Provider
	clientID string
	db       *ent.Client
}

func newFlow(t *testing.T) *flow {
	t.Helper()
	ctx := context.Background()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	owner, err := db.Principal.Create().SetType(principal.TypeService).SetIdentifier("owner").SetDisplayName("Owner").Save(ctx)
	if err != nil {
		t.Fatalf("owner: %v", err)
	}
	clientID := "spa-" + uuid.NewString()[:8]
	if _, err := db.OAuthApp.Create().SetClientID(clientID).SetName("SPA").SetOwnerID(owner.ID).SetPublic(true).
		SetRedirectUris([]string{flowRedirect, flowOtherRedirect}).
		SetAllowedGrants([]string{"authorization_code", "refresh_token"}).
		SetAllowedResponseTypes([]string{"code"}).
		SetAllowedScopes([]string{"openid", "offline", "read"}).
		Save(ctx); err != nil {
		t.Fatalf("app: %v", err)
	}
	p, err := NewProvider(db, DefaultConfig("https://issuer.example", []byte("0123456789abcdef0123456789abcdef")))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	return &flow{t: t, p: p, clientID: clientID, db: db}
}

func pkcePair() (verifier, challenge string) {
	verifier = strings.Repeat("v", 20) + uuid.NewString() + uuid.NewString()
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// authorize runs the authorization endpoint for flowSubject and returns
// the code.
func (f *flow) authorize(challenge string) string {
	f.t.Helper()
	ctx := context.Background()
	q := url.Values{
		"response_type": {"code"}, "client_id": {f.clientID}, "redirect_uri": {flowRedirect},
		"scope": {"openid offline read"}, "state": {"state-" + uuid.NewString()},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
	op := f.p.OAuth2Provider()
	ar, err := op.NewAuthorizeRequest(ctx, httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil))
	if err != nil {
		f.t.Fatalf("NewAuthorizeRequest: %v", err)
	}
	for _, s := range ar.GetRequestedScopes() {
		ar.GrantScope(s)
	}
	resp, err := op.NewAuthorizeResponse(ctx, ar, f.p.Session(flowSubject))
	if err != nil {
		f.t.Fatalf("NewAuthorizeResponse: %v", err)
	}
	return resp.GetParameters().Get("code")
}

// token runs the token endpoint with form.
func (f *flow) token(form url.Values) (fosite.AccessResponder, error) {
	ctx := context.Background()
	form.Set("client_id", f.clientID)
	r := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	op := f.p.OAuth2Provider()
	ar, err := op.NewAccessRequest(ctx, r, f.p.Session(""))
	if err != nil {
		return nil, err
	}
	return op.NewAccessResponse(ctx, ar)
}

// subject introspects an access token and returns its subject, or "" when
// the token is not active.
func (f *flow) subject(accessToken string) string {
	f.t.Helper()
	_, ar, err := f.p.OAuth2Provider().IntrospectToken(context.Background(), accessToken, fosite.AccessToken, f.p.Session(""))
	if err != nil {
		return ""
	}
	return ar.GetSession().GetSubject()
}

func codeExchange(code, verifier, redirect string) url.Values {
	v := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect}}
	if verifier != "" {
		v.Set("code_verifier", verifier)
	}
	return v
}

// TestCodeExchangeEnforcesPKCEAndRedirect verifies that a code can be
// exchanged only with its PKCE verifier and its redirect URI.
func TestCodeExchangeEnforcesPKCEAndRedirect(t *testing.T) {
	f := newFlow(t)

	verifier, challenge := pkcePair()
	if _, err := f.token(codeExchange(f.authorize(challenge), "", flowRedirect)); err == nil {
		t.Error("code exchanged without the PKCE verifier")
	}
	wrongVerifier, _ := pkcePair()
	if _, err := f.token(codeExchange(f.authorize(challenge), wrongVerifier, flowRedirect)); err == nil {
		t.Error("code exchanged with the wrong PKCE verifier")
	}
	if _, err := f.token(codeExchange(f.authorize(challenge), verifier, flowOtherRedirect)); err == nil {
		t.Error("code exchanged with a different redirect URI")
	}

	resp, err := f.token(codeExchange(f.authorize(challenge), verifier, flowRedirect))
	if err != nil {
		t.Fatalf("valid exchange: %v", err)
	}
	if got := f.subject(resp.GetAccessToken()); got != flowSubject {
		t.Errorf("access token subject = %q, want %q", got, flowSubject)
	}
}

// TestCodeReplayRevokesTokens verifies that exchanging a code twice fails
// and revokes the tokens the first exchange issued.
func TestCodeReplayRevokesTokens(t *testing.T) {
	f := newFlow(t)
	verifier, challenge := pkcePair()
	code := f.authorize(challenge)
	first, err := f.token(codeExchange(code, verifier, flowRedirect))
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if _, err := f.token(codeExchange(code, verifier, flowRedirect)); err == nil {
		t.Error("code exchanged twice")
	}
	if got := f.subject(first.GetAccessToken()); got != "" {
		t.Error("tokens from a replayed code stay active")
	}
}

// TestRefreshKeepsSubjectAndDetectsReuse verifies that refreshing keeps
// the subject and that reusing a rotated refresh token revokes the family.
func TestRefreshKeepsSubjectAndDetectsReuse(t *testing.T) {
	f := newFlow(t)
	verifier, challenge := pkcePair()
	first, err := f.token(codeExchange(f.authorize(challenge), verifier, flowRedirect))
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	firstRefresh, _ := first.GetExtra("refresh_token").(string)
	if firstRefresh == "" {
		t.Fatal("no refresh token issued")
	}

	second, err := f.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {firstRefresh}})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if got := f.subject(second.GetAccessToken()); got != flowSubject {
		t.Errorf("refreshed access token subject = %q, want %q", got, flowSubject)
	}
	if got := f.subject(first.GetAccessToken()); got != "" {
		t.Error("the rotated access token stays active")
	}

	// Reusing the rotated refresh token revokes the whole family.
	if _, err := f.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {firstRefresh}}); err == nil {
		t.Error("a rotated refresh token was accepted")
	}
	if got := f.subject(second.GetAccessToken()); got != "" {
		t.Error("the family's current access token survives refresh token reuse")
	}
}

// authorizeHTTP sends an authorization request through the API's router,
// optionally with an X-User-ID header, as a client of the server would.
func (f *flow) authorizeHTTP(t *testing.T, opts []Option, userHeader string) *httptest.ResponseRecorder {
	t.Helper()
	api, err := NewAPI(f.p, opts...)
	if err != nil {
		t.Fatalf("NewAPI: %v", err)
	}
	_, challenge := pkcePair()
	q := url.Values{
		"response_type": {"code"}, "client_id": {f.clientID}, "redirect_uri": {flowRedirect},
		"scope": {"openid read"}, "state": {"state-" + uuid.NewString()},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	req.RemoteAddr = "203.0.113.9:5555"
	if userHeader != "" {
		req.Header.Set("X-User-ID", userHeader)
	}
	w := httptest.NewRecorder()
	api.ServeHTTP(w, req)
	return w
}

// redirectParam returns a query parameter of the response's redirect.
func redirectParam(t *testing.T, w *httptest.ResponseRecorder, name string) string {
	t.Helper()
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("Location %q: %v", w.Header().Get("Location"), err)
	}
	return u.Query().Get(name)
}

// TestAuthorizeNeverTrustsAClientSuppliedHeader verifies that the
// authorization endpoint does not take identity from a request header
// unless a gate admitting the request was configured.
func TestAuthorizeNeverTrustsAClientSuppliedHeader(t *testing.T) {
	f := newFlow(t)

	// No authenticator: refused, whatever the header says.
	w := f.authorizeHTTP(t, nil, "victim")
	if w.Code != http.StatusSeeOther && w.Code != http.StatusFound {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if redirectParam(t, w, "code") != "" || redirectParam(t, w, "error") != "server_error" {
		t.Errorf("no authenticator: Location %q, want server_error", w.Header().Get("Location"))
	}

	// A header without a gate trusts nothing.
	w = f.authorizeHTTP(t, []Option{WithTrustedUserIDHeader("X-User-ID", nil)}, "victim")
	if redirectParam(t, w, "code") != "" {
		t.Errorf("a header with no gate produced a code: %q", w.Header().Get("Location"))
	}

	// A gate that does not admit the request trusts nothing either.
	gate, err := systemauth.TrustedProxyNetworks("10.0.0.0/8")
	if err != nil {
		t.Fatalf("TrustedProxyNetworks: %v", err)
	}
	w = f.authorizeHTTP(t, []Option{WithTrustedUserIDHeader("X-User-ID", gate)}, "victim")
	if redirectParam(t, w, "code") != "" {
		t.Errorf("a request from outside the trusted network produced a code: %q", w.Header().Get("Location"))
	}
	if got := redirectParam(t, w, "error"); got != "login_required" {
		t.Errorf("outside the trusted network: error %q, want login_required", got)
	}

	// From the trusted network the header is believed, and the code is for
	// that user.
	inside, err := systemauth.TrustedProxyNetworks("203.0.113.0/24")
	if err != nil {
		t.Fatalf("TrustedProxyNetworks: %v", err)
	}
	consented := WithConsent(func(context.Context, string, fosite.Client, []string) (bool, error) { return true, nil })
	w = f.authorizeHTTP(t, []Option{WithTrustedUserIDHeader("X-User-ID", inside), consented}, "kim")
	if redirectParam(t, w, "code") == "" {
		t.Errorf("a trusted request got no code: %q", w.Header().Get("Location"))
	}
}

func TestAuthorizeLoginRedirectEscapesTheReturnAddress(t *testing.T) {
	f := newFlow(t)
	w := f.authorizeHTTP(t, []Option{
		WithUserAuthenticator(func(*http.Request) string { return "" }),
		WithLoginURL("/signin?tenant=x"),
	}, "")
	if w.Code != http.StatusFound {
		t.Fatalf("status %d", w.Code)
	}
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	ret := u.Query().Get("redirect")
	if u.Path != "/signin" || u.Query().Get("tenant") != "x" || !strings.HasPrefix(ret, "/oauth/authorize?") || strings.Count(w.Header().Get("Location"), "redirect=") != 1 {
		t.Errorf("login redirect %q", w.Header().Get("Location"))
	}
	if q, err := url.ParseQuery(strings.TrimPrefix(ret, "/oauth/authorize?")); err != nil || q.Get("client_id") != f.clientID {
		t.Errorf("return address %q does not round-trip: %v", ret, err)
	}
}

// TestAuthorizeConsent verifies that only first-party clients skip consent.
func TestAuthorizeConsent(t *testing.T) {
	ctx := context.Background()
	f := newFlow(t)
	signedIn := WithUserAuthenticator(func(*http.Request) string { return "kim" })

	w := f.authorizeHTTP(t, []Option{signedIn}, "")
	if redirectParam(t, w, "code") != "" || redirectParam(t, w, "error") != "access_denied" {
		t.Errorf("third-party client without a consent mechanism: %q", w.Header().Get("Location"))
	}

	var asked []string
	granted := func(ok bool) Option {
		return WithConsent(func(_ context.Context, user string, c fosite.Client, scopes []string) (bool, error) {
			asked = append(asked, user+"/"+c.GetID())
			return ok, nil
		})
	}
	if w := f.authorizeHTTP(t, []Option{signedIn, granted(false)}, ""); redirectParam(t, w, "code") != "" || redirectParam(t, w, "error") != "consent_required" {
		t.Errorf("consent withheld: %q", w.Header().Get("Location"))
	}
	if w := f.authorizeHTTP(t, []Option{signedIn, granted(true)}, ""); redirectParam(t, w, "code") == "" {
		t.Errorf("consent given: %q", w.Header().Get("Location"))
	}
	if len(asked) != 2 || asked[0] != "kim/"+f.clientID {
		t.Errorf("consent was asked for %v", asked)
	}
	failing := WithConsent(func(context.Context, string, fosite.Client, []string) (bool, error) {
		return false, errors.New("store down")
	})
	if w := f.authorizeHTTP(t, []Option{signedIn, failing}, ""); redirectParam(t, w, "code") != "" || redirectParam(t, w, "error") != "server_error" {
		t.Errorf("consent store failing: %q", w.Header().Get("Location"))
	}

	// First-party clients need no consent.
	if err := f.db.OAuthApp.Update().SetFirstParty(true).Exec(ctx); err != nil {
		t.Fatalf("mark first-party: %v", err)
	}
	if w := f.authorizeHTTP(t, []Option{signedIn}, ""); redirectParam(t, w, "code") == "" {
		t.Errorf("first-party client: %q", w.Header().Get("Location"))
	}
}
