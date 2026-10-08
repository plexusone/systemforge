package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/ory/fosite"

	"github.com/plexusone/systemforge/identity/ent/enttest"
	"github.com/plexusone/systemforge/identity/ent/principal"
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
	return &flow{t: t, p: p, clientID: clientID}
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
