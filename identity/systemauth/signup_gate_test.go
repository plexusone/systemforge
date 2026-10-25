package systemauth

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
)

// stubGate allows the addresses in allowed and records who signed up.
type stubGate struct {
	mu       sync.Mutex
	allowed  map[string]bool
	signedUp []uuid.UUID
}

func (g *stubGate) AllowSignup(_ context.Context, login ExternalLogin) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.allowed[login.Email] {
		return ErrSignupNotInvited
	}
	return nil
}

func (g *stubGate) SignedUp(_ context.Context, _ ExternalLogin, id uuid.UUID) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.signedUp = append(g.signedUp, id)
	return nil
}

func newGatedServer(t *testing.T, f *fakeGitHub, dir PrincipalDirectory, opts ...Option) (*Server, error) {
	t.Helper()
	return NewEmbedded(Config{
		Issuer: testIssuer,
		Clients: []ClientConfig{{
			ID: "spa", Type: "public", Name: "SPA",
			RedirectURIs:  []string{"https://app.example.com/callback"},
			GrantTypes:    []string{"authorization_code"},
			ResponseTypes: []string{"code"},
			Scopes:        []string{"openid", "profile", "email"},
		}},
		SocialLogin: &SocialLoginConfig{AllowedRedirectOrigins: []string{"https://app.example.com"}, SkipConsent: true},
	}, append([]Option{WithSocialConnector(f.connector()), WithPrincipalDirectory(dir)}, opts...)...)
}

func TestSignupGateRefusesUninvitedAndCreatesNothing(t *testing.T) {
	f := newFakeGitHub(t)
	dir := NewMemoryPrincipalDirectory()
	gate := &stubGate{allowed: map[string]bool{}}
	s, err := newGatedServer(t, f, dir, WithSignupGate(gate))
	if err != nil {
		t.Fatal(err)
	}

	state, stateCookie := startLogin(t, s, "")
	w := callback(s, state, stateCookie)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "invitation only") {
		t.Fatalf("uninvited: %d %q, want 403 invitation only", w.Code, w.Body.String())
	}
	if findCookie(t, w.Result(), LoginCookieName) != nil {
		t.Error("a session was issued to an uninvited login")
	}
	if len(dir.principals) != 0 {
		t.Errorf("principals = %d, want none", len(dir.principals))
	}
	if len(gate.signedUp) != 0 {
		t.Error("SignedUp ran for a refused sign-up")
	}
}

func TestSignupGateRedirectsToDeniedPage(t *testing.T) {
	f := newFakeGitHub(t)
	s, err := newGatedServer(t, f, NewMemoryPrincipalDirectory(),
		WithSignupGate(&stubGate{allowed: map[string]bool{}}),
		WithSignupDeniedURL("https://app.example.com/invite-only?src=login"))
	if err != nil {
		t.Fatal(err)
	}
	state, stateCookie := startLogin(t, s, "")
	w := callback(s, state, stateCookie)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d, want 303", w.Code)
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Path != "/invite-only" || loc.Query().Get("error") != "invite_required" || loc.Query().Get("src") != "login" {
		t.Errorf("redirect = %s", loc)
	}
}

func TestSignupGateAllowsInvitedAndLeavesExistingAccounts(t *testing.T) {
	f := newFakeGitHub(t)
	dir := NewMemoryPrincipalDirectory()
	gate := &stubGate{allowed: map[string]bool{"octo@example.com": true}}
	s, err := newGatedServer(t, f, dir, WithSignupGate(gate))
	if err != nil {
		t.Fatal(err)
	}

	state, stateCookie := startLogin(t, s, "")
	if w := callback(s, state, stateCookie); w.Code != http.StatusFound {
		t.Fatalf("invited login: %d %s", w.Code, w.Body.String())
	}
	p, err := dir.FindByExternalIdentity(context.Background(), "github", "4242")
	if err != nil {
		t.Fatalf("principal not created: %v", err)
	}
	if len(gate.signedUp) != 1 || gate.signedUp[0] != p.ID {
		t.Errorf("SignedUp = %v, want the new principal %s", gate.signedUp, p.ID)
	}

	// The invite is gone, but the account signs in: the gate is not asked.
	gate.allowed = map[string]bool{}
	state, stateCookie = startLogin(t, s, "")
	if w := callback(s, state, stateCookie); w.Code != http.StatusFound {
		t.Fatalf("existing account refused after the invite was used: %d %s", w.Code, w.Body.String())
	}
	if len(gate.signedUp) != 1 {
		t.Errorf("SignedUp ran again for an existing account: %v", gate.signedUp)
	}
}

func TestSignupDeniedURLValidation(t *testing.T) {
	f := newFakeGitHub(t)
	gate := &stubGate{allowed: map[string]bool{}}
	for _, bad := range []string{
		"http://app.example.com/x",          // plain http to a non-loopback host
		"/invite-only",                      // relative
		"https://user:pw@app.example.com/x", // credentials
		"javascript:alert(1)",               // not a web URL
		"https:///path-only",                // no host
	} {
		if _, err := newGatedServer(t, f, NewMemoryPrincipalDirectory(), WithSignupGate(gate), WithSignupDeniedURL(bad)); err == nil {
			t.Errorf("denied URL %q accepted", bad)
		}
	}
	for _, good := range []string{"https://app.example.com/x", "http://localhost:3000/x", "http://127.0.0.1/x"} {
		if _, err := newGatedServer(t, f, NewMemoryPrincipalDirectory(), WithSignupGate(gate), WithSignupDeniedURL(good)); err != nil {
			t.Errorf("denied URL %q refused: %v", good, err)
		}
	}
}

// abortingGate is a stubGate that records aborted sign-ups.
type abortingGate struct {
	stubGate
	aborted []string
}

func (g *abortingGate) SignupAborted(_ context.Context, login ExternalLogin) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.aborted = append(g.aborted, login.Email)
}

// failingDirectory fails every account creation.
type failingDirectory struct {
	PrincipalDirectory
	err error
}

func (d failingDirectory) CreateFromExternal(context.Context, ExternalLogin) (*HumanPrincipal, error) {
	return nil, d.err
}

func TestGatedDirectoryAbortsWhenCreationFails(t *testing.T) {
	gate := &abortingGate{stubGate: stubGate{allowed: map[string]bool{"ada@example.com": true}}}
	d := &gatedDirectory{PrincipalDirectory: failingDirectory{err: errSignupAgeRequired}, gate: gate}
	ctx := t.Context()
	if _, err := d.CreateFromExternal(ctx, ExternalLogin{Email: "ada@example.com"}); err != errSignupAgeRequired { //nolint:errorlint // the sentinel is returned as is
		t.Fatalf("err = %v", err)
	}
	if _, err := d.CreateFromExternal(ctx, ExternalLogin{Email: "grace@example.com"}); err != ErrSignupNotInvited { //nolint:errorlint // the sentinel is returned as is
		t.Fatalf("uninvited err = %v", err)
	}
	if len(gate.aborted) != 1 || gate.aborted[0] != "ada@example.com" {
		t.Errorf("aborted = %v; want only the allowed sign-up whose creation failed", gate.aborted)
	}
	if len(gate.signedUp) != 0 {
		t.Errorf("signed up = %v", gate.signedUp)
	}
}

func TestSignupCodeContext(t *testing.T) {
	ctx := t.Context()
	if got := SignupCodeFromContext(ctx); got != "" {
		t.Errorf("empty context carries %q", got)
	}
	if got := SignupCodeFromContext(WithSignupCode(ctx, "")); got != "" {
		t.Errorf("empty code carried as %q", got)
	}
	if got := SignupCodeFromContext(WithSignupCode(ctx, "ABCD")); got != "ABCD" {
		t.Errorf("code = %q", got)
	}
}
