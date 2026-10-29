package systemauth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/ory/fosite"
)

func TestParsePrompt(t *testing.T) {
	for raw, want := range map[string]authorizePrompt{
		"":                     {},
		"none":                 {none: true},
		"login":                {login: true},
		"consent":              {consent: true},
		"login consent":        {login: true, consent: true},
		"select_account":       {},
		"  consent   login  ":  {login: true, consent: true},
		"select_account login": {login: true},
	} {
		got, err := parsePrompt(raw)
		if err != nil || got != want {
			t.Errorf("parsePrompt(%q) = %+v, %v; want %+v", raw, got, err, want)
		}
	}
	for _, raw := range []string{"none login", "consent none", "none none", "bogus", "Login"} {
		if _, err := parsePrompt(raw); !errors.Is(err, fosite.ErrInvalidRequest) {
			t.Errorf("parsePrompt(%q): %v, want invalid_request", raw, err)
		}
	}
}

func TestAuthorizeReturnURLDropsPrompt(t *testing.T) {
	for in, want := range map[string]string{
		"/oauth/authorize?client_id=a&prompt=login":         "/oauth/authorize?client_id=a",
		"/oauth/authorize?client_id=a&prompt=login+consent": "/oauth/authorize?client_id=a&prompt=consent",
		"/oauth/authorize?b=2&a=1":                          "/oauth/authorize?b=2&a=1", // untouched
	} {
		r := httptest.NewRequest(http.MethodGet, in, nil)
		if got := authorizeReturnURL(r, "login"); got != want {
			t.Errorf("authorizeReturnURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// promptURL is authorizeURL with a prompt parameter.
func promptURL(scope, prompt string) string {
	return authorizeURL(scope) + "&prompt=" + url.QueryEscape(prompt)
}

// clientError checks that loc is an error redirect to the client with the
// request's state.
func clientError(t *testing.T, loc *url.URL, want string) {
	t.Helper()
	if loc.Host != "app.example.com" || loc.Query().Get("error") != want || loc.Query().Get("state") != "rp-state-12345" || loc.Query().Get("code") != "" {
		t.Fatalf("redirect %s, want error=%s with the state at the client", loc, want)
	}
}

func TestPromptNone(t *testing.T) {
	t.Run("no session", func(t *testing.T) {
		s := newPartyServer(t, PartyFirst, false)
		clientError(t, authorizeLocation(t, s, promptURL("openid", "none"), nil), "login_required")
	})
	t.Run("consent needed", func(t *testing.T) {
		s := newPartyServer(t, PartyThird, false)
		sess := socialSession(t, s)
		clientError(t, authorizeLocation(t, s, promptURL("openid email", "none"), sess), "consent_required")
	})
	t.Run("first-party silent", func(t *testing.T) {
		s := newPartyServer(t, PartyFirst, false)
		sess := socialSession(t, s)
		loc := authorizeLocation(t, s, promptURL("openid email", "none"), sess)
		if loc.Host != "app.example.com" || loc.Query().Get("code") == "" || loc.Query().Get("state") != "rp-state-12345" {
			t.Fatalf("prompt=none for a signed-in first-party user: %s", loc)
		}
	})
	t.Run("third-party with consent silent", func(t *testing.T) {
		s := newPartyServer(t, PartyThird, false)
		sess := socialSession(t, s)
		if err := s.social.consents.SaveConsent(t.Context(), sessionPrincipal(t, s, sess), "spa", []string{"openid", "email"}); err != nil {
			t.Fatalf("SaveConsent: %v", err)
		}
		loc := authorizeLocation(t, s, promptURL("openid email", "none"), sess)
		if loc.Query().Get("code") == "" {
			t.Fatalf("prompt=none with recorded consent: %s", loc)
		}
	})
	t.Run("combined", func(t *testing.T) {
		s := newPartyServer(t, PartyFirst, false)
		sess := socialSession(t, s)
		clientError(t, authorizeLocation(t, s, promptURL("openid", "none login"), sess), "invalid_request")
		clientError(t, authorizeLocation(t, s, promptURL("openid", "bogus"), sess), "invalid_request")
	})
}

func TestPromptLoginReauthenticates(t *testing.T) {
	s := newPartyServer(t, PartyFirst, false)
	sess := socialSession(t, s)
	target := promptURL("openid", "login")

	// With a login session the user is still sent to log in, and comes
	// back to the request without prompt=login.
	loc := authorizeLocation(t, s, target, sess)
	returnTo := loc.Query().Get("return_to")
	if loc.Path != LoginPath || returnTo != authorizeURL("openid") {
		t.Fatalf("prompt=login went to %s, want the login page returning to the plain request", loc)
	}

	// Without one too.
	if loc := authorizeLocation(t, s, target, nil); loc.Path != LoginPath || loc.Query().Get("return_to") != authorizeURL("openid") {
		t.Fatalf("prompt=login signed out: %s", loc)
	}

	// After logging in again the request completes.
	state, stateCookie := startLogin(t, s, returnTo)
	w := callback(s, state, stateCookie)
	if w.Code != http.StatusFound || w.Header().Get("Location") != returnTo {
		t.Fatalf("login: %d %q", w.Code, w.Header().Get("Location"))
	}
	fresh := findCookie(t, w.Result(), LoginCookieName)
	if fresh == nil || fresh.Value == sess.Value {
		t.Fatal("logging in again did not start a new session")
	}
	authorizeCode(t, s, "openid", withCookie(fresh))

	// login and consent: login first, keeping the consent prompt.
	loc = authorizeLocation(t, s, promptURL("openid", "login consent"), fresh)
	if back, err := url.Parse(loc.Query().Get("return_to")); err != nil || back.Query().Get("prompt") != "consent" {
		t.Fatalf("prompt=login consent returns to %q", loc.Query().Get("return_to"))
	}
}

func TestPromptConsentShowsConsent(t *testing.T) {
	for _, party := range []ClientParty{PartyFirst, PartyThird} {
		t.Run(string(party), func(t *testing.T) {
			s := newPartyServer(t, party, false)
			sess := socialSession(t, s)
			if err := s.social.consents.SaveConsent(t.Context(), sessionPrincipal(t, s, sess), "spa", []string{"openid"}); err != nil {
				t.Fatalf("SaveConsent: %v", err)
			}
			loc := authorizeLocation(t, s, promptURL("openid", "consent"), sess)
			plain := authorizeURL("openid")
			if loc.Path != ConsentPath || loc.Query().Get("return_to") != plain {
				t.Fatalf("prompt=consent went to %s, want the consent page returning to the plain request", loc)
			}
			form := url.Values{"return_to": {plain}, "decision": {"allow"}, "csrf_token": {consentCSRF(sess.Value)}}
			if w := postForm(s, ConsentPath, testIssuer, form, sess); w.Code != http.StatusSeeOther || w.Header().Get("Location") != plain {
				t.Fatalf("allow: %d %q", w.Code, w.Header().Get("Location"))
			}
			authorizeCode(t, s, "openid", withCookie(sess))
		})
	}
}
