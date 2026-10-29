package systemauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// newPartyServer is SystemAuth with social login and one config client
// "spa" of the given party ("" leaves it unset), optionally with the
// deprecated skip_consent set.
func newPartyServer(t *testing.T, party ClientParty, skipConsent bool) *Server {
	t.Helper()
	f := newFakeGitHub(t)
	s, err := NewEmbedded(Config{
		Issuer: testIssuer,
		Clients: []ClientConfig{{
			ID:            "spa",
			Type:          "public",
			Name:          "Example App",
			Party:         string(party),
			RedirectURIs:  []string{testRPCB},
			GrantTypes:    []string{"authorization_code", "refresh_token"},
			ResponseTypes: []string{"code"},
			Scopes:        []string{"openid", "profile", "email", "offline_access"},
		}},
		SocialLogin: &SocialLoginConfig{
			AllowedRedirectOrigins: []string{"https://app.example.com"},
			SkipConsent:            skipConsent,
		},
	}, WithSocialConnector(f.connector()))
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	return s
}

// authorizeLocation runs /oauth/authorize with the session cookie and
// returns the redirect target.
func authorizeLocation(t *testing.T, s *Server, target string, sess *http.Cookie) *url.URL {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if sess != nil {
		req.AddCookie(sess)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusFound && w.Code != http.StatusSeeOther {
		t.Fatalf("authorize: %d %s", w.Code, w.Body.String())
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

func TestFirstPartyClientSkipsConsent(t *testing.T) {
	// Unset party on a config client means first_party.
	for _, party := range []ClientParty{"", PartyFirst} {
		s := newPartyServer(t, party, false)
		sess := socialSession(t, s)
		loc := authorizeLocation(t, s, authorizeURL("openid email"), sess)
		if loc.Host != "app.example.com" || loc.Query().Get("code") == "" {
			t.Errorf("party %q: authorize went to %s, want a code at the client", party, loc)
		}
	}
}

func TestNonFirstPartyClientRequiresAndRecordsConsent(t *testing.T) {
	for _, party := range []ClientParty{PartySecond, PartyThird} {
		t.Run(string(party), func(t *testing.T) {
			s := newPartyServer(t, party, false)
			sess := socialSession(t, s)
			authorize := authorizeURL("openid email")

			loc := authorizeLocation(t, s, authorize, sess)
			if loc.Path != ConsentPath || loc.Query().Get("return_to") != authorize {
				t.Fatalf("authorize without consent went to %s, want the consent page", loc)
			}

			form := url.Values{"return_to": {authorize}, "decision": {"allow"}, "csrf_token": {consentCSRF(sess.Value)}}
			if w := postForm(s, ConsentPath, testIssuer, form, sess); w.Code != http.StatusSeeOther {
				t.Fatalf("allow: %d %s", w.Code, w.Body.String())
			}
			principal := sessionPrincipal(t, s, sess)
			ok, err := s.social.consents.HasConsent(context.Background(), principal, "spa", []string{"openid", "email"})
			if err != nil {
				t.Fatalf("HasConsent: %v", err)
			}
			if !ok {
				t.Fatal("consent was not recorded")
			}
			authorizeCode(t, s, "openid email", withCookie(sess))
		})
	}
}

// sessionPrincipal returns the principal ID of a login session cookie.
func sessionPrincipal(t *testing.T, s *Server, sess *http.Cookie) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(sess)
	id := s.sessionProvider.GetAuthenticatedUser(req)
	if id == "" {
		t.Fatal("session cookie authenticates nobody")
	}
	return id
}

func TestSkipConsentNoLongerBypassesThirdParty(t *testing.T) {
	s := newPartyServer(t, PartyThird, true)
	sess := socialSession(t, s)
	loc := authorizeLocation(t, s, authorizeURL("openid"), sess)
	if loc.Path != ConsentPath {
		t.Fatalf("skip_consent let a third-party client through: %s", loc)
	}
}

func TestDefaultProviderSkipConsentNoLongerBypassesThirdParty(t *testing.T) {
	s, err := NewEmbedded(Config{Issuer: testIssuer},
		WithSessionProvider(NewDefaultSessionProvider(
			WithTrustedUserIDHeader("X-User-ID", TrustAllRequests),
			WithSkipConsent(true),
			WithConsentURL("/app-consent"),
		)))
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	for _, party := range []ClientParty{"", PartySecond, PartyThird, PartyFirst} {
		id := "rt-" + string(party)
		if err := s.RegisterClient(&Client{
			ID:            id,
			Type:          ClientTypePublic,
			Name:          "Runtime client",
			Party:         party,
			RedirectURIs:  []string{testRPCB},
			GrantTypes:    []string{"authorization_code"},
			ResponseTypes: []string{"code"},
			Scopes:        []string{"openid"},
		}); err != nil {
			t.Fatalf("RegisterClient: %v", err)
		}
		params := url.Values{
			"response_type": {"code"}, "client_id": {id}, "redirect_uri": {testRPCB},
			"scope": {"openid"}, "state": {"rp-state-12345"}, "nonce": {"rp-nonce-12345"},
			"code_challenge": {testChallenge}, "code_challenge_method": {"S256"},
		}
		req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+params.Encode(), nil)
		req.Header.Set("X-User-ID", uuid.NewString())
		w := httptest.NewRecorder()
		s.ServeHTTP(w, req)
		loc := w.Header().Get("Location")
		wantConsent := party != PartyFirst
		if got := strings.HasPrefix(loc, "/app-consent"); got != wantConsent {
			t.Errorf("party %q: authorize went to %q, consent wanted: %v", party, loc, wantConsent)
		}
	}
}
