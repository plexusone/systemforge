package systemauth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPageStyleIsServedAndLinked(t *testing.T) {
	f := newFakeGitHub(t)
	s := newSocialTestServer(t, f, NewMemoryPrincipalDirectory())

	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, PageStylePath+"?v="+pageStyleVersion, nil))
	if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/css") || !strings.Contains(w.Body.String(), "prefers-color-scheme") {
		t.Fatalf("stylesheet: %d %q", w.Code, w.Header().Get("Content-Type"))
	}
	if cc := w.Header().Get("Cache-Control"); !strings.Contains(cc, "immutable") {
		t.Errorf("a versioned stylesheet is cached as %q", cc)
	}
	w = httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, PageStylePath, nil))
	if cc := w.Header().Get("Cache-Control"); strings.Contains(cc, "immutable") {
		t.Errorf("an unversioned stylesheet is cached as %q", cc)
	}

	// The sign-in page links it, from the issuer's own origin, which its
	// content security policy allows, and offers each provider in a nav.
	w = httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/login", nil))
	body := w.Body.String()
	if !strings.Contains(body, `<link rel="stylesheet" href="`+PageStylePath+`?v=`+pageStyleVersion+`">`) {
		t.Errorf("the sign-in page does not link the stylesheet: %s", body)
	}
	if !strings.Contains(body, `<nav aria-label="Sign-in options">`) || !strings.Contains(body, `>Continue with GitHub</a>`) {
		t.Errorf("the sign-in options: %s", body)
	}
	if csp := w.Header().Get("Content-Security-Policy"); csp != "" && !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("the page's policy would block its stylesheet: %s", csp)
	}
}

// Every page template links the stylesheet.
func TestEveryPageLinksTheStylesheet(t *testing.T) {
	for name, src := range map[string]string{
		"login": chooserTemplate.Tree.Root.String(), "logout": logoutTemplate.Tree.Root.String(),
		"consent": consentTemplate.Tree.Root.String(), "signup": signupCodeTemplate.Tree.Root.String(),
		"signup-age": signupAgeTemplate.Tree.Root.String(), "waitlist": waitlistTemplate.Tree.Root.String(),
		"account-email": accountEmailTemplate.Tree.Root.String(), "verify-email": verifyEmailTemplate.Tree.Root.String(),
	} {
		if !strings.Contains(src, pageStyleLink) {
			t.Errorf("%s does not link the stylesheet", name)
		}
	}
}
