package systemauth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/plexusone/systemforge/identity/oauthclient"
)

// googleTestConnector is a Google connector that is never called: it only
// makes the login page offer two providers.
func googleTestConnector() *oauthclient.Connector {
	return oauthclient.NewGoogleConnector(oauthclient.ProviderConfig{
		ClientID: "g-client", ClientSecret: "g-secret", RedirectURL: testIssuer + "/login/google/callback",
	})
}

// newBrandingServer is SystemAuth with two login providers, so /login
// renders the chooser, and one client with the given name and logo.
func newBrandingServer(t *testing.T, name, logo string) *Server {
	t.Helper()
	f := newFakeGitHub(t)
	s, err := NewEmbedded(Config{
		Issuer: testIssuer,
		Clients: []ClientConfig{{
			ID: "spa", Type: "public", Name: name, LogoURL: logo,
			RedirectURIs: []string{testRPCB}, Scopes: []string{"openid"},
		}},
		SocialLogin: &SocialLoginConfig{AllowedRedirectOrigins: []string{"https://app.example.com"}},
	}, WithSocialConnector(f.connector()), WithSocialConnector(googleTestConnector()))
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	return s
}

func TestLoginPageNamesRequestingClient(t *testing.T) {
	s := newBrandingServer(t, `Evil <script>alert(1)</script> & "Co"`, `https://cdn.example.com/logo.png?a=1&b="x"`)
	chooser := func(returnTo string) *httptest.ResponseRecorder {
		target := LoginPath
		if returnTo != "" {
			target += "?return_to=" + url.QueryEscape(returnTo)
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, target, nil))
		if w.Code != http.StatusOK {
			t.Fatalf("login page: %d %s", w.Code, w.Body.String())
		}
		return w
	}

	w := chooser(authorizeURL("openid"))
	body := w.Body.String()
	if strings.Contains(body, "<script>") || strings.Contains(body, `"Co"`) {
		t.Fatalf("client name not escaped: %s", body)
	}
	if !strings.Contains(body, "to continue to Evil &lt;script&gt;alert(1)&lt;/script&gt; &amp; &#34;Co&#34;") {
		t.Errorf("client name missing: %s", body)
	}
	if !strings.Contains(body, `<img src="https://cdn.example.com/logo.png?a=1&amp;b=%22x%22"`) {
		t.Errorf("logo missing or unescaped: %s", body)
	}
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "img-src 'self' https://cdn.example.com;") || !strings.Contains(csp, "default-src 'self'") || !strings.Contains(csp, "form-action 'self'") {
		t.Errorf("CSP %q does not allow exactly the logo origin", csp)
	}
	checkNoInlineCode(t, "login page", w)

	// Not started by an authorization request, or by an unknown client:
	// no client is named.
	for _, returnTo := range []string{"", "/account", "/oauth/authorize?client_id=unknown&scope=openid"} {
		w := chooser(returnTo)
		if strings.Contains(w.Body.String(), "continue to") || strings.Contains(w.Body.String(), "<img") {
			t.Errorf("return_to %q: login page names a client: %s", returnTo, w.Body.String())
		}
		if strings.Contains(w.Header().Get("Content-Security-Policy"), "img-src") {
			t.Errorf("return_to %q: CSP widened", returnTo)
		}
	}

	// A client without a logo is named without one.
	s = newBrandingServer(t, "Plain App", "")
	w = httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, LoginPath+"?return_to="+url.QueryEscape(authorizeURL("openid")), nil))
	if !strings.Contains(w.Body.String(), "to continue to Plain App") || strings.Contains(w.Body.String(), "<img") {
		t.Errorf("client without logo: %s", w.Body.String())
	}
}
