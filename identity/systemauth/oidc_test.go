package systemauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v3"
	gojwt "github.com/golang-jwt/jwt/v5"

	"github.com/plexusone/systemforge/identity/ent/enttest"
)

// verifyJWT checks a token against the server's JWKS (by kid).
func verifyJWT(t *testing.T, s *Server, raw string) gojwt.MapClaims {
	t.Helper()
	out, err := s.jwksHandler(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	claims := gojwt.MapClaims{}
	_, err = gojwt.ParseWithClaims(raw, claims, func(tok *gojwt.Token) (any, error) {
		kid, _ := tok.Header["kid"].(string)
		keys := out.Body.Key(kid)
		if len(keys) != 1 {
			t.Fatalf("kid %q not in JWKS", kid)
		}
		return keys[0].Key, nil
	}, gojwt.WithValidMethods([]string{string(jose.RS256)}), gojwt.WithIssuer(testIssuer))
	if err != nil {
		t.Fatalf("verify %q: %v", raw, err)
	}
	return claims
}

func checkIDTokenFlow(t *testing.T, s *Server) {
	t.Helper()
	sess := socialSession(t, s)
	tokens := exchangeCode(t, s, authorizeCode(t, s, "openid email profile offline_access", withCookie(sess)))
	idToken, _ := tokens["id_token"].(string)
	if idToken == "" {
		t.Fatalf("no id_token: %v", tokens)
	}
	claims := verifyJWT(t, s, idToken)
	req, err := http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(sess)
	ls, err := s.CurrentLoginSession(req)
	if err != nil {
		t.Fatal(err)
	}
	if claims["sub"] != ls.PrincipalID.String() || claims["nonce"] != "rp-nonce-12345" {
		t.Errorf("id token claims: %v", claims)
	}
	if aud, err := claims.GetAudience(); err != nil || len(aud) != 1 || aud[0] != "spa" {
		t.Errorf("aud = %v (%v)", aud, err)
	}
	if claims["email"] != "octo@example.com" || claims["email_verified"] != true || claims["auth_time"] == nil {
		t.Errorf("id token profile claims: %v", claims)
	}

	// Refresh issues a fresh ID token for the same subject.
	rt, _ := tokens["refresh_token"].(string)
	status, refreshed := refresh(t, s, rt)
	if status != http.StatusOK {
		t.Fatalf("refresh: %d %v", status, refreshed)
	}
	id2, _ := refreshed["id_token"].(string)
	if id2 == "" || verifyJWT(t, s, id2)["sub"] != claims["sub"] {
		t.Errorf("refreshed id token: %v", refreshed)
	}
}

func TestIDTokenIssuedAndVerifiable(t *testing.T) {
	checkIDTokenFlow(t, newSocialFlowServer(t, true))
}

func TestIDTokenIssuedEnt(t *testing.T) {
	client := enttest.Open(t, "sqlite3", "file:oidc_ent?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	owner := createTestUser(t, client)
	f := newFakeGitHub(t)
	s, err := NewEmbedded(Config{
		Issuer: testIssuer,
		Clients: []ClientConfig{{
			ID: "spa", Type: "public", Name: "Example App",
			RedirectURIs:  []string{testRPCB},
			GrantTypes:    []string{"authorization_code", "refresh_token"},
			ResponseTypes: []string{"code"},
			Scopes:        []string{"openid", "profile", "email", "offline_access"},
		}},
		SocialLogin: &SocialLoginConfig{SkipConsent: true},
	}, WithStorage(NewEntStorage(client, WithDefaultOwner(owner))), WithSocialConnector(f.connector()))
	if err != nil {
		t.Fatal(err)
	}
	checkIDTokenFlow(t, s)
}

func TestJWTAccessTokens(t *testing.T) {
	f := newFakeGitHub(t)
	s, err := NewEmbedded(Config{
		Issuer: testIssuer,
		Clients: []ClientConfig{{
			ID: "spa", Type: "public", Name: "Example App",
			RedirectURIs:  []string{testRPCB},
			GrantTypes:    []string{"authorization_code", "refresh_token"},
			ResponseTypes: []string{"code"},
			Scopes:        []string{"openid", "email", "offline_access"},
		}},
		Features:    FeatureConfig{EnableJWTAccessTokens: true, RequirePKCE: true},
		SocialLogin: &SocialLoginConfig{SkipConsent: true},
	}, WithSocialConnector(f.connector()), WithPrincipalDirectory(NewMemoryPrincipalDirectory()))
	if err != nil {
		t.Fatal(err)
	}
	sess := socialSession(t, s)
	tokens := exchangeCode(t, s, authorizeCode(t, s, "openid email offline_access", withCookie(sess)))
	at, _ := tokens["access_token"].(string)
	if strings.Count(at, ".") != 2 {
		t.Fatalf("access token is not a JWT: %q", at)
	}
	claims := verifyJWT(t, s, at)
	if claims["client_id"] != "spa" || claims["sub"] == "" || claims["sub"] == "spa" {
		t.Errorf("access token claims: %v", claims)
	}
	scp, _ := claims["scp"].([]any)
	if len(scp) != 3 {
		t.Errorf("scp = %v", claims["scp"])
	}

	// JWT access tokens are still stored: userinfo and revocation work.
	if w, info := userinfo(t, s, bearer(at), http.MethodGet, nil); w.Code != http.StatusOK || info["sub"] != claims["sub"] {
		t.Errorf("userinfo with JWT: %d %v", w.Code, info)
	}
	if w := postForm(s, LogoutPath, testIssuer, url.Values{}, sess); w.Code != http.StatusSeeOther {
		t.Fatal(w.Code)
	}
	if w, _ := userinfo(t, s, bearer(at), http.MethodGet, nil); w.Code != http.StatusUnauthorized {
		t.Errorf("revoked JWT accepted by userinfo: %d", w.Code)
	}
}

func TestIDPHintSkipsChooser(t *testing.T) {
	s := newSocialFlowServer(t, true)
	u := authorizeURL("openid") + "&" + IDPHintParam + "=github"
	w := httptestRecorder(s, u)
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Path != LoginPath+"/github" || loc.Query().Get("return_to") != u {
		t.Errorf("idp_hint redirect = %s", loc)
	}
	// Unknown providers fall back to the chooser.
	w = httptestRecorder(s, authorizeURL("openid")+"&"+IDPHintParam+"=myspace")
	if !strings.HasPrefix(w.Header().Get("Location"), LoginPath+"?") {
		t.Errorf("unknown hint redirect = %s", w.Header().Get("Location"))
	}
}

func httptestRecorder(s *Server, target string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, target, nil))
	return w
}
