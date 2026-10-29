package systemauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

func userinfo(t *testing.T, s *Server, decorate func(*http.Request), method string, body url.Values) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, UserInfoPath, strings.NewReader(body.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(method, UserInfoPath, nil)
	}
	if decorate != nil {
		decorate(req)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	var claims map[string]any
	if w.Body.Len() > 0 {
		if err := json.Unmarshal(w.Body.Bytes(), &claims); err != nil {
			t.Fatalf("userinfo body not JSON (%d): %s", w.Code, w.Body.String())
		}
	}
	return w, claims
}

func bearer(token string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) }
}

func TestUserInfoScopes(t *testing.T) {
	s := newSocialFlowServer(t, PartyFirst)
	sess := socialSession(t, s)
	loginReq := httptest.NewRequest(http.MethodGet, "/", nil)
	loginReq.AddCookie(sess)
	ls, err := s.CurrentLoginSession(loginReq)
	if err != nil {
		t.Fatal(err)
	}
	principalID := ls.PrincipalID.String()

	tokenFor := func(scope string) string {
		t.Helper()
		tokens := exchangeCode(t, s, authorizeCode(t, s, scope, withCookie(sess)))
		at, _ := tokens["access_token"].(string)
		return at
	}

	// openid + email: email claims only.
	w, claims := userinfo(t, s, dpopAuth(t, tokenFor("openid email")), http.MethodGet, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("userinfo: %d %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
		t.Errorf("headers: %v", w.Header())
	}
	if claims["sub"] != principalID || claims["email"] != "octo@example.com" || claims["email_verified"] != true {
		t.Errorf("email claims: %v", claims)
	}
	if _, ok := claims["name"]; ok {
		t.Errorf("profile claim released without profile scope: %v", claims)
	}
	// The verification time is a NumericDate, released with the email scope.
	if at, ok := claims[EmailVerifiedAtClaim].(float64); !ok || at <= 0 || at > float64(time.Now().Unix()) {
		t.Errorf("email_verified_at = %v", claims[EmailVerifiedAtClaim])
	}

	// A DPoP-bound token cannot travel in a POST body, which carries only
	// Bearer tokens.
	profileToken := tokenFor("openid profile")
	w, claims = userinfo(t, s, nil, http.MethodPost, url.Values{"access_token": {profileToken}})
	if w.Code != http.StatusUnauthorized || claims["error"] != "invalid_token" {
		t.Errorf("bound token in a POST body: %d %v", w.Code, claims)
	}

	// openid + profile: profile claims, no email; POST with DPoP.
	w, claims = userinfo(t, s, dpopAuth(t, profileToken), http.MethodPost, url.Values{})
	if w.Code != http.StatusOK || claims["name"] != "Octo Cat" || claims["sub"] != principalID {
		t.Fatalf("profile claims: %d %v", w.Code, claims)
	}
	if _, ok := claims["email"]; ok {
		t.Errorf("email released without email scope: %v", claims)
	}
	if _, ok := claims[EmailVerifiedAtClaim]; ok {
		t.Errorf("email_verified_at released without email scope: %v", claims)
	}

	// No openid scope: 403 insufficient_scope.
	w, claims = userinfo(t, s, dpopAuth(t, tokenFor("email")), http.MethodGet, nil)
	if w.Code != http.StatusForbidden || claims["error"] != "insufficient_scope" ||
		!strings.Contains(w.Header().Get("WWW-Authenticate"), `error="insufficient_scope"`) {
		t.Errorf("no openid: %d %v %q", w.Code, claims, w.Header().Get("WWW-Authenticate"))
	}
}

func TestUserInfoInvalidToken(t *testing.T) {
	s := newSocialFlowServer(t, PartyFirst)

	// Missing token: 401 with a bare challenge.
	w, _ := userinfo(t, s, nil, http.MethodGet, nil)
	if w.Code != http.StatusUnauthorized || !slices.Equal(w.Header().Values("WWW-Authenticate"), []string{`Bearer realm="systemauth"`, `DPoP algs="ES256 ES384 ES512"`}) {
		t.Errorf("missing token: %d %q", w.Code, w.Header().Values("WWW-Authenticate"))
	}

	// Unknown token: 401 invalid_token.
	w, claims := userinfo(t, s, bearer("not-a-token"), http.MethodGet, nil)
	if w.Code != http.StatusUnauthorized || claims["error"] != "invalid_token" ||
		!strings.Contains(w.Header().Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Errorf("invalid token: %d %v %q", w.Code, claims, w.Header().Get("WWW-Authenticate"))
	}

	// Token in the query string is not accepted.
	sess := socialSession(t, s)
	tokens := exchangeCode(t, s, authorizeCode(t, s, "openid email", withCookie(sess)))
	at, _ := tokens["access_token"].(string)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, UserInfoPath+"?access_token="+url.QueryEscape(at), nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("query token accepted: %d", w.Code)
	}

	// Revoked (after logout): 401 invalid_token.
	if w := postForm(s, LogoutPath, testIssuer, url.Values{}, sess); w.Code != http.StatusSeeOther {
		t.Fatalf("logout: %d", w.Code)
	}
	if w, _ := userinfo(t, s, dpopAuth(t, at), http.MethodGet, nil); w.Code != http.StatusUnauthorized {
		t.Errorf("revoked token: %d", w.Code)
	}
}

func TestUserInfoClaimsFiltering(t *testing.T) {
	claims := map[string]any{
		"sub":            "spoofed",
		"email":          "a@example.com",
		"email_verified": true,
		"name":           "A",
		"picture":        "https://example.com/a.png",
		"org_ids":        []string{"o1"},
	}
	got := UserInfoClaims("p1", claims, []string{"openid", "profile"})
	if got["sub"] != "p1" || got["name"] != "A" || got["picture"] == nil || got["org_ids"] == nil {
		t.Errorf("filtered = %v", got)
	}
	if _, ok := got["email"]; ok {
		t.Errorf("email released without scope: %v", got)
	}
}

func TestDiscoveryAdvertisesUserInfo(t *testing.T) {
	s := newSocialFlowServer(t, PartyFirst)
	out, err := s.openIDConfigHandler(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Body.UserinfoEndpoint != testIssuer+UserInfoPath {
		t.Errorf("userinfo_endpoint = %q", out.Body.UserinfoEndpoint)
	}
}
