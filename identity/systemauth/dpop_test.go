package systemauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/grokify/goauth/dpop"
	"github.com/ory/fosite"

	"github.com/plexusone/systemforge/identity/ent/enttest"
)

const testTokenURL = testIssuer + "/oauth/token"

// rawTokenRequest posts form (with client_id spa) to the token endpoint
// with the given DPoP header values.
func rawTokenRequest(t *testing.T, s *Server, form url.Values, proofs ...string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	if form.Get("client_id") == "" && form.Get("client_secret") == "" {
		form.Set("client_id", "spa")
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, p := range proofs {
		req.Header.Add("DPoP", p)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("token response not JSON (%d): %s", w.Code, w.Body.String())
	}
	return w, body
}

func codeForm(code string) url.Values {
	return url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {testRPCB},
		"code_verifier": {testVerifier},
	}
}

func refreshForm(rt string) url.Values {
	return url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}
}

// authorizeCodeFor runs /oauth/authorize for subject with extra
// parameters, returning the redirect.
func authorizeCodeFor(t *testing.T, s *Server, subject string, extra url.Values) *url.URL {
	t.Helper()
	u, err := url.Parse(authorizeURL("openid offline_access"))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	for k, v := range extra {
		q[k] = v
	}
	u.RawQuery = q.Encode()
	req := httptest.NewRequest(http.MethodGet, u.String(), nil)
	headerUser(subject)(req)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusFound && w.Code != http.StatusSeeOther {
		t.Fatalf("authorize: %d %s", w.Code, w.Body.String())
	}
	cb, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return cb
}

func tokenProof(t *testing.T, kp *dpop.KeyPair) string {
	t.Helper()
	return proofFor(t, kp, http.MethodPost, testTokenURL, "")
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// TestDPoPCodeFlowWithDPoPJKT verifies RFC 9449 §10: a code issued for a
// dpop_jkt is redeemed only with a proof by that key, and the tokens are
// bound to it.
func TestDPoPCodeFlowWithDPoPJKT(t *testing.T) {
	checkDPoPCodeFlowWithDPoPJKT(t, newRefreshTestServer(t))
}

// TestDPoPCodeFlowWithDPoPJKTEnt is TestDPoPCodeFlowWithDPoPJKT with Ent
// storage: a refused exchange leaves the code usable with either storage.
func TestDPoPCodeFlowWithDPoPJKTEnt(t *testing.T) {
	client := enttest.Open(t, "sqlite3", "file:dpop_code_flow?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	owner := createTestOwner(t, client)
	checkDPoPCodeFlowWithDPoPJKT(t, newRefreshTestServer(t, WithStorage(NewEntStorage(client, WithDefaultOwner(owner)))))
}

func checkDPoPCodeFlowWithDPoPJKT(t *testing.T, s *Server) {
	t.Helper()
	subject := newPrincipal(t, s)
	kp, other := newDPoPKey(t), newDPoPKey(t)
	jkt := url.Values{"dpop_jkt": {kp.Thumbprint}}

	// No proof: refused, and the code still works afterwards.
	code := authorizeCodeFor(t, s, subject, jkt).Query().Get("code")
	if w, body := rawTokenRequest(t, s, codeForm(code)); w.Code != http.StatusBadRequest || body["error"] != "invalid_dpop_proof" {
		t.Errorf("no proof: %d %v", w.Code, body)
	}
	// A proof by another key: refused before Fosite handles the grant, so
	// the code still works afterwards with every storage.
	if w, body := rawTokenRequest(t, s, codeForm(code), tokenProof(t, other)); w.Code != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Errorf("other key: %d %v", w.Code, body)
	}
	// The bound key: tokens bound to it.
	w, body := rawTokenRequest(t, s, codeForm(code), tokenProof(t, kp))
	if w.Code != http.StatusOK || body["token_type"] != TokenTypeDPoP {
		t.Fatalf("bound key: %d %v", w.Code, body)
	}
	ar, err := s.introspect(context.Background(), str(body["access_token"]), fosite.AccessToken, s.Session(""))
	if err != nil {
		t.Fatal(err)
	}
	if got := ar.GetSession().(*Session).DPoPJKT; got != kp.Thumbprint { //nolint:forcetypeassert // SystemAuth sessions
		t.Errorf("access token bound to %q, want %q", got, kp.Thumbprint)
	}

	// A malformed dpop_jkt is refused at the authorization endpoint.
	cb := authorizeCodeFor(t, s, subject, url.Values{"dpop_jkt": {"not a thumbprint"}})
	if cb.Query().Get("error") != "invalid_request" || cb.Query().Get("code") != "" {
		t.Errorf("malformed dpop_jkt: %s", cb)
	}
}

// TestDPoPRefreshBinding verifies RFC 9449 §5: a refresh token works only
// with a proof by the key it is bound to, and a refused attempt does not
// spend it.
func TestDPoPRefreshBinding(t *testing.T) {
	s := newRefreshTestServer(t)
	subject := newPrincipal(t, s)
	kp, other := newDPoPKey(t), newDPoPKey(t)

	code := authorizeCodeFor(t, s, subject, nil).Query().Get("code")
	w, first := rawTokenRequest(t, s, codeForm(code), tokenProof(t, kp))
	if w.Code != http.StatusOK || first["token_type"] != TokenTypeDPoP {
		t.Fatalf("code exchange: %d %v", w.Code, first)
	}
	rt := str(first["refresh_token"])

	if w, body := rawTokenRequest(t, s, refreshForm(rt)); w.Code != http.StatusBadRequest || body["error"] != "invalid_dpop_proof" {
		t.Errorf("refresh without a proof: %d %v", w.Code, body)
	}
	if w, body := rawTokenRequest(t, s, refreshForm(rt), tokenProof(t, other)); w.Code != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Errorf("refresh with another key: %d %v", w.Code, body)
	}
	w, second := rawTokenRequest(t, s, refreshForm(rt), tokenProof(t, kp))
	if w.Code != http.StatusOK || second["token_type"] != TokenTypeDPoP || str(second["refresh_token"]) == rt {
		t.Fatalf("refresh with the bound key: %d %v", w.Code, second)
	}
	// The rotated refresh token is bound to the same key.
	if w, body := rawTokenRequest(t, s, refreshForm(str(second["refresh_token"])), tokenProof(t, other)); w.Code == http.StatusOK {
		t.Errorf("rotated refresh token with another key: %d %v", w.Code, body)
	}
}

// TestDPoPProofChecksAtTokenEndpoint verifies that a proof must be for
// POST at the token endpoint URL, and is accepted once.
func TestDPoPProofChecksAtTokenEndpoint(t *testing.T) {
	s := newRefreshTestServer(t)
	subject := newPrincipal(t, s)
	kp := newDPoPKey(t)

	for name, proof := range map[string]string{
		"wrong htu":     proofFor(t, kp, http.MethodPost, "https://elsewhere.example.com/oauth/token", ""),
		"wrong htm":     proofFor(t, kp, http.MethodGet, testTokenURL, ""),
		"not a JWT":     "nonsense",
		"empty jwk set": "e30.e30.e30",
	} {
		code := authorizeCodeFor(t, s, subject, nil).Query().Get("code")
		if w, body := rawTokenRequest(t, s, codeForm(code), proof); w.Code != http.StatusBadRequest || body["error"] != "invalid_dpop_proof" {
			t.Errorf("%s: %d %v", name, w.Code, body)
		}
	}

	// Two DPoP headers: refused.
	code := authorizeCodeFor(t, s, subject, nil).Query().Get("code")
	if w, body := rawTokenRequest(t, s, codeForm(code), tokenProof(t, kp), tokenProof(t, kp)); w.Code != http.StatusBadRequest || body["error"] != "invalid_dpop_proof" {
		t.Errorf("two proofs: %d %v", w.Code, body)
	}

	// A replayed proof: refused the second time.
	proof := tokenProof(t, kp)
	if w, body := rawTokenRequest(t, s, codeForm(code), proof); w.Code != http.StatusOK {
		t.Fatalf("first use: %d %v", w.Code, body)
	}
	code = authorizeCodeFor(t, s, subject, nil).Query().Get("code")
	if w, body := rawTokenRequest(t, s, codeForm(code), proof); w.Code != http.StatusBadRequest || body["error"] != "invalid_dpop_proof" {
		t.Errorf("replayed proof: %d %v", w.Code, body)
	}
}

func newDPoPServiceServer(t *testing.T, cfg Config) *Server {
	t.Helper()
	cfg.Issuer = testIssuer
	cfg.Clients = []ClientConfig{
		{ID: "svc", Type: "confidential", Name: "Service", Secret: "svc-secret",
			GrantTypes: []string{"client_credentials"}, Scopes: []string{"read", "introspect"}},
		{ID: "legacy", Type: "confidential", Name: "Legacy", Secret: "legacy-secret",
			GrantTypes: []string{"client_credentials"}, Scopes: []string{"read"}, AllowBearerTokens: true},
	}
	s, err := NewEmbedded(cfg)
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	return s
}

func serviceForm(id, secret string) url.Values {
	return url.Values{"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {secret}, "scope": {"read"}}
}

// TestDPoPClientCredentials verifies that client credentials need a proof
// unless the client is registered with the bearer exception, and that a
// bound token carries cnf.jkt in the JWT, in introspection and in
// token_type.
func TestDPoPClientCredentials(t *testing.T) {
	s := newDPoPServiceServer(t, Config{Features: FeatureConfig{EnableJWTAccessTokens: true, RequirePKCE: true}})
	kp := newDPoPKey(t)

	if w, body := rawTokenRequest(t, s, serviceForm("svc", "svc-secret")); w.Code != http.StatusBadRequest || body["error"] != "invalid_dpop_proof" {
		t.Errorf("no proof: %d %v", w.Code, body)
	}
	w, body := rawTokenRequest(t, s, serviceForm("svc", "svc-secret"), tokenProof(t, kp))
	if w.Code != http.StatusOK || body["token_type"] != TokenTypeDPoP {
		t.Fatalf("with proof: %d %v", w.Code, body)
	}
	at := str(body["access_token"])
	claims := gojwt.MapClaims{}
	if _, _, err := gojwt.NewParser().ParseUnverified(at, claims); err != nil {
		t.Fatal(err)
	}
	if cnf, _ := claims["cnf"].(map[string]any); cnf["jkt"] != kp.Thumbprint {
		t.Errorf("JWT cnf = %v, want jkt %s", claims["cnf"], kp.Thumbprint)
	}

	// Introspection reports the binding.
	introspected := introspectAs(t, s, at)
	if introspected["active"] != true || introspected["token_type"] != TokenTypeDPoP {
		t.Errorf("introspection: %v", introspected)
	}
	if cnf, _ := introspected["cnf"].(map[string]any); cnf["jkt"] != kp.Thumbprint {
		t.Errorf("introspection cnf = %v", introspected["cnf"])
	}
	info, err := (&EmbeddedOAuthProvider{server: s}).Introspect(context.Background(), at, "")
	if err != nil || info.TokenType != TokenTypeDPoP || info.Cnf == nil || info.Cnf.JKT != kp.Thumbprint {
		t.Errorf("provider introspection: %+v %v", info, err)
	}

	// The legacy client gets a bearer token without a proof, and a bound
	// one when it does send a proof.
	w, body = rawTokenRequest(t, s, serviceForm("legacy", "legacy-secret"))
	if w.Code != http.StatusOK || body["token_type"] != TokenTypeBearer {
		t.Fatalf("legacy without proof: %d %v", w.Code, body)
	}
	plain := gojwt.MapClaims{}
	if _, _, err := gojwt.NewParser().ParseUnverified(str(body["access_token"]), plain); err != nil {
		t.Fatal(err)
	}
	if _, bound := plain["cnf"]; bound {
		t.Errorf("bearer token carries cnf: %v", plain["cnf"])
	}
	if got := introspectAs(t, s, str(body["access_token"])); got["token_type"] != TokenTypeBearer || got["cnf"] != nil {
		t.Errorf("bearer introspection: %v", got)
	}
	w, body = rawTokenRequest(t, s, serviceForm("legacy", "legacy-secret"), tokenProof(t, kp))
	if w.Code != http.StatusOK || body["token_type"] != TokenTypeDPoP {
		t.Errorf("legacy with proof: %d %v", w.Code, body)
	}
}

// introspectAs introspects token as the confidential svc client.
func introspectAs(t *testing.T, s *Server, token string) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/oauth/introspect", strings.NewReader(url.Values{"token": {token}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("svc", "svc-secret")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("introspection: %d %s", w.Code, w.Body)
	}
	return out
}

// TestDPoPResourceEndpoints verifies that SystemAuth's own resources take
// a bound token only with the DPoP scheme and a valid, fresh proof by its
// key for the request, carrying the token's hash.
func TestDPoPResourceEndpoints(t *testing.T) {
	s := newRefreshTestServer(t)
	subject := newPrincipal(t, s)
	kp, other := testDPoPKey(t), newDPoPKey(t)
	code := authorizeCodeFor(t, s, subject, nil).Query().Get("code")
	_, tokens := rawTokenRequest(t, s, codeForm(code), tokenProof(t, kp))
	at := str(tokens["access_token"])
	userinfoURL := testIssuer + UserInfoPath

	call := func(scheme string, proofs ...string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, UserInfoPath, nil)
		req.Header.Set("Authorization", scheme+" "+at)
		for _, p := range proofs {
			req.Header.Add("DPoP", p)
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, req)
		return w
	}

	if w := call("DPoP", proofFor(t, kp, http.MethodGet, userinfoURL, at)); w.Code != http.StatusOK {
		t.Fatalf("valid proof: %d %s", w.Code, w.Body)
	}
	replayed := proofFor(t, kp, http.MethodGet, userinfoURL, at)
	if w := call("DPoP", replayed); w.Code != http.StatusOK {
		t.Fatalf("first use: %d", w.Code)
	}
	for name, tc := range map[string]struct {
		scheme string
		proofs []string
		code   string
	}{
		"bound token as Bearer": {"Bearer", []string{proofFor(t, kp, http.MethodGet, userinfoURL, at)}, "invalid_token"},
		"no proof":              {"DPoP", nil, "invalid_dpop_proof"},
		"other key":             {"DPoP", []string{proofFor(t, other, http.MethodGet, userinfoURL, at)}, "invalid_dpop_proof"},
		"no ath":                {"DPoP", []string{proofFor(t, kp, http.MethodGet, userinfoURL, "")}, "invalid_dpop_proof"},
		"ath of another token":  {"DPoP", []string{proofFor(t, kp, http.MethodGet, userinfoURL, "another-token")}, "invalid_dpop_proof"},
		"wrong htu":             {"DPoP", []string{proofFor(t, kp, http.MethodGet, testIssuer+"/elsewhere", at)}, "invalid_dpop_proof"},
		"wrong htm":             {"DPoP", []string{proofFor(t, kp, http.MethodPost, userinfoURL, at)}, "invalid_dpop_proof"},
		"replayed":              {"DPoP", []string{replayed}, "invalid_dpop_proof"},
	} {
		w := call(tc.scheme, tc.proofs...)
		challenge := w.Header().Get("WWW-Authenticate")
		if w.Code != http.StatusUnauthorized || !strings.HasPrefix(challenge, "DPoP ") || !strings.Contains(challenge, `error="`+tc.code+`"`) {
			t.Errorf("%s: %d %q", name, w.Code, challenge)
		}
	}
}

// TestDPoPDiscovery verifies the advertised proof algorithms.
func TestDPoPDiscovery(t *testing.T) {
	s := newRefreshTestServer(t)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
	var md map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &md); err != nil {
		t.Fatal(err)
	}
	algs, _ := md["dpop_signing_alg_values_supported"].([]any)
	if len(algs) == 0 || algs[0] != "ES256" {
		t.Errorf("dpop_signing_alg_values_supported = %v", md["dpop_signing_alg_values_supported"])
	}
}

// TestDPoPServerNonce verifies RFC 9449 §8: with nonces required, a proof
// without one is refused with use_dpop_nonce and a DPoP-Nonce to retry
// with, which then succeeds.
func TestDPoPServerNonce(t *testing.T) {
	s := newDPoPServiceServer(t, Config{DPoP: DPoPConfig{RequireNonce: true, NonceSecret: strings.Repeat("n", 32)}})
	kp := newDPoPKey(t)

	w, body := rawTokenRequest(t, s, serviceForm("svc", "svc-secret"), tokenProof(t, kp))
	nonce := w.Header().Get("DPoP-Nonce")
	if w.Code != http.StatusBadRequest || body["error"] != "use_dpop_nonce" || nonce == "" {
		t.Fatalf("without a nonce: %d %v %q", w.Code, body, nonce)
	}
	proof, err := dpop.CreateProofWithOptions(kp, http.MethodPost, testTokenURL, dpop.ProofOptions{Nonce: nonce})
	if err != nil {
		t.Fatal(err)
	}
	if w, body := rawTokenRequest(t, s, serviceForm("svc", "svc-secret"), proof); w.Code != http.StatusOK || body["token_type"] != TokenTypeDPoP {
		t.Errorf("with the nonce: %d %v", w.Code, body)
	}
	bad, err := dpop.CreateProofWithOptions(kp, http.MethodPost, testTokenURL, dpop.ProofOptions{Nonce: "forged"})
	if err != nil {
		t.Fatal(err)
	}
	if w, body := rawTokenRequest(t, s, serviceForm("svc", "svc-secret"), bad); w.Code != http.StatusBadRequest || body["error"] != "use_dpop_nonce" {
		t.Errorf("forged nonce: %d %v", w.Code, body)
	}
}

func TestDPoPConfigValidation(t *testing.T) {
	cfg := DefaultConfig(testIssuer)
	cfg.DPoP.RequireNonce = true
	if err := cfg.Validate(); err == nil {
		t.Error("require_nonce without a secret validated")
	}
	cfg.DPoP.NonceSecret = strings.Repeat("s", 32)
	if err := cfg.Validate(); err != nil {
		t.Errorf("valid nonce configuration: %v", err)
	}
}
