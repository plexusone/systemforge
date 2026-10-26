package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/grokify/goauth/dpop"
	"golang.org/x/crypto/bcrypt"

	"github.com/plexusone/systemforge/identity/dpopproof"
	"github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/systemauth"
)

const (
	dpopIssuer   = "https://issuer.example"
	dpopTokenURL = dpopIssuer + "/oauth/token"
)

// dpopServer is an API over a provider with a first-party public client
// (spa), a confidential client that must use DPoP (svc) and one with the
// bearer-token exception (legacy), and a principal to sign in.
type dpopServer struct {
	*flow
	api     *API
	subject string
}

func newDPoPServer(t *testing.T, mutate func(*Config), opts ...Option) *dpopServer {
	t.Helper()
	ctx := context.Background()
	f := newFlow(t)
	if _, err := f.db.OAuthApp.Update().SetFirstParty(true).Save(ctx); err != nil {
		t.Fatalf("first-party: %v", err)
	}
	owner, err := f.db.Principal.Query().First(ctx)
	if err != nil {
		t.Fatalf("owner: %v", err)
	}
	for _, c := range []struct {
		id     string
		bearer bool
	}{{"svc", false}, {"legacy", true}} {
		app, err := f.db.OAuthApp.Create().SetClientID(c.id).SetName(c.id).SetOwnerID(owner.ID).
			SetAllowedGrants([]string{"client_credentials"}).SetAllowedScopes([]string{"read", "introspect"}).
			SetAllowBearerTokens(c.bearer).Save(ctx)
		if err != nil {
			t.Fatalf("app %s: %v", c.id, err)
		}
		h, err := bcrypt.GenerateFromPassword([]byte(c.id+"-secret"), bcrypt.MinCost)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.OAuthAppSecret.Create().SetAppID(app.ID).SetSecretHash(string(h)).SetSecretPrefix(c.id).Save(ctx); err != nil {
			t.Fatalf("secret %s: %v", c.id, err)
		}
	}
	user, err := f.db.Principal.Create().SetType(principal.TypeHuman).SetIdentifier(uuid.NewString() + "@example.com").SetDisplayName("Ada").Save(ctx)
	if err != nil {
		t.Fatalf("principal: %v", err)
	}

	cfg := ephemeralConfig(DefaultConfig(dpopIssuer, []byte("0123456789abcdef0123456789abcdef")))
	if mutate != nil {
		mutate(cfg)
	}
	p, err := NewProvider(f.db, cfg)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	f.p = p
	opts = append([]Option{WithTrustedUserIDHeader("X-User-ID", systemauth.TrustAllRequests), WithAnyClient()}, opts...)
	api, err := NewAPI(p, opts...)
	if err != nil {
		t.Fatalf("NewAPI: %v", err)
	}
	return &dpopServer{flow: f, api: api, subject: user.ID.String()}
}

func newDPoPKey(t *testing.T) *dpop.KeyPair {
	t.Helper()
	kp, err := dpop.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func proofFor(t *testing.T, kp *dpop.KeyPair, method, uri, accessToken string) string {
	t.Helper()
	proof, err := dpop.CreateProofWithOptions(kp, method, uri, dpop.ProofOptions{AccessToken: accessToken})
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func tokenProof(t *testing.T, kp *dpop.KeyPair) string {
	t.Helper()
	return proofFor(t, kp, http.MethodPost, dpopTokenURL, "")
}

// code runs the authorization endpoint with extra parameters and returns
// the code and the PKCE verifier.
func (s *dpopServer) code(t *testing.T, extra url.Values) (code, verifier string) {
	t.Helper()
	verifier, challenge := pkcePair()
	q := url.Values{
		"response_type": {"code"}, "client_id": {s.clientID}, "redirect_uri": {flowRedirect},
		"scope": {"openid offline read"}, "state": {"state-" + uuid.NewString()},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
	for k, v := range extra {
		q[k] = v
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	req.Header.Set("X-User-ID", s.subject)
	w := httptest.NewRecorder()
	s.api.ServeHTTP(w, req)
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return loc.Query().Get("code"), verifier
}

// token posts form to the token endpoint with the given DPoP headers.
func (s *dpopServer) token(t *testing.T, form url.Values, proofs ...string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	if form.Get("client_id") == "" {
		form.Set("client_id", s.clientID)
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, p := range proofs {
		req.Header.Add("DPoP", p)
	}
	w := httptest.NewRecorder()
	s.api.ServeHTTP(w, req)
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("token response not JSON (%d): %s", w.Code, w.Body.String())
	}
	return w, body
}

func serviceForm(id string) url.Values {
	return url.Values{"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {id + "-secret"}, "scope": {"read introspect"}}
}

// introspect introspects token as the svc client, which presents its own
// token as authenticate does.
func (s *dpopServer) introspect(t *testing.T, token string) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/oauth/introspect", strings.NewReader(url.Values{"token": {token}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("svc", "svc-secret")
	w := httptest.NewRecorder()
	s.api.ServeHTTP(w, req)
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("introspection: %d %s", w.Code, w.Body)
	}
	return out
}

// TestDPoPCodeFlowWithDPoPJKT verifies RFC 9449 §10: a code issued for a
// dpop_jkt is redeemed only with a proof by that key, a refused exchange
// leaves the code usable, and the tokens are bound to the key.
func TestDPoPCodeFlowWithDPoPJKT(t *testing.T) {
	s := newDPoPServer(t, nil)
	kp, other := newDPoPKey(t), newDPoPKey(t)

	code, verifier := s.code(t, url.Values{"dpop_jkt": {kp.Thumbprint}})
	form := func() url.Values { return codeExchange(code, verifier, flowRedirect) }
	if w, body := s.token(t, form()); w.Code != http.StatusBadRequest || body["error"] != "invalid_dpop_proof" {
		t.Errorf("no proof: %d %v", w.Code, body)
	}
	if w, body := s.token(t, form(), tokenProof(t, other)); w.Code != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Errorf("other key: %d %v", w.Code, body)
	}
	w, body := s.token(t, form(), tokenProof(t, kp))
	if w.Code != http.StatusOK || body["token_type"] != systemauth.TokenTypeDPoP {
		t.Fatalf("bound key: %d %v", w.Code, body)
	}
	got := s.introspect(t, str(body["access_token"]))
	if cnf, _ := got["cnf"].(map[string]any); got["active"] != true || got["token_type"] != systemauth.TokenTypeDPoP || cnf["jkt"] != kp.Thumbprint {
		t.Errorf("introspection: %v", got)
	}

	// A malformed dpop_jkt is refused at the authorization endpoint.
	if code, _ := s.code(t, url.Values{"dpop_jkt": {"not a thumbprint"}}); code != "" {
		t.Error("malformed dpop_jkt produced a code")
	}
}

// TestDPoPRefreshBinding verifies RFC 9449 §5: a refresh token works only
// with a proof by the key it is bound to, and a refused attempt does not
// spend it.
func TestDPoPRefreshBinding(t *testing.T) {
	s := newDPoPServer(t, nil)
	kp, other := newDPoPKey(t), newDPoPKey(t)

	code, verifier := s.code(t, nil)
	w, first := s.token(t, codeExchange(code, verifier, flowRedirect), tokenProof(t, kp))
	if w.Code != http.StatusOK || first["token_type"] != systemauth.TokenTypeDPoP {
		t.Fatalf("code exchange: %d %v", w.Code, first)
	}
	rt := str(first["refresh_token"])
	refresh := func() url.Values { return url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}} }

	if w, body := s.token(t, refresh()); w.Code != http.StatusBadRequest || body["error"] != "invalid_dpop_proof" {
		t.Errorf("refresh without a proof: %d %v", w.Code, body)
	}
	if w, body := s.token(t, refresh(), tokenProof(t, other)); w.Code != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Errorf("refresh with another key: %d %v", w.Code, body)
	}
	w, second := s.token(t, refresh(), tokenProof(t, kp))
	if w.Code != http.StatusOK || second["token_type"] != systemauth.TokenTypeDPoP || str(second["refresh_token"]) == rt {
		t.Fatalf("refresh with the bound key: %d %v", w.Code, second)
	}
	rt = str(second["refresh_token"])
	if w, body := s.token(t, refresh(), tokenProof(t, other)); w.Code == http.StatusOK {
		t.Errorf("rotated refresh token with another key: %d %v", w.Code, body)
	}
}

// TestDPoPProofChecksAtTokenEndpoint verifies that a proof must be for
// POST at the token endpoint URL, one per request, and is accepted once.
func TestDPoPProofChecksAtTokenEndpoint(t *testing.T) {
	s := newDPoPServer(t, nil)
	kp := newDPoPKey(t)

	for name, proofs := range map[string][]string{
		"wrong htu":   {proofFor(t, kp, http.MethodPost, "https://elsewhere.example.com/oauth/token", "")},
		"wrong htm":   {proofFor(t, kp, http.MethodGet, dpopTokenURL, "")},
		"not a JWT":   {"nonsense"},
		"two headers": {tokenProof(t, kp), tokenProof(t, kp)},
	} {
		if w, body := s.token(t, serviceForm("svc"), proofs...); w.Code != http.StatusBadRequest || body["error"] != "invalid_dpop_proof" {
			t.Errorf("%s: %d %v", name, w.Code, body)
		}
	}
	proof := tokenProof(t, kp)
	if w, body := s.token(t, serviceForm("svc"), proof); w.Code != http.StatusOK {
		t.Fatalf("first use: %d %v", w.Code, body)
	}
	if w, body := s.token(t, serviceForm("svc"), proof); w.Code != http.StatusBadRequest || body["error"] != "invalid_dpop_proof" {
		t.Errorf("replayed proof: %d %v", w.Code, body)
	}
}

// TestDPoPClientCredentials verifies that client credentials need a proof
// unless the client has the bearer-token exception, and that a bound JWT
// access token carries cnf.jkt.
func TestDPoPClientCredentials(t *testing.T) {
	s := newDPoPServer(t, func(c *Config) { c.JWTAccessTokens = true })
	kp := newDPoPKey(t)

	if w, body := s.token(t, serviceForm("svc")); w.Code != http.StatusBadRequest || body["error"] != "invalid_dpop_proof" {
		t.Errorf("no proof: %d %v", w.Code, body)
	}
	w, body := s.token(t, serviceForm("svc"), tokenProof(t, kp))
	if w.Code != http.StatusOK || body["token_type"] != systemauth.TokenTypeDPoP {
		t.Fatalf("with proof: %d %v", w.Code, body)
	}
	at := str(body["access_token"])
	claims := gojwt.MapClaims{}
	parsed, _, err := gojwt.NewParser().ParseUnverified(at, claims)
	if err != nil {
		t.Fatal(err)
	}
	if cnf, _ := claims["cnf"].(map[string]any); cnf["jkt"] != kp.Thumbprint || claims["client_id"] != "svc" || claims["sub"] != "svc" {
		t.Errorf("JWT claims = %v", claims)
	}
	if parsed.Header["typ"] != systemauth.AccessTokenType || parsed.Header["kid"] != s.p.KeyID() {
		t.Errorf("JWT header = %v", parsed.Header)
	}

	// The legacy client gets a bearer token without a proof.
	w, body = s.token(t, serviceForm("legacy"))
	if w.Code != http.StatusOK || body["token_type"] != systemauth.TokenTypeBearer {
		t.Fatalf("legacy without proof: %d %v", w.Code, body)
	}
	plain := gojwt.MapClaims{}
	if _, _, err := gojwt.NewParser().ParseUnverified(str(body["access_token"]), plain); err != nil {
		t.Fatal(err)
	}
	if _, bound := plain["cnf"]; bound {
		t.Errorf("bearer token carries cnf: %v", plain["cnf"])
	}
	if w, body := s.token(t, serviceForm("legacy"), tokenProof(t, kp)); w.Code != http.StatusOK || body["token_type"] != systemauth.TokenTypeDPoP {
		t.Errorf("legacy with proof: %d %v", w.Code, body)
	}
}

// TestDPoPMiddleware verifies that Middleware takes a bound token only with
// the DPoP scheme and a valid, fresh proof by its key for the request at
// the resource base URL, carrying the token's hash, and an unbound token
// only with the Bearer scheme.
func TestDPoPMiddleware(t *testing.T) {
	const base = "https://api.example.com/v1"
	s := newDPoPServer(t, nil, WithResourceBaseURL(base+"/"))
	kp, other := newDPoPKey(t), newDPoPKey(t)
	code, verifier := s.code(t, nil)
	_, tokens := s.token(t, codeExchange(code, verifier, flowRedirect), tokenProof(t, kp))
	at := str(tokens["access_token"])
	htu := base + "/items"

	var seen string
	h := s.api.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = UserIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	call := func(scheme, token string, proofs ...string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/items", nil)
		req.Header.Set("Authorization", scheme+" "+token)
		for _, p := range proofs {
			req.Header.Add("DPoP", p)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}

	if w := call("DPoP", at, proofFor(t, kp, http.MethodGet, htu, at)); w.Code != http.StatusOK || seen != s.subject {
		t.Fatalf("valid proof: %d %s, subject %q", w.Code, w.Body, seen)
	}
	replayed := proofFor(t, kp, http.MethodGet, htu, at)
	if w := call("DPoP", at, replayed); w.Code != http.StatusOK {
		t.Fatalf("first use: %d", w.Code)
	}
	for name, tc := range map[string]struct {
		scheme string
		proofs []string
		code   string
	}{
		"bound token as Bearer": {"Bearer", []string{proofFor(t, kp, http.MethodGet, htu, at)}, "invalid_token"},
		"no proof":              {"DPoP", nil, "invalid_dpop_proof"},
		"other key":             {"DPoP", []string{proofFor(t, other, http.MethodGet, htu, at)}, "invalid_dpop_proof"},
		"no ath":                {"DPoP", []string{proofFor(t, kp, http.MethodGet, htu, "")}, "invalid_dpop_proof"},
		"issuer origin htu":     {"DPoP", []string{proofFor(t, kp, http.MethodGet, dpopIssuer+"/items", at)}, "invalid_dpop_proof"},
		"wrong htm":             {"DPoP", []string{proofFor(t, kp, http.MethodPost, htu, at)}, "invalid_dpop_proof"},
		"replayed":              {"DPoP", []string{replayed}, "invalid_dpop_proof"},
	} {
		w := call(tc.scheme, at, tc.proofs...)
		challenge := w.Header().Get("WWW-Authenticate")
		if w.Code != http.StatusUnauthorized || !strings.HasPrefix(challenge, "DPoP ") || !strings.Contains(challenge, `error="`+tc.code+`"`) {
			t.Errorf("%s: %d %q", name, w.Code, challenge)
		}
	}

	// An unbound token from the legacy client: Bearer only.
	_, legacy := s.token(t, serviceForm("legacy"))
	bearer := str(legacy["access_token"])
	if w := call("Bearer", bearer); w.Code != http.StatusOK {
		t.Errorf("bearer token: %d %q", w.Code, w.Header().Get("WWW-Authenticate"))
	}
	if w := call("DPoP", bearer, proofFor(t, kp, http.MethodGet, htu, bearer)); w.Code != http.StatusUnauthorized {
		t.Errorf("unbound token with the DPoP scheme: %d", w.Code)
	}
}

// TestDPoPDiscovery verifies the advertised proof algorithms.
func TestDPoPDiscovery(t *testing.T) {
	s := newDPoPServer(t, nil)
	w := httptest.NewRecorder()
	s.api.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
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
	nonces, err := dpopproof.NewNonces([]byte(strings.Repeat("n", 32)), 0)
	if err != nil {
		t.Fatal(err)
	}
	s := newDPoPServer(t, func(c *Config) { c.DPoP.Nonces = nonces })
	kp := newDPoPKey(t)

	w, body := s.token(t, serviceForm("svc"), tokenProof(t, kp))
	nonce := w.Header().Get("DPoP-Nonce")
	if w.Code != http.StatusBadRequest || body["error"] != "use_dpop_nonce" || nonce == "" {
		t.Fatalf("without a nonce: %d %v %q", w.Code, body, nonce)
	}
	proof, err := dpop.CreateProofWithOptions(kp, http.MethodPost, dpopTokenURL, dpop.ProofOptions{Nonce: nonce})
	if err != nil {
		t.Fatal(err)
	}
	if w, body := s.token(t, serviceForm("svc"), proof); w.Code != http.StatusOK || body["token_type"] != systemauth.TokenTypeDPoP {
		t.Errorf("with the nonce: %d %v", w.Code, body)
	}
}
