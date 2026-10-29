package systemauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
)

// newProductionTestServer serves a confidential web client, a client
// registered with the bearer-token exception, and a public client, under
// policy.
func newProductionTestServer(t *testing.T, policy ProductionPolicy) *Server {
	t.Helper()
	s, err := NewEmbedded(Config{
		Issuer: testIssuer,
		Clients: []ClientConfig{
			// The default grants of a confidential client include
			// client_credentials.
			{ID: "web", Type: "confidential", Name: "Web", Secret: "web-secret",
				RedirectURIs: []string{testRPCB}, Scopes: []string{"openid", "offline_access", "read"}},
			{ID: "legacy", Type: "confidential", Name: "Legacy", Secret: "legacy-secret",
				GrantTypes: []string{"client_credentials"}, Scopes: []string{"read"}, AllowBearerTokens: true},
		},
	},
		WithSessionProvider(NewDefaultSessionProvider(WithTrustedUserIDHeader("X-User-ID", TrustAllRequests))),
		WithProductionPolicy(policy),
	)
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	return s
}

// TestProductionPolicyRefusesClientSecretClientCredentials verifies that
// the client_credentials grant with a shared secret is refused with a
// plain unauthorized_client, while the same confidential client keeps
// using its secret for the authorization code and refresh token grants.
func TestProductionPolicyRefusesClientSecretClientCredentials(t *testing.T) {
	s := newProductionTestServer(t, ProductionPolicy{RefuseClientSecretClientCredentials: true})
	kp := newDPoPKey(t)

	w, body := rawTokenRequest(t, s, serviceForm("web", "web-secret"), tokenProof(t, kp))
	if w.Code != http.StatusBadRequest || body["error"] != "unauthorized_client" {
		t.Fatalf("client_credentials: %d %v", w.Code, body)
	}
	if strings.Contains(w.Body.String(), "shared") || strings.Contains(w.Body.String(), "production") {
		t.Errorf("the refusal carries internal detail: %s", w.Body.String())
	}
	// A wrong secret is still invalid_client: the policy runs after the
	// client is authenticated.
	if w, body := rawTokenRequest(t, s, serviceForm("web", "wrong"), tokenProof(t, kp)); body["error"] != "invalid_client" {
		t.Errorf("wrong secret: %d %v", w.Code, body)
	}

	// The confidential client's code and refresh token grants work.
	subject := newPrincipal(t, s)
	code := authorizeCodeFor(t, s, subject, url.Values{"client_id": {"web"}}).Query().Get("code")
	if code == "" {
		t.Fatal("no authorization code")
	}
	form := codeForm(code)
	form.Set("client_id", "web")
	form.Set("client_secret", "web-secret")
	w, first := rawTokenRequest(t, s, form, tokenProof(t, kp))
	if w.Code != http.StatusOK || first["token_type"] != TokenTypeDPoP {
		t.Fatalf("code exchange: %d %v", w.Code, first)
	}
	refresh := refreshForm(str(first["refresh_token"]))
	refresh.Set("client_id", "web")
	refresh.Set("client_secret", "web-secret")
	if w, body := rawTokenRequest(t, s, refresh, tokenProof(t, kp)); w.Code != http.StatusOK {
		t.Errorf("refresh: %d %v", w.Code, body)
	}

	// Discovery no longer offers the grant.
	if slices.Contains(s.OpenIDConfiguration().GrantTypesSupported, "client_credentials") {
		t.Error("discovery offers client_credentials")
	}
}

// TestProductionPolicyRefusesBearerTokenClients verifies that a client
// registered with allow_bearer_tokens gets no token, with or without a
// proof.
func TestProductionPolicyRefusesBearerTokenClients(t *testing.T) {
	s := newProductionTestServer(t, ProductionPolicy{RefuseBearerTokenClients: true})
	for name, proofs := range map[string][]string{"no proof": nil, "proof": {tokenProof(t, newDPoPKey(t))}} {
		if w, body := rawTokenRequest(t, s, serviceForm("legacy", "legacy-secret"), proofs...); w.Code != http.StatusBadRequest || body["error"] != "unauthorized_client" {
			t.Errorf("%s: %d %v", name, w.Code, body)
		}
	}
	// Other clients are unaffected, client_credentials included.
	if w, body := rawTokenRequest(t, s, serviceForm("web", "web-secret"), tokenProof(t, newDPoPKey(t))); w.Code != http.StatusOK {
		t.Errorf("web client_credentials: %d %v", w.Code, body)
	}
}

// TestProductionPolicyOffByDefault verifies that NewEmbedded without the
// option serves both, and discovery offers client_credentials.
func TestProductionPolicyOffByDefault(t *testing.T) {
	s := newProductionTestServer(t, ProductionPolicy{})
	if w, body := rawTokenRequest(t, s, serviceForm("web", "web-secret"), tokenProof(t, newDPoPKey(t))); w.Code != http.StatusOK {
		t.Errorf("client_credentials: %d %v", w.Code, body)
	}
	if w, body := rawTokenRequest(t, s, serviceForm("legacy", "legacy-secret")); w.Code != http.StatusOK || body["token_type"] != TokenTypeBearer {
		t.Errorf("bearer client: %d %v", w.Code, body)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
	var d OpenIDConfiguration
	if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(d.GrantTypesSupported, "client_credentials") {
		t.Errorf("discovery grant types %v", d.GrantTypesSupported)
	}
}

// TestProductionAllowValidation verifies that production.allow accepts
// the named checks only.
func TestProductionAllowValidation(t *testing.T) {
	cfg := DefaultConfig(testIssuer)
	cfg.Production.Allow = []string{AllowEphemeralHMACSecret, AllowClientSecretClientCredentials, AllowBearerTokenClients}
	if err := cfg.Validate(); err != nil {
		t.Errorf("known names: %v", err)
	}
	if !cfg.Production.Allows(AllowBearerTokenClients) || (ProductionConfig{}).Allows(AllowBearerTokenClients) {
		t.Error("Allows")
	}
	cfg.Production.Allow = []string{"ephemeral-hmac-secret"}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "production.allow") {
		t.Errorf("unknown name: %v", err)
	}
}
