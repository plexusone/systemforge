package systemauth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/grokify/goauth/dpop"

	"github.com/plexusone/systemforge/identity/serviceaccount"
)

// e2eJWTBearer is an embedded SystemAuth served over HTTP, with the
// JWT-bearer grant on, a service account holding a billing role, and a
// confidential client "rs" that introspects tokens.
type e2eJWTBearer struct {
	t    *testing.T
	f    *saFixture
	srv  *httptest.Server
	acct *serviceaccount.Account
	dpop *dpop.KeyPair
}

const e2eIntrospectionSecret = "rs-introspection-secret" //nolint:gosec // G101: a test client secret

func newE2EJWTBearer(t *testing.T) *e2eJWTBearer {
	t.Helper()
	f := newSAFixture(t)
	acct := f.account("ci-publisher")
	if err := f.svc.GrantRole(context.Background(), acct.ID, "billing", "viewer", f.owner); err != nil {
		t.Fatal(err)
	}
	var sa *Server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { sa.ServeHTTP(w, r) }))
	t.Cleanup(srv.Close)
	var err error
	sa, err = NewEmbedded(Config{
		Issuer:   srv.URL,
		Features: FeatureConfig{EnableJWTAccessTokens: true},
		OAuth:    OAuthConfig{JWTBearer: JWTBearerConfig{Enabled: true}},
		Clients: []ClientConfig{{
			ID: "rs", Type: "confidential", Name: "Resource server", Secret: e2eIntrospectionSecret,
			GrantTypes: []string{"client_credentials"},
		}},
	},
		WithStorage(NewEntStorage(f.db, WithDefaultOwner(f.owner))),
		WithOrgsSource(NewEntOrgsSource(f.db, f.roles)),
	)
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	return &e2eJWTBearer{t: t, f: f, srv: srv, acct: acct, dpop: newDPoPKey(t)}
}

func (e *e2eJWTBearer) tokenURL() string { return e.srv.URL + "/oauth/token" }

// assertion returns a valid assertion for the account's key, with mutate
// applied.
func (e *e2eJWTBearer) assertion(kid string, mutate func(*assertion)) assertion {
	a := assertion{iss: e.acct.Identifier, sub: e.acct.Identifier, aud: e.tokenURL(), kid: kid}
	if mutate != nil {
		mutate(&a)
	}
	return a
}

// token posts a JWT-bearer token request over HTTP, with a DPoP proof
// unless withProof is false.
func (e *e2eJWTBearer) token(signed string, withProof bool) (int, map[string]any) {
	e.t.Helper()
	req, err := http.NewRequest(http.MethodPost, e.tokenURL(), strings.NewReader(jwtBearerForm(signed).Encode()))
	if err != nil {
		e.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if withProof {
		req.Header.Set("DPoP", proofFor(e.t, e.dpop, http.MethodPost, e.tokenURL(), ""))
	}
	return e.do(req)
}

// introspect introspects token as the resource server.
func (e *e2eJWTBearer) introspect(token string) map[string]any {
	e.t.Helper()
	req, err := http.NewRequest(http.MethodPost, e.srv.URL+"/oauth/introspect", strings.NewReader(url.Values{"token": {token}}.Encode()))
	if err != nil {
		e.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("rs", e2eIntrospectionSecret)
	code, body := e.do(req)
	if code != http.StatusOK {
		e.t.Fatalf("introspection = %d %v", code, body)
	}
	return body
}

func (e *e2eJWTBearer) do(req *http.Request) (int, map[string]any) {
	e.t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			e.t.Errorf("closing response body: %v", err)
		}
	}()
	body := map[string]any{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		e.t.Fatalf("response %d is not JSON: %v", resp.StatusCode, err)
	}
	return resp.StatusCode, body
}

// issue exchanges a valid assertion signed by key and returns the access
// token.
func (e *e2eJWTBearer) issue(kid string, key crypto.Signer, alg jose.SignatureAlgorithm) string {
	e.t.Helper()
	code, body := e.token(e.assertion(kid, nil).sign(e.t, key, alg), true)
	if code != http.StatusOK {
		e.t.Fatalf("token request = %d %v", code, body)
	}
	if _, ok := body["refresh_token"]; ok {
		e.t.Error("the grant issued a refresh token")
	}
	token, _ := body["access_token"].(string)
	return token
}

// checkIntrospection verifies an active token's introspection response.
func (e *e2eJWTBearer) checkIntrospection(token string) {
	e.t.Helper()
	got := e.introspect(token)
	if got["active"] != true {
		e.t.Fatalf("introspection = %v, want active", got)
	}
	if got["sub"] != e.acct.ID.String() {
		e.t.Errorf("sub = %v, want %s", got["sub"], e.acct.ID)
	}
	if got[PrincipalTypeClaim] != PrincipalTypeService || got["token_type"] != TokenTypeDPoP {
		e.t.Errorf("principal_type = %v, token_type = %v", got[PrincipalTypeClaim], got["token_type"])
	}
	jkt, err := dpop.ComputeThumbprint(e.dpop.PublicKey())
	if err != nil {
		e.t.Fatal(err)
	}
	if cnf, _ := got["cnf"].(map[string]any); cnf["jkt"] != jkt {
		e.t.Errorf("cnf = %v, want jkt %s", got["cnf"], jkt)
	}
	orgs, _ := got[OrgsClaim].([]any)
	if len(orgs) != 1 {
		e.t.Fatalf("orgs = %v", got[OrgsClaim])
	}
	org, _ := orgs[0].(map[string]any)
	apps, _ := org["apps"].(map[string]any)
	if org["id"] != e.f.org.ID.String() || org["role"] != serviceaccount.MembershipRole || apps["billing"] != "viewer" {
		e.t.Errorf("orgs[0] = %v", org)
	}
}

func TestE2EJWTBearerP256(t *testing.T) {
	e := newE2EJWTBearer(t)
	k := e.f.key(e.acct, serviceaccount.KeyInput{})
	token := e.issue(k.KeyID, parsePrivateKey(t, k.PrivateKeyPEM), jose.ES256)
	e.checkIntrospection(token)
}

func TestE2EJWTBearerRSA(t *testing.T) {
	e := newE2EJWTBearer(t)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	k := e.f.key(e.acct, serviceaccount.KeyInput{PublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))})
	if k.Algorithm != "RS256" {
		t.Fatalf("algorithm = %s", k.Algorithm)
	}
	token := e.issue(k.KeyID, rsaKey, jose.RS256)
	e.checkIntrospection(token)
}

// requireRefused fails unless a token request was refused with code.
func requireRefused(t *testing.T, what string, status int, body map[string]any, code string) {
	t.Helper()
	if status != http.StatusBadRequest || body["error"] != code {
		t.Errorf("%s = %d %v, want 400 %s", what, status, body, code)
	}
	if _, ok := body["access_token"]; ok {
		t.Errorf("%s issued a token", what)
	}
}

func TestE2EJWTBearerRefusals(t *testing.T) {
	e := newE2EJWTBearer(t)
	k := e.f.key(e.acct, serviceaccount.KeyInput{})
	key := parsePrivateKey(t, k.PrivateKeyPEM)
	now := time.Now()

	replayed := e.assertion(k.KeyID, nil).sign(t, key, jose.ES256)
	if code, body := e.token(replayed, true); code != http.StatusOK {
		t.Fatalf("first use = %d %v", code, body)
	}
	code, body := e.token(replayed, true)
	requireRefused(t, "replay", code, body, "jti_known")

	cases := map[string]func(*assertion){
		"expired assertion": func(a *assertion) { a.iat, a.exp = now.Add(-10*time.Minute), now.Add(-5*time.Minute) },
		"overlong lifetime": func(a *assertion) { a.iat, a.exp = now, now.Add(10*time.Minute) },
		"missing jti":       func(a *assertion) { a.noJTI = true },
		"missing iat":       func(a *assertion) { a.noIAT = true },
		"wrong audience":    func(a *assertion) { a.aud = "https://elsewhere.example.com/oauth/token" },
		"another subject":   func(a *assertion) { a.sub = "sa_someoneelse" },
	}
	for name, mutate := range cases {
		code, body := e.token(e.assertion(k.KeyID, mutate).sign(t, key, jose.ES256), true)
		requireRefused(t, name, code, body, "invalid_grant")
	}

	code, body = e.token(e.assertion(k.KeyID, nil).sign(t, key, jose.ES256), false)
	requireRefused(t, "missing DPoP proof", code, body, "invalid_dpop_proof")
}

func TestE2EJWTBearerRevokedKey(t *testing.T) {
	e := newE2EJWTBearer(t)
	ctx := context.Background()
	k := e.f.key(e.acct, serviceaccount.KeyInput{})
	key := parsePrivateKey(t, k.PrivateKeyPEM)
	e.issue(k.KeyID, key, jose.ES256)
	if err := e.f.svc.RevokeKey(ctx, e.acct.ID, k.KeyID, "leaked"); err != nil {
		t.Fatal(err)
	}
	code, body := e.token(e.assertion(k.KeyID, nil).sign(t, key, jose.ES256), true)
	requireRefused(t, "revoked key", code, body, "invalid_grant")
	code, body = e.token(e.assertion("", nil).sign(t, key, jose.ES256), true)
	requireRefused(t, "revoked key without kid", code, body, "invalid_grant")
}

func TestE2EJWTBearerDisabledAccount(t *testing.T) {
	e := newE2EJWTBearer(t)
	ctx := context.Background()
	k := e.f.key(e.acct, serviceaccount.KeyInput{})
	key := parsePrivateKey(t, k.PrivateKeyPEM)
	token := e.issue(k.KeyID, key, jose.ES256)
	if err := e.f.svc.Disable(ctx, e.acct.ID, e.f.owner); err != nil {
		t.Fatal(err)
	}
	code, body := e.token(e.assertion(k.KeyID, nil).sign(t, key, jose.ES256), true)
	requireRefused(t, "disabled account", code, body, "invalid_grant")
	if got := e.introspect(token); got["active"] != false {
		t.Errorf("a disabled account's token introspects as %v, want inactive", got)
	}
}
