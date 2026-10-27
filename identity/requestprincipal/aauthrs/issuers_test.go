package aauthrs_test

import (
	"context"
	"crypto"
	"errors"
	"net/http"
	"testing"
	"time"

	aauth "github.com/aauth-dev/aauth-go"

	"github.com/plexusone/systemforge/identity/requestprincipal/aauthrs"
)

// agentKeyPair returns an agent signing key and its JWK.
func agentKeyPair(t *testing.T) (crypto.Signer, aauth.JWK) {
	t.Helper()
	key, err := aauth.GenerateKey(aauth.AlgEd25519)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := aauth.NewJWK(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	return key, jwk
}

// TestAuthTokenIssuers checks who may issue the auth tokens a resource
// accepts: in three-party only a trusted Person Server for itself, in
// four-party only the resource's Access Server. A Person Server trusted for
// person tokens cannot grant itself scopes that bypass the Access Server.
func TestAuthTokenIssuers(t *testing.T) {
	ps := newFakeIssuer(t)
	as := newFakeIssuer(t)
	key, jwk := agentKeyPair(t)
	now := time.Now()
	exp := now.Add(10 * time.Minute)

	three := newResourceServer(t, aauth.AccessModeAuthToken, ps.url)
	four := newResourceServerWith(t, aauth.AccessModeAuthToken, func(c *aauthrs.Config) { c.Audience = as.url }, ps.url)

	cases := []struct {
		name  string
		rs    *resourceServer
		token string
		want  int
	}{
		{"three-party: a trusted PS issuing for itself", three, ps.authToken(t, three.url, jwk, now, exp), http.StatusOK},
		{"three-party: a trusted issuer acting as an AS", three, ps.authTokenAs(t, aauth.WellKnownAccess, ps.url, three.url, jwk, now, exp), http.StatusUnauthorized},
		{"four-party: the resource's AS", four, as.authTokenAs(t, aauth.WellKnownAccess, ps.url, four.url, jwk, now, exp), http.StatusOK},
		{"four-party: a trusted PS bypassing the AS", four, ps.authToken(t, four.url, jwk, now, exp), http.StatusUnauthorized},
		{"four-party: a trusted PS posing as an AS", four, ps.authTokenAs(t, aauth.WellKnownAccess, ps.url, four.url, jwk, now, exp), http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, body := do(t, http.DefaultClient, signedGet(t, tc.rs.url+"/things", tc.token, key))
			if res.StatusCode != tc.want {
				t.Fatalf("status %d, want %d: %s", res.StatusCode, tc.want, body)
			}
			if tc.want == http.StatusUnauthorized && res.Header.Get(aauth.HeaderSignatureError) == "" {
				t.Errorf("no Signature-Error: %v", res.Header)
			}
		})
	}
}

// TestWrongAuthority checks that a request signed for another server is
// refused, although its token and signature are valid: it cannot be
// replayed here from the server it was meant for.
func TestWrongAuthority(t *testing.T) {
	ps := newFakeIssuer(t)
	rs := newResourceServer(t, aauth.AccessModeAuthToken, ps.url)
	key, jwk := agentKeyPair(t)
	now := time.Now()
	tok := ps.authToken(t, rs.url, jwk, now, now.Add(10*time.Minute))

	req := get(t, rs.url+"/things")
	req.Host = "other.example"
	aauth.AttachSignatureKey(req, tok)
	if err := aauth.SignRequest(req, key, ""); err != nil {
		t.Fatal(err)
	}
	if res, _ := do(t, http.DefaultClient, req); res.StatusCode != http.StatusUnauthorized || res.Header.Get(aauth.HeaderSignatureError) == "" {
		t.Errorf("request signed for another server: %d %v", res.StatusCode, res.Header)
	}
	// The same request signed for this resource is accepted.
	if res, body := do(t, http.DefaultClient, signedGet(t, rs.url+"/things", tok, key)); res.StatusCode != http.StatusOK {
		t.Errorf("request signed for this resource: %d %s", res.StatusCode, body)
	}
}

// TestIsRevoked checks the revocation hook: a revoked token is a 401
// revoked_jwt, and unavailable revocation state a 500.
func TestIsRevoked(t *testing.T) {
	ps := newFakeIssuer(t)
	key, jwk := agentKeyPair(t)
	now := time.Now()
	var answer error
	rs := newResourceServerWith(t, aauth.AccessModeAuthToken, func(c *aauthrs.Config) {
		c.IsRevoked = func(context.Context, string, string) error { return answer }
	}, ps.url)
	tok := ps.authToken(t, rs.url, jwk, now, now.Add(10*time.Minute))

	if res, body := do(t, http.DefaultClient, signedGet(t, rs.url+"/things", tok, key)); res.StatusCode != http.StatusOK {
		t.Fatalf("token in force: %d %s", res.StatusCode, body)
	}
	answer = aauth.ErrRevoked
	res, _ := do(t, http.DefaultClient, signedGet(t, rs.url+"/things", tok, key))
	se, err := aauth.SignatureErrorFromResponse(res)
	if res.StatusCode != http.StatusUnauthorized || err != nil || se.Code != aauth.SigErrRevokedJWT {
		t.Errorf("revoked token: %d %+v %v", res.StatusCode, se, err)
	}
	answer = errors.New("revocation store unreachable")
	if res, _ := do(t, http.DefaultClient, signedGet(t, rs.url+"/things", tok, key)); res.StatusCode != http.StatusInternalServerError {
		t.Errorf("unavailable revocation state: %d", res.StatusCode)
	}
}
