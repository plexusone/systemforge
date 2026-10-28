package relyingparty_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/grokify/goauth/dpop"

	"github.com/plexusone/systemforge/identity/relyingparty"
)

// seen is what the fake SystemAuth API received in one request.
type seen struct {
	authz, proof, body string
}

// fakeAPI records requests and answers with answer, which may ask for a
// nonce.
type fakeAPI struct {
	mu     sync.Mutex
	got    []seen
	answer func(n int, r *http.Request) (status int, header http.Header)
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.got = append(f.got, seen{authz: r.Header.Get("Authorization"), proof: r.Header.Get(dpop.HeaderDPoP), body: string(body)})
	n := len(f.got)
	f.mu.Unlock()
	status, header := http.StatusOK, http.Header{}
	if f.answer != nil {
		status, header = f.answer(n, r)
	}
	for k, v := range header {
		w.Header()[k] = v
	}
	w.WriteHeader(status)
}

func (f *fakeAPI) requests() []seen {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]seen(nil), f.got...)
}

const transportIssuer = "https://auth.example.test"

// signer is SystemAuth's token signing key, published at a JWKS URL.
type signer struct {
	key     *rsa.PrivateKey
	jwksURL string
}

// newSigner publishes a new RS256 key as kid k1.
func newSigner(t *testing.T) *signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(set); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(srv.Close)
	return &signer{key: key, jwksURL: srv.URL}
}

// transportClient is a relying party whose DPoP key is kp, trusting sig's
// keys, for a SystemAuth whose other endpoints are never called.
//
//nolint:gosec // G101: endpoint URLs of a fake SystemAuth, not credentials
func transportClient(t *testing.T, kp *dpop.KeyPair, sig *signer) *relyingparty.Client {
	t.Helper()
	c, err := relyingparty.NewClientWithMetadata(relyingparty.Config{
		Issuer: transportIssuer, ClientID: "app", RedirectURL: "https://app.example.test/cb", DPoPKey: kp,
	}, relyingparty.Metadata{
		Issuer:                transportIssuer,
		AuthorizationEndpoint: transportIssuer + "/oauth/authorize",
		TokenEndpoint:         transportIssuer + "/oauth/token",
		JWKSURI:               sig.jwksURL,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// jwtWithCNF is an access token signed by key as kid k1, bound to jkt
// unless it is empty, expiring at exp.
func jwtWithCNF(t *testing.T, key *rsa.PrivateKey, jkt string, exp time.Time) string {
	t.Helper()
	claims := gojwt.MapClaims{"iss": transportIssuer, "sub": "p1", "client_id": "app", "exp": exp.Unix()}
	if jkt != "" {
		claims["cnf"] = map[string]any{"jkt": jkt}
	}
	tok := gojwt.NewWithClaims(gojwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "k1"
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// checkProof checks that proof is by kp for method and url, bound to token,
// carrying nonce.
func checkProof(t *testing.T, proof string, kp *dpop.KeyPair, method, url, token, nonce string) {
	t.Helper()
	p, err := dpop.ParseProof(proof)
	if err != nil {
		t.Fatalf("proof: %v", err)
	}
	c := p.Claims
	if p.Thumbprint != kp.Thumbprint || c.HTTPMethod != method || c.HTTPURI != url ||
		c.AccessTokenHash != dpop.ComputeAccessTokenHash(token) || c.Nonce != nonce {
		t.Fatalf("proof: key %s htm %s htu %s ath %s nonce %q", p.Thumbprint, c.HTTPMethod, c.HTTPURI, c.AccessTokenHash, c.Nonce)
	}
}

func post(t *testing.T, rt http.RoundTripper, url, authz string, body io.Reader) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, url, body)
	if err != nil {
		t.Fatal(err)
	}
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	resp, err := rt.RoundTrip(req)
	if err == nil {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Fatal(cerr)
		}
	}
	return resp, err
}

func TestTransportPresentsTokens(t *testing.T) {
	kp, err := dpop.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	api := &fakeAPI{}
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	sig := newSigner(t)
	rt := transportClient(t, kp, sig).Transport(srv.Client().Transport)
	url := srv.URL + "/managed-principals/x?after=1"
	later := time.Now().Add(time.Hour)

	// No token: the request passes through unchanged.
	if _, err := post(t, rt, url, "", nil); err != nil {
		t.Fatal(err)
	}
	// A token bound to the key, an expired one (SystemAuth answers it), and
	// an opaque one go as DPoP with a proof for the request's method and URL
	// without its query.
	bound := jwtWithCNF(t, sig.key, kp.Thumbprint, later)
	expired := jwtWithCNF(t, sig.key, kp.Thumbprint, time.Now().Add(-time.Hour))
	tokens := []string{bound, expired, "opaque-token"}
	for _, tok := range tokens {
		if _, err := post(t, rt, url, "Bearer "+tok, strings.NewReader("{}")); err != nil {
			t.Fatal(err)
		}
	}
	// An unbound JWT goes as Bearer, with no proof.
	unbound := jwtWithCNF(t, sig.key, "", later)
	if _, err := post(t, rt, url, "DPoP "+unbound, nil); err != nil {
		t.Fatal(err)
	}

	got := api.requests()
	if len(got) != 5 {
		t.Fatalf("%d requests", len(got))
	}
	if got[0].authz != "" || got[0].proof != "" {
		t.Errorf("without a token: %+v", got[0])
	}
	for i, tok := range tokens {
		if got[i+1].authz != "DPoP "+tok || got[i+1].body != "{}" {
			t.Errorf("token %d: %+v", i, got[i+1])
		}
		checkProof(t, got[i+1].proof, kp, http.MethodPost, srv.URL+"/managed-principals/x", tok, "")
	}
	if got[4].authz != "Bearer "+unbound || got[4].proof != "" {
		t.Errorf("unbound token: %+v", got[4])
	}
}

// closeTracker records whether a request body was closed.
type closeTracker struct {
	io.Reader
	closed bool
}

func (c *closeTracker) Close() error { c.closed = true; return nil }

func TestTransportRefusesAnotherKeysToken(t *testing.T) {
	kp, err := dpop.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	other, err := dpop.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	api := &fakeAPI{}
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	sig := newSigner(t)
	rt := transportClient(t, kp, sig).Transport(srv.Client().Transport)

	body := &closeTracker{Reader: strings.NewReader("{}")}
	_, err = post(t, rt, srv.URL+"/x", "Bearer "+jwtWithCNF(t, sig.key, other.Thumbprint, time.Now().Add(time.Hour)), body)
	if !errors.Is(err, relyingparty.ErrForeignDPoPToken) {
		t.Fatalf("a token bound to another key: %v", err)
	}
	if !body.closed {
		t.Error("the request body was not closed")
	}
	if n := len(api.requests()); n != 0 {
		t.Errorf("%d requests sent", n)
	}
}

// TestTransportRefusesATokenSystemAuthDidNotSign checks that a JWT claiming
// the client's key gets no proof unless SystemAuth's keys verify it, so the
// transport never signs for a token someone made up.
func TestTransportRefusesATokenSystemAuthDidNotSign(t *testing.T) {
	kp, err := dpop.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	api := &fakeAPI{}
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	sig := newSigner(t)
	rt := transportClient(t, kp, sig).Transport(srv.Client().Transport)

	forger, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	forged := jwtWithCNF(t, forger, kp.Thumbprint, time.Now().Add(time.Hour))
	body := &closeTracker{Reader: strings.NewReader("{}")}
	if _, err := post(t, rt, srv.URL+"/x", "Bearer "+forged, body); !errors.Is(err, relyingparty.ErrInvalidToken) {
		t.Fatalf("a forged token: %v", err)
	}
	if !body.closed {
		t.Error("the request body was not closed")
	}
	if n := len(api.requests()); n != 0 {
		t.Errorf("%d requests sent", n)
	}
}

// askForNonce answers the first request with 401 use_dpop_nonce and the
// nonce, and accepts later ones that carry it.
func askForNonce(t *testing.T, nonce string) func(int, *http.Request) (int, http.Header) {
	return func(n int, r *http.Request) (int, http.Header) {
		h := http.Header{}
		if n == 1 {
			h.Set("WWW-Authenticate", `DPoP error="use_dpop_nonce", error_description="Resource server requires nonce in DPoP proof"`)
			h.Set("DPoP-Nonce", nonce)
			return http.StatusUnauthorized, h
		}
		p, err := dpop.ParseProof(r.Header.Get(dpop.HeaderDPoP))
		if err != nil || p.Claims.Nonce != nonce {
			t.Errorf("request %d without the nonce", n)
			return http.StatusUnauthorized, h
		}
		return http.StatusOK, h
	}
}

func TestTransportRetriesWithANonce(t *testing.T) {
	kp, err := dpop.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	api := &fakeAPI{answer: askForNonce(t, "n-1")}
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	rt := transportClient(t, kp, newSigner(t)).Transport(srv.Client().Transport)

	// A body that can be sent again (GetBody) is, with a new proof.
	resp, err := post(t, rt, srv.URL+"/x", "Bearer opaque", bytes.NewReader([]byte(`{"a":1}`)))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("retry: %v %v", resp, err)
	}
	got := api.requests()
	if len(got) != 2 || got[1].body != `{"a":1}` || got[0].proof == got[1].proof {
		t.Fatalf("requests: %+v", got)
	}
	checkProof(t, got[1].proof, kp, http.MethodPost, srv.URL+"/x", "opaque", "n-1")
}

func TestTransportDoesNotResendAStreamedBody(t *testing.T) {
	kp, err := dpop.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	api := &fakeAPI{answer: askForNonce(t, "n-2")}
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	rt := transportClient(t, kp, newSigner(t)).Transport(srv.Client().Transport)

	// A body without GetBody, as a reverse proxy forwards it, went with the
	// first attempt: the refusal is returned, and the nonce is kept for the
	// next request.
	streamed := io.NopCloser(strings.NewReader("{}"))
	resp, err := post(t, rt, srv.URL+"/x", "Bearer opaque", streamed)
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("streamed body: %v %v", resp, err)
	}
	if n := len(api.requests()); n != 1 {
		t.Fatalf("%d requests, want the body sent once", n)
	}
	if resp, err := post(t, rt, srv.URL+"/x", "Bearer opaque", nil); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("next request: %v %v", resp, err)
	}
}
