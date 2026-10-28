package relyingparty

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/grokify/goauth/dpop"
)

// The Client proves possession of a DPoP key (RFC 9449) to SystemAuth:
// every token request carries a DPoP proof by Config.DPoPKey, so SystemAuth
// binds the tokens it issues to that key, and the Client presents them to
// SystemAuth's userinfo, memberships and access-changes endpoints with the
// DPoP scheme and a proof. A token copied out of a session store is
// useless without the key.

// ErrForeignDPoPToken is returned when the Client is asked to present a
// DPoP-bound token bound to a key it does not hold, such as the token of a
// caller authenticated by BearerMiddleware: only its holder can use it.
var ErrForeignDPoPToken = errors.New("relyingparty: the access token is bound to another DPoP key")

// dpopNonceHeader carries a server-provided nonce (RFC 9449 §8).
const dpopNonceHeader = "DPoP-Nonce"

// dpopSigner signs DPoP proofs with the Client's key and remembers the
// latest nonce SystemAuth handed out.
type dpopSigner struct {
	key *dpop.KeyPair

	mu    sync.Mutex
	nonce string
}

func newDPoPSigner(key *dpop.KeyPair) (*dpopSigner, error) {
	if key == nil {
		var err error
		key, err = dpop.GenerateKeyPair()
		if err != nil {
			return nil, fmt.Errorf("relyingparty: generating a DPoP key: %w", err)
		}
	}
	return &dpopSigner{key: key}, nil
}

func (d *dpopSigner) proof(method, uri, accessToken string) (string, error) {
	d.mu.Lock()
	nonce := d.nonce
	d.mu.Unlock()
	return dpop.CreateProofWithOptions(d.key, method, uri, dpop.ProofOptions{AccessToken: accessToken, Nonce: nonce})
}

// takeNonce records the nonce of resp, reporting whether it asked for a
// retry with it.
func (d *dpopSigner) takeNonce(resp *http.Response, retry bool) bool {
	nonce := resp.Header.Get(dpopNonceHeader)
	if nonce == "" {
		return false
	}
	d.mu.Lock()
	d.nonce = nonce
	d.mu.Unlock()
	return retry
}

// htu is a request's URL without query and fragment.
func htu(r *http.Request) string {
	u := *r.URL
	u.RawQuery, u.Fragment, u.RawFragment = "", "", ""
	return u.String()
}

// tokenTransport adds a DPoP proof to every request to the token
// endpoint, and retries once with SystemAuth's nonce when it asks for one.
type tokenTransport struct {
	base     http.RoundTripper
	signer   *dpopSigner
	tokenURL string
}

// RoundTrip implements http.RoundTripper.
func (t *tokenTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method != http.MethodPost || htu(r) != t.tokenURL {
		return t.base.RoundTrip(r)
	}
	resp, err := t.send(r)
	if err != nil || resp.StatusCode != http.StatusBadRequest || r.GetBody == nil {
		return resp, err
	}
	// RFC 9449 §8: a 400 use_dpop_nonce with a DPoP-Nonce header asks for
	// a retry carrying that nonce.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDocumentSize))
	if cerr := resp.Body.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, err
	}
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &e) != nil || e.Error != "use_dpop_nonce" || !t.signer.takeNonce(resp, true) {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return resp, nil
	}
	retry := r.Clone(r.Context())
	if retry.Body, err = r.GetBody(); err != nil {
		return nil, err
	}
	return t.send(retry)
}

func (t *tokenTransport) send(r *http.Request) (*http.Response, error) {
	proof, err := t.signer.proof(http.MethodPost, t.tokenURL, "")
	if err != nil {
		return nil, fmt.Errorf("relyingparty: DPoP proof: %w", err)
	}
	r = r.Clone(r.Context())
	r.Header.Set(dpop.HeaderDPoP, proof)
	resp, err := t.base.RoundTrip(r)
	if err == nil {
		t.signer.takeNonce(resp, false)
	}
	return resp, err
}

// tokenHTTPClient is cfg.HTTPClient with the token transport.
func tokenHTTPClient(base *http.Client, signer *dpopSigner, tokenURL string) *http.Client {
	c := *base
	rt := base.Transport
	if rt == nil {
		rt = http.DefaultTransport
	}
	c.Transport = &tokenTransport{base: rt, signer: signer, tokenURL: tokenURL}
	return &c
}

// tokenScheme is how a token is presented to SystemAuth: "DPoP" for a
// token bound to this client's key or an opaque one (which this client
// obtained, so it is bound to its key), "Bearer" for a JWT without cnf. A
// JWT is read only once its signature verifies against SystemAuth's keys,
// so no proof is made for a token SystemAuth did not issue; a JWT bound to
// another key cannot be presented. An opaque token's binding cannot be
// read here, so it is presented as DPoP and SystemAuth refuses it if it is
// bound to another key.
func (c *Client) tokenScheme(ctx context.Context, token string) (string, error) {
	if strings.Count(token, ".") != 2 {
		return "DPoP", nil
	}
	claims, err := c.keys.verifySignature(ctx, token, c.cfg.Issuer)
	if err != nil {
		return "", fmt.Errorf("relyingparty: the access token is not one SystemAuth issued: %w", err)
	}
	cnf, _ := claims["cnf"].(map[string]any)
	jkt, _ := cnf["jkt"].(string)
	switch jkt {
	case "":
		return "Bearer", nil
	case c.dpop.key.Thumbprint:
		return "DPoP", nil
	default:
		return "", ErrForeignDPoPToken
	}
}

// doWithToken sends req to a SystemAuth resource with token, through
// Transport.
func (c *Client) doWithToken(req *http.Request, token string) (*http.Response, error) {
	r := req.Clone(req.Context())
	r.Header.Set("Authorization", "Bearer "+token)
	hc := *c.cfg.HTTPClient
	hc.Transport = c.Transport(hc.Transport)
	return hc.Do(r)
}

// Transport returns an http.RoundTripper for calls to SystemAuth's APIs
// that carry an access token the Client obtained, such as a session's
// token sent to the managed-principal API by mpclient or a reverse proxy.
// The caller sets the token in the Authorization header, as "Bearer
// <token>" or "DPoP <token>"; the transport presents it the way the Client
// presents its own:
//
//   - a token bound to Config.DPoPKey, or an opaque one, with the DPoP
//     scheme and a new proof by the key for the request's method and URL;
//   - an unbound JWT, from a client registered with allow_bearer_tokens,
//     with the Bearer scheme and no proof;
//   - a JWT bound to another key is refused with ErrForeignDPoPToken,
//     since only its holder can make proofs for it. An opaque token's
//     binding cannot be read, so it is sent with this client's proof and
//     SystemAuth refuses it if it is bound to another key;
//   - a JWT whose signature SystemAuth's keys do not verify, or from
//     another issuer, is refused with ErrInvalidToken, so no proof is made
//     for a token SystemAuth did not issue. Its expiry is not checked:
//     SystemAuth answers an expired token itself.
//
// A request refused with 401 use_dpop_nonce is retried once with
// SystemAuth's nonce when its body can be sent again (none, or GetBody);
// otherwise the refusal is returned and the next request carries the
// nonce. Requests without an Authorization header pass through unchanged.
//
// The proof's htu is the request's URL without query and fragment, so send
// the requests to the URL SystemAuth checks proofs against: its issuer
// origin, or dpop.resource_base_url when SystemAuth sets one. base nil is
// http.DefaultTransport.
func (c *Client) Transport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &apiTransport{c: c, base: base}
}

// apiTransport is Client.Transport.
type apiTransport struct {
	c    *Client
	base http.RoundTripper
}

// RoundTrip implements http.RoundTripper.
func (t *apiTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	token, ok := presentedToken(r.Header.Get("Authorization"))
	if !ok {
		return t.base.RoundTrip(r)
	}
	scheme, err := t.c.tokenScheme(r.Context(), token)
	if err != nil {
		return nil, errors.Join(err, closeRequestBody(r))
	}
	resp, err := t.send(r, scheme, token)
	if err != nil || scheme != "DPoP" || resp.StatusCode != http.StatusUnauthorized {
		return resp, err
	}
	if !strings.Contains(resp.Header.Get("WWW-Authenticate"), `error="use_dpop_nonce"`) || !t.c.dpop.takeNonce(resp, true) {
		return resp, nil
	}
	if r.Body != nil && r.Body != http.NoBody && r.GetBody == nil {
		return resp, nil // the body went with the first attempt
	}
	if _, err := io.Copy(io.Discard, io.LimitReader(resp.Body, maxDocumentSize)); err != nil {
		return nil, errors.Join(fmt.Errorf("relyingparty: reading a refused response: %w", err), resp.Body.Close())
	}
	if err := resp.Body.Close(); err != nil {
		return nil, fmt.Errorf("relyingparty: closing a refused response: %w", err)
	}
	retry := r.Clone(r.Context())
	if r.GetBody != nil {
		if retry.Body, err = r.GetBody(); err != nil {
			return nil, fmt.Errorf("relyingparty: resending the request body: %w", err)
		}
	}
	return t.send(retry, scheme, token)
}

// send sends a copy of r presenting token with scheme, and a proof for
// DPoP, and records the nonce SystemAuth returns. Like any RoundTripper it
// closes r's body, also when it fails before sending.
func (t *apiTransport) send(r *http.Request, scheme, token string) (*http.Response, error) {
	out := r.Clone(r.Context())
	out.Header.Set("Authorization", scheme+" "+token)
	out.Header.Del(dpop.HeaderDPoP)
	if scheme == "DPoP" {
		proof, err := t.c.dpop.proof(out.Method, htu(out), token)
		if err != nil {
			return nil, errors.Join(fmt.Errorf("relyingparty: DPoP proof: %w", err), closeRequestBody(r))
		}
		out.Header.Set(dpop.HeaderDPoP, proof)
	}
	resp, err := t.base.RoundTrip(out)
	if err == nil {
		t.c.dpop.takeNonce(resp, false)
	}
	return resp, err
}

// presentedToken returns the token of a Bearer or DPoP Authorization
// header.
func presentedToken(authz string) (string, bool) {
	scheme, token, ok := strings.Cut(authz, " ")
	if !ok || (!strings.EqualFold(scheme, "Bearer") && !strings.EqualFold(scheme, "DPoP")) {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}

// closeRequestBody closes a request body that will not be sent, as the
// RoundTripper contract requires.
func closeRequestBody(r *http.Request) error {
	if r.Body == nil || r.Body == http.NoBody {
		return nil
	}
	if err := r.Body.Close(); err != nil {
		return fmt.Errorf("relyingparty: closing the request body: %w", err)
	}
	return nil
}

// DPoPThumbprint returns the thumbprint of the DPoP key the Client binds
// its tokens to.
func (c *Client) DPoPThumbprint() string { return c.dpop.key.Thumbprint }
