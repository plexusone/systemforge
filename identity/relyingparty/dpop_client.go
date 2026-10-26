package relyingparty

import (
	"bytes"
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
// JWT bound to another key cannot be presented.
func (c *Client) tokenScheme(token string) (string, error) {
	if strings.Count(token, ".") != 2 {
		return "DPoP", nil
	}
	_, claims, err := unverified(token)
	if err != nil {
		return "DPoP", nil
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

// doWithToken sends req to a SystemAuth resource with token, as DPoP with
// a proof when the token is bound to this client's key, retrying once with
// SystemAuth's nonce when it asks for one (req must have no body).
func (c *Client) doWithToken(req *http.Request, token string) (*http.Response, error) {
	scheme, err := c.tokenScheme(token)
	if err != nil {
		return nil, err
	}
	send := func() (*http.Response, error) {
		r := req.Clone(req.Context())
		r.Header.Set("Authorization", scheme+" "+token)
		if scheme == "DPoP" {
			proof, err := c.dpop.proof(r.Method, htu(r), token)
			if err != nil {
				return nil, fmt.Errorf("relyingparty: DPoP proof: %w", err)
			}
			r.Header.Set(dpop.HeaderDPoP, proof)
		}
		return c.cfg.HTTPClient.Do(r)
	}
	resp, err := send()
	if err != nil || scheme != "DPoP" || resp.StatusCode != http.StatusUnauthorized {
		if err == nil {
			c.dpop.takeNonce(resp, false)
		}
		return resp, err
	}
	if !strings.Contains(resp.Header.Get("WWW-Authenticate"), `error="use_dpop_nonce"`) || !c.dpop.takeNonce(resp, true) {
		return resp, nil
	}
	if err := resp.Body.Close(); err != nil {
		return nil, err
	}
	return send()
}

// DPoPThumbprint returns the thumbprint of the DPoP key the Client binds
// its tokens to.
func (c *Client) DPoPThumbprint() string { return c.dpop.key.Thumbprint }
