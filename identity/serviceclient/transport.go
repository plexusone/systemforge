package serviceclient

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/grokify/goauth/dpop"
)

// maxDrain bounds how much of a refused response is read before a retry.
const maxDrain = 64 << 10

// HTTPClient returns an http.Client whose requests carry the account's
// token and proofs (see Transport), based on Config.HTTPClient.
func (c *Client) HTTPClient() *http.Client {
	hc := *c.http
	hc.Transport = c.Transport(hc.Transport)
	return &hc
}

// Transport returns an http.RoundTripper that authenticates each request as
// the service account: Authorization: DPoP with a valid token and a proof
// for the request's method and URL. A request refused with 401 is retried
// once when its body can be sent again: with the server's nonce for
// use_dpop_nonce, or with a new token for invalid_token. base nil is
// http.DefaultTransport.
func (c *Client) Transport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &transport{c: c, base: base}
}

type transport struct {
	c    *Client
	base http.RoundTripper
}

// RoundTrip implements http.RoundTripper.
func (t *transport) RoundTrip(r *http.Request) (*http.Response, error) {
	tok, err := t.c.Token(r.Context())
	if err != nil {
		return nil, errors.Join(err, closeBody(r))
	}
	resp, err := t.send(r, tok)
	if err != nil || resp.StatusCode != http.StatusUnauthorized || (r.Body != nil && r.Body != http.NoBody && r.GetBody == nil) {
		return resp, err
	}
	challenge := resp.Header.Get("WWW-Authenticate")
	retryNonce := strings.Contains(challenge, `error="use_dpop_nonce"`) && resp.Header.Get(nonceHeader) != ""
	retryToken := strings.Contains(challenge, `error="invalid_token"`)
	if !retryNonce && !retryToken {
		return resp, nil
	}
	if err := drain(resp); err != nil {
		return nil, err
	}
	if retryToken {
		if tok, err = t.c.tokenAfter(r.Context(), tok); err != nil {
			return nil, err
		}
	}
	retry := r.Clone(r.Context())
	if r.GetBody != nil {
		if retry.Body, err = r.GetBody(); err != nil {
			return nil, fmt.Errorf("serviceclient: resending the request body: %w", err)
		}
	}
	return t.send(retry, tok)
}

// send sends a copy of r with the token and a proof, and records the nonce
// the server returns. Like any RoundTripper, it closes r's body.
func (t *transport) send(r *http.Request, tok string) (*http.Response, error) {
	origin := r.URL.Scheme + "://" + r.URL.Host
	proof, err := dpop.CreateProofWithOptions(t.c.proofKey, r.Method, htu(r), dpop.ProofOptions{
		AccessToken: tok, Nonce: t.c.nonce(origin),
	})
	if err != nil {
		return nil, errors.Join(fmt.Errorf("serviceclient: DPoP proof: %w", err), closeBody(r))
	}
	out := r.Clone(r.Context())
	out.Header.Set("Authorization", "DPoP "+tok)
	out.Header.Set(dpop.HeaderDPoP, proof)
	resp, err := t.base.RoundTrip(out)
	if err == nil {
		if n := resp.Header.Get(nonceHeader); n != "" {
			t.c.setNonce(origin, n)
		}
	}
	return resp, err
}

func (c *Client) nonce(origin string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.nonces[origin]
}

func (c *Client) setNonce(origin, nonce string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nonces[origin] = nonce
}

// htu is a request's URL without query and fragment (RFC 9449 section 4.2).
func htu(r *http.Request) string {
	u := *r.URL
	u.RawQuery, u.Fragment, u.RawFragment = "", "", ""
	return u.String()
}

func closeBody(r *http.Request) error {
	if r.Body == nil || r.Body == http.NoBody {
		return nil
	}
	if err := r.Body.Close(); err != nil {
		return fmt.Errorf("serviceclient: closing the request body: %w", err)
	}
	return nil
}

func drain(resp *http.Response) error {
	_, err := io.Copy(io.Discard, io.LimitReader(resp.Body, maxDrain))
	if cerr := resp.Body.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("serviceclient: reading a refused response: %w", err)
	}
	return nil
}
