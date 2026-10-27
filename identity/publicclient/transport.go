package publicclient

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/grokify/goauth/dpop"
)

// nonceHeader carries a server-provided DPoP nonce (RFC 9449 §8).
const nonceHeader = "DPoP-Nonce"

// maxDrain bounds how much of a refused response is read before a retry,
// so the connection can be reused.
const maxDrain = 64 << 10

// HTTPClient returns an http.Client whose requests the session
// authenticates (see Transport), based on cfg.HTTPClient.
func (s *Session) HTTPClient() *http.Client {
	c := *s.cfg.httpClient()
	c.Transport = s.Transport(c.Transport)
	return &c
}

// Transport returns an http.RoundTripper that authenticates each request
// as the session's person: Authorization: DPoP with a valid access token,
// and a DPoP proof by the session's key for the request's method and URL,
// bound to the token. It refreshes the token when it is about to expire.
// A request refused with 401 is retried once, when its body can be sent
// again (GetBody): with the server's nonce for use_dpop_nonce, or with a
// refreshed token for invalid_token. base nil is http.DefaultTransport.
//
// Send these requests only to the APIs the person means to use: a server
// that receives them can present the token for as long as it lives, but
// cannot make new proofs, so it cannot use the token elsewhere.
func (s *Session) Transport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &transport{s: s, base: base}
}

type transport struct {
	s    *Session
	base http.RoundTripper
}

// RoundTrip implements http.RoundTripper.
func (t *transport) RoundTrip(r *http.Request) (*http.Response, error) {
	tok, err := t.s.token(r.Context(), "")
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
		if tok, err = t.s.token(r.Context(), tok); err != nil {
			return nil, err // the body went with the first attempt
		}
	}
	retry := r.Clone(r.Context())
	if r.GetBody != nil {
		if retry.Body, err = r.GetBody(); err != nil {
			return nil, fmt.Errorf("publicclient: resending the request body: %w", err)
		}
	}
	return t.send(retry, tok)
}

// send sends a copy of r with the token and a proof, and records the
// nonce the server returns. Like any RoundTripper, it closes r's body,
// also when it fails before sending.
func (t *transport) send(r *http.Request, tok string) (*http.Response, error) {
	origin := r.URL.Scheme + "://" + r.URL.Host
	proof, err := dpop.CreateProofWithOptions(t.s.key, r.Method, htu(r), dpop.ProofOptions{
		AccessToken: tok, Nonce: t.s.nonce(origin),
	})
	if err != nil {
		return nil, errors.Join(fmt.Errorf("publicclient: DPoP proof: %w", err), closeBody(r))
	}
	out := r.Clone(r.Context())
	out.Header.Set("Authorization", "DPoP "+tok)
	out.Header.Set(dpop.HeaderDPoP, proof)
	resp, err := t.base.RoundTrip(out)
	if err == nil {
		if n := resp.Header.Get(nonceHeader); n != "" {
			t.s.setNonce(origin, n)
		}
	}
	return resp, err
}

func (s *Session) nonce(origin string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nonces[origin]
}

func (s *Session) setNonce(origin, nonce string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nonces[origin] = nonce
}

// htu is a request's URL without query and fragment (RFC 9449 §4.2).
func htu(r *http.Request) string {
	u := *r.URL
	u.RawQuery, u.Fragment, u.RawFragment = "", "", ""
	return u.String()
}

// closeBody closes a request body that will not be sent, as the
// RoundTripper contract requires.
func closeBody(r *http.Request) error {
	if r.Body == nil || r.Body == http.NoBody {
		return nil
	}
	if err := r.Body.Close(); err != nil {
		return fmt.Errorf("publicclient: closing the request body: %w", err)
	}
	return nil
}

// drain reads and closes a response that will be retried.
func drain(resp *http.Response) error {
	_, err := io.Copy(io.Discard, io.LimitReader(resp.Body, maxDrain))
	if cerr := resp.Body.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("publicclient: reading a refused response: %w", err)
	}
	return nil
}
