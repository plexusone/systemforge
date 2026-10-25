package oauthcore

import (
	"context"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"strings"

	"github.com/ory/fosite"

	"github.com/plexusone/systemforge/identity/dpopproof"
)

// TokenAuthError is why a request's access token was not accepted.
type TokenAuthError struct {
	status      int
	code        string
	description string
	// scheme is the challenge's scheme: "DPoP" for errors about a bound
	// token or a DPoP request, "" to offer both schemes.
	scheme string
	// nonce is a fresh server nonce to retry with (DPoP-Nonce header).
	nonce string
	err   error
}

// UnauthorizedError is a 401 refusal with the RFC 6750 error code and
// description (both may be empty), challenging with both schemes.
func UnauthorizedError(code, description string) *TokenAuthError {
	return &TokenAuthError{status: http.StatusUnauthorized, code: code, description: description}
}

func (e *TokenAuthError) Error() string {
	if e.err != nil {
		return e.description + ": " + e.err.Error()
	}
	return e.description
}

func (e *TokenAuthError) Unwrap() error { return e.err }

// NoToken reports whether the request carried no access token.
func (e *TokenAuthError) NoToken() bool { return errors.Is(e.err, errNoAccessToken) }

// StatusCode is the HTTP status of the refusal: 401, or 500 when the
// token could not be checked.
func (e *TokenAuthError) StatusCode() int { return e.status }

// errNoAccessToken means the request carried no access token.
var errNoAccessToken = errors.New("oauthcore: no access token")

// AccessTokenCredentials returns the scheme ("bearer" or "dpop") and the
// access token of a request: the Authorization header, or for Bearer the
// form body of a POST (RFC 6750 §2.2). Query parameters are not accepted.
func AccessTokenCredentials(r *http.Request) (scheme, token string) {
	if auth := r.Header.Get("Authorization"); auth != "" {
		sch, tok, ok := strings.Cut(auth, " ")
		if !ok {
			return "", ""
		}
		switch sch = strings.ToLower(sch); sch {
		case "bearer", "dpop":
			return sch, strings.TrimSpace(tok)
		}
		return "", ""
	}
	if r.Method == http.MethodPost {
		ct, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err == nil && ct == "application/x-www-form-urlencoded" {
			if tok := r.PostFormValue("access_token"); tok != "" {
				return "bearer", tok
			}
		}
	}
	return "", ""
}

// AuthenticateAccessToken validates the access token of a request to a
// resource at htu, the request's external URL without query. introspect
// returns the request of an active, acceptable access token, or an error
// to refuse it with invalid_token; jkt reads the DPoP binding of its
// session. A DPoP-bound token must come with the DPoP scheme and a fresh,
// unreplayed proof by its key (checked by checker) for the request's
// method and htu, carrying the token's hash; an unbound token must come
// with the Bearer scheme. A request without a token returns a
// *TokenAuthError for which NoToken reports true. Write a refusal with
// WriteTokenAuthError.
func AuthenticateAccessToken(r *http.Request, checker *dpopproof.Checker, htu string, introspect func(ctx context.Context, token string) (fosite.AccessRequester, error), jkt SessionJKT) (fosite.AccessRequester, *TokenAuthError) {
	ctx := r.Context()
	scheme, token := AccessTokenCredentials(r)
	if token == "" {
		return nil, &TokenAuthError{status: http.StatusUnauthorized, err: errNoAccessToken}
	}
	challenge := ""
	if scheme == "dpop" {
		challenge = schemeDPoP
	}
	ar, err := introspect(ctx, token)
	if err != nil {
		return nil, &TokenAuthError{status: http.StatusUnauthorized, code: "invalid_token", description: "The access token is invalid, expired or revoked.", scheme: challenge, err: err}
	}
	bound := jkt(ar.GetSession())
	if bound == "" {
		if scheme == "dpop" {
			return nil, &TokenAuthError{status: http.StatusUnauthorized, code: "invalid_token", description: "The access token is not DPoP-bound; use the Bearer scheme.", scheme: schemeDPoP}
		}
		return ar, nil
	}
	if scheme != "dpop" {
		return nil, &TokenAuthError{status: http.StatusUnauthorized, code: "invalid_token", description: "The access token is DPoP-bound; use the DPoP scheme with a DPoP proof.", scheme: schemeDPoP}
	}
	proof, err := checker.Check(ctx, r, dpopproof.Target{Method: r.Method, URI: htu, AccessToken: token})
	switch {
	case errors.Is(err, dpopproof.ErrUseNonce):
		nonce, nerr := checker.Nonce()
		if nerr != nil {
			return nil, &TokenAuthError{status: http.StatusInternalServerError, err: nerr}
		}
		return nil, &TokenAuthError{status: http.StatusUnauthorized, code: errUseDPoPNonce, description: "Resource server requires a nonce in the DPoP proof.", scheme: schemeDPoP, nonce: nonce, err: err}
	case errors.Is(err, dpopproof.ErrInvalid), errors.Is(err, dpopproof.ErrMissing):
		return nil, &TokenAuthError{status: http.StatusUnauthorized, code: errInvalidDPoPProof, description: "A valid DPoP proof for this request is required.", scheme: schemeDPoP, err: err}
	case err != nil:
		return nil, &TokenAuthError{status: http.StatusInternalServerError, err: err}
	}
	if proof.JKT() != bound {
		return nil, &TokenAuthError{status: http.StatusUnauthorized, code: errInvalidDPoPProof, description: "The DPoP proof was not signed by the key the access token is bound to.", scheme: schemeDPoP}
	}
	return ar, nil
}

// DPoPChallenge is the DPoP WWW-Authenticate challenge (RFC 9449 §7.1).
func DPoPChallenge(code, description string) string {
	c := `DPoP algs="` + strings.Join(dpopproof.Algorithms, " ") + `"`
	if code != "" {
		c += `, error="` + code + `"`
	}
	if description != "" {
		c += `, error_description="` + description + `"`
	}
	return c
}

// BearerChallenge is an RFC 6750 §3 Bearer challenge.
func BearerChallenge(code, description, scope string) string {
	challenge := `Bearer realm="systemauth"`
	if code != "" {
		challenge += `, error="` + code + `"`
	}
	if description != "" {
		challenge += `, error_description="` + description + `"`
	}
	if scope != "" {
		challenge += `, scope="` + scope + `"`
	}
	return challenge
}

// WriteChallengeError writes an error response with WWW-Authenticate
// challenges and, when code is set, an error body.
func WriteChallengeError(w http.ResponseWriter, status int, challenges []string, code, description string) {
	for _, c := range challenges {
		w.Header().Add("WWW-Authenticate", c)
	}
	w.Header().Set("Cache-Control", "no-store")
	if code == "" {
		w.WriteHeader(status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// The status line and challenge are already written; an encoding
	// failure here can only be a broken connection.
	if err := json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": description}); err != nil {
		return
	}
}

// WriteTokenAuthError writes the response for a request whose access
// token AuthenticateAccessToken did not accept: 401 with WWW-Authenticate
// challenges (RFC 6750 §3, RFC 9449 §7.1) and a DPoP-Nonce to retry with
// when one is needed, or 500 when the token could not be checked.
func WriteTokenAuthError(w http.ResponseWriter, e *TokenAuthError) {
	if e.status == http.StatusInternalServerError {
		http.Error(w, "could not check the access token", http.StatusInternalServerError)
		return
	}
	if e.nonce != "" {
		w.Header().Set(DPoPNonceHeader, e.nonce)
	}
	if e.scheme == schemeDPoP {
		WriteChallengeError(w, e.status, []string{DPoPChallenge(e.code, e.description)}, e.code, e.description)
		return
	}
	// No token, or an invalid Bearer one: offer both schemes.
	WriteChallengeError(w, e.status, []string{BearerChallenge(e.code, e.description, ""), DPoPChallenge("", "")}, e.code, e.description)
}
