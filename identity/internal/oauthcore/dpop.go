package oauthcore

import (
	"context"
	"errors"
	"net/http"
	"regexp"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/token/jwt"

	"github.com/plexusone/systemforge/identity/dpopproof"
)

// DPoP error codes (RFC 9449 §5, §7.1, §8).
const (
	errInvalidDPoPProof = "invalid_dpop_proof"
	errUseDPoPNonce     = "use_dpop_nonce"
)

// DPoPNonceHeader is the response header carrying a server nonce.
const DPoPNonceHeader = "DPoP-Nonce"

// schemeDPoP is the DPoP authorization scheme and token_type.
const schemeDPoP = "DPoP"

// SessionJKT returns the RFC 7638 thumbprint of the DPoP key a Fosite
// session is bound to: "" for an unbound session, a nil one, or one of
// another type than the server's own.
type SessionJKT func(fosite.Session) string

// dpopError builds a token endpoint error with an RFC 9449 code.
func dpopError(code, description string) *fosite.RFC6749Error {
	return &fosite.RFC6749Error{ErrorField: code, DescriptionField: description, CodeField: http.StatusBadRequest}
}

// VerifyTokenRequestProof verifies the DPoP proof of a token request to
// the token endpoint at tokenURL (its external URL, as discovery
// advertises it), if the request carries one. A request without one
// returns nil: whether a proof is required depends on the client. The
// error is an RFC 6749 error to write with WriteAccessError:
// invalid_dpop_proof, use_dpop_nonce or server_error.
func VerifyTokenRequestProof(ctx context.Context, checker *dpopproof.Checker, r *http.Request, tokenURL string) (*dpopproof.Proof, error) {
	if !dpopproof.Present(r) {
		return nil, nil
	}
	proof, err := checker.Check(ctx, r, dpopproof.Target{Method: http.MethodPost, URI: tokenURL})
	switch {
	case err == nil:
		return proof, nil
	case errors.Is(err, dpopproof.ErrUseNonce):
		return nil, dpopError(errUseDPoPNonce, "Authorization server requires a nonce in the DPoP proof.")
	case errors.Is(err, dpopproof.ErrInvalid), errors.Is(err, dpopproof.ErrMissing):
		return nil, dpopError(errInvalidDPoPProof, "The DPoP proof is invalid.").WithWrap(err)
	default:
		return nil, fosite.ErrServerError.WithWrap(err)
	}
}

// DPoPProofRequiredError is the token endpoint error for a client that must
// use DPoP and sent no proof.
func DPoPProofRequiredError() *fosite.RFC6749Error {
	return dpopError(errInvalidDPoPProof, "This client must use DPoP: a DPoP proof is required.")
}

// CodeStorage reads authorization codes for CheckCodeDPoPBinding.
type CodeStorage interface {
	GetAuthorizeCodeSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error)
}

// CheckCodeDPoPBinding refuses an authorization_code token request whose
// code is bound to a DPoP key (dpop_jkt, RFC 9449 §10) when the request
// carries no proof by that key. Call it before Fosite handles the request:
// Fosite's grant handling has side effects even when the exchange is then
// refused (it deletes the code's PKCE request, which with some storage
// makes the code unusable), so a refused exchange must not reach it. The
// code is looked up by its signature under codes into session, an empty
// session of the server's type, and jkt reads its binding. A request for
// another grant, or a code that cannot be read, is left to Fosite.
func CheckCodeDPoPBinding(ctx context.Context, codes CodeStorage, strategy oauth2.AuthorizeCodeStrategy, r *http.Request, proof *dpopproof.Proof, session fosite.Session, jkt SessionJKT) error {
	if r.PostForm.Get("grant_type") != "authorization_code" {
		return nil
	}
	code := r.PostForm.Get("code")
	if code == "" {
		return nil
	}
	ar, err := codes.GetAuthorizeCodeSession(ctx, strategy.AuthorizeCodeSignature(ctx, code), session)
	if err != nil || ar == nil {
		// Unknown, used or expired: Fosite refuses it.
		return nil //nolint:nilerr // Fosite reports the code's own error
	}
	bound := jkt(ar.GetSession())
	if bound == "" {
		return nil
	}
	if proof == nil {
		return dpopError(errInvalidDPoPProof, "The grant is bound to a DPoP key; a DPoP proof by that key is required.")
	}
	if proof.JKT() != bound {
		return fosite.ErrInvalidGrant.WithHint("The DPoP proof was not signed by the key the grant is bound to.")
	}
	return nil
}

// BindDPoPGrant applies the DPoP policy to a token request Fosite has
// parsed and binds the tokens it issues to the proof's key. bound is the
// DPoP binding of the request's session (its key thumbprint field), which
// is set to the proof's key:
//
//   - without a proof, the request is refused when requireProof is set
//     (the client has no bearer-token exception);
//   - a code issued for a dpop_jkt, and a refresh token bound to a key,
//     need a proof by that key (RFC 9449 §10, §5);
//   - with a proof, the access and refresh tokens are bound to its key.
func BindDPoPGrant(bound *string, proof *dpopproof.Proof, requireProof bool) error {
	if proof == nil {
		if *bound != "" {
			return dpopError(errInvalidDPoPProof, "The grant is bound to a DPoP key; a DPoP proof by that key is required.")
		}
		if requireProof {
			return DPoPProofRequiredError()
		}
		return nil
	}
	if *bound != "" && *bound != proof.JKT() {
		return fosite.ErrInvalidGrant.WithHint("The DPoP proof was not signed by the key the grant is bound to.")
	}
	*bound = proof.JKT()
	return nil
}

// dpopJKTPattern matches a base64url SHA-256 thumbprint.
var dpopJKTPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// AuthorizationDPoPJKT returns the dpop_jkt of an authorization request
// (RFC 9449 §10), which binds the code to that key, or an error for a
// malformed one.
func AuthorizationDPoPJKT(ar fosite.AuthorizeRequester) (string, error) {
	values := ar.GetRequestForm()["dpop_jkt"]
	switch {
	case len(values) == 0 || (len(values) == 1 && values[0] == ""):
		return "", nil
	case len(values) > 1 || !dpopJKTPattern.MatchString(values[0]):
		return "", fosite.ErrInvalidRequest.WithHint("dpop_jkt must be one base64url SHA-256 JWK thumbprint.")
	}
	return values[0], nil
}

// SetConfirmationClaim sets or clears the cnf claim of JWT access tokens
// to match jkt, the session's DPoP binding.
func SetConfirmationClaim(jkt string, claims *jwt.JWTClaims) {
	if jkt == "" {
		delete(claims.Extra, "cnf")
		return
	}
	claims.Add("cnf", map[string]interface{}{"jkt": jkt})
}
