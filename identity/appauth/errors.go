package appauth

import (
	"errors"

	"github.com/plexusone/systemforge/identity/requestprincipal"
)

// DPoPChallenge is the WWW-Authenticate value for a request refused without
// a more specific challenge: a DPoP-bound access token is expected.
const DPoPChallenge = `DPoP algs="ES256 ES384 ES512"`

var (
	// ErrUnauthenticated is wrapped by Authenticate's error for a missing,
	// invalid or expired credential (a 401).
	ErrUnauthenticated = errors.New("appauth: unauthenticated")
	// ErrForbidden is wrapped by Authenticate's error for a valid
	// credential on a refused request, such as a cross-origin write with
	// the session cookie (a 403).
	ErrForbidden = errors.New("appauth: forbidden")
	// ErrNoSessionToken is returned by SessionToken for a request without a
	// browser session, or one that presented its own credential.
	ErrNoSessionToken = errors.New("appauth: the request has no session token")
)

// authError is a refusal: one of the sentinels, and the protocol's response.
type authError struct {
	sentinel error
	rp       *requestprincipal.Error
}

func (e *authError) Error() string   { return e.sentinel.Error() + ": " + e.rp.Message }
func (e *authError) Unwrap() []error { return []error{e.sentinel, e.rp} }

// Challenges returns the WWW-Authenticate values to send with a refusal from
// Authenticate: the ones the refusing method chose, such as
// error="invalid_token", which a client acts on, or DPoPChallenge.
func Challenges(err error) []string {
	var rpErr *requestprincipal.Error
	if errors.As(err, &rpErr) {
		if v := rpErr.Header.Values("WWW-Authenticate"); len(v) > 0 {
			return v
		}
	}
	if errors.Is(err, ErrForbidden) {
		return nil
	}
	return []string{DPoPChallenge}
}
