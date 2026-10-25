package systemauth

import (
	"context"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/token/jwt"

	"github.com/plexusone/systemforge/identity/dpopproof"
	"github.com/plexusone/systemforge/session/middleware"
)

// SystemAuth issues DPoP-bound tokens (RFC 9449). Every token request must
// carry a valid DPoP proof, and every token is bound to the proof's key:
// the access token carries cnf.jkt, introspection reports it, and the
// refresh token works only with a proof by the same key. Only a client
// registered with the AllowBearerTokens exception may call the token
// endpoint without a proof, and then gets unbound bearer tokens.
//
// SystemAuth's own resource endpoints (userinfo, memberships, access
// changes, BearerAccess and Middleware) accept a bound token only with the
// DPoP authorization scheme and a proof by its key, and an unbound token
// only with the Bearer scheme.

// DPoP error codes (RFC 9449 §5, §7.1, §8).
const (
	errInvalidDPoPProof = "invalid_dpop_proof"
	errUseDPoPNonce     = "use_dpop_nonce"
)

// dpopNonceHeader is the response header carrying a server nonce.
const dpopNonceHeader = "DPoP-Nonce"

// WithDPoPReplayCache sets the cache that rejects a DPoP proof whose jti
// was used before. Without it SystemAuth keeps an in-memory cache, which
// suits a single instance; when several instances serve SystemAuth, pass
// one they share, such as middleware.NewRedisReplayCache.
func WithDPoPReplayCache(cache dpopproof.ReplayCache) Option {
	return func(s *Server) { s.dpopCache = cache }
}

// setupDPoP builds the proof checker.
func (s *Server) setupDPoP() error {
	cache := s.dpopCache
	if cache == nil {
		s.logger.Warn("DPoP proofs checked against an in-memory replay cache; pass WithDPoPReplayCache with a shared cache when several instances serve SystemAuth")
		cache = middleware.NewMemoryReplayCache()
	}
	cfg := dpopproof.Config{
		MaxAge:      s.config.DPoP.ProofMaxAge.Duration(),
		ClockSkew:   s.config.DPoP.ClockSkew.Duration(),
		ReplayCache: cache,
	}
	if s.config.DPoP.RequireNonce {
		nonces, err := dpopproof.NewNonces([]byte(s.config.DPoP.NonceSecret), s.config.DPoP.NonceLifetime.Duration())
		if err != nil {
			return fmt.Errorf("%w: dpop: %v", ErrInvalidConfig, err)
		}
		cfg.Nonces = nonces
	}
	checker, err := dpopproof.NewChecker(cfg)
	if err != nil {
		return err
	}
	s.dpop = checker
	return nil
}

// TokenEndpointURL is the token endpoint as advertised in discovery: the
// htu a proof for a token request must name. It is built from the issuer,
// the external URL, so it is right behind a proxy that terminates TLS.
func (s *Server) TokenEndpointURL() string {
	return s.config.Issuer + "/oauth/token"
}

// endpointURL is the external URL of one of SystemAuth's own endpoints.
func (s *Server) endpointURL(path string) string {
	return s.config.Issuer + path
}

// requestURL is the external URL of a request to another route served by
// this server, such as an API behind BearerAccess: dpop.resource_base_url,
// or by default the issuer's origin, and the request path.
func (s *Server) requestURL(r *http.Request) string {
	if base := strings.TrimSuffix(s.config.DPoP.ResourceBaseURL, "/"); base != "" {
		return base + r.URL.Path
	}
	u, err := url.Parse(s.config.Issuer)
	if err != nil || u.Host == "" {
		return s.config.Issuer + r.URL.Path
	}
	return u.Scheme + "://" + u.Host + r.URL.Path
}

// dpopError builds a token endpoint error with an RFC 9449 code.
func dpopError(code, description string) *fosite.RFC6749Error {
	return &fosite.RFC6749Error{ErrorField: code, DescriptionField: description, CodeField: http.StatusBadRequest}
}

// tokenRequestProof verifies the DPoP proof of a token request, if it
// carries one; see VerifyTokenRequestProof.
func (s *Server) tokenRequestProof(ctx context.Context, r *http.Request) (*dpopproof.Proof, error) {
	return VerifyTokenRequestProof(ctx, s.dpop, r, s.TokenEndpointURL())
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

// requireProofBeforeGrant refuses a token request without a proof from a
// client that must use DPoP before Fosite handles the grant, which has
// side effects (it consumes the PKCE request of a code with some
// storage). The client is the one the request names; bindDPoP checks the
// authenticated client again afterwards.
func (s *Server) requireProofBeforeGrant(ctx context.Context, r *http.Request, proof *dpopproof.Proof) error {
	if proof != nil {
		return nil
	}
	id := r.PostFormValue("client_id")
	if user, _, ok := r.BasicAuth(); ok {
		if unescaped, err := url.QueryUnescape(user); err == nil {
			id = unescaped
		}
	}
	if id == "" {
		return nil
	}
	c, err := s.storage.GetClientByID(ctx, id)
	if errors.Is(err, ErrClientNotFound) {
		// An unknown client fails client authentication in Fosite.
		return nil
	}
	if err != nil {
		return fosite.ErrServerError.WithWrap(err)
	}
	if c.DPoPBoundAccessTokens() {
		return DPoPProofRequiredError()
	}
	return nil
}

// CodeDPoPBindingStorage reads authorization codes for CheckCodeDPoPBinding.
type CodeDPoPBindingStorage interface {
	GetAuthorizeCodeSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error)
}

// CheckCodeDPoPBinding refuses an authorization_code token request whose
// code is bound to a DPoP key (dpop_jkt, RFC 9449 §10) when the request
// carries no proof by that key. Call it before Fosite handles the request:
// Fosite's grant handling has side effects even when the exchange is then
// refused (it deletes the code's PKCE request, which with some storage
// makes the code unusable), so a refused exchange must not reach it. The
// code is looked up by its signature under codes. A request for another
// grant, or a code that cannot be read, is left to Fosite.
func CheckCodeDPoPBinding(ctx context.Context, codes CodeDPoPBindingStorage, strategy oauth2.AuthorizeCodeStrategy, r *http.Request, proof *dpopproof.Proof) error {
	if r.PostForm.Get("grant_type") != "authorization_code" {
		return nil
	}
	code := r.PostForm.Get("code")
	if code == "" {
		return nil
	}
	ar, err := codes.GetAuthorizeCodeSession(ctx, strategy.AuthorizeCodeSignature(ctx, code), &Session{})
	if err != nil || ar == nil {
		// Unknown, used or expired: Fosite refuses it.
		return nil //nolint:nilerr // Fosite reports the code's own error
	}
	sess, ok := ar.GetSession().(*Session)
	if !ok || sess.DPoPJKT == "" {
		return nil
	}
	if proof == nil {
		return dpopError(errInvalidDPoPProof, "The grant is bound to a DPoP key; a DPoP proof by that key is required.")
	}
	if proof.JKT() != sess.DPoPJKT {
		return fosite.ErrInvalidGrant.WithHint("The DPoP proof was not signed by the key the grant is bound to.")
	}
	return nil
}

// bindDPoP applies the DPoP policy to a parsed token request; see
// BindDPoPGrant. A client must send a proof unless it is registered with
// the AllowBearerTokens exception.
func (s *Server) bindDPoP(ar fosite.AccessRequester, proof *dpopproof.Proof) error {
	return BindDPoPGrant(ar, proof, requiresDPoP(ar.GetClient()))
}

// BindDPoPGrant applies the DPoP policy to a token request Fosite has
// parsed, whose session is a *Session, and binds the tokens it issues to
// the proof's key:
//
//   - without a proof, the request is refused when requireProof is set
//     (the client has no bearer-token exception);
//   - a code issued for a dpop_jkt, and a refresh token bound to a key,
//     need a proof by that key (RFC 9449 §10, §5);
//   - with a proof, the access and refresh tokens are bound to its key.
func BindDPoPGrant(ar fosite.AccessRequester, proof *dpopproof.Proof, requireProof bool) error {
	sess, ok := ar.GetSession().(*Session)
	if !ok || sess.DefaultSession == nil {
		return fosite.ErrServerError.WithHint("unexpected session type")
	}
	bound := sess.DPoPJKT
	if proof == nil {
		if bound != "" {
			return dpopError(errInvalidDPoPProof, "The grant is bound to a DPoP key; a DPoP proof by that key is required.")
		}
		if requireProof {
			return DPoPProofRequiredError()
		}
		return nil
	}
	if bound != "" && bound != proof.JKT() {
		return fosite.ErrInvalidGrant.WithHint("The DPoP proof was not signed by the key the grant is bound to.")
	}
	sess.DPoPJKT = proof.JKT()
	return nil
}

// requiresDPoP reports whether a client must send DPoP proofs. Only a
// SystemAuth client registered with AllowBearerTokens is exempt.
func requiresDPoP(c fosite.Client) bool {
	sc, ok := c.(*Client)
	return !ok || sc.DPoPBoundAccessTokens()
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
// to match the session's binding.
func SetConfirmationClaim(sess *Session, claims *jwt.JWTClaims) {
	if sess.DPoPJKT == "" {
		delete(claims.Extra, "cnf")
		return
	}
	claims.Add("cnf", map[string]interface{}{"jkt": sess.DPoPJKT})
}

// setDPoPNonce adds a fresh server nonce to a response when nonces are on.
func (s *Server) setDPoPNonce(ctx context.Context, w http.ResponseWriter) {
	nonce, err := s.dpop.Nonce()
	if err != nil {
		LoggerFromContext(ctx).ErrorContext(ctx, "issuing a DPoP nonce", "error", err)
		return
	}
	if nonce != "" {
		w.Header().Set(dpopNonceHeader, nonce)
	}
}

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

// errNoAccessToken means the request carried no access token.
var errNoAccessToken = errors.New("systemauth: no access token")

// authenticateAccessToken validates the access token of a request to one
// of this server's resources at htu; see AuthenticateAccessToken. The
// token must be active and its principal active.
func (s *Server) authenticateAccessToken(r *http.Request, htu string) (fosite.AccessRequester, *TokenAuthError) {
	return AuthenticateAccessToken(r, s.dpop, htu, func(ctx context.Context, token string) (fosite.AccessRequester, error) {
		return s.introspect(ctx, token, fosite.AccessToken, s.Session(""))
	})
}

// AuthenticateAccessToken validates the access token of a request to a
// resource at htu, the request's external URL without query. introspect
// returns the request of an active, acceptable access token, whose session
// is a *Session, or an error to refuse it with invalid_token. A
// DPoP-bound token must come with the DPoP scheme and a fresh, unreplayed
// proof by its key (checked by checker) for the request's method and htu,
// carrying the token's hash; an unbound token must come with the Bearer
// scheme. A request without a token returns a *TokenAuthError for which
// NoToken reports true. Write a refusal with WriteTokenAuthError.
func AuthenticateAccessToken(r *http.Request, checker *dpopproof.Checker, htu string, introspect func(ctx context.Context, token string) (fosite.AccessRequester, error)) (fosite.AccessRequester, *TokenAuthError) {
	ctx := r.Context()
	scheme, token := AccessTokenCredentials(r)
	if token == "" {
		return nil, &TokenAuthError{status: http.StatusUnauthorized, err: errNoAccessToken}
	}
	challenge := ""
	if scheme == "dpop" {
		challenge = TokenTypeDPoP
	}
	ar, err := introspect(ctx, token)
	if err != nil {
		return nil, &TokenAuthError{status: http.StatusUnauthorized, code: "invalid_token", description: "The access token is invalid, expired or revoked.", scheme: challenge, err: err}
	}
	sess, _ := ar.GetSession().(*Session)
	jkt := ""
	if sess != nil {
		jkt = sess.DPoPJKT
	}
	if jkt == "" {
		if scheme == "dpop" {
			return nil, &TokenAuthError{status: http.StatusUnauthorized, code: "invalid_token", description: "The access token is not DPoP-bound; use the Bearer scheme.", scheme: TokenTypeDPoP}
		}
		return ar, nil
	}
	if scheme != "dpop" {
		return nil, &TokenAuthError{status: http.StatusUnauthorized, code: "invalid_token", description: "The access token is DPoP-bound; use the DPoP scheme with a DPoP proof.", scheme: TokenTypeDPoP}
	}
	proof, err := checker.Check(ctx, r, dpopproof.Target{Method: r.Method, URI: htu, AccessToken: token})
	switch {
	case errors.Is(err, dpopproof.ErrUseNonce):
		nonce, nerr := checker.Nonce()
		if nerr != nil {
			return nil, &TokenAuthError{status: http.StatusInternalServerError, err: nerr}
		}
		return nil, &TokenAuthError{status: http.StatusUnauthorized, code: errUseDPoPNonce, description: "Resource server requires a nonce in the DPoP proof.", scheme: TokenTypeDPoP, nonce: nonce, err: err}
	case errors.Is(err, dpopproof.ErrInvalid), errors.Is(err, dpopproof.ErrMissing):
		return nil, &TokenAuthError{status: http.StatusUnauthorized, code: errInvalidDPoPProof, description: "A valid DPoP proof for this request is required.", scheme: TokenTypeDPoP, err: err}
	case err != nil:
		return nil, &TokenAuthError{status: http.StatusInternalServerError, err: err}
	}
	if proof.JKT() != jkt {
		return nil, &TokenAuthError{status: http.StatusUnauthorized, code: errInvalidDPoPProof, description: "The DPoP proof was not signed by the key the access token is bound to.", scheme: TokenTypeDPoP}
	}
	return ar, nil
}

// dpopChallenge is the DPoP WWW-Authenticate challenge (RFC 9449 §7.1).
func dpopChallenge(code, description string) string {
	c := `DPoP algs="` + strings.Join(dpopproof.Algorithms, " ") + `"`
	if code != "" {
		c += `, error="` + code + `"`
	}
	if description != "" {
		c += `, error_description="` + description + `"`
	}
	return c
}

// writeTokenAuthError writes the response for a request whose access token
// was not accepted, with WWW-Authenticate challenges (RFC 6750 §3, RFC 9449
// §7.1).
func (s *Server) writeTokenAuthError(w http.ResponseWriter, e *TokenAuthError) {
	writeTokenAuthError(w, e)
}

// WriteTokenAuthError writes the response for a request whose access
// token AuthenticateAccessToken did not accept: 401 with WWW-Authenticate
// challenges (RFC 6750 §3, RFC 9449 §7.1) and a DPoP-Nonce to retry with
// when one is needed, or 500 when the token could not be checked.
func WriteTokenAuthError(w http.ResponseWriter, e *TokenAuthError) {
	writeTokenAuthError(w, e)
}

func writeTokenAuthError(w http.ResponseWriter, e *TokenAuthError) {
	if e.status == http.StatusInternalServerError {
		http.Error(w, "could not check the access token", http.StatusInternalServerError)
		return
	}
	if e.nonce != "" {
		w.Header().Set(dpopNonceHeader, e.nonce)
	}
	if e.scheme == TokenTypeDPoP {
		writeChallengeError(w, e.status, []string{dpopChallenge(e.code, e.description)}, e.code, e.description)
		return
	}
	// No token, or an invalid Bearer one: offer both schemes.
	writeChallengeError(w, e.status, []string{bearerChallenge(e.code, e.description, ""), dpopChallenge("", "")}, e.code, e.description)
}
