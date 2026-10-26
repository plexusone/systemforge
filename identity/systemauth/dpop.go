package systemauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/ory/fosite"

	"github.com/plexusone/systemforge/identity/dpopproof"
	"github.com/plexusone/systemforge/identity/internal/oauthcore"
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

// tokenRequestProof verifies the DPoP proof of a token request, if it
// carries one. A request without one returns nil: whether a proof is
// required depends on the client, which is known only after the request
// is parsed.
func (s *Server) tokenRequestProof(ctx context.Context, r *http.Request) (*dpopproof.Proof, error) {
	return oauthcore.VerifyTokenRequestProof(ctx, s.dpop, r, s.TokenEndpointURL())
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
		return oauthcore.DPoPProofRequiredError()
	}
	return nil
}

// checkCodeDPoPBinding refuses an authorization_code token request whose
// code is bound to a DPoP key (dpop_jkt) without a proof by that key,
// before Fosite handles it; see oauthcore.CheckCodeDPoPBinding.
func (s *Server) checkCodeDPoPBinding(ctx context.Context, r *http.Request, proof *dpopproof.Proof) error {
	return oauthcore.CheckCodeDPoPBinding(ctx, s.storage, s.codeStrategy, r, proof, &Session{}, sessionDPoPJKT)
}

// bindDPoP applies the DPoP policy to a parsed token request and binds the
// tokens it issues to the proof's key (see oauthcore.BindDPoPGrant). A
// client must send a proof unless it is registered with the
// AllowBearerTokens exception.
func (s *Server) bindDPoP(ar fosite.AccessRequester, proof *dpopproof.Proof) error {
	sess, ok := ar.GetSession().(*Session)
	if !ok || sess.DefaultSession == nil {
		return fosite.ErrServerError.WithHint("unexpected session type")
	}
	return oauthcore.BindDPoPGrant(&sess.DPoPJKT, proof, requiresDPoP(ar.GetClient()))
}

// requiresDPoP reports whether a client must send DPoP proofs. Only a
// SystemAuth client registered with AllowBearerTokens is exempt.
func requiresDPoP(c fosite.Client) bool {
	sc, ok := c.(*Client)
	return !ok || sc.DPoPBoundAccessTokens()
}

// sessionDPoPJKT returns the DPoP binding of a SystemAuth session: the
// thumbprint of the key it is bound to, or "" for an unbound session or
// a session of another type.
func sessionDPoPJKT(sess fosite.Session) string {
	if s, ok := sess.(*Session); ok && s != nil {
		return s.DPoPJKT
	}
	return ""
}

// setDPoPNonce adds a fresh server nonce to a response when nonces are on.
func (s *Server) setDPoPNonce(ctx context.Context, w http.ResponseWriter) {
	nonce, err := s.dpop.Nonce()
	if err != nil {
		LoggerFromContext(ctx).ErrorContext(ctx, "issuing a DPoP nonce", "error", err)
		return
	}
	if nonce != "" {
		w.Header().Set(oauthcore.DPoPNonceHeader, nonce)
	}
}

// authenticateAccessToken validates the access token of a request to one
// of this server's resources at htu (see oauthcore.AuthenticateAccessToken).
// The token must be active and its principal active; a DPoP-bound token
// must come with the DPoP scheme and a proof by its key.
func (s *Server) authenticateAccessToken(r *http.Request, htu string) (fosite.AccessRequester, *oauthcore.TokenAuthError) {
	return oauthcore.AuthenticateAccessToken(r, s.dpop, htu, func(ctx context.Context, token string) (fosite.AccessRequester, error) {
		return s.introspect(ctx, token, fosite.AccessToken, s.Session(""))
	}, sessionDPoPJKT)
}

// writeTokenAuthError writes the response for a request whose access token
// was not accepted, with WWW-Authenticate challenges (RFC 6750 §3, RFC 9449
// §7.1).
func (s *Server) writeTokenAuthError(w http.ResponseWriter, e *oauthcore.TokenAuthError) {
	oauthcore.WriteTokenAuthError(w, e)
}
