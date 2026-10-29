package systemauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/google/uuid"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/rfc7523"
)

// GrantTypeJWTBearer is the JWT-bearer grant type (RFC 7523 section 2.1).
const GrantTypeJWTBearer = string(fosite.GrantTypeJWTBearer)

// JWTBearerClientID is the reserved client that tokens issued by the
// JWT-bearer grant are stored under. The grant authenticates no client:
// the signed assertion and the DPoP proof are the credential. The client
// exists because token storage records the client of every token; it has
// no secret and no redirect URI, so nothing can authenticate as it.
const JWTBearerClientID = "systemauth-jwt-bearer" //nolint:gosec // G101: a public client identifier, not a credential

// JWTBearerKeyStorage is the key storage of the JWT-bearer grant.
// EntJWTBearerKeys is the standard implementation.
type JWTBearerKeyStorage interface {
	rfc7523.RFC7523KeyStorage

	// PrincipalID returns the principal ID of the usable service account
	// whose identifier is subject, the subject of a verified assertion.
	PrincipalID(ctx context.Context, subject string) (uuid.UUID, error)

	// RecordKeyUse records that the account's key authenticated a token
	// request from ip.
	RecordKeyUse(ctx context.Context, principalID uuid.UUID, keyID, ip string) error
}

// The claim telling a relying party what kind of principal a token's
// subject is. It is set for service principals only.
const (
	PrincipalTypeClaim   = "principal_type"
	PrincipalTypeService = "service"
)

// WithJWTBearerKeys sets the key storage of the JWT-bearer grant. Without
// it, a server whose storage is an EntStorage uses NewEntJWTBearerKeys
// over the same database; any other storage needs it when
// oauth.jwt_bearer.enabled is set.
func WithJWTBearerKeys(keys JWTBearerKeyStorage) Option {
	return func(s *Server) { s.jwtBearerKeys = keys }
}

// jwtBearerEnabled reports whether the JWT-bearer grant is on.
func (s *Server) jwtBearerEnabled() bool {
	return s.config.OAuth.JWTBearer.Enabled
}

// setupJWTBearer resolves the grant's key storage and registers its
// reserved client, when the grant is enabled.
func (s *Server) setupJWTBearer(ctx context.Context) error {
	if !s.jwtBearerEnabled() {
		return nil
	}
	if s.jwtBearerKeys == nil {
		es, ok := s.storage.(*EntStorage)
		if !ok {
			return fmt.Errorf("%w: oauth.jwt_bearer needs Ent storage or WithJWTBearerKeys", ErrInvalidConfig)
		}
		s.jwtBearerKeys = NewEntJWTBearerKeys(es.db)
	}
	client := jwtBearerClient()
	err := s.storage.CreateClient(ctx, client)
	if errors.Is(err, ErrClientExists) {
		err = s.storage.UpdateClient(ctx, client)
	}
	if err != nil {
		return fmt.Errorf("registering the JWT-bearer client: %w", err)
	}
	return nil
}

// jwtBearerClient is the reserved client of the JWT-bearer grant.
func jwtBearerClient() *Client {
	now := time.Now()
	return &Client{
		ID:         JWTBearerClientID,
		Type:       ClientTypeConfidential,
		Name:       "Service accounts (JWT-bearer grant)",
		GrantTypes: []string{GrantTypeJWTBearer},
		CreatedAt:  now,
		UpdatedAt:  now,
	}
}

// jwtBearerConfig is the Fosite configuration of the JWT-bearer handler:
// the server's, with the grant's own audience, assertion lifetime and
// token lifetime, and with client authentication skipped and jti and iat
// required.
type jwtBearerConfig struct {
	*fosite.Config
	tokenURLs     []string
	maxAssertion  time.Duration
	tokenLifetime time.Duration
}

// GetTokenURLs returns the audiences an assertion may name: the token
// endpoint and the issuer.
func (c *jwtBearerConfig) GetTokenURLs(context.Context) []string { return c.tokenURLs }

// GetJWTMaxDuration bounds an assertion's lifetime from iat to exp.
func (c *jwtBearerConfig) GetJWTMaxDuration(context.Context) time.Duration { return c.maxAssertion }

// GetAccessTokenLifespan is the lifetime of the grant's access tokens.
func (c *jwtBearerConfig) GetAccessTokenLifespan(context.Context) time.Duration {
	return c.tokenLifetime
}

// GetGrantTypeJWTBearerCanSkipClientAuth is true: the assertion and the
// DPoP proof are the credential.
func (c *jwtBearerConfig) GetGrantTypeJWTBearerCanSkipClientAuth(context.Context) bool {
	return true
}

// GetGrantTypeJWTBearerIDOptional is false: jti is required.
func (c *jwtBearerConfig) GetGrantTypeJWTBearerIDOptional(context.Context) bool { return false }

// GetGrantTypeJWTBearerIssuedDateOptional is false: iat is required.
func (c *jwtBearerConfig) GetGrantTypeJWTBearerIssuedDateOptional(context.Context) bool {
	return false
}

// jwtBearerHandler is Fosite's RFC 7523 handler, issuing its tokens under
// the reserved client to the service account's principal ID.
type jwtBearerHandler struct {
	*rfc7523.Handler
	keys   JWTBearerKeyStorage
	client *Client
}

var _ fosite.TokenEndpointHandler = (*jwtBearerHandler)(nil)

// HandleTokenEndpointRequest implements fosite.TokenEndpointHandler.
func (h *jwtBearerHandler) HandleTokenEndpointRequest(ctx context.Context, req fosite.AccessRequester) error {
	if !h.CanHandleTokenEndpointRequest(ctx, req) {
		return fosite.ErrUnknownRequest
	}
	ar, ok := req.(*fosite.AccessRequest)
	if !ok {
		return fosite.ErrServerError.WithHintf("unexpected access request type %T", req)
	}
	// Whatever client authentication the request attempted, the token
	// belongs to the account alone.
	ar.Client = h.client
	if err := h.Handler.HandleTokenEndpointRequest(ctx, req); err != nil {
		return err
	}
	return h.bindAccount(ctx, ar)
}

// bindAccount makes the verified assertion's account the token's subject.
// Fosite sets the assertion's subject, the account identifier; the
// token's subject is the principal ID instead, so the orgs claim and
// revocation work as for any principal. The token is marked as a service
// principal's, and gets no audience from the assertion, whose audience
// names this server rather than a resource.
func (h *jwtBearerHandler) bindAccount(ctx context.Context, ar *fosite.AccessRequest) error {
	sess, ok := ar.GetSession().(*Session)
	if !ok || sess.DefaultSession == nil {
		return fosite.ErrServerError.WithHint("unexpected session type")
	}
	keyID, err := h.assertionKey(ctx, ar.GetRequestForm().Get("assertion"))
	if err != nil {
		return err
	}
	id, err := h.keys.PrincipalID(ctx, sess.GetSubject())
	if err != nil {
		return fosite.ErrInvalidGrant.WithHint("The assertion's account cannot be used.").WithWrap(err)
	}
	sess.SetSubject(id.String())
	sess.PrincipalType = PrincipalTypeService
	sess.jwtBearerKeyID = keyID
	ar.GrantedAudience = nil
	return nil
}

// assertionKey returns the ID of the key that verified the assertion, and
// refuses an assertion signed with another algorithm than its key's.
func (h *jwtBearerHandler) assertionKey(ctx context.Context, signed string) (string, error) {
	token, err := jwt.ParseSigned(signed)
	if err != nil || len(token.Headers) == 0 {
		return "", fosite.ErrInvalidGrant.WithHint("The assertion cannot be parsed.")
	}
	var claims jwt.Claims
	if err := token.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return "", fosite.ErrInvalidGrant.WithHint("The assertion has no claims.").WithWrap(err)
	}
	header := token.Headers[0]
	key, err := h.verifyingKey(ctx, token, claims, header.KeyID)
	if err != nil {
		return "", err
	}
	if key.Algorithm != header.Algorithm {
		return "", fosite.ErrInvalidGrant.WithHint("The assertion's algorithm does not match its key.")
	}
	return key.KeyID, nil
}

// verifyingKey returns the key kid names, or without a kid the account's
// key that verifies the token.
func (h *jwtBearerHandler) verifyingKey(ctx context.Context, token *jwt.JSONWebToken, claims jwt.Claims, kid string) (*jose.JSONWebKey, error) {
	refused := fosite.ErrInvalidGrant.WithHint("The assertion's key cannot be used.")
	if kid != "" {
		key, err := h.keys.GetPublicKey(ctx, claims.Issuer, claims.Subject, kid)
		if err != nil {
			return nil, refused.WithWrap(err)
		}
		return key, nil
	}
	set, err := h.keys.GetPublicKeys(ctx, claims.Issuer, claims.Subject)
	if err != nil {
		return nil, refused.WithWrap(err)
	}
	for i := range set.Keys {
		if token.Claims(set.Keys[i], &jwt.Claims{}) == nil {
			return &set.Keys[i], nil
		}
	}
	return nil, refused
}

// jwtBearerFactory builds the JWT-bearer handler for compose.Compose.
func (s *Server) jwtBearerFactory() compose.Factory {
	jb := s.config.OAuth.JWTBearer
	return func(config fosite.Configurator, storage, strategy interface{}) interface{} {
		base, ok := config.(*fosite.Config)
		if !ok {
			panic(fmt.Sprintf("systemauth: unexpected Fosite configuration type %T", config))
		}
		cfg := &jwtBearerConfig{
			Config:        base,
			tokenURLs:     []string{s.TokenEndpointURL(), s.config.Issuer},
			maxAssertion:  jb.MaxAssertionLifetime.Duration(),
			tokenLifetime: jb.TokenLifetime.Duration(),
		}
		return &jwtBearerHandler{
			Handler: &rfc7523.Handler{
				Storage: s.jwtBearerKeys,
				HandleHelper: &oauth2.HandleHelper{
					AccessTokenStrategy: strategy.(oauth2.AccessTokenStrategy),
					AccessTokenStorage:  storage.(oauth2.AccessTokenStorage),
					Config:              cfg,
				},
				Config: cfg,
			},
			keys:   s.jwtBearerKeys,
			client: jwtBearerClient(),
		}
	}
}

// recordJWTBearerUse records the key and account of a token the JWT-bearer
// grant issued as used. The token is already issued, so a failure is
// logged rather than returned.
func (s *Server) recordJWTBearerUse(ctx context.Context, r *http.Request, sess *Session) {
	if sess.jwtBearerKeyID == "" || s.jwtBearerKeys == nil {
		return
	}
	logger := LoggerFromContext(ctx)
	id, err := uuid.Parse(sess.GetSubject())
	if err != nil {
		logger.ErrorContext(ctx, "recording service account key use: subject is not a principal ID", "error", err)
		return
	}
	if err := s.jwtBearerKeys.RecordKeyUse(ctx, id, sess.jwtBearerKeyID, s.tokenClientIP(r)); err != nil {
		logger.ErrorContext(ctx, "recording service account key use", "principal_id", id, "key_id", sess.jwtBearerKeyID, "error", err)
	}
}

// requireJWTBearerProof refuses a JWT-bearer token request without a DPoP
// proof, before any client rule is considered, so no exception applies.
func (s *Server) requireJWTBearerProof(r *http.Request) error {
	if !s.jwtBearerEnabled() || r.PostFormValue("grant_type") != GrantTypeJWTBearer {
		return nil
	}
	return &fosite.RFC6749Error{
		ErrorField:       "invalid_dpop_proof",
		DescriptionField: "The JWT-bearer grant requires a DPoP proof.",
		CodeField:        http.StatusBadRequest,
	}
}
