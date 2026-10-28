package systemauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

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
}

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
// the reserved client.
type jwtBearerHandler struct {
	*rfc7523.Handler
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
	return h.Handler.HandleTokenEndpointRequest(ctx, req)
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
			client: jwtBearerClient(),
		}
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
