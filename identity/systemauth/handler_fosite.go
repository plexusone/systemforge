package systemauth

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/ory/fosite"
	"github.com/plexusone/omniobserve/observops"
	"github.com/plexusone/systemforge/observability"
)

// fositeInterceptor intercepts OAuth requests and delegates to Fosite handlers.
// This runs before Huma processes the request, allowing Fosite to handle
// the full request/response lifecycle.
func (s *Server) fositeInterceptor(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/authorize":
			s.authorizeEndpoint(w, r)
			return
		case "/oauth/token":
			if r.Method == http.MethodPost {
				s.tokenEndpoint(w, r)
				return
			}
		case "/oauth/introspect":
			if r.Method == http.MethodPost {
				s.introspectionEndpoint(w, r)
				return
			}
		case "/oauth/revoke":
			if r.Method == http.MethodPost {
				s.revocationEndpoint(w, r)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// registerOpenAPIOperations registers Huma operations for OpenAPI documentation.
// These handlers are never called because the middleware intercepts first.
func (s *Server) registerOpenAPIOperations() {
	// Authorization endpoint (GET and POST)
	huma.Register(s.huma, huma.Operation{
		OperationID:   "authorize",
		Method:        http.MethodGet,
		Path:          "/oauth/authorize",
		Summary:       "OAuth 2.0 Authorization Endpoint",
		Description:   "Initiates the authorization flow. Redirects to login if not authenticated, then to consent, and finally back to the client with an authorization code or token.",
		Tags:          []string{"OAuth"},
		DefaultStatus: http.StatusFound,
	}, s.authorizeOpenAPI)

	huma.Register(s.huma, huma.Operation{
		OperationID:   "authorizePost",
		Method:        http.MethodPost,
		Path:          "/oauth/authorize",
		Summary:       "OAuth 2.0 Authorization Endpoint (POST)",
		Description:   "Handles authorization form submission (consent approval).",
		Tags:          []string{"OAuth"},
		DefaultStatus: http.StatusFound,
	}, s.authorizeOpenAPI)

	// Token endpoint
	huma.Register(s.huma, huma.Operation{
		OperationID:   "token",
		Method:        http.MethodPost,
		Path:          "/oauth/token",
		Summary:       "OAuth 2.0 Token Endpoint",
		Description:   "Exchanges authorization codes for tokens, refreshes tokens, or issues tokens for client credentials.",
		Tags:          []string{"OAuth"},
		DefaultStatus: http.StatusOK,
	}, s.tokenOpenAPI)

	// Introspection endpoint
	huma.Register(s.huma, huma.Operation{
		OperationID:   "introspect",
		Method:        http.MethodPost,
		Path:          "/oauth/introspect",
		Summary:       "OAuth 2.0 Token Introspection",
		Description:   "Returns metadata about a token, including whether it is active (RFC 7662).",
		Tags:          []string{"OAuth"},
		DefaultStatus: http.StatusOK,
	}, s.introspectOpenAPI)

	// Revocation endpoint
	huma.Register(s.huma, huma.Operation{
		OperationID:   "revoke",
		Method:        http.MethodPost,
		Path:          "/oauth/revoke",
		Summary:       "OAuth 2.0 Token Revocation",
		Description:   "Revokes an access token or refresh token (RFC 7009).",
		Tags:          []string{"OAuth"},
		DefaultStatus: http.StatusOK,
	}, s.revokeOpenAPI)
}

// OpenAPI handler stubs - these are never called due to middleware interception,
// but define the request/response types for OpenAPI documentation.

func (s *Server) authorizeOpenAPI(_ context.Context, _ *AuthorizeInput) (*AuthorizeOutput, error) {
	return &AuthorizeOutput{}, nil
}

func (s *Server) tokenOpenAPI(_ context.Context, _ *TokenInput) (*TokenOutput, error) {
	return &TokenOutput{}, nil
}

func (s *Server) introspectOpenAPI(_ context.Context, _ *IntrospectInput) (*IntrospectOutput, error) {
	return &IntrospectOutput{}, nil
}

func (s *Server) revokeOpenAPI(_ context.Context, _ *RevokeInput) (*RevokeOutput, error) {
	return &RevokeOutput{}, nil
}

// Actual Fosite handlers

// authorizeEndpoint handles GET/POST /oauth/authorize.
func (s *Server) authorizeEndpoint(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := LoggerFromContext(ctx)
	start := time.Now()

	// Start span if observability is configured
	if s.observability != nil {
		var span observops.Span
		ctx, span = s.observability.StartSpan(ctx, observability.SpanAuthorize,
			observops.WithSpanKind(observops.SpanKindServer),
		)
		defer span.End()
	}

	// Parse the authorization request
	ar, err := s.oauth2.NewAuthorizeRequest(ctx, r)
	if err != nil {
		logger.Warn("authorize request failed", "error", err)
		s.recordAuthMetrics(ctx, "authorize", "", observability.StatusError, start)
		s.oauth2.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	clientID := ar.GetClient().GetID()
	requestedScopes := ar.GetRequestedScopes()

	logger.Debug("authorize request",
		"client_id", clientID,
		"scopes", requestedScopes,
	)

	// Step 1: Check if user is authenticated
	userID := s.sessionProvider.GetAuthenticatedUser(r)
	if userID == "" {
		// Redirect to login
		returnURL := r.URL.String()
		loginURL := s.sessionProvider.RedirectToLogin(returnURL)
		logger.Debug("redirecting to login", "return_url", returnURL)
		//nolint:gosec // G710: loginURL is generated by server-controlled sessionProvider, not user input
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	// Step 2: Check if user has already consented to these scopes
	if !s.sessionProvider.HasConsent(ctx, userID, clientID, requestedScopes) {
		// Redirect to consent
		returnURL := r.URL.String()
		consentURL := s.sessionProvider.RedirectToConsent(returnURL)
		logger.Debug("redirecting to consent", "user_id", userID, "client_id", clientID)
		//nolint:gosec // G710: consentURL is generated by server-controlled sessionProvider, not user input
		http.Redirect(w, r, consentURL, http.StatusFound)
		return
	}

	// Step 3: Get user claims for the ID token
	claims := s.sessionProvider.GetUserClaims(ctx, userID, requestedScopes)

	// Create session for the user with claims
	session := s.OIDCSession(userID, claims)

	// Grant the requested scopes (user has consented)
	for _, scope := range requestedScopes {
		ar.GrantScope(scope)
	}

	// Create the authorization response
	response, err := s.oauth2.NewAuthorizeResponse(ctx, ar, session)
	if err != nil {
		logger.Warn("authorize response failed", "error", err)
		s.recordAuthMetrics(ctx, "authorize", clientID, observability.StatusError, start)
		s.oauth2.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	logger.Info("authorization code issued",
		"user_id", userID,
		"client_id", clientID,
		"scopes", requestedScopes,
	)

	// Record success metrics
	s.recordAuthMetrics(ctx, "authorize", clientID, observability.StatusSuccess, start)

	// Write the response (redirect with code)
	s.oauth2.WriteAuthorizeResponse(ctx, w, ar, response)
}

// tokenEndpoint handles POST /oauth/token.
func (s *Server) tokenEndpoint(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := LoggerFromContext(ctx)
	start := time.Now()

	grantType := r.FormValue("grant_type")

	// Start span if observability is configured
	if s.observability != nil {
		var span observops.Span
		ctx, span = s.observability.StartSpan(ctx, observability.SpanToken,
			observops.WithSpanKind(observops.SpanKindServer),
			observops.WithSpanAttributes(
				observops.Attribute("oauth.grant_type", grantType),
			),
		)
		defer span.End()
	}

	// Limit request body size to prevent memory exhaustion (1MB max for token requests)
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	// Create session (will be populated by the grant handler)
	session := s.Session("")
	logger.Debug("token request", "grant_type", grantType)

	// Process the token request
	ar, err := s.oauth2.NewAccessRequest(ctx, r, session)
	if err != nil {
		logger.Warn("token request failed", "grant_type", grantType, "error", err)
		s.recordAuthMetrics(ctx, grantType, "", observability.StatusError, start)
		s.oauth2.WriteAccessError(ctx, w, ar, err)
		return
	}

	clientID := ar.GetClient().GetID()

	// Bound refresh-token rotation by the family's absolute lifetime.
	if err := s.applyTokenFamilyLifetime(ctx, ar); err != nil {
		logger.Info("token request rejected", "grant_type", grantType, "client_id", clientID, "error", err)
		s.recordAuthMetrics(ctx, grantType, clientID, observability.StatusError, start)
		s.oauth2.WriteAccessError(ctx, w, ar, err)
		return
	}

	// Grant the requested scopes
	for _, scope := range ar.GetRequestedScopes() {
		ar.GrantScope(scope)
	}

	// Create the token response
	response, err := s.oauth2.NewAccessResponse(ctx, ar)
	if err != nil {
		logger.Warn("token response failed",
			"grant_type", grantType,
			"client_id", clientID,
			"error", err,
		)
		s.recordAuthMetrics(ctx, grantType, clientID, observability.StatusError, start)
		s.oauth2.WriteAccessError(ctx, w, ar, err)
		return
	}

	logger.Info("token issued",
		"grant_type", grantType,
		"client_id", clientID,
		"scopes", ar.GetGrantedScopes(),
	)

	// Record success metrics
	s.recordAuthMetrics(ctx, grantType, clientID, observability.StatusSuccess, start)
	if s.observability != nil {
		s.observability.RecordTokenIssued(ctx, grantType, clientID)
	}

	// Write the response
	s.oauth2.WriteAccessResponse(ctx, w, ar, response)
}

// applyTokenFamilyLifetime enforces the absolute lifetime of a refresh-token
// family. Fosite rotates refresh tokens on every use (and detects reuse of a
// rotated token); this caps each new refresh token at the family deadline
// and rejects, and revokes, a family that has outlived it.
func (s *Server) applyTokenFamilyLifetime(ctx context.Context, ar fosite.AccessRequester) error {
	sess, ok := ar.GetSession().(*Session)
	if !ok || sess.DefaultSession == nil {
		return nil
	}
	now := time.Now().UTC()
	if sess.FamilyIssuedAt.IsZero() {
		sess.FamilyIssuedAt = now
	}
	maxLifetime := s.config.Tokens.RefreshTokenAbsoluteLifetime.Duration()
	if maxLifetime <= 0 {
		return nil
	}
	deadline := sess.FamilyIssuedAt.Add(maxLifetime)
	if ar.GetGrantTypes().ExactOne("refresh_token") && !now.Before(deadline) {
		if err := s.storage.RevokeRefreshToken(ctx, ar.GetID()); err != nil {
			return fosite.ErrServerError.WithWrap(err)
		}
		if err := s.storage.RevokeAccessToken(ctx, ar.GetID()); err != nil {
			return fosite.ErrServerError.WithWrap(err)
		}
		return fosite.ErrInvalidGrant.WithHint("The refresh token family exceeded its absolute lifetime; sign in again.")
	}
	if exp := sess.GetExpiresAt(fosite.RefreshToken); exp.IsZero() || exp.After(deadline) {
		sess.SetExpiresAt(fosite.RefreshToken, deadline)
	}
	return nil
}

// introspectionEndpoint handles POST /oauth/introspect.
func (s *Server) introspectionEndpoint(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Start span if observability is configured
	if s.observability != nil {
		var span observops.Span
		ctx, span = s.observability.StartSpan(ctx, observability.SpanIntrospect,
			observops.WithSpanKind(observops.SpanKindServer),
		)
		defer span.End()
	}

	session := s.Session("")

	ir, err := s.oauth2.NewIntrospectionRequest(ctx, r, session)
	if err != nil {
		// Introspection MUST return 200 even for invalid tokens
		if s.observability != nil {
			s.observability.RecordTokenValidation(ctx, observability.ResultInvalid)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"active": false,
		})
		return
	}

	if s.observability != nil {
		s.observability.RecordTokenValidation(ctx, observability.ResultValid)
	}

	s.oauth2.WriteIntrospectionResponse(ctx, w, ir)
}

// revocationEndpoint handles POST /oauth/revoke.
func (s *Server) revocationEndpoint(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Start span if observability is configured
	if s.observability != nil {
		var span observops.Span
		ctx, span = s.observability.StartSpan(ctx, observability.SpanRevoke,
			observops.WithSpanKind(observops.SpanKindServer),
		)
		defer span.End()
	}

	err := s.oauth2.NewRevocationRequest(ctx, r)
	if err != nil {
		s.oauth2.WriteRevocationResponse(ctx, w, err)
		return
	}

	s.oauth2.WriteRevocationResponse(ctx, w, nil)
}

// SessionProvider returns the session provider.
func (s *Server) SessionProvider() SessionProvider {
	return s.sessionProvider
}

// recordAuthMetrics records authentication metrics if observability is configured.
func (s *Server) recordAuthMetrics(ctx context.Context, grantType, clientID, status string, start time.Time) {
	if s.observability == nil {
		return
	}
	s.observability.RecordAuthRequest(ctx, grantType, clientID, status)
	s.observability.RecordAuthLatency(ctx, grantType, "/oauth/token", float64(time.Since(start).Milliseconds()))
}
