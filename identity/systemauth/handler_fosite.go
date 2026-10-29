package systemauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/ory/fosite"
	"github.com/ory/fosite/token/jwt"
	"github.com/plexusone/omniobserve/observops"
	"github.com/plexusone/systemforge/identity/internal/oauthcore"
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
		case UserInfoPath:
			if r.Method == http.MethodGet || r.Method == http.MethodPost {
				s.userinfoEndpoint(w, r)
				return
			}
		case AccessChangesPath:
			if r.Method == http.MethodGet {
				s.accessChangesEndpoint(w, r)
				return
			}
		case MembershipsPath:
			if r.Method == http.MethodGet {
				s.membershipsEndpoint(w, r)
				return
			}
		case ResolveMembershipPath:
			if r.Method == http.MethodGet {
				s.resolveMembershipEndpoint(w, r)
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

	s.registerUserInfoOperation()
	s.registerMembershipsOperation()
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
		logger.Warn("authorize request failed", oauthcore.ErrorAttr(ctx, logger, err))
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

	// The OIDC prompt parameter: none shows no page, login re-authenticates
	// the user, consent asks for consent again.
	prompt, err := parsePrompt(ar.GetRequestForm().Get("prompt"))
	if err != nil {
		logger.Info("authorize request refused: prompt", "client_id", clientID, oauthcore.ErrorAttr(ctx, logger, err))
		s.recordAuthMetrics(ctx, "authorize", clientID, observability.StatusError, start)
		s.oauth2.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	// Step 1: Check if user is authenticated
	userID := s.sessionProvider.GetAuthenticatedUser(r)
	if userID == "" || prompt.login {
		if prompt.none {
			logger.Debug("prompt=none without a login session", "client_id", clientID)
			s.recordAuthMetrics(ctx, "authorize", clientID, observability.StatusError, start)
			s.oauth2.WriteAuthorizeError(ctx, w, ar, fosite.ErrLoginRequired.WithHint("The user is not signed in and prompt=none forbids showing the login page."))
			return
		}
		// Redirect to login. The request returned to after login no longer
		// asks for it, or it would send the user to login again.
		returnURL := authorizeReturnURL(r, "login")
		loginURL := s.sessionProvider.RedirectToLogin(returnURL)
		logger.Debug("redirecting to login", "return_url", returnURL, "prompt_login", prompt.login)
		//nolint:gosec // G710: loginURL is generated by server-controlled sessionProvider, not user input
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	// A managed principal is authorized only for clients that allow
	// managed principals, whichever client its login session began with.
	allowed, err := s.clientAllowsSubject(ctx, userID, clientID)
	if err != nil {
		logger.Error("checking managed principal client", "user_id", userID, "client_id", clientID, "error", err)
		s.recordAuthMetrics(ctx, "authorize", clientID, observability.StatusError, start)
		s.oauth2.WriteAuthorizeError(ctx, w, ar, fosite.ErrServerError.WithWrap(err))
		return
	}
	if !allowed {
		logger.Info("managed principal refused by client", "user_id", userID, "client_id", clientID)
		s.recordAuthMetrics(ctx, "authorize", clientID, observability.StatusError, start)
		s.oauth2.WriteAuthorizeError(ctx, w, ar, fosite.ErrAccessDenied.WithHint("This application does not allow managed accounts."))
		return
	}

	// Step 2: First-party clients need no consent; any other client needs
	// the user's recorded consent to these scopes. prompt=consent asks
	// every client's user again (OIDC Core 3.1.2.1).
	if prompt.consent || !s.hasConsent(ctx, ar.GetClient(), userID, requestedScopes) {
		if prompt.none {
			logger.Debug("prompt=none without consent", "user_id", userID, "client_id", clientID)
			s.recordAuthMetrics(ctx, "authorize", clientID, observability.StatusError, start)
			s.oauth2.WriteAuthorizeError(ctx, w, ar, fosite.ErrConsentRequired.WithHint("The user has not consented to this client and prompt=none forbids showing the consent page."))
			return
		}
		// Redirect to consent. The request returned to after consent no
		// longer asks for it, or it would show the consent page again.
		returnURL := authorizeReturnURL(r, "consent")
		consentURL := s.sessionProvider.RedirectToConsent(returnURL)
		logger.Debug("redirecting to consent", "user_id", userID, "client_id", clientID)
		//nolint:gosec // G710: consentURL is generated by server-controlled sessionProvider, not user input
		http.Redirect(w, r, consentURL, http.StatusFound)
		return
	}

	// Step 3: Get user claims for the ID token
	claims, err := s.addOrgsClaims(ctx, userID, s.sessionProvider.GetUserClaims(ctx, userID, requestedScopes), false)
	if err != nil {
		logger.Error("reading organizations for the ID token", "user_id", userID, "error", err)
		s.recordAuthMetrics(ctx, "authorize", clientID, observability.StatusError, start)
		s.oauth2.WriteAuthorizeError(ctx, w, ar, fosite.ErrServerError.WithWrap(err))
		return
	}

	// Create session for the user with claims
	session := s.OIDCSession(userID, claims)
	session.Claims.AuthTime = s.authTime(r)
	session.Claims.RequestedAt = ar.GetRequestedAt()

	// dpop_jkt binds the code to a DPoP key: only a token request with a
	// proof by that key can redeem it (RFC 9449 §10).
	jkt, err := oauthcore.AuthorizationDPoPJKT(ar)
	if err != nil {
		s.recordAuthMetrics(ctx, "authorize", clientID, observability.StatusError, start)
		s.oauth2.WriteAuthorizeError(ctx, w, ar, err)
		return
	}
	session.DPoPJKT = jkt

	// Grant the requested scopes (user has consented)
	for _, scope := range requestedScopes {
		ar.GrantScope(scope)
	}

	// Create the authorization response
	response, err := s.oauth2.NewAuthorizeResponse(ctx, ar, session)
	if err != nil {
		logger.Warn("authorize response failed", oauthcore.ErrorAttr(ctx, logger, err))
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

// firstPartyClient is implemented by clients that know their party. A
// fosite.Client from a custom Storage that does not is not first-party.
type firstPartyClient interface {
	IsFirstParty() bool
}

// hasConsent reports whether an authorization request may proceed without
// the consent screen. A first-party client needs no consent: the service
// provider owns it. A second- or third-party client, or a client that does
// not say what it is, needs the user's recorded consent to every scope,
// whatever the SessionProvider's configuration.
func (s *Server) hasConsent(ctx context.Context, client fosite.Client, userID string, scopes []string) bool {
	if fp, ok := client.(firstPartyClient); ok && fp.IsFirstParty() {
		return true
	}
	return s.sessionProvider.HasConsent(ctx, userID, client.GetID(), scopes)
}

// tokenEndpoint handles POST /oauth/token.
func (s *Server) tokenEndpoint(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := LoggerFromContext(ctx)
	start := time.Now()

	// The body is limited before anything reads it.
	if err := oauthcore.ParseTokenRequest(w, r); err != nil {
		logger.Info("token request rejected: unreadable body", oauthcore.ErrorAttr(ctx, logger, err))
		s.tokenRefused(ctx, nil, "", "", "unreadable_request", err)
		s.recordAuthMetrics(ctx, "", "", observability.StatusError, start)
		s.oauth2.WriteAccessError(ctx, w, nil, err)
		return
	}
	grantType := r.PostForm.Get("grant_type")

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

	// Create session (will be populated by the grant handler)
	session := s.Session("")
	logger.Debug("token request", "grant_type", grantType)

	// A DPoP proof, when sent, is checked before anything else: a request
	// with a bad proof is refused whatever its grant (RFC 9449 §5).
	if s.dpop.NoncesRequired() {
		s.setDPoPNonce(ctx, w)
	}
	proof, err := s.tokenRequestProof(ctx, r)
	if err == nil {
		err = s.requireProofBeforeGrant(ctx, r, proof)
	}
	if err == nil {
		// A code bound to a key is checked before Fosite handles it, so a
		// refused exchange leaves the code usable with every storage.
		err = s.checkCodeDPoPBinding(ctx, r, proof)
	}
	if err != nil {
		logger.Info("token request rejected: DPoP proof", "grant_type", grantType, oauthcore.ErrorAttr(ctx, logger, err))
		s.tokenRefused(ctx, r, grantType, "", "dpop_proof", err)
		s.recordAuthMetrics(ctx, grantType, "", observability.StatusError, start)
		s.oauth2.WriteAccessError(ctx, w, nil, err)
		return
	}

	// Process the token request
	ar, err := s.oauth2.NewAccessRequest(ctx, r, session)
	if err != nil {
		logger.Warn("token request failed", "grant_type", grantType, oauthcore.ErrorAttr(ctx, logger, err))
		s.tokenRequestFailed(ctx, r, grantType, err)
		s.recordAuthMetrics(ctx, grantType, "", observability.StatusError, start)
		s.oauth2.WriteAccessError(ctx, w, ar, err)
		return
	}

	clientID := ar.GetClient().GetID()

	// In production, grants and clients the deployment must not serve are
	// refused once the client is authenticated.
	if reason, err := s.checkProductionPolicy(ar); err != nil {
		logger.Warn("token request rejected: production policy", "grant_type", grantType, "client_id", clientID, "reason", reason)
		s.tokenRefused(ctx, r, grantType, clientID, "production_policy", err)
		s.recordAuthMetrics(ctx, grantType, clientID, observability.StatusError, start)
		s.oauth2.WriteAccessError(ctx, w, ar, err)
		return
	}

	// Tokens are bound to the proof's key, and a client must send one
	// unless it is registered with the bearer-token exception; a grant
	// already bound to a key needs a proof by it.
	if err := s.bindDPoP(ar, proof); err != nil {
		logger.Info("token request rejected: DPoP", "grant_type", grantType, "client_id", clientID, oauthcore.ErrorAttr(ctx, logger, err))
		s.tokenRefused(ctx, r, grantType, clientID, "dpop_binding", err)
		s.recordAuthMetrics(ctx, grantType, clientID, observability.StatusError, start)
		s.oauth2.WriteAccessError(ctx, w, ar, err)
		return
	}

	// Tokens are not issued or refreshed for a principal that is no longer
	// active, and its token family is revoked.
	if err := s.requireActiveSubject(ctx, ar); err != nil {
		logger.Info("token request rejected", "grant_type", grantType, "client_id", clientID, oauthcore.ErrorAttr(ctx, logger, err))
		refusal := fosite.ErrInvalidGrant.WithHint("The principal is no longer active.")
		s.tokenRefused(ctx, r, grantType, clientID, "principal_inactive", refusal)
		s.recordAuthMetrics(ctx, grantType, clientID, observability.StatusError, start)
		s.oauth2.WriteAccessError(ctx, w, ar, refusal)
		return
	}

	// Nor for a managed principal and a client that no longer allows
	// managed principals.
	allowed, err := s.clientAllowsSubject(ctx, sessionSubject(ar.GetSession()), clientID)
	if err != nil {
		logger.Error("checking managed principal client", "grant_type", grantType, "client_id", clientID, "error", err)
		s.tokenRefused(ctx, r, grantType, clientID, "server_error", fosite.ErrServerError)
		s.recordAuthMetrics(ctx, grantType, clientID, observability.StatusError, start)
		s.oauth2.WriteAccessError(ctx, w, ar, fosite.ErrServerError.WithWrap(err))
		return
	}
	if !allowed {
		logger.Info("token request rejected: managed principal refused by client", "grant_type", grantType, "client_id", clientID)
		refusal := fosite.ErrInvalidGrant.WithHint("This application does not allow managed accounts.")
		s.tokenRefused(ctx, r, grantType, clientID, "managed_principal_refused", refusal)
		s.recordAuthMetrics(ctx, grantType, clientID, observability.StatusError, start)
		s.oauth2.WriteAccessError(ctx, w, ar, refusal)
		return
	}

	// Bound refresh-token rotation by the family's absolute lifetime.
	if err := s.applyTokenFamilyLifetime(ctx, ar); err != nil {
		logger.Info("token request rejected", "grant_type", grantType, "client_id", clientID, oauthcore.ErrorAttr(ctx, logger, err))
		s.tokenRefused(ctx, r, grantType, clientID, "token_family_lifetime", err)
		s.recordAuthMetrics(ctx, grantType, clientID, observability.StatusError, start)
		s.oauth2.WriteAccessError(ctx, w, ar, err)
		return
	}

	// Grant the requested scopes
	for _, scope := range ar.GetRequestedScopes() {
		ar.GrantScope(scope)
	}
	if err := s.prepareAccessClaims(ctx, ar); err != nil {
		logger.Error("reading organizations for the access token", "grant_type", grantType, "client_id", clientID, "error", err)
		s.tokenRefused(ctx, r, grantType, clientID, "server_error", fosite.ErrServerError)
		s.recordAuthMetrics(ctx, grantType, clientID, observability.StatusError, start)
		s.oauth2.WriteAccessError(ctx, w, ar, fosite.ErrServerError.WithWrap(err))
		return
	}

	// Create the token response
	response, err := s.oauth2.NewAccessResponse(ctx, ar)
	if errors.Is(err, fosite.ErrInvalidatedAuthorizeCode) {
		// A concurrent exchange of the same code won at the storage's
		// conditional update. Fosite reports any invalidation failure as a
		// server error; this one is the client's replayed code.
		err = fosite.ErrInvalidGrant.WithHint(codeReusedHint)
		s.codeReused(ctx, grantType, clientID, false)
	}
	if err != nil {
		logger.Warn("token response failed",
			"grant_type", grantType,
			"client_id", clientID,
			oauthcore.ErrorAttr(ctx, logger, err),
		)
		s.tokenRefused(ctx, r, grantType, clientID, "response_failed", err)
		s.recordAuthMetrics(ctx, grantType, clientID, observability.StatusError, start)
		s.oauth2.WriteAccessError(ctx, w, ar, err)
		return
	}
	if sess, ok := ar.GetSession().(*Session); ok {
		response.SetTokenType(sess.TokenType())
		s.recordJWTBearerUse(ctx, r, sess)
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
		s.tokenFamilyRevoked(ctx, ar.GetID(), sessionSubject(sess), requesterClientID(ar), "token_family_lifetime")
		return fosite.ErrInvalidGrant.WithHint("The refresh token family exceeded its absolute lifetime; sign in again.")
	}
	if exp := sess.GetExpiresAt(fosite.RefreshToken); exp.IsZero() || exp.After(deadline) {
		sess.SetExpiresAt(fosite.RefreshToken, deadline)
	}
	return nil
}

// authTime returns when the end-user authenticated: the start of the
// SystemAuth login session when social login is on, otherwise now (the
// SessionProvider authenticated the request just now).
func (s *Server) authTime(r *http.Request) time.Time {
	if s.social != nil {
		if sess, err := s.social.currentSession(r); err == nil {
			return sess.CreatedAt.UTC().Truncate(time.Second)
		}
	}
	return time.Now().UTC().Truncate(time.Second)
}

// prepareAccessClaims sets the per-issuance claims of JWT access tokens:
// a subject (the client itself for client_credentials), client_id, a
// fresh issued-at time, and the at+jwt header. For a principal it also sets the compact orgs claim
// and, so that a refresh carries current organizations and roles rather
// than those of the original login, refreshes the orgs claim of the ID
// token the session will issue.
func (s *Server) prepareAccessClaims(ctx context.Context, ar fosite.AccessRequester) error {
	sess, ok := ar.GetSession().(*Session)
	if !ok || sess.DefaultSession == nil {
		return nil
	}
	clientID := ar.GetClient().GetID()
	claims := sess.AccessClaims
	if claims == nil {
		claims = &jwt.JWTClaims{}
		sess.AccessClaims = claims
	}
	claims.Subject = sessionSubject(sess)
	if claims.Subject == "" {
		claims.Subject = clientID
	}
	claims.IssuedAt = time.Time{}
	claims.NotBefore = time.Time{}
	claims.JTI = ""
	claims.Add("client_id", clientID)
	if sess.PrincipalType != "" {
		claims.Add(PrincipalTypeClaim, sess.PrincipalType)
	}
	oauthcore.SetConfirmationClaim(sess.DPoPJKT, claims)
	// Always reset the header: a session stored before access tokens were
	// typed, or before a key rotation, must not keep its old header.
	sess.AccessHeader = s.accessTokenHeaders()
	return s.setOrgsClaims(ctx, sess, claims)
}

// setOrgsClaims puts the orgs claim into the access-token claims (compact)
// and the ID-token claims (full) of a principal's session.
func (s *Server) setOrgsClaims(ctx context.Context, sess *Session, access *jwt.JWTClaims) error {
	if s.orgs == nil {
		return nil
	}
	id, ok := principalSubject(access.Subject)
	if !ok {
		return nil
	}
	compact, err := s.OrgsClaim(ctx, id, true)
	if err != nil {
		return err
	}
	access.Add(OrgsClaim, compact.Orgs)
	access.Add(OrgsTruncatedClaim, compact.Truncated)
	if idc := sess.IDTokenClaims(); idc != nil {
		full, err := s.OrgsClaim(ctx, id, false)
		if err != nil {
			return err
		}
		if idc.Extra == nil {
			idc.Extra = map[string]interface{}{}
		}
		idc.Extra[OrgsClaim] = full.Orgs
		idc.Extra[OrgsTruncatedClaim] = full.Truncated
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

	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if !AuthorizeIntrospectionCaller(r,
		func(id string) (bool, bool) {
			c, err := s.storage.GetClientByID(ctx, id)
			if err != nil {
				return false, false
			}
			return true, c.IsPublic()
		},
		func(string) []string {
			// The caller's own token is checked as at any resource: a
			// DPoP-bound one needs the DPoP scheme and a proof by its key.
			ar, authErr := s.authenticateAccessToken(r, s.endpointURL("/oauth/introspect"))
			if authErr != nil {
				return nil
			}
			return ar.GetGrantedScopes()
		}) {
		if s.observability != nil {
			s.observability.RecordTokenValidation(ctx, observability.ResultInvalid)
		}
		writeIntrospectionUnauthorized(w)
		return
	}

	session := s.Session("")

	// Fosite reads only the Bearer scheme; a DPoP caller's token and proof
	// were checked above, so hand it the token as Bearer.
	if scheme, token := oauthcore.AccessTokenCredentials(r); scheme == "dpop" {
		r = r.Clone(ctx)
		r.Header.Set("Authorization", "Bearer "+token)
	}
	ir, err := s.oauth2.NewIntrospectionRequest(ctx, r, session)
	if err == nil && ir.IsActive() {
		// A token of a principal that is no longer active is inactive.
		err = s.requireActiveSubject(ctx, ir.GetAccessRequester())
	}
	if err != nil {
		// Introspection MUST return 200 even for invalid tokens
		if s.observability != nil {
			s.observability.RecordTokenValidation(ctx, observability.ResultInvalid)
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"active": false,
		}); err != nil {
			LoggerFromContext(ctx).ErrorContext(ctx, "writing introspection response", "error", err)
		}
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
	s.tokenRevoked(ctx, r, err)
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
