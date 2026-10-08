package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/ory/fosite"
)

// registerFositeEndpoints registers OAuth endpoints that use Fosite directly.
// We register Huma operations for OpenAPI documentation, then use middleware
// to intercept requests and delegate to Fosite before Huma processes them.
func (a *API) registerFositeEndpoints() {
	// The Fosite interceptor is installed in NewAPI: chi requires every
	// middleware to be added before any route.

	// Register Huma operations for OpenAPI documentation
	a.registerFositeOpenAPI()
}

// fositeInterceptor intercepts OAuth requests and delegates to Fosite handlers.
// This runs before Huma processes the request, allowing Fosite to handle
// the full request/response lifecycle.
func (a *API) fositeInterceptor(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/authorize":
			a.authorizeEndpoint(w, r)
			return
		case "/oauth/token":
			if r.Method == http.MethodPost {
				a.tokenEndpoint(w, r)
				return
			}
		case "/oauth/introspect":
			if r.Method == http.MethodPost {
				a.introspectionEndpoint(w, r)
				return
			}
		case "/oauth/revoke":
			if r.Method == http.MethodPost {
				a.revocationEndpoint(w, r)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// registerFositeOpenAPI registers Huma operations for OpenAPI documentation.
// These handlers are never called because the middleware intercepts first.
func (a *API) registerFositeOpenAPI() {
	// Authorization endpoint (GET and POST)
	huma.Register(a.huma, huma.Operation{
		OperationID:   "authorize",
		Method:        http.MethodGet,
		Path:          "/oauth/authorize",
		Summary:       "OAuth 2.0 Authorization Endpoint",
		Description:   "Initiates the authorization flow. Redirects to login if not authenticated, then to consent, and finally back to the client with an authorization code or token.",
		Tags:          []string{"OAuth"},
		DefaultStatus: http.StatusFound,
	}, a.authorizeOpenAPI)

	huma.Register(a.huma, huma.Operation{
		OperationID:   "authorizePost",
		Method:        http.MethodPost,
		Path:          "/oauth/authorize",
		Summary:       "OAuth 2.0 Authorization Endpoint (POST)",
		Description:   "Handles authorization form submission (consent approval).",
		Tags:          []string{"OAuth"},
		DefaultStatus: http.StatusFound,
	}, a.authorizeOpenAPI)

	// Token endpoint
	huma.Register(a.huma, huma.Operation{
		OperationID:   "token",
		Method:        http.MethodPost,
		Path:          "/oauth/token",
		Summary:       "OAuth 2.0 Token Endpoint",
		Description:   "Exchanges authorization codes for tokens, refreshes tokens, or issues tokens for client credentials.",
		Tags:          []string{"OAuth"},
		DefaultStatus: http.StatusOK,
	}, a.tokenOpenAPI)

	// Introspection endpoint
	huma.Register(a.huma, huma.Operation{
		OperationID:   "introspect",
		Method:        http.MethodPost,
		Path:          "/oauth/introspect",
		Summary:       "OAuth 2.0 Token Introspection",
		Description:   "Returns metadata about a token, including whether it is active (RFC 7662).",
		Tags:          []string{"OAuth"},
		DefaultStatus: http.StatusOK,
	}, a.introspectOpenAPI)

	// Revocation endpoint
	huma.Register(a.huma, huma.Operation{
		OperationID:   "revoke",
		Method:        http.MethodPost,
		Path:          "/oauth/revoke",
		Summary:       "OAuth 2.0 Token Revocation",
		Description:   "Revokes an access token or refresh token (RFC 7009).",
		Tags:          []string{"OAuth"},
		DefaultStatus: http.StatusOK,
	}, a.revokeOpenAPI)
}

// OpenAPI handler stubs - these are never called due to middleware interception,
// but define the request/response types for OpenAPI documentation.

func (a *API) authorizeOpenAPI(ctx context.Context, input *AuthorizeInput) (*AuthorizeOutput, error) {
	// Never called - intercepted by fositeInterceptor
	return &AuthorizeOutput{}, nil
}

func (a *API) tokenOpenAPI(ctx context.Context, input *TokenInput) (*TokenOutput, error) {
	// Never called - intercepted by fositeInterceptor
	return &TokenOutput{}, nil
}

func (a *API) introspectOpenAPI(ctx context.Context, input *IntrospectInput) (*IntrospectOutput, error) {
	// Never called - intercepted by fositeInterceptor
	return &IntrospectOutput{}, nil
}

func (a *API) revokeOpenAPI(ctx context.Context, input *RevokeInput) (*RevokeOutput, error) {
	// Never called - intercepted by fositeInterceptor
	return &RevokeOutput{}, nil
}

// Actual Fosite handlers

// authorizeEndpoint handles GET/POST /oauth/authorize.
// This is where the authorization flow begins.
func (a *API) authorizeEndpoint(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := LoggerFromContext(ctx)
	oauth2 := a.provider.OAuth2Provider()

	// Parse the authorization request
	ar, err := oauth2.NewAuthorizeRequest(ctx, r)
	if err != nil {
		logger.Warn("authorize request failed", "error", err)
		oauth2.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	logger.Debug("authorize request", "client_id", ar.GetClient().GetID(), "scopes", ar.GetRequestedScopes())

	// Who is the user? Without an authenticator the server cannot tell,
	// and must not guess.
	if a.authenticate == nil {
		logger.Error("authorize request refused: no user authenticator configured (see WithUserAuthenticator)")
		oauth2.WriteAuthorizeError(ctx, w, ar, fosite.ErrServerError.WithHint("The server has no way to authenticate users."))
		return
	}
	userID := a.authenticate(r)
	if userID == "" {
		if a.loginURL == "" {
			oauth2.WriteAuthorizeError(ctx, w, ar, fosite.ErrLoginRequired)
			return
		}
		//nolint:gosec // G710: the target is the configured login URL; the return address is query-escaped
		http.Redirect(w, r, appendQueryParam(a.loginURL, "redirect", r.URL.RequestURI()), http.StatusFound)
		return
	}

	// Consent: first-party clients act for the user by design; any other
	// client needs the user's recorded consent.
	if !isFirstParty(ar.GetClient()) {
		if a.consent == nil {
			oauth2.WriteAuthorizeError(ctx, w, ar, fosite.ErrAccessDenied.WithHint("Consent is required and the server has no way to record it."))
			return
		}
		ok, err := a.consent(ctx, userID, ar.GetClient(), ar.GetRequestedScopes())
		if err != nil {
			logger.Error("checking consent", "client_id", ar.GetClient().GetID(), "error", err)
			oauth2.WriteAuthorizeError(ctx, w, ar, fosite.ErrServerError.WithWrap(err))
			return
		}
		if !ok {
			oauth2.WriteAuthorizeError(ctx, w, ar, fosite.ErrConsentRequired)
			return
		}
	}

	// Create session for the user
	session := a.provider.Session(userID)

	// Grant the requested scopes; Fosite already limited them to the
	// client's registered scopes.
	for _, scope := range ar.GetRequestedScopes() {
		ar.GrantScope(scope)
	}

	// Create the authorization response
	response, err := oauth2.NewAuthorizeResponse(ctx, ar, session)
	if err != nil {
		oauth2.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	// Write the response (redirect with code)
	oauth2.WriteAuthorizeResponse(ctx, w, ar, response)
}

// tokenEndpoint handles POST /oauth/token.
// This handles all token grant types.
func (a *API) tokenEndpoint(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := LoggerFromContext(ctx)
	oauth2 := a.provider.OAuth2Provider()

	// Limit request body size to prevent memory exhaustion (1MB max for token requests)
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	// Create session (will be populated by the grant handler)
	session := a.provider.Session("")
	grantType := r.FormValue("grant_type")
	logger.Debug("token request", "grant_type", grantType)

	// Process the token request
	ar, err := oauth2.NewAccessRequest(ctx, r, session)
	if err != nil {
		logger.Warn("token request failed", "grant_type", grantType, "error", err)
		oauth2.WriteAccessError(ctx, w, ar, err)
		return
	}

	clientID := ar.GetClient().GetID()

	// Grant the requested scopes (Fosite has already validated them for this request)
	for _, scope := range ar.GetRequestedScopes() {
		ar.GrantScope(scope)
	}

	// Create the token response
	response, err := oauth2.NewAccessResponse(ctx, ar)
	if err != nil {
		logger.Warn("token response failed", "grant_type", grantType, "client_id", clientID, "error", err)
		oauth2.WriteAccessError(ctx, w, ar, err)
		return
	}

	logger.Info("token issued", "grant_type", grantType, "client_id", clientID, "scopes", ar.GetGrantedScopes())

	// Write the response
	oauth2.WriteAccessResponse(ctx, w, ar, response)
}

// introspectionEndpoint handles POST /oauth/introspect.
// This allows resource servers to validate tokens.
func (a *API) introspectionEndpoint(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	oauth2 := a.provider.OAuth2Provider()

	session := a.provider.Session("")

	ir, err := oauth2.NewIntrospectionRequest(ctx, r, session)
	if err != nil {
		// Introspection MUST return 200 even for invalid tokens
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"active": false,
		})
		return
	}

	oauth2.WriteIntrospectionResponse(ctx, w, ir)
}

// revocationEndpoint handles POST /oauth/revoke.
// This allows clients to revoke tokens.
func (a *API) revocationEndpoint(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	oauth2 := a.provider.OAuth2Provider()

	err := oauth2.NewRevocationRequest(ctx, r)
	if err != nil {
		oauth2.WriteRevocationResponse(ctx, w, err)
		return
	}

	oauth2.WriteRevocationResponse(ctx, w, nil)
}

// isFirstParty reports whether the client is one the operator runs.
func isFirstParty(c fosite.Client) bool {
	client, ok := c.(*Client)
	return ok && client.app.FirstParty
}

// appendQueryParam appends key=value, query-escaped, to base, which may
// already carry a query string.
func appendQueryParam(base, key, value string) string {
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	return base + sep + url.QueryEscape(key) + "=" + url.QueryEscape(value)
}
