package systemauth

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
)

// SessionProvider handles user authentication and consent for the authorization flow.
// Implement this interface to integrate with your authentication system.
type SessionProvider interface {
	// GetAuthenticatedUser returns the authenticated user ID from the request.
	// Returns empty string if the user is not authenticated.
	GetAuthenticatedUser(r *http.Request) string

	// RedirectToLogin returns the URL to redirect unauthenticated users to.
	// The returnURL is the original authorization request URL to return to after login.
	RedirectToLogin(returnURL string) string

	// HasConsent checks if the user has already granted consent for the client and scopes.
	// Returns true if consent exists and is still valid.
	HasConsent(ctx context.Context, userID, clientID string, scopes []string) bool

	// RedirectToConsent returns the URL to redirect users for consent approval.
	// The returnURL is the original authorization request URL to return to after consent.
	RedirectToConsent(returnURL string) string

	// SaveConsent records that the user has granted consent for the client and scopes.
	SaveConsent(ctx context.Context, userID, clientID string, scopes []string) error

	// GetUserClaims returns additional claims to include in the ID token.
	// Common claims: name, email, picture, etc.
	GetUserClaims(ctx context.Context, userID string, scopes []string) map[string]interface{}
}

// DefaultSessionProvider provides a basic session provider for testing.
// In production, implement SessionProvider with your authentication system.
type DefaultSessionProvider struct {
	// loginURL is the URL to redirect unauthenticated users to.
	loginURL string

	// consentURL is the URL to redirect users for consent approval.
	consentURL string

	// userIDHeader is the header containing the authenticated user ID.
	// Useful for BFF (Backend for Frontend) patterns where a gateway handles auth.
	userIDHeader string

	// skipConsent when true, automatically grants all requested scopes.
	// Useful for first-party applications.
	skipConsent bool
}

// DefaultSessionProviderOption configures a DefaultSessionProvider.
type DefaultSessionProviderOption func(*DefaultSessionProvider)

// WithLoginURL sets the login redirect URL.
func WithLoginURL(url string) DefaultSessionProviderOption {
	return func(p *DefaultSessionProvider) {
		p.loginURL = url
	}
}

// WithConsentURL sets the consent redirect URL.
func WithConsentURL(url string) DefaultSessionProviderOption {
	return func(p *DefaultSessionProvider) {
		p.consentURL = url
	}
}

// WithUserIDHeader sets the header to read user ID from.
// Default is "X-User-ID".
func WithUserIDHeader(header string) DefaultSessionProviderOption {
	return func(p *DefaultSessionProvider) {
		p.userIDHeader = header
	}
}

// WithSkipConsent enables automatic consent for all requests.
func WithSkipConsent(skip bool) DefaultSessionProviderOption {
	return func(p *DefaultSessionProvider) {
		p.skipConsent = skip
	}
}

// NewDefaultSessionProvider creates a default session provider.
func NewDefaultSessionProvider(opts ...DefaultSessionProviderOption) *DefaultSessionProvider {
	p := &DefaultSessionProvider{
		loginURL:     "/login",
		consentURL:   "/consent",
		userIDHeader: "X-User-ID",
		skipConsent:  false,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// GetAuthenticatedUser returns the user ID from the configured header.
func (p *DefaultSessionProvider) GetAuthenticatedUser(r *http.Request) string {
	return r.Header.Get(p.userIDHeader)
}

// RedirectToLogin returns the login URL with the return URL as a
// query-escaped redirect parameter.
func (p *DefaultSessionProvider) RedirectToLogin(returnURL string) string {
	return appendQueryParam(p.loginURL, "redirect", returnURL)
}

// appendQueryParam appends key=value (query-escaped) to base, which may
// already carry a query string.
func appendQueryParam(base, key, value string) string {
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	return base + sep + url.QueryEscape(key) + "=" + url.QueryEscape(value)
}

// HasConsent always returns the value of skipConsent.
// Override this in production to check actual consent records.
func (p *DefaultSessionProvider) HasConsent(_ context.Context, _, _ string, _ []string) bool {
	return p.skipConsent
}

// RedirectToConsent returns the consent URL with return URL parameter.
func (p *DefaultSessionProvider) RedirectToConsent(returnURL string) string {
	return appendQueryParam(p.consentURL, "redirect", returnURL)
}

// SaveConsent is a no-op in the default provider.
// Override this in production to persist consent records.
func (p *DefaultSessionProvider) SaveConsent(_ context.Context, _, _ string, _ []string) error {
	return nil
}

// GetUserClaims returns an empty map.
// Override this in production to return actual user claims.
func (p *DefaultSessionProvider) GetUserClaims(_ context.Context, userID string, _ []string) map[string]interface{} {
	return map[string]interface{}{
		"sub": userID,
	}
}

// Ensure DefaultSessionProvider implements SessionProvider.
var _ SessionProvider = (*DefaultSessionProvider)(nil)

// AuthorizationSession holds the session data for an authorization request.
// This can be stored in a session store to persist across redirects.
type AuthorizationSession struct {
	// RequestID uniquely identifies this authorization request.
	RequestID string `json:"request_id"`

	// ClientID is the OAuth client requesting authorization.
	ClientID string `json:"client_id"`

	// RedirectURI is the client's callback URL.
	RedirectURI string `json:"redirect_uri"`

	// Scopes requested by the client.
	Scopes []string `json:"scopes"`

	// State is the client's CSRF token.
	State string `json:"state"`

	// Nonce is the OpenID Connect nonce for replay protection.
	Nonce string `json:"nonce,omitempty"`

	// CodeChallenge is the PKCE code challenge.
	CodeChallenge string `json:"code_challenge,omitempty"`

	// CodeChallengeMethod is the PKCE challenge method.
	CodeChallengeMethod string `json:"code_challenge_method,omitempty"`

	// UserID is set after authentication.
	UserID string `json:"user_id,omitempty"`

	// ConsentGranted is set after user consents to scopes.
	ConsentGranted bool `json:"consent_granted"`

	// GrantedScopes are the scopes the user consented to.
	GrantedScopes []string `json:"granted_scopes,omitempty"`

	// CreatedAt is when this session was created.
	CreatedAt time.Time `json:"created_at"`

	// ExpiresAt is when this session expires.
	ExpiresAt time.Time `json:"expires_at"`
}

// IsExpired returns true if the session has expired.
func (s *AuthorizationSession) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// NewAuthorizationSession creates a new authorization session from a Fosite request.
func NewAuthorizationSession(ar fosite.AuthorizeRequester) *AuthorizationSession {
	form := ar.GetRequestForm()
	return &AuthorizationSession{
		RequestID:           ar.GetID(),
		ClientID:            ar.GetClient().GetID(),
		RedirectURI:         form.Get("redirect_uri"),
		Scopes:              ar.GetRequestedScopes(),
		State:               form.Get("state"),
		Nonce:               form.Get("nonce"),
		CodeChallenge:       form.Get("code_challenge"),
		CodeChallengeMethod: form.Get("code_challenge_method"),
		CreatedAt:           time.Now(),
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}
}

// OIDCSession creates an OpenID Connect session for Fosite.
func (s *Server) OIDCSession(subject string, claims map[string]interface{}) *Session {
	now := time.Now()

	// Build ID token claims
	idClaims := &jwt.IDTokenClaims{
		Issuer:    s.config.Issuer,
		Subject:   subject,
		IssuedAt:  now,
		ExpiresAt: now.Add(s.config.Tokens.IDTokenLifetime.Duration()),
		Extra:     claims,
	}

	// Add audience (the client ID will be added by Fosite)
	idClaims.Audience = []string{}

	return &Session{
		DefaultSession: &openid.DefaultSession{
			Claims:  idClaims,
			Headers: s.jwtHeaders(),
			Subject: subject,
		},
		AccessHeader: s.jwtHeaders(),
	}
}
