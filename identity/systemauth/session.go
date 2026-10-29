package systemauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
	"github.com/plexusone/systemforge/session/clientaddr"
)

// SessionProvider handles user authentication and consent for the authorization flow.
// Implement this interface to integrate with your authentication system.
//
// The user IDs it returns are principal IDs (ADR-004): they become the
// subject of the tokens SystemAuth issues, and a token whose subject is
// not an active principal in the server's Storage is refused (see
// PrincipalStatus). A provider backed by another user store must map its
// users to principals rather than return its own IDs.
type SessionProvider interface {
	// GetAuthenticatedUser returns the principal ID of the authenticated
	// user, or an empty string if the user is not authenticated.
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

// RequestGate decides whether a request may be believed when it carries
// identity in a header. Headers are written by the client unless a proxy
// in front of the server overwrites them, so identity read from one is
// only as trustworthy as the gate that admits the request.
type RequestGate func(r *http.Request) bool

// TrustAllRequests is a RequestGate that admits every request. Use it only
// when the server cannot be reached except through a proxy that removes
// the identity header from client requests and sets it itself; otherwise
// any client can sign in as anyone by sending the header.
func TrustAllRequests(*http.Request) bool { return true }

// TrustedProxyNetworks returns a RequestGate that admits requests whose
// direct peer address (r.RemoteAddr, never a forwarded-for header) is in
// one of the networks, such as the load balancer's, given in CIDR
// notation or as single addresses. It matches peers as clientaddr does.
func TrustedProxyNetworks(cidrs ...string) (RequestGate, error) {
	if len(cidrs) == 0 {
		return nil, errors.New("systemauth: no trusted proxy networks given")
	}
	res, err := clientaddr.New(clientaddr.Config{TrustedProxies: cidrs})
	if err != nil {
		return nil, fmt.Errorf("systemauth: %w", err)
	}
	return res.TrustsPeer, nil
}

// DefaultSessionProvider is a minimal session provider. It authenticates
// nobody unless configured with WithTrustedUserIDHeader, so by default
// every authorization request is sent to the login URL. For a real
// deployment configure social login, supply your own SessionProvider, or
// trust a header written by your gateway.
type DefaultSessionProvider struct {
	// loginURL is the URL to redirect unauthenticated users to.
	loginURL string

	// consentURL is the URL to redirect users for consent approval.
	consentURL string

	// trustedHeader is the header a trusted gateway sets to the
	// authenticated user ID; empty means no header is trusted.
	trustedHeader string

	// gate admits the requests whose trustedHeader is believed.
	gate RequestGate

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

// WithTrustedUserIDHeader makes the provider authenticate requests as the
// user named in header, for a gateway that authenticates users and
// forwards the result (a backend-for-frontend). Only requests the gate
// admits are believed: pass TrustedProxyNetworks for the gateway's
// addresses, or TrustAllRequests when the server is reachable only
// through a gateway that overwrites the header. A nil gate or an empty
// header trusts nothing.
func WithTrustedUserIDHeader(header string, gate RequestGate) DefaultSessionProviderOption {
	return func(p *DefaultSessionProvider) {
		p.trustedHeader = header
		p.gate = gate
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
		loginURL:    "/login",
		consentURL:  "/consent",
		skipConsent: false,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// GetAuthenticatedUser returns the user ID from the trusted header when
// one is configured and the request passes the gate, and "" otherwise.
func (p *DefaultSessionProvider) GetAuthenticatedUser(r *http.Request) string {
	if !p.trustsHeader(r) {
		return ""
	}
	return strings.TrimSpace(r.Header.Get(p.trustedHeader))
}

// trustsHeader reports whether the request's identity header is believed.
func (p *DefaultSessionProvider) trustsHeader(r *http.Request) bool {
	return p.trustedHeader != "" && p.gate != nil && p.gate(r)
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
		AccessHeader: s.accessTokenHeaders(),
	}
}
