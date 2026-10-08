package bff

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/grokify/goauth/dpop"
)

// RefreshConfig contains configuration for the token refresh handler.
type RefreshConfig struct {
	// Store is the session store.
	Store Store

	// CookieManager handles session cookies.
	CookieManager *CookieManager

	// TokenEndpoint is the OAuth token endpoint URL.
	TokenEndpoint string

	// ClientID is the OAuth client ID.
	ClientID string

	// ClientSecret is the OAuth client secret (optional for public clients).
	ClientSecret string //nolint:gosec // G117: config field, not a hardcoded secret

	// UseDPoP enables DPoP for token refresh requests.
	// When true, generates a new DPoP key pair and binds the new tokens to it.
	// Default: true.
	UseDPoP bool

	// Client is the HTTP client to use for refresh requests.
	// If nil, uses http.DefaultClient.
	Client *http.Client

	// Timeout is the refresh request timeout.
	// Default: 30 seconds.
	Timeout time.Duration

	// RefreshThreshold is how early before expiry to refresh tokens.
	// Default: 5 minutes.
	RefreshThreshold time.Duration

	// OnRefreshSuccess is called when tokens are successfully refreshed.
	OnRefreshSuccess func(ctx context.Context, session *Session)

	// OnRefreshError is called when token refresh fails.
	OnRefreshError func(w http.ResponseWriter, r *http.Request, err error)

	// ParseTokenResponse allows custom parsing of the token response.
	// If nil, uses the default OAuth2 token response format.
	ParseTokenResponse func(body []byte) (*TokenResponse, error)
}

// DefaultRefreshConfig returns default refresh configuration.
func DefaultRefreshConfig() RefreshConfig {
	return RefreshConfig{
		UseDPoP:          true,
		Timeout:          30 * time.Second,
		RefreshThreshold: 5 * time.Minute,
	}
}

// TokenResponse represents the OAuth2 token response.
//
//nolint:gosec // G117: struct fields for OAuth protocol response, not hardcoded secrets
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// TokenErrorResponse represents an OAuth2 error response.
type TokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// Refresher handles automatic token refresh.
type Refresher struct {
	config RefreshConfig
	client *http.Client
	locks  keyedLocker
}

// keyedLocker serializes work per key and forgets a key once nobody holds or
// awaits it.
type keyedLocker struct {
	mu      sync.Mutex
	entries map[string]*lockEntry
}

type lockEntry struct {
	mu   sync.Mutex
	refs int
}

// lock blocks until the caller holds key, and returns the function that
// releases it.
func (k *keyedLocker) lock(key string) (unlock func()) {
	k.mu.Lock()
	if k.entries == nil {
		k.entries = make(map[string]*lockEntry)
	}
	e, ok := k.entries[key]
	if !ok {
		e = &lockEntry{}
		k.entries[key] = e
	}
	e.refs++
	k.mu.Unlock()

	e.mu.Lock()
	return func() {
		e.mu.Unlock()
		k.mu.Lock()
		e.refs--
		if e.refs == 0 {
			delete(k.entries, key)
		}
		k.mu.Unlock()
	}
}

// ErrRefreshFailed is returned when token refresh fails.
var ErrRefreshFailed = errors.New("token refresh failed")

// ErrRefreshTokenExpired is returned when the refresh token has expired.
var ErrRefreshTokenExpired = errors.New("refresh token expired")

// ErrTokenEndpointRequired is returned when the token endpoint is not configured.
var ErrTokenEndpointRequired = errors.New("token endpoint required")

// NewRefresher creates a new token refresher.
func NewRefresher(config RefreshConfig) (*Refresher, error) {
	if config.TokenEndpoint == "" {
		return nil, ErrTokenEndpointRequired
	}

	client := config.Client
	if client == nil {
		client = &http.Client{
			Timeout: config.Timeout,
		}
	}

	return &Refresher{
		config: config,
		client: client,
	}, nil
}

// Middleware returns HTTP middleware that automatically refreshes expired access tokens.
func (r *Refresher) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			session := GetSession(req.Context())
			if session == nil {
				next.ServeHTTP(w, req)
				return
			}

			// Check if access token needs refresh
			if session.NeedsRefresh(r.config.RefreshThreshold) {
				// Attempt to refresh
				err := r.RefreshSession(req.Context(), session)
				if err != nil {
					// If refresh fails and token is expired, handle error
					if session.IsAccessTokenExpired() {
						r.handleRefreshError(w, req, err)
						return
					}
					// Otherwise continue with current token (it's still valid)
				}
			}

			next.ServeHTTP(w, req)
		})
	}
}

// RefreshSession refreshes the tokens for a session.
//
// Refreshes for one session are serialized within this process. Without that,
// concurrent requests each spend the same refresh token; the token endpoint
// rotates it on the first and then treats the rest as reuse of a stolen token
// and revokes the session. The session is re-read once the lock is held, so a
// request that waited adopts the tokens the first one obtained instead of
// refreshing again. Across several instances the token endpoint's reuse
// detection still applies, so keep a session's requests on one instance or
// share a lock through the Store.
func (r *Refresher) RefreshSession(ctx context.Context, session *Session) error {
	if r.config.Store != nil && session.ID != "" {
		unlock := r.locks.lock(session.ID)
		defer unlock()

		fresh, err := r.config.Store.Get(ctx, session.ID)
		if err != nil {
			return fmt.Errorf("reload session: %w", err)
		}
		// A different refresh token means another request already refreshed
		// while this one waited: adopt its result rather than spend a token
		// that has been rotated away.
		rotated := fresh.RefreshToken != session.RefreshToken
		*session = *fresh
		if rotated {
			return nil
		}
	}

	// Check if refresh token is expired
	if session.IsRefreshTokenExpired() {
		return ErrRefreshTokenExpired
	}

	// Generate new DPoP key pair if enabled
	var newKeyPair *dpop.KeyPair
	var dpopProof string
	if r.config.UseDPoP {
		var err error
		newKeyPair, err = dpop.GenerateKeyPair()
		if err != nil {
			return fmt.Errorf("generate DPoP key pair: %w", err)
		}

		// Create DPoP proof for the token request
		dpopProof, err = dpop.CreateProof(newKeyPair, "POST", r.config.TokenEndpoint)
		if err != nil {
			return fmt.Errorf("create DPoP proof: %w", err)
		}
	}

	// Build refresh request
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", session.RefreshToken)
	data.Set("client_id", r.config.ClientID)
	if r.config.ClientSecret != "" {
		data.Set("client_secret", r.config.ClientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", r.config.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if dpopProof != "" {
		req.Header.Set("DPoP", dpopProof)
	}

	// Send request
	resp, err := r.client.Do(req) //nolint:gosec // G704: request to configured token endpoint URL
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	// Handle error response
	if resp.StatusCode != http.StatusOK {
		var errResp TokenErrorResponse
		if err := json.Unmarshal(body, &errResp); err == nil && errResp.Error != "" {
			return fmt.Errorf("%w: %s - %s", ErrRefreshFailed, errResp.Error, errResp.ErrorDescription)
		}
		return fmt.Errorf("%w: status %d", ErrRefreshFailed, resp.StatusCode)
	}

	// Parse token response
	var tokenResp *TokenResponse
	if r.config.ParseTokenResponse != nil {
		tokenResp, err = r.config.ParseTokenResponse(body)
	} else {
		tokenResp, err = parseDefaultTokenResponse(body)
	}
	if err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	// Update session with new tokens
	now := time.Now()
	session.AccessToken = tokenResp.AccessToken
	session.AccessTokenExpiresAt = now.Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	session.UpdatedAt = now

	// Update refresh token if a new one was issued
	if tokenResp.RefreshToken != "" {
		session.RefreshToken = tokenResp.RefreshToken
		// Note: Refresh token expiry is typically not returned; keep existing or estimate
	}

	// Update DPoP key pair if we generated a new one
	if newKeyPair != nil {
		if err := session.SetDPoPKeyPair(newKeyPair); err != nil {
			return fmt.Errorf("set DPoP key pair: %w", err)
		}
	}

	// Save updated session
	if r.config.Store != nil {
		if err := r.config.Store.Update(ctx, session); err != nil {
			return fmt.Errorf("update session: %w", err)
		}
	}

	// Call success hook
	if r.config.OnRefreshSuccess != nil {
		r.config.OnRefreshSuccess(ctx, session)
	}

	return nil
}

// handleRefreshError handles token refresh errors.
func (r *Refresher) handleRefreshError(w http.ResponseWriter, req *http.Request, err error) {
	if r.config.OnRefreshError != nil {
		r.config.OnRefreshError(w, req, err)
		return
	}

	// Default: clear session and return 401
	if r.config.CookieManager != nil {
		r.config.CookieManager.ClearSessionCookie(w)
	}
	http.Error(w, "Unauthorized: Token refresh failed", http.StatusUnauthorized)
}

// parseDefaultTokenResponse parses a standard OAuth2 token response.
func parseDefaultTokenResponse(body []byte) (*TokenResponse, error) {
	var resp TokenResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	if resp.AccessToken == "" {
		return nil, errors.New("missing access_token in response")
	}
	return &resp, nil
}

// RefreshHandler returns an HTTP handler for explicit token refresh requests.
// This can be used by the frontend to proactively refresh tokens.
func RefreshHandler(config RefreshConfig) http.Handler {
	refresher, err := NewRefresher(config)
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Refresh not configured", http.StatusInternalServerError)
		})
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		session := GetSession(r.Context())
		if session == nil {
			http.Error(w, "Unauthorized: No session", http.StatusUnauthorized)
			return
		}

		err := refresher.RefreshSession(r.Context(), session)
		if err != nil {
			if errors.Is(err, ErrRefreshTokenExpired) {
				// Clear session on refresh token expiry
				if config.CookieManager != nil {
					config.CookieManager.ClearSessionCookie(w)
				}
				http.Error(w, "Unauthorized: Session expired", http.StatusUnauthorized)
				return
			}
			http.Error(w, "Token refresh failed", http.StatusInternalServerError)
			return
		}

		// Return success with new expiry info
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success":    true,
			"expires_at": session.AccessTokenExpiresAt.Unix(),
		})
	})
}

// AutoRefreshMiddleware creates middleware that automatically refreshes tokens before expiry.
func AutoRefreshMiddleware(config RefreshConfig) (func(http.Handler) http.Handler, error) {
	refresher, err := NewRefresher(config)
	if err != nil {
		return nil, err
	}
	return refresher.Middleware(), nil
}
