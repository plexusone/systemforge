package bff

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// HandlerConfig contains configuration for the BFF handler.
type HandlerConfig struct {
	// Store is the session store. Required.
	Store Store

	// CookieConfig configures session cookies.
	// If zero value, uses DefaultCookieConfig().
	CookieConfig CookieConfig

	// ProxyConfig configures the API proxy.
	// TargetURL is required if using the proxy.
	ProxyConfig ProxyConfig

	// AllowedOrigins is a list of allowed origins for CSRF protection.
	// Required for security. Example: ["https://myapp.com", "https://app.myapp.com"]
	AllowedOrigins []string

	// ClientIPConfig configures client IP extraction.
	// If zero value, uses DefaultClientIPConfig().
	ClientIPConfig ClientIPConfig

	// SessionIDGenerator generates session IDs.
	// If nil, uses GenerateSessionID().
	SessionIDGenerator func() (string, error)

	// OnCreateSession is called when a session is created.
	// Can be used to persist refresh tokens to a database.
	OnCreateSession func(ctx context.Context, session *Session) error

	// OnRefresh is called to refresh tokens.
	// Must return new access token, optional new refresh token, and expiry.
	// If nil, the /refresh endpoint returns 501 Not Implemented.
	OnRefresh func(ctx context.Context, session *Session) (*TokenRefreshResult, error)

	// OnLogout is called when a session is logged out, before it is
	// deleted. The BFF does not revoke tokens itself: set OnLogout to
	// revoke the refresh token (and access token, if supported) at the
	// authorization server. If it returns an error the session is still
	// deleted, but /logout responds 500.
	OnLogout func(ctx context.Context, session *Session) error

	// OnSessionLoad is called after a session is loaded from the store.
	// Can be used for logging or enriching session data.
	OnSessionLoad func(ctx context.Context, session *Session) error

	// BasePath is the base path for BFF routes.
	// Default: "" (routes at root of the mounted router).
	BasePath string

	// APIPathPrefix is the path prefix for proxied API requests.
	// Default: "/api".
	APIPathPrefix string

	// EnableProxyForPublicRoutes allows unauthenticated proxy requests.
	// When true, /api/* routes work without a session (for public APIs).
	// Default: false.
	EnableProxyForPublicRoutes bool

	// RateLimitConfig configures rate limiting for BFF endpoints.
	// If nil, rate limiting is disabled.
	RateLimitConfig *RateLimitConfig

	// IdleTimeout ends a session not used for this long. Zero means
	// DefaultIdleTimeout; a negative value disables the check.
	IdleTimeout time.Duration

	// MaxLifetime ends a session this long after it was created, however
	// often its tokens are refreshed, so the user must sign in again. The
	// session and cookie expiry never extend past it. Zero means
	// DefaultMaxLifetime; a negative value disables the check.
	MaxLifetime time.Duration
}

// TokenRefreshResult contains the result of a token refresh operation.
//
//nolint:gosec // G117: struct fields for OAuth tokens, not hardcoded secrets
type TokenRefreshResult struct {
	AccessToken           string
	RefreshToken          string // Optional: new refresh token
	AccessTokenExpiresIn  time.Duration
	RefreshTokenExpiresIn time.Duration // Optional: if new refresh token issued
}

// Handler provides BFF endpoints with built-in security.
type Handler struct {
	config          HandlerConfig
	store           Store
	cookieManager   *CookieManager
	proxy           *Proxy
	originValidator *OriginValidator
	ipExtractor     *ClientIPExtractor
	rateLimiter     *RateLimiter
}

// NewHandler creates a new BFF handler.
func NewHandler(config HandlerConfig) (*Handler, error) {
	if config.Store == nil {
		return nil, ErrStoreRequired
	}

	if len(config.AllowedOrigins) == 0 {
		return nil, ErrOriginsRequired
	}

	// Apply defaults
	cookieConfig := config.CookieConfig
	if cookieConfig.Name == "" {
		cookieConfig = DefaultCookieConfig()
	}

	clientIPConfig := config.ClientIPConfig
	if clientIPConfig.isZero() {
		clientIPConfig = DefaultClientIPConfig()
	}

	if config.APIPathPrefix == "" {
		config.APIPathPrefix = "/api"
	}
	config.IdleTimeout = resolveLifetimeLimit(config.IdleTimeout, DefaultIdleTimeout)
	config.MaxLifetime = resolveLifetimeLimit(config.MaxLifetime, DefaultMaxLifetime)

	// Create components
	cookieManager := NewCookieManager(cookieConfig)
	if err := cookieManager.Config().Validate(); err != nil {
		return nil, err
	}

	originValidator := NewOriginValidator(OriginConfig{
		AllowedOrigins: config.AllowedOrigins,
		CheckReferer:   true,
		// Allow missing origin for GET/HEAD (safe methods)
		SkipMethods: []string{"GET", "HEAD", "OPTIONS"},
	})

	ipExtractor := NewClientIPExtractor(clientIPConfig)

	// Create proxy if target URL is configured
	var proxy *Proxy
	if config.ProxyConfig.TargetURL != "" {
		var err error
		proxy, err = NewProxy(config.ProxyConfig)
		if err != nil {
			return nil, err
		}
	}

	// Create rate limiter if configured
	var rateLimiter *RateLimiter
	if config.RateLimitConfig != nil {
		rlc := *config.RateLimitConfig
		if rlc.ClientIPConfig.isZero() && !rlc.TrustCloudflare {
			// Limit by the same client address the sessions record.
			rlc.ClientIPConfig = clientIPConfig
		}
		rateLimiter = NewRateLimiter(rlc)
	}

	return &Handler{
		config:          config,
		store:           config.Store,
		cookieManager:   cookieManager,
		proxy:           proxy,
		originValidator: originValidator,
		ipExtractor:     ipExtractor,
		rateLimiter:     rateLimiter,
	}, nil
}

// Router returns a chi router with all BFF routes.
func (h *Handler) Router() chi.Router {
	r := chi.NewRouter()

	// Rate limiting (if configured)
	if h.rateLimiter != nil {
		r.Use(h.rateLimiter.Middleware())
	}

	// Origin validation for state-changing requests
	r.Use(h.originValidator.Middleware())

	// Session endpoints
	r.Get("/session", h.handleGetSession)
	r.Post("/logout", h.handleLogout)
	r.Post("/refresh", h.handleRefresh)

	// API proxy
	if h.proxy != nil {
		r.Route(h.config.APIPathPrefix, func(r chi.Router) {
			// Proxied requests carry the user's token whatever the method,
			// so reads are origin-checked too.
			r.Use(h.originValidator.SafeMethodMiddleware())
			r.Use(SessionMiddleware(MiddlewareConfig{
				Store:          h.store,
				CookieManager:  h.cookieManager,
				RequireSession: !h.config.EnableProxyForPublicRoutes,
				TouchOnAccess:  true,
				IdleTimeout:    h.lifetimeLimit(h.config.IdleTimeout),
				MaxLifetime:    h.lifetimeLimit(h.config.MaxLifetime),
			}))
			r.HandleFunc("/*", h.handleProxy)
		})
	}

	return r
}

// lifetimeLimit converts a resolved limit (0 = unchecked) back to the
// MiddlewareConfig convention (negative = unchecked).
func (h *Handler) lifetimeLimit(d time.Duration) time.Duration {
	if d == 0 {
		return -1
	}
	return d
}

// sessionLifetimeExceeded reports whether a loaded session has run past
// the handler's idle or absolute limit.
func (h *Handler) sessionLifetimeExceeded(session *Session) bool {
	return session.LifetimeExceeded(time.Now(), h.config.IdleTimeout, h.config.MaxLifetime)
}

// Store returns the session store.
func (h *Handler) Store() Store {
	return h.store
}

// CookieManager returns the cookie manager.
func (h *Handler) CookieManager() *CookieManager {
	return h.cookieManager
}

// CreateSession creates a new BFF session and sets the cookie.
// This is typically called after OAuth callback completes.
func (h *Handler) CreateSession(ctx context.Context, w http.ResponseWriter, r *http.Request, params CreateSessionParams) (*Session, error) {
	// Generate session ID
	var sessionID string
	var err error
	if h.config.SessionIDGenerator != nil {
		sessionID, err = h.config.SessionIDGenerator()
	} else {
		sessionID, err = GenerateSessionID()
	}
	if err != nil {
		return nil, err
	}

	now := time.Now()
	session := &Session{
		ID:                    sessionID,
		UserID:                params.UserID,
		OrganizationID:        params.OrganizationID,
		AccessToken:           params.AccessToken,
		RefreshToken:          params.RefreshToken,
		AccessTokenExpiresAt:  now.Add(params.AccessTokenExpiresIn),
		RefreshTokenExpiresAt: now.Add(params.RefreshTokenExpiresIn),
		Metadata:              params.Metadata,
		CreatedAt:             now,
		UpdatedAt:             now,
		LastAccessedAt:        now,
		IPAddress:             h.ipExtractor.GetClientIP(r),
		UserAgent:             r.UserAgent(),
	}

	session.ExpiresAt = session.capExpiry(now.Add(params.RefreshTokenExpiresIn), h.config.MaxLifetime)

	// Add Cloudflare metadata if available
	if h.ipExtractor.IsCloudflareRequest(r) {
		cfMeta := GetCloudflareMetadata(r)
		if session.Metadata == nil {
			session.Metadata = make(map[string]string)
		}
		for k, v := range cfMeta {
			session.Metadata[k] = v
		}
	}

	// Store DPoP key pair if provided
	if len(params.DPoPKeyPairJSON) > 0 {
		session.DPoPKeyPairJSON = params.DPoPKeyPairJSON
		session.DPoPThumbprint = params.DPoPThumbprint
	}

	// Call hook before storing
	if h.config.OnCreateSession != nil {
		if err := h.config.OnCreateSession(ctx, session); err != nil {
			return nil, err
		}
	}

	// Store session
	if err := h.store.Create(ctx, session); err != nil {
		return nil, err
	}

	// Set cookie
	h.cookieManager.SetSessionCookie(w, session.ID, session.ExpiresAt)

	return session, nil
}

// CreateSessionParams contains parameters for creating a session.
//
//nolint:gosec // G117: struct fields for OAuth tokens, not hardcoded secrets
type CreateSessionParams struct {
	UserID                uuid.UUID
	OrganizationID        *uuid.UUID
	AccessToken           string
	RefreshToken          string
	AccessTokenExpiresIn  time.Duration
	RefreshTokenExpiresIn time.Duration
	DPoPKeyPairJSON       []byte // Serialized DPoP key pair (from dpop.KeyPair.SerializeJSON())
	DPoPThumbprint        string // JWK thumbprint of the DPoP key pair
	Metadata              map[string]string
}

// handleGetSession returns the current session status.
func (h *Handler) handleGetSession(w http.ResponseWriter, r *http.Request) {
	sessionID := h.cookieManager.GetSessionID(r)
	if sessionID == "" {
		h.writeJSON(w, http.StatusOK, SessionInfoResponse{Authenticated: false})
		return
	}

	session, err := h.store.Get(r.Context(), sessionID)
	if err != nil {
		// Clear invalid cookie
		h.cookieManager.ClearSessionCookie(w)
		h.writeJSON(w, http.StatusOK, SessionInfoResponse{Authenticated: false})
		return
	}

	if h.sessionLifetimeExceeded(session) {
		endSession(r.Context(), h.store, session.ID)
		h.cookieManager.ClearSessionCookie(w)
		h.writeJSON(w, http.StatusOK, SessionInfoResponse{Authenticated: false})
		return
	}

	// Call session load hook
	if h.config.OnSessionLoad != nil {
		if err := h.config.OnSessionLoad(r.Context(), session); err != nil {
			h.cookieManager.ClearSessionCookie(w)
			h.writeJSON(w, http.StatusOK, SessionInfoResponse{Authenticated: false})
			return
		}
	}

	h.writeJSON(w, http.StatusOK, SessionInfoResponse{
		Authenticated: true,
		UserID:        &session.UserID,
		ExpiresAt:     &session.ExpiresAt,
	})
}

// SessionInfoResponse is the response for session info requests.
type SessionInfoResponse struct {
	Authenticated bool       `json:"authenticated"`
	UserID        *uuid.UUID `json:"user_id,omitempty"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
}

// handleLogout ends the session. It fails closed: if the session cannot be
// loaded or deleted it responds 500 and keeps the cookie, so the client
// still holds the session and can retry, instead of reporting success while
// the server-side session stays valid. If the OnLogout hook fails the
// session is still deleted and the cookie cleared, but the response is 500
// so the client knows token revocation did not complete.
func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sessionID := h.cookieManager.GetSessionID(r)
	if sessionID == "" {
		h.cookieManager.ClearSessionCookie(w)
		h.writeJSON(w, http.StatusOK, map[string]string{"message": "Logged out successfully"})
		return
	}

	// Delete only a session the store returns for the cookie: the cookie
	// value is client-controlled and must never be passed to Delete
	// unchecked, since a store may keep other records (such as per-user
	// session indexes) in the same key space.
	session, err := h.store.Get(ctx, sessionID)
	if err != nil {
		if errors.Is(err, ErrSessionNotFound) || errors.Is(err, ErrSessionExpired) {
			h.cookieManager.ClearSessionCookie(w)
			h.writeJSON(w, http.StatusOK, map[string]string{"message": "Logged out successfully"})
			return
		}
		slog.ErrorContext(ctx, "bff: loading session at logout failed", "error", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "logout_failed", "message": "Logout failed; retry"})
		return
	}

	revokeFailed := false
	if h.config.OnLogout != nil {
		// Call logout hook (e.g., to revoke refresh token in DB)
		if err := h.config.OnLogout(ctx, session); err != nil {
			slog.ErrorContext(ctx, "bff: logout hook failed", "error", err)
			revokeFailed = true
		}
	}

	if err := h.store.Delete(ctx, session.ID); err != nil && !errors.Is(err, ErrSessionNotFound) {
		slog.ErrorContext(ctx, "bff: deleting session at logout failed", "error", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "logout_failed", "message": "Logout failed; retry"})
		return
	}

	h.cookieManager.ClearSessionCookie(w)

	if revokeFailed {
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":   "revocation_failed",
			"message": "Session ended, but token revocation failed",
		})
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]string{"message": "Logged out successfully"})
}

// handleRefresh refreshes the session tokens.
func (h *Handler) handleRefresh(w http.ResponseWriter, r *http.Request) {
	if h.config.OnRefresh == nil {
		http.Error(w, "Token refresh not configured", http.StatusNotImplemented)
		return
	}

	sessionID := h.cookieManager.GetSessionID(r)
	if sessionID == "" {
		http.Error(w, "Unauthorized: No session", http.StatusUnauthorized)
		return
	}

	session, err := h.store.Get(r.Context(), sessionID)
	if err != nil {
		h.cookieManager.ClearSessionCookie(w)
		http.Error(w, "Unauthorized: Invalid session", http.StatusUnauthorized)
		return
	}

	// Check if refresh token is still valid and the session within its
	// idle and absolute limits; refreshing must not keep a session alive
	// past them.
	if session.IsRefreshTokenExpired() || h.sessionLifetimeExceeded(session) {
		if err := h.store.Delete(r.Context(), session.ID); err != nil && !errors.Is(err, ErrSessionNotFound) {
			slog.ErrorContext(r.Context(), "bff: deleting expired session failed", "error", err)
		}
		h.cookieManager.ClearSessionCookie(w)
		http.Error(w, "Unauthorized: Session expired", http.StatusUnauthorized)
		return
	}

	// Call refresh hook
	result, err := h.config.OnRefresh(r.Context(), session)
	if err != nil {
		// Don't expose internal errors
		http.Error(w, "Token refresh failed", http.StatusInternalServerError)
		return
	}

	// Update session with new tokens
	now := time.Now()
	session.AccessToken = result.AccessToken
	session.AccessTokenExpiresAt = now.Add(result.AccessTokenExpiresIn)
	session.UpdatedAt = now
	session.LastAccessedAt = now

	if result.RefreshToken != "" {
		session.RefreshToken = result.RefreshToken
		session.RefreshTokenExpiresAt = now.Add(result.RefreshTokenExpiresIn)
		session.ExpiresAt = session.capExpiry(session.RefreshTokenExpiresAt, h.config.MaxLifetime)
	}

	// Update session in store
	if err := h.store.Update(r.Context(), session); err != nil {
		http.Error(w, "Failed to update session", http.StatusInternalServerError)
		return
	}

	// Update cookie expiry if refresh token was renewed
	if result.RefreshToken != "" {
		h.cookieManager.SetSessionCookie(w, session.ID, session.ExpiresAt)
	}

	h.writeJSON(w, http.StatusOK, map[string]any{
		"message":    "Session refreshed",
		"expires_at": session.AccessTokenExpiresAt.Unix(),
	})
}

// handleProxy proxies API requests.
func (h *Handler) handleProxy(w http.ResponseWriter, r *http.Request) {
	if h.proxy == nil {
		http.Error(w, "Proxy not configured", http.StatusNotImplemented)
		return
	}
	h.proxy.Handler().ServeHTTP(w, r)
}

// writeJSON writes a JSON response.
//
//nolint:unparam // status may vary in future use
func (h *Handler) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Close closes the handler and releases resources.
func (h *Handler) Close() error {
	if h.rateLimiter != nil {
		h.rateLimiter.Close()
	}
	return h.store.Close()
}
