package bff

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"
)

// contextKey is a type for BFF context keys.
type contextKey string

const (
	// ContextKeySession is the context key for the session.
	ContextKeySession contextKey = "bff_session"
)

// MiddlewareConfig contains configuration for the BFF middleware.
type MiddlewareConfig struct {
	// Store is the session store.
	Store Store

	// CookieManager handles session cookies.
	CookieManager *CookieManager

	// RefreshThreshold is how long before access token expiry to trigger refresh.
	// Default: 5 minutes.
	RefreshThreshold time.Duration

	// OnSessionLoad is called after a session is loaded.
	// Can be used for logging or session modification.
	OnSessionLoad func(ctx context.Context, session *Session) error

	// OnSessionExpired is called when a session is expired.
	OnSessionExpired func(w http.ResponseWriter, r *http.Request)

	// OnSessionInvalid is called when a session is invalid.
	OnSessionInvalid func(w http.ResponseWriter, r *http.Request)

	// OnNoSession is called when no session is found and RequireSession is true.
	OnNoSession func(w http.ResponseWriter, r *http.Request)

	// RequireSession when true rejects requests without valid sessions.
	RequireSession bool

	// TouchOnAccess when true updates LastAccessedAt on each request.
	// IdleTimeout is measured from LastAccessedAt, so without it a session
	// ends IdleTimeout after its last refresh even while in use.
	TouchOnAccess bool

	// IdleTimeout ends a session not used for this long. Zero means
	// DefaultIdleTimeout; a negative value disables the check.
	IdleTimeout time.Duration

	// MaxLifetime ends a session this long after it was created, however
	// often its tokens are refreshed. Zero means DefaultMaxLifetime; a
	// negative value disables the check.
	MaxLifetime time.Duration
}

// SessionMiddleware creates middleware that loads sessions from cookies.
func SessionMiddleware(config MiddlewareConfig) func(http.Handler) http.Handler {
	if config.RefreshThreshold == 0 {
		config.RefreshThreshold = 5 * time.Minute
	}
	idleTimeout := resolveLifetimeLimit(config.IdleTimeout, DefaultIdleTimeout)
	maxLifetime := resolveLifetimeLimit(config.MaxLifetime, DefaultMaxLifetime)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract session ID from cookie
			sessionID := config.CookieManager.GetSessionID(r)
			if sessionID == "" {
				if config.RequireSession {
					handleNoSession(w, r, config)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			// Load session from store
			session, err := config.Store.Get(r.Context(), sessionID)
			if err != nil {
				if err == ErrSessionExpired {
					handleSessionExpired(w, r, config)
					return
				}
				if err == ErrSessionNotFound {
					// Clear the invalid cookie
					config.CookieManager.ClearSessionCookie(w)
					if config.RequireSession {
						handleNoSession(w, r, config)
						return
					}
					next.ServeHTTP(w, r)
					return
				}
				// Other errors
				handleSessionInvalid(w, r, config)
				return
			}

			// End a session that has been idle or alive too long.
			if session.LifetimeExceeded(time.Now(), idleTimeout, maxLifetime) {
				endSession(r.Context(), config.Store, session.ID)
				config.CookieManager.ClearSessionCookie(w)
				handleSessionExpired(w, r, config)
				return
			}

			// Touch session if configured
			if config.TouchOnAccess {
				if err := config.Store.Touch(r.Context(), session.ID); err != nil {
					slog.ErrorContext(r.Context(), "bff: touching session failed", "error", err)
				}
			}

			// Call session load hook if configured
			if config.OnSessionLoad != nil {
				if err := config.OnSessionLoad(r.Context(), session); err != nil {
					handleSessionInvalid(w, r, config)
					return
				}
			}

			// Add session to context
			ctx := context.WithValue(r.Context(), ContextKeySession, session)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// endSession deletes a session that has run past its lifetime, logging a
// failure: the request is refused either way, since the session is checked
// again on every load.
func endSession(ctx context.Context, store Store, id string) {
	if err := store.Delete(ctx, id); err != nil && !errors.Is(err, ErrSessionNotFound) {
		slog.ErrorContext(ctx, "bff: deleting expired session failed", "error", err)
	}
}

// handleNoSession handles missing session errors.
func handleNoSession(w http.ResponseWriter, r *http.Request, config MiddlewareConfig) {
	if config.OnNoSession != nil {
		config.OnNoSession(w, r)
		return
	}
	http.Error(w, "Unauthorized: Session required", http.StatusUnauthorized)
}

// handleSessionExpired handles expired session errors.
func handleSessionExpired(w http.ResponseWriter, r *http.Request, config MiddlewareConfig) {
	if config.OnSessionExpired != nil {
		config.OnSessionExpired(w, r)
		return
	}
	http.Error(w, "Unauthorized: Session expired", http.StatusUnauthorized)
}

// handleSessionInvalid handles invalid session errors.
func handleSessionInvalid(w http.ResponseWriter, r *http.Request, config MiddlewareConfig) {
	if config.OnSessionInvalid != nil {
		config.OnSessionInvalid(w, r)
		return
	}
	http.Error(w, "Unauthorized: Invalid session", http.StatusUnauthorized)
}

// GetSession retrieves the session from the request context.
func GetSession(ctx context.Context) *Session {
	session, _ := ctx.Value(ContextKeySession).(*Session)
	return session
}

// RequireSessionMiddleware creates middleware that requires a valid session.
// This is a convenience function that wraps SessionMiddleware.
func RequireSessionMiddleware(store Store, cookieManager *CookieManager) func(http.Handler) http.Handler {
	return SessionMiddleware(MiddlewareConfig{
		Store:          store,
		CookieManager:  cookieManager,
		RequireSession: true,
		TouchOnAccess:  true,
	})
}

// OptionalSessionMiddleware creates middleware that loads sessions if present.
// Requests without sessions are allowed through.
func OptionalSessionMiddleware(store Store, cookieManager *CookieManager) func(http.Handler) http.Handler {
	return SessionMiddleware(MiddlewareConfig{
		Store:          store,
		CookieManager:  cookieManager,
		RequireSession: false,
		TouchOnAccess:  true,
	})
}
