package contract

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// SystemAuthClaims represents the JWT claims from SystemAuth.
type SystemAuthClaims struct {
	jwt.RegisteredClaims
	FederationID string   `json:"federation_id"`
	Permissions  []string `json:"permissions"`
}

// Middleware returns HTTP middleware for SystemAuth authentication.
// In standalone mode, requests are allowed without authentication.
// In federated mode, SystemAuth JWTs are validated.
func (a *API) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// In standalone mode, allow all requests
			if !a.provider.FederationState().IsFederated() {
				next.ServeHTTP(w, r)
				return
			}

			// Extract token from Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				WriteError(w, ErrUnauthorized("missing authorization header"))
				return
			}

			// Expect "Bearer <token>"
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
				WriteError(w, ErrUnauthorized("invalid authorization header format"))
				return
			}
			tokenString := parts[1]

			// Validate token
			claims, err := a.validateToken(tokenString)
			if err != nil {
				WriteError(w, ErrUnauthorized("invalid token: "+err.Error()))
				return
			}

			// Add claims to context
			ctx := r.Context()
			if claims.FederationID != "" {
				fedID, err := uuid.Parse(claims.FederationID)
				if err == nil {
					ctx = WithFederationID(ctx, fedID)
				}
			}
			ctx = WithPermissions(ctx, claims.Permissions)
			ctx = WithSubject(ctx, claims.Subject)
			if len(claims.Audience) > 0 {
				ctx = WithAudience(ctx, claims.Audience[0])
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// validateToken validates a SystemAuth JWT.
func (a *API) validateToken(tokenString string) (*SystemAuthClaims, error) {
	config := a.provider.Config()

	// Parse and validate token
	token, err := jwt.ParseWithClaims(tokenString, &SystemAuthClaims{}, func(token *jwt.Token) (any, error) {
		// Validate signing method
		switch key := config.SystemAuthPublicKey.(type) {
		case *rsa.PublicKey:
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, errors.New("unexpected signing method")
			}
			return key, nil
		case *ecdsa.PublicKey:
			if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, errors.New("unexpected signing method")
			}
			return key, nil
		default:
			return nil, errors.New("unsupported key type")
		}
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*SystemAuthClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token claims")
	}

	// Validate issuer
	if config.SystemAuthIssuer != "" && claims.Issuer != config.SystemAuthIssuer {
		return nil, errors.New("invalid issuer")
	}

	// Validate audience (should be our app_id)
	if config.AppID != "" {
		found := false
		for _, aud := range claims.Audience {
			if aud == config.AppID {
				found = true
				break
			}
		}
		if !found {
			return nil, errors.New("invalid audience")
		}
	}

	// Validate expiration
	if claims.ExpiresAt != nil && claims.ExpiresAt.Before(time.Now()) {
		return nil, errors.New("token expired")
	}

	// Validate federation ID matches our federation
	expectedFedID := a.provider.FederationState().FederationID()
	if expectedFedID != nil {
		claimFedID, err := uuid.Parse(claims.FederationID)
		if err != nil || claimFedID != *expectedFedID {
			return nil, errors.New("federation ID mismatch")
		}
	}

	return claims, nil
}

// RequireAuth is a middleware that ensures authentication in any mode.
// Use this for endpoints that always require authentication.
func RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if we have a subject in context (set by Middleware)
		if SubjectFromContext(r.Context()) == "" {
			WriteError(w, ErrUnauthorized("authentication required"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequirePermission returns middleware that checks for a specific permission.
func RequirePermission(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !HasPermission(r.Context(), permission) {
				WriteError(w, ErrForbidden("missing required permission: "+permission))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
