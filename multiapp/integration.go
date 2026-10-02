package multiapp

import (
	"context"

	"github.com/google/uuid"
	"github.com/plexusone/systemforge/contract"
	"github.com/plexusone/systemforge/rls"
	"github.com/plexusone/systemforge/session/jwt"
	"github.com/plexusone/systemforge/session/middleware"
)

// This file provides integration helpers that bridge the multiapp context
// with existing SystemForge context systems (session/middleware, rls, contract).

// FullContext represents the complete context available in a multi-app request.
// It combines app context with authentication context.
type FullContext struct {
	// App context (from X-App-ID header routing)
	App *AppContext

	// JWT claims (from session/middleware)
	Claims *jwt.Claims

	// RLS context
	TenantID uuid.UUID
	UserID   uuid.UUID

	// Federation context (from SystemAuth, optional)
	FederationID uuid.UUID
}

// FullContextFromContext extracts all context values into a unified struct.
// Returns nil for any values that are not present.
func FullContextFromContext(ctx context.Context) *FullContext {
	fc := &FullContext{
		App:      AppContextFromContext(ctx),
		Claims:   middleware.ClaimsFromContext(ctx),
		TenantID: rls.TenantIDFromContext(ctx),
		UserID:   rls.UserIDFromContext(ctx),
	}

	// Federation ID is optional
	if fedID, ok := contract.FederationIDFromContext(ctx); ok {
		fc.FederationID = fedID
	}

	return fc
}

// IsAuthenticated returns true if the context has valid authentication.
func (fc *FullContext) IsAuthenticated() bool {
	return fc.Claims != nil && fc.Claims.PrincipalID != uuid.Nil
}

// HasApp returns true if the context has app context (multi-app mode).
func (fc *FullContext) HasApp() bool {
	return fc.App != nil
}

// IsFederated returns true if the user has a SystemAuth federation ID.
func (fc *FullContext) IsFederated() bool {
	return fc.FederationID != uuid.Nil
}

// PrincipalID returns the authenticated principal ID.
// Returns uuid.Nil if not authenticated.
func (fc *FullContext) PrincipalID() uuid.UUID {
	if fc.Claims == nil {
		return uuid.Nil
	}
	return fc.Claims.PrincipalID
}

// OrganizationID returns the current organization context.
// Returns nil if no organization is selected.
func (fc *FullContext) OrganizationID() *uuid.UUID {
	if fc.Claims == nil {
		return nil
	}
	return fc.Claims.OrganizationID
}

// EnrichContext adds app context to an existing context that may already
// have authentication context from session middleware.
// This is useful when you need to add app context to a context that
// was created outside of the multi-app middleware.
func EnrichContext(ctx context.Context, appCtx *AppContext) context.Context {
	return WithAppContext(ctx, appCtx)
}

// WithRLSFromClaims adds RLS context from JWT claims.
// This bridges session/middleware claims to rls context.
func WithRLSFromClaims(ctx context.Context) context.Context {
	claims := middleware.ClaimsFromContext(ctx)
	if claims == nil {
		return ctx
	}

	// Set user ID from claims
	if claims.PrincipalID != uuid.Nil {
		ctx = rls.ContextWithUser(ctx, claims.PrincipalID)
	}

	// Set tenant ID from organization if present
	if claims.OrganizationID != nil && *claims.OrganizationID != uuid.Nil {
		ctx = rls.ContextWithTenant(ctx, *claims.OrganizationID)
	}

	return ctx
}

// ValidateAppAccess validates that the authenticated user has access to the app.
// This is a placeholder for future app-level access control.
// Currently, it just checks that the app context is present.
func ValidateAppAccess(ctx context.Context) error {
	if !HasAppContext(ctx) {
		return ErrNoAppContext
	}
	return nil
}

// ValidateAppFeature validates that a feature is enabled for the current app.
func ValidateAppFeature(ctx context.Context, feature string) error {
	if !HasFeature(ctx, feature) {
		return ErrFeatureNotEnabled
	}
	return nil
}

// RequireAuth is a middleware helper that ensures the request is authenticated.
// Returns the principal ID if authenticated, or an error if not.
func RequireAuth(ctx context.Context) (uuid.UUID, error) {
	claims := middleware.ClaimsFromContext(ctx)
	if claims == nil || claims.PrincipalID == uuid.Nil {
		return uuid.Nil, ErrNotAuthenticated
	}
	return claims.PrincipalID, nil
}

// RequireAppAndAuth is a middleware helper that ensures both app context
// and authentication are present. Returns the full context if valid.
func RequireAppAndAuth(ctx context.Context) (*FullContext, error) {
	fc := FullContextFromContext(ctx)

	if !fc.HasApp() {
		return nil, ErrNoAppContext
	}

	if !fc.IsAuthenticated() {
		return nil, ErrNotAuthenticated
	}

	return fc, nil
}
