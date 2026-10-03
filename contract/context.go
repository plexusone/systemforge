package contract

import (
	"context"
	"slices"

	"github.com/google/uuid"
)

// contextKey is a type for context keys to avoid collisions.
type contextKey string

const (
	// contextKeyFederationID stores the federation ID from SystemAuth tokens.
	contextKeyFederationID contextKey = "contract_federation_id"
	// contextKeyPermissions stores the permissions from SystemAuth tokens.
	contextKeyPermissions contextKey = "contract_permissions"
	// contextKeySubject stores the token subject.
	contextKeySubject contextKey = "contract_subject"
	// contextKeyAudience stores the token audience (app_id).
	contextKeyAudience contextKey = "contract_audience"
)

// WithFederationID adds a federation ID to the context.
func WithFederationID(ctx context.Context, federationID uuid.UUID) context.Context {
	return context.WithValue(ctx, contextKeyFederationID, federationID)
}

// FederationIDFromContext extracts the federation ID from context.
func FederationIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	v, ok := ctx.Value(contextKeyFederationID).(uuid.UUID)
	return v, ok
}

// WithPermissions adds permissions to the context.
func WithPermissions(ctx context.Context, permissions []string) context.Context {
	return context.WithValue(ctx, contextKeyPermissions, permissions)
}

// PermissionsFromContext extracts permissions from context.
func PermissionsFromContext(ctx context.Context) []string {
	v, _ := ctx.Value(contextKeyPermissions).([]string)
	return v
}

// HasPermission checks if a permission exists in the context.
func HasPermission(ctx context.Context, permission string) bool {
	return slices.Contains(PermissionsFromContext(ctx), permission)
}

// WithSubject adds a subject to the context.
func WithSubject(ctx context.Context, subject string) context.Context {
	return context.WithValue(ctx, contextKeySubject, subject)
}

// SubjectFromContext extracts the subject from context.
func SubjectFromContext(ctx context.Context) string {
	v, _ := ctx.Value(contextKeySubject).(string)
	return v
}

// WithAudience adds an audience to the context.
func WithAudience(ctx context.Context, audience string) context.Context {
	return context.WithValue(ctx, contextKeyAudience, audience)
}

// AudienceFromContext extracts the audience from context.
func AudienceFromContext(ctx context.Context) string {
	v, _ := ctx.Value(contextKeyAudience).(string)
	return v
}

// Permission scopes as defined in the product contract specification.
const (
	PermissionIdentityRead = "identity:read"
	PermissionIdentitySync = "identity:sync"
	PermissionPolicyRead   = "policy:read"
	PermissionPolicySync   = "policy:sync"
	PermissionAuditConfig  = "audit:config"
	PermissionHealthRead   = "health:read"
)
