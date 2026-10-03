// Package token provides token management for principals.
// Tokens are issued to principals for authentication and authorization.
package token

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/plexusone/systemforge/identity/principal"
)

// Token represents a token record.
type Token struct {
	ID               uuid.UUID       `json:"id"`
	PrincipalID      uuid.UUID       `json:"principal_id"`
	PrincipalType    principal.Type  `json:"principal_type"`
	IssuedByAppID    *uuid.UUID      `json:"issued_by_app_id,omitempty"`
	FamilyID         uuid.UUID       `json:"family_id"`
	ParentTokenID    *uuid.UUID      `json:"parent_token_id,omitempty"`
	Scopes           []string        `json:"scopes"`
	Audience         []string        `json:"audience,omitempty"`
	Capabilities     map[string]bool `json:"capabilities"`
	DelegationChain  []string        `json:"delegation_chain,omitempty"`
	DPoPJKT          string          `json:"dpop_jkt,omitempty"` // DPoP JWK thumbprint
	SessionID        string          `json:"session_id,omitempty"`
	AccessExpiresAt  time.Time       `json:"access_expires_at"`
	RefreshExpiresAt *time.Time      `json:"refresh_expires_at,omitempty"`
	Revoked          bool            `json:"revoked"`
	RevokedAt        *time.Time      `json:"revoked_at,omitempty"`
	RevokedReason    string          `json:"revoked_reason,omitempty"`
	ClientIP         string          `json:"client_ip,omitempty"`
	UserAgent        string          `json:"user_agent,omitempty"`
	LastUsedAt       *time.Time      `json:"last_used_at,omitempty"`
	CreatedAt        time.Time       `json:"created_at"`
}

// IssuedToken contains both the token record and the raw tokens.
//
//nolint:gosec // G117: fields hold runtime token values, not hardcoded secrets
type IssuedToken struct {
	Token        *Token `json:"token"`
	AccessToken  string `json:"access_token"`  // JWT or opaque token
	RefreshToken string `json:"refresh_token"` // Optional
	TokenType    string `json:"token_type"`    // "Bearer"
	ExpiresIn    int    `json:"expires_in"`    // Seconds until access token expires
}

// Capabilities defines what a token can do.
type Capabilities struct {
	CanAccessUI       bool `json:"can_access_ui"`
	CanManageProfile  bool `json:"can_manage_profile"`
	CanActOnBehalf    bool `json:"can_act_on_behalf"`
	CanDelegate       bool `json:"can_delegate"`
	RequiresApproval  bool `json:"requires_approval"`
	CanBypassRLS      bool `json:"can_bypass_rls"`
	CanRequestOffline bool `json:"can_request_offline"`
}

// IssueInput contains fields for issuing a new token.
type IssueInput struct {
	PrincipalID     uuid.UUID
	PrincipalType   principal.Type
	IssuedByAppID   *uuid.UUID
	Scopes          []string
	Audience        []string
	Capabilities    map[string]bool
	DelegationChain []string
	DPoPJKT         string // DPoP JWK thumbprint for proof-of-possession
	SessionID       string
	AccessTTL       time.Duration
	RefreshTTL      time.Duration // 0 means no refresh token
	ClientIP        string
	UserAgent       string
	ParentTokenID   *uuid.UUID // For delegation
}

// RefreshInput contains fields for refreshing a token.
type RefreshInput struct {
	RefreshToken string   `json:"-"` //nolint:gosec // G117: field holds runtime token value, not a hardcoded secret
	Scopes       []string // Optional: narrow scopes
	DPoPJKT      string   // For DPoP binding continuity
	ClientIP     string
	UserAgent    string
}

// Service defines the business logic interface for tokens.
type Service interface {
	// Issue issues a new token pair.
	Issue(ctx context.Context, input IssueInput) (*IssuedToken, error)

	// Refresh refreshes a token using the refresh token.
	Refresh(ctx context.Context, input RefreshInput) (*IssuedToken, error)

	// Validate validates an access token and returns the token record.
	Validate(ctx context.Context, accessToken string) (*Token, error)

	// Revoke revokes a token.
	// If revokeFamily is true, all tokens in the same family are revoked.
	Revoke(ctx context.Context, tokenID uuid.UUID, revokeFamily bool, reason string) error

	// RevokeBySignature revokes a token by its access token signature.
	RevokeBySignature(ctx context.Context, accessTokenSignature string, revokeFamily bool, reason string) error

	// GetCapabilitiesForType returns the default capabilities for a principal type.
	GetCapabilitiesForType(principalType principal.Type) Capabilities

	// ListForPrincipal lists all active tokens for a principal.
	ListForPrincipal(ctx context.Context, principalID uuid.UUID) ([]*Token, error)

	// RevokeAllForPrincipal revokes all tokens for a principal.
	RevokeAllForPrincipal(ctx context.Context, principalID uuid.UUID, reason string) error
}
