package jwt

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Claims represents the SystemForge JWT claims structure.
// It embeds standard JWT claims and adds SystemForge-specific fields.
type Claims struct {
	jwt.RegisteredClaims

	// PrincipalID is the unique identifier for the authenticated principal.
	PrincipalID uuid.UUID `json:"pid,omitempty"`

	// PrincipalType is the type of principal (human, application, agent, service).
	// Empty string defaults to "human" for backward compatibility.
	PrincipalType string `json:"pty,omitempty"`

	// Email is the principal's email address (primarily for human principals).
	Email string `json:"email,omitempty"`

	// Name is the principal's display name.
	Name string `json:"name,omitempty"`

	// OrganizationID is the current organization context (optional).
	OrganizationID *uuid.UUID `json:"org_id,omitempty"`

	// OrganizationSlug is the current organization slug (optional).
	OrganizationSlug string `json:"org_slug,omitempty"`

	// Role is the principal's role in the current organization (optional).
	Role string `json:"role,omitempty"`

	// ClientID is the OAuth client/application ID that obtained this token.
	// This is the "azp" (authorized party) claim from OAuth 2.0.
	// Used for per-application rate limiting and audit logging.
	ClientID string `json:"azp,omitempty"`

	// Scopes are the OAuth scopes granted to this token.
	Scopes []string `json:"scp,omitempty"`

	// Permissions are fine-grained permissions (optional).
	Permissions []string `json:"perms,omitempty"`

	// IsPlatformAdmin indicates cross-organization admin access.
	IsPlatformAdmin bool `json:"platform_admin,omitempty"`

	// TokenType distinguishes access tokens from refresh tokens.
	TokenType TokenType `json:"type,omitempty"`

	// TokenFamily is used for refresh token rotation tracking.
	TokenFamily string `json:"family,omitempty"`

	// Confirmation contains the DPoP binding (cnf claim with jkt).
	// When set, the token is bound to a specific DPoP key pair.
	Confirmation *CNFClaim `json:"cnf,omitempty"`
}

// Principal type constants for the PrincipalType field.
const (
	PrincipalTypeHuman       = "human"
	PrincipalTypeApplication = "application"
	PrincipalTypeAgent       = "agent"
	PrincipalTypeService     = "service"
)

// TokenType identifies the type of token.
type TokenType string

const (
	// AccessToken is a short-lived token for API access.
	AccessToken TokenType = "access"
	// RefreshToken is a long-lived token for obtaining new access tokens.
	RefreshToken TokenType = "refresh"
)

// NewAccessClaims creates claims for a new access token.
func NewAccessClaims(cfg *Config, principalID uuid.UUID, email, name string) *Claims {
	now := time.Now()
	return &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    cfg.Issuer,
			Audience:  cfg.Audience,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(cfg.AccessTokenExpiry)),
			ID:        uuid.NewString(),
		},
		PrincipalID:   principalID,
		PrincipalType: PrincipalTypeHuman, // Default to human
		Email:         email,
		Name:          name,
		TokenType:     AccessToken,
	}
}

// NewRefreshClaims creates claims for a new refresh token.
func NewRefreshClaims(cfg *Config, principalID uuid.UUID, family string) *Claims {
	now := time.Now()
	return &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    cfg.Issuer,
			Audience:  cfg.Audience,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(cfg.RefreshTokenExpiry)),
			ID:        uuid.NewString(),
		},
		PrincipalID:   principalID,
		PrincipalType: PrincipalTypeHuman, // Default to human
		TokenType:     RefreshToken,
		TokenFamily:   family,
	}
}

// WithPrincipalType sets the principal type on the claims.
func (c *Claims) WithPrincipalType(principalType string) *Claims {
	c.PrincipalType = principalType
	return c
}

// WithScopes sets the OAuth scopes on the claims.
func (c *Claims) WithScopes(scopes []string) *Claims {
	c.Scopes = scopes
	return c
}

// WithOrganization adds organization context to the claims.
func (c *Claims) WithOrganization(orgID uuid.UUID, slug, role string, permissions []string) *Claims {
	c.OrganizationID = &orgID
	c.OrganizationSlug = slug
	c.Role = role
	c.Permissions = permissions
	return c
}

// WithPlatformAdmin marks the user as a platform administrator.
func (c *Claims) WithPlatformAdmin(isPlatformAdmin bool) *Claims {
	c.IsPlatformAdmin = isPlatformAdmin
	return c
}

// WithClientID sets the OAuth client/application ID (azp claim).
func (c *Claims) WithClientID(clientID string) *Claims {
	c.ClientID = clientID
	return c
}

// IsExpired returns true if the token has expired.
func (c *Claims) IsExpired() bool {
	if c.ExpiresAt == nil {
		return true
	}
	return c.ExpiresAt.Before(time.Now())
}

// IsAccessToken returns true if this is an access token.
func (c *Claims) IsAccessToken() bool {
	return c.TokenType == AccessToken
}

// IsRefreshToken returns true if this is a refresh token.
func (c *Claims) IsRefreshToken() bool {
	return c.TokenType == RefreshToken
}

// Audience returns the first audience value, or empty string if none.
func (c *Claims) Audience() string {
	if len(c.RegisteredClaims.Audience) > 0 {
		return c.RegisteredClaims.Audience[0]
	}
	return ""
}

// HasAudience checks if the claims include a specific audience.
func (c *Claims) HasAudience(aud string) bool {
	for _, a := range c.RegisteredClaims.Audience {
		if a == aud {
			return true
		}
	}
	return false
}

// HasAnyAudience reports whether the claims include at least one of the
// audiences. It is false when audiences is empty.
func (c *Claims) HasAnyAudience(audiences ...string) bool {
	for _, a := range audiences {
		if c.HasAudience(a) {
			return true
		}
	}
	return false
}

// WithAudience sets the audience claim (builder pattern).
// This overrides any audience set from Config.
func (c *Claims) WithAudience(audiences ...string) *Claims {
	c.RegisteredClaims.Audience = audiences
	return c
}

// withKind puts a client-kind audience (AudienceBFF, AudienceAPI, ...)
// first and keeps the configured application audience, so the token is
// addressed both to a kind of client and to this application.
func (c *Claims) withKind(kind string) *Claims {
	aud := []string{kind}
	for _, a := range c.RegisteredClaims.Audience {
		if a != kind {
			aud = append(aud, a)
		}
	}
	c.RegisteredClaims.Audience = aud
	return c
}
