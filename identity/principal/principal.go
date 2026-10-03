// Package principal provides the core principal abstraction for identity management.
// A Principal is a unified identity root that can represent different types of actors:
// Human (interactive users), Application (OAuth clients), Agent (AI assistants),
// or Service (backend systems).
package principal

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Type represents the type of principal.
type Type string

const (
	// TypeHuman represents an interactive human user.
	TypeHuman Type = "human"
	// TypeApplication represents an OAuth 2.0 client application.
	TypeApplication Type = "application"
	// TypeAgent represents an AI assistant or automated agent.
	TypeAgent Type = "agent"
	// TypeService represents a backend service or system.
	TypeService Type = "service"
)

// AllTypes returns all valid principal types.
func AllTypes() []Type {
	return []Type{TypeHuman, TypeApplication, TypeAgent, TypeService}
}

// String returns the string representation of the principal type.
func (t Type) String() string {
	return string(t)
}

// Valid returns true if the type is a valid principal type.
func (t Type) Valid() bool {
	switch t {
	case TypeHuman, TypeApplication, TypeAgent, TypeService:
		return true
	default:
		return false
	}
}

// Capabilities represents what a principal is allowed to do.
type Capabilities struct {
	CanAccessUI       bool `json:"can_access_ui"`
	CanManageProfile  bool `json:"can_manage_profile"`
	CanActOnBehalf    bool `json:"can_act_on_behalf"`
	CanDelegate       bool `json:"can_delegate"`
	RequiresApproval  bool `json:"requires_approval"`
	CanBypassRLS      bool `json:"can_bypass_rls"`
	CanRequestOffline bool `json:"can_request_offline"`
}

// DefaultCapabilitiesForType returns the default capabilities for a principal type.
func DefaultCapabilitiesForType(t Type) Capabilities {
	switch t {
	case TypeHuman:
		return Capabilities{
			CanAccessUI:      true,
			CanManageProfile: true,
			CanDelegate:      true,
		}
	case TypeApplication:
		return Capabilities{
			CanActOnBehalf:    true,
			CanRequestOffline: true,
		}
	case TypeAgent:
		return Capabilities{
			RequiresApproval: true,
		}
	case TypeService:
		return Capabilities{
			CanBypassRLS: false, // Must be explicitly enabled
		}
	default:
		return Capabilities{}
	}
}

// Principal represents the core identity abstraction.
type Principal struct {
	ID             uuid.UUID      `json:"id"`
	Type           Type           `json:"type"`
	Identifier     string         `json:"identifier"` // Unique identifier (email, client_id, service@org)
	DisplayName    string         `json:"display_name"`
	OrganizationID *uuid.UUID     `json:"organization_id,omitempty"`
	Active         bool           `json:"active"`
	Capabilities   Capabilities   `json:"capabilities"`
	AllowedScopes  []string       `json:"allowed_scopes"`
	Metadata       map[string]any `json:"metadata,omitempty"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`

	// Type-specific extensions (only one will be populated based on Type)
	Human       *Human       `json:"human,omitempty"`
	Application *Application `json:"application,omitempty"`
	Agent       *Agent       `json:"agent,omitempty"`
	Service     *ServiceData `json:"service,omitempty"`
}

// Human represents human-specific principal data.
type Human struct {
	Email           string     `json:"email"`
	GivenName       string     `json:"given_name,omitempty"`
	FamilyName      string     `json:"family_name,omitempty"`
	AvatarURL       *string    `json:"avatar_url,omitempty"`
	Locale          string     `json:"locale,omitempty"`
	Timezone        string     `json:"timezone,omitempty"`
	IsPlatformAdmin bool       `json:"is_platform_admin"`
	LastLoginAt     *time.Time `json:"last_login_at,omitempty"`
	EmailVerifiedAt *time.Time `json:"email_verified_at,omitempty"`
}

// Application represents OAuth application-specific principal data.
type Application struct {
	ClientID               string   `json:"client_id"`
	AppType                AppType  `json:"app_type"`
	RedirectURIs           []string `json:"redirect_uris"`
	AllowedGrants          []string `json:"allowed_grants"`
	AllowedResponseTypes   []string `json:"allowed_response_types,omitempty"`
	AccessTokenTTLSeconds  int      `json:"access_token_ttl_seconds"`
	RefreshTokenTTLSeconds int      `json:"refresh_token_ttl_seconds"`
	RefreshTokenRotation   bool     `json:"refresh_token_rotation"`
	FirstParty             bool     `json:"first_party"`
	Public                 bool     `json:"public"`
	LogoURL                *string  `json:"logo_url,omitempty"`
	Description            *string  `json:"description,omitempty"`
}

// AppType represents the type of OAuth application.
type AppType string

const (
	// AppTypeWeb is a confidential web application.
	AppTypeWeb AppType = "web"
	// AppTypeSPA is a single-page application (public client).
	AppTypeSPA AppType = "spa"
	// AppTypeNative is a native mobile/desktop application.
	AppTypeNative AppType = "native"
	// AppTypeMachine is a machine-to-machine application.
	AppTypeMachine AppType = "machine"
)

// Agent represents AI agent-specific principal data.
type Agent struct {
	ModelID                 string     `json:"model_id"`
	Version                 string     `json:"version,omitempty"`
	DelegatingPrincipalID   *uuid.UUID `json:"delegating_principal_id,omitempty"`
	CapabilityConstraints   []string   `json:"capability_constraints,omitempty"`
	ResourceConstraints     []string   `json:"resource_constraints,omitempty"`
	MaxTokenLifetimeSeconds int        `json:"max_token_lifetime_seconds,omitempty"`
	SessionID               *string    `json:"session_id,omitempty"`
	RequiresConfirmation    bool       `json:"requires_confirmation"`
}

// ServiceData represents backend service-specific principal data.
type ServiceData struct {
	ServiceType string     `json:"service_type"`
	Description *string    `json:"description,omitempty"`
	CreatedBy   *uuid.UUID `json:"created_by,omitempty"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	AllowedIPs  []string   `json:"allowed_ips,omitempty"`
}

// CreateHumanInput contains fields for creating a human principal.
type CreateHumanInput struct {
	Email           string
	DisplayName     string
	GivenName       string
	FamilyName      string
	AvatarURL       *string
	Locale          string
	Timezone        string
	OrganizationID  *uuid.UUID
	IsPlatformAdmin bool
	AllowedScopes   []string
	Metadata        map[string]any
}

// CreateApplicationInput contains fields for creating an application principal.
type CreateApplicationInput struct {
	ClientID               string
	DisplayName            string
	Description            *string
	LogoURL                *string
	AppType                AppType
	RedirectURIs           []string
	AllowedGrants          []string
	AllowedResponseTypes   []string
	AccessTokenTTLSeconds  int
	RefreshTokenTTLSeconds int
	RefreshTokenRotation   bool
	FirstParty             bool
	Public                 bool
	OrganizationID         *uuid.UUID
	AllowedScopes          []string
	Metadata               map[string]any
}

// CreateAgentInput contains fields for creating an agent principal.
type CreateAgentInput struct {
	Identifier              string
	DisplayName             string
	ModelID                 string
	Version                 string
	DelegatingPrincipalID   *uuid.UUID
	CapabilityConstraints   []string
	ResourceConstraints     []string
	MaxTokenLifetimeSeconds int
	RequiresConfirmation    bool
	OrganizationID          *uuid.UUID
	AllowedScopes           []string
	Metadata                map[string]any
}

// CreateServiceInput contains fields for creating a service principal.
type CreateServiceInput struct {
	Identifier     string
	DisplayName    string
	ServiceType    string
	Description    *string
	CreatedBy      *uuid.UUID
	AllowedIPs     []string
	OrganizationID *uuid.UUID
	AllowedScopes  []string
	Metadata       map[string]any
}

// UpdateInput contains fields for updating any principal type.
type UpdateInput struct {
	DisplayName   *string
	Active        *bool
	AllowedScopes []string
	Capabilities  *Capabilities
	Metadata      map[string]any
}

// UpdateHumanInput contains fields for updating a human principal.
type UpdateHumanInput struct {
	UpdateInput
	GivenName       *string
	FamilyName      *string
	AvatarURL       *string
	Locale          *string
	Timezone        *string
	IsPlatformAdmin *bool
}

// UpdateApplicationInput contains fields for updating an application principal.
type UpdateApplicationInput struct {
	UpdateInput
	Description            *string
	LogoURL                *string
	RedirectURIs           []string
	AllowedGrants          []string
	AllowedResponseTypes   []string
	AccessTokenTTLSeconds  *int
	RefreshTokenTTLSeconds *int
	RefreshTokenRotation   *bool
	FirstParty             *bool
}

// UpdateAgentInput contains fields for updating an agent principal.
type UpdateAgentInput struct {
	UpdateInput
	Version                 *string
	CapabilityConstraints   []string
	ResourceConstraints     []string
	MaxTokenLifetimeSeconds *int
	RequiresConfirmation    *bool
}

// UpdateServiceInput contains fields for updating a service principal.
type UpdateServiceInput struct {
	UpdateInput
	Description *string
	AllowedIPs  []string
}

// Repository defines the data access interface for principals.
type Repository interface {
	// GetByID retrieves a principal by ID.
	GetByID(ctx context.Context, id uuid.UUID) (*Principal, error)

	// GetByIdentifier retrieves a principal by unique identifier.
	GetByIdentifier(ctx context.Context, identifier string) (*Principal, error)

	// Create creates a new principal with its type-specific extension.
	Create(ctx context.Context, p *Principal) error

	// Update updates an existing principal.
	Update(ctx context.Context, p *Principal) error

	// Delete deletes a principal (soft delete via Active=false).
	Delete(ctx context.Context, id uuid.UUID) error

	// ListByOrganization lists principals in an organization.
	ListByOrganization(ctx context.Context, orgID uuid.UUID, types []Type) ([]*Principal, error)

	// ListByType lists principals of a specific type.
	ListByType(ctx context.Context, t Type) ([]*Principal, error)
}

// Service defines the business logic interface for principals.
type Service interface {
	// GetByID retrieves a principal by ID.
	GetByID(ctx context.Context, id uuid.UUID) (*Principal, error)

	// GetByIdentifier retrieves a principal by unique identifier.
	GetByIdentifier(ctx context.Context, identifier string) (*Principal, error)

	// CreateHuman creates a new human principal.
	CreateHuman(ctx context.Context, input CreateHumanInput) (*Principal, error)

	// CreateApplication creates a new application principal.
	CreateApplication(ctx context.Context, input CreateApplicationInput) (*Principal, error)

	// CreateAgent creates a new agent principal.
	CreateAgent(ctx context.Context, input CreateAgentInput) (*Principal, error)

	// CreateService creates a new service principal.
	CreateService(ctx context.Context, input CreateServiceInput) (*Principal, error)

	// Update updates an existing principal.
	Update(ctx context.Context, id uuid.UUID, input UpdateInput) (*Principal, error)

	// UpdateHuman updates a human principal.
	UpdateHuman(ctx context.Context, id uuid.UUID, input UpdateHumanInput) (*Principal, error)

	// UpdateApplication updates an application principal.
	UpdateApplication(ctx context.Context, id uuid.UUID, input UpdateApplicationInput) (*Principal, error)

	// UpdateAgent updates an agent principal.
	UpdateAgent(ctx context.Context, id uuid.UUID, input UpdateAgentInput) (*Principal, error)

	// UpdateService updates a service principal.
	UpdateService(ctx context.Context, id uuid.UUID, input UpdateServiceInput) (*Principal, error)

	// Deactivate deactivates a principal.
	Deactivate(ctx context.Context, id uuid.UUID) error

	// Reactivate reactivates a principal.
	Reactivate(ctx context.Context, id uuid.UUID) error
}
