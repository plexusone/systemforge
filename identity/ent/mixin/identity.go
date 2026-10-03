// Package mixin provides Ent mixins for composing SystemForge identity fields
// into application schemas.
package mixin

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"entgo.io/ent/schema/mixin"
	"github.com/google/uuid"
)

// PrincipalType defines the types of principals in the identity system.
type PrincipalType string

const (
	// PrincipalTypeHuman represents a human user.
	PrincipalTypeHuman PrincipalType = "human"
	// PrincipalTypeApplication represents an OAuth application/client.
	PrincipalTypeApplication PrincipalType = "application"
	// PrincipalTypeAgent represents an AI agent or automated actor.
	PrincipalTypeAgent PrincipalType = "agent"
	// PrincipalTypeService represents a service account for system processes.
	PrincipalTypeService PrincipalType = "service"
)

// PrincipalTypes returns all valid principal types for use in Ent enum fields.
func PrincipalTypes() []string {
	return []string{
		string(PrincipalTypeHuman),
		string(PrincipalTypeApplication),
		string(PrincipalTypeAgent),
		string(PrincipalTypeService),
	}
}

// PrincipalMixin provides fields for the Principal entity.
// Principal is the unified identity type representing any actor in the system.
// Use this mixin to create Principal entities in your app.
//
// Apps must define edges to:
//   - Human (one-to-one, optional) - for human-specific data
//   - OAuthAccount (one-to-many) - for OAuth connections
//   - RefreshToken (one-to-many) - for token management
//   - PrincipalMembership (one-to-many) - for organization membership
//
// Example usage:
//
//	type Principal struct {
//	    ent.Schema
//	}
//
//	func (Principal) Mixin() []ent.Mixin {
//	    return []ent.Mixin{
//	        cfmixin.PrincipalMixin{},
//	    }
//	}
//
//	func (Principal) Fields() []ent.Field {
//	    return []ent.Field{
//	        // App-specific fields if needed
//	    }
//	}
//
//	func (Principal) Edges() []ent.Edge {
//	    return []ent.Edge{
//	        edge.To("human", Human.Type).Unique(),
//	        edge.To("oauth_accounts", OAuthAccount.Type),
//	        edge.To("refresh_tokens", RefreshToken.Type),
//	        edge.To("memberships", PrincipalMembership.Type),
//	    }
//	}
type PrincipalMixin struct {
	mixin.Schema
}

// Fields returns the Principal fields.
func (PrincipalMixin) Fields() []ent.Field {
	baseFields := BaseMixin{}.Fields()
	principalFields := []ent.Field{
		field.Enum("type").
			Values(PrincipalTypes()...).
			Comment("Principal type: human, application, agent, or service"),
		field.String("identifier").
			NotEmpty().
			Comment("Unique identifier within type (email for humans, client_id for apps)"),
		field.String("display_name").
			NotEmpty().
			Comment("Human-readable name for display"),
		field.UUID("organization_id", uuid.UUID{}).
			Optional().
			Nillable().
			Comment("Owning organization for non-human principals"),
		field.Bool("active").
			Default(true).
			Comment("Whether this principal can authenticate"),
		field.JSON("capabilities", []string{}).
			Optional().
			Comment("Principal capabilities/features"),
		field.JSON("allowed_scopes", []string{}).
			Optional().
			Comment("OAuth scopes this principal can request"),
		field.JSON("metadata", map[string]any{}).
			Optional().
			Comment("App-specific metadata"),
		field.UUID("sf_principal_id", uuid.UUID{}).
			Optional().
			Nillable().
			Unique().
			Comment("SystemAuth Principal ID for SSO federation"),
	}
	return append(baseFields, principalFields...)
}

// Indexes returns indexes for the Principal entity.
func (PrincipalMixin) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("type", "identifier").Unique(),
		index.Fields("organization_id"),
		index.Fields("sf_principal_id"),
		index.Fields("active"),
	}
}

// HumanMixin provides fields for the Human entity.
// Human extends Principal with human-specific data (email, name, avatar, etc.).
// Use this mixin to create Human entities in your app.
//
// Apps must define:
//   - principal_id field (FK to Principal)
//   - Edge from Principal to Human
//
// Example usage:
//
//	type Human struct {
//	    ent.Schema
//	}
//
//	func (Human) Mixin() []ent.Mixin {
//	    return []ent.Mixin{
//	        cfmixin.HumanMixin{},
//	    }
//	}
//
//	func (Human) Fields() []ent.Field {
//	    return []ent.Field{
//	        // App-specific fields (e.g., bio, headline, username)
//	    }
//	}
//
//	func (Human) Edges() []ent.Edge {
//	    return []ent.Edge{
//	        edge.From("principal", Principal.Type).
//	            Ref("human").
//	            Field("principal_id").
//	            Unique().
//	            Required().
//	            Immutable(),
//	    }
//	}
type HumanMixin struct {
	mixin.Schema
}

// Fields returns the Human fields.
func (HumanMixin) Fields() []ent.Field {
	baseFields := BaseMixin{}.Fields()
	humanFields := []ent.Field{
		field.UUID("principal_id", uuid.UUID{}).
			Unique().
			Immutable().
			Comment("Parent Principal ID"),
		field.String("email").
			NotEmpty().
			Unique().
			Comment("Primary email address"),
		field.String("name").
			Optional().
			Comment("Full name for display"),
		field.String("password_hash").
			Optional().
			Sensitive().
			Comment("Bcrypt password hash for local auth"),
		field.String("avatar_url").
			Optional().
			Nillable().
			Comment("Profile avatar URL"),
		field.Bool("is_platform_admin").
			Default(false).
			Comment("Cross-organization admin access"),
		field.Time("last_login_at").
			Optional().
			Nillable().
			Comment("Last successful authentication time"),
		field.Time("email_verified_at").
			Optional().
			Nillable().
			Comment("When email was verified"),
		// Public profile fields
		field.String("slug").
			Optional().
			Nillable().
			MinLen(3).
			MaxLen(39).
			Comment("URL-safe username for public profile (e.g., /u/{slug})"),
		field.String("headline").
			Optional().
			Nillable().
			MaxLen(120).
			Comment("Professional headline (e.g., 'AI Researcher at Stanford')"),
		field.Text("bio").
			Optional().
			Nillable().
			Comment("Public biography (Markdown supported)"),
		field.String("linkedin_url").
			Optional().
			Nillable().
			Comment("LinkedIn profile URL"),
		field.String("github_url").
			Optional().
			Nillable().
			Comment("GitHub profile URL"),
		field.String("twitter_url").
			Optional().
			Nillable().
			Comment("Twitter/X profile URL"),
		field.String("website_url").
			Optional().
			Nillable().
			Comment("Personal website URL"),
		field.Bool("public_profile").
			Default(false).
			Comment("Whether public profile is visible"),
	}
	return append(baseFields, humanFields...)
}

// Indexes returns indexes for the Human entity.
func (HumanMixin) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("email").Unique(),
		index.Fields("principal_id").Unique(),
		index.Fields("slug").Unique(),
		index.Fields("public_profile"),
	}
}

// OAuthAccountMixin provides fields for the OAuthAccount entity.
// OAuthAccount stores OAuth provider connections for principals.
// Use this mixin to create OAuthAccount entities in your app.
//
// Apps must define:
//   - principal_id field (FK to Principal)
//   - Edge from Principal to OAuthAccount
//
// Example usage:
//
//	type OAuthAccount struct {
//	    ent.Schema
//	}
//
//	func (OAuthAccount) Mixin() []ent.Mixin {
//	    return []ent.Mixin{
//	        cfmixin.OAuthAccountMixin{},
//	    }
//	}
//
//	func (OAuthAccount) Edges() []ent.Edge {
//	    return []ent.Edge{
//	        edge.From("principal", Principal.Type).
//	            Ref("oauth_accounts").
//	            Field("principal_id").
//	            Unique().
//	            Required(),
//	    }
//	}
type OAuthAccountMixin struct {
	mixin.Schema
}

// Fields returns the OAuthAccount fields.
func (OAuthAccountMixin) Fields() []ent.Field {
	baseFields := BaseMixin{}.Fields()
	oauthFields := []ent.Field{
		field.UUID("principal_id", uuid.UUID{}).
			Comment("Parent Principal ID"),
		field.String("provider").
			NotEmpty().
			Comment("OAuth provider name (google, github, etc.)"),
		field.String("provider_account_id").
			NotEmpty().
			Comment("Account ID from the provider"),
		field.String("access_token").
			Optional().
			Sensitive().
			Comment("OAuth access token"),
		field.String("refresh_token").
			Optional().
			Sensitive().
			Comment("OAuth refresh token"),
		field.Time("token_expires_at").
			Optional().
			Nillable().
			Comment("Access token expiration time"),
		field.JSON("scopes", []string{}).
			Optional().
			Comment("Granted OAuth scopes"),
		field.JSON("raw_data", map[string]any{}).
			Optional().
			Comment("Raw user data from provider"),
	}
	return append(baseFields, oauthFields...)
}

// Indexes returns indexes for the OAuthAccount entity.
func (OAuthAccountMixin) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("provider", "provider_account_id").Unique(),
		index.Fields("principal_id"),
	}
}

// PrincipalMembershipMixin provides fields for the PrincipalMembership entity.
// PrincipalMembership links Principals to Organizations with roles.
// Use this mixin to create PrincipalMembership entities in your app.
//
// Apps must define:
//   - Edges from Principal and Organization to PrincipalMembership
//
// Example usage:
//
//	type PrincipalMembership struct {
//	    ent.Schema
//	}
//
//	func (PrincipalMembership) Mixin() []ent.Mixin {
//	    return []ent.Mixin{
//	        cfmixin.PrincipalMembershipMixin{},
//	    }
//	}
//
//	func (PrincipalMembership) Edges() []ent.Edge {
//	    return []ent.Edge{
//	        edge.From("principal", Principal.Type).
//	            Ref("memberships").
//	            Field("principal_id").
//	            Unique().
//	            Required(),
//	        edge.From("organization", Organization.Type).
//	            Ref("principal_memberships").
//	            Field("organization_id").
//	            Unique().
//	            Required(),
//	    }
//	}
type PrincipalMembershipMixin struct {
	mixin.Schema
}

// MembershipRole defines the standard roles for organization membership.
type MembershipRole string

const (
	// MembershipRoleOwner has full control including billing and deletion.
	MembershipRoleOwner MembershipRole = "owner"
	// MembershipRoleAdmin can manage members and most settings.
	MembershipRoleAdmin MembershipRole = "admin"
	// MembershipRoleEditor can create and modify content.
	MembershipRoleEditor MembershipRole = "editor"
	// MembershipRoleViewer can only view content.
	MembershipRoleViewer MembershipRole = "viewer"
)

// MembershipRoles returns all standard membership roles.
func MembershipRoles() []string {
	return []string{
		string(MembershipRoleOwner),
		string(MembershipRoleAdmin),
		string(MembershipRoleEditor),
		string(MembershipRoleViewer),
	}
}

// Fields returns the PrincipalMembership fields.
func (PrincipalMembershipMixin) Fields() []ent.Field {
	baseFields := BaseMixin{}.Fields()
	membershipFields := []ent.Field{
		field.UUID("principal_id", uuid.UUID{}).
			Comment("Principal ID"),
		field.UUID("organization_id", uuid.UUID{}).
			Comment("Organization ID"),
		field.Enum("role").
			Values(MembershipRoles()...).
			Default(string(MembershipRoleViewer)).
			Comment("Role in the organization"),
		field.Bool("active").
			Default(true).
			Comment("Whether membership is active"),
		field.JSON("permissions", []string{}).
			Optional().
			Comment("Optional fine-grained permissions"),
		field.Time("joined_at").
			Default(time.Now).
			Comment("When the principal joined the organization"),
		field.Time("expires_at").
			Optional().
			Nillable().
			Comment("Optional membership expiration"),
	}
	return append(baseFields, membershipFields...)
}

// Indexes returns indexes for the PrincipalMembership entity.
func (PrincipalMembershipMixin) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("principal_id", "organization_id").Unique(),
		index.Fields("organization_id"),
		index.Fields("active"),
	}
}

// RefreshTokenMixin provides fields for the RefreshToken entity.
// RefreshToken stores refresh tokens for token-based authentication.
// Use this mixin to create RefreshToken entities in your app.
//
// Apps must define:
//   - principal_id field (FK to Principal)
//   - Edge from Principal to RefreshToken
//
// Example usage:
//
//	type RefreshToken struct {
//	    ent.Schema
//	}
//
//	func (RefreshToken) Mixin() []ent.Mixin {
//	    return []ent.Mixin{
//	        cfmixin.RefreshTokenMixin{},
//	    }
//	}
//
//	func (RefreshToken) Edges() []ent.Edge {
//	    return []ent.Edge{
//	        edge.From("principal", Principal.Type).
//	            Ref("refresh_tokens").
//	            Field("principal_id").
//	            Unique().
//	            Required(),
//	    }
//	}
type RefreshTokenMixin struct {
	mixin.Schema
}

// Fields returns the RefreshToken fields.
func (RefreshTokenMixin) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),
		field.UUID("principal_id", uuid.UUID{}).
			Comment("Principal this refresh token belongs to"),
		field.String("token").
			NotEmpty().
			Unique().
			Sensitive().
			Comment("The refresh token value"),
		field.String("family").
			Optional().
			Comment("Token family for rotation tracking"),
		field.Time("expires_at").
			Comment("When the refresh token expires"),
		field.Bool("revoked").
			Default(false).
			Comment("Whether the token has been revoked"),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
	}
}

// Indexes returns indexes for the RefreshToken entity.
func (RefreshTokenMixin) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("token").Unique(),
		index.Fields("principal_id"),
		index.Fields("family"),
		index.Fields("expires_at"),
	}
}

// ApplicationMixin provides fields for the Application entity (OAuth clients).
// Application extends Principal with OAuth client-specific data.
// Use this mixin for OAuth2 client applications.
//
// Apps must define:
//   - principal_id field (FK to Principal)
//   - Edge from Principal to Application
type ApplicationMixin struct {
	mixin.Schema
}

// Fields returns the Application fields.
func (ApplicationMixin) Fields() []ent.Field {
	baseFields := BaseMixin{}.Fields()
	appFields := []ent.Field{
		field.UUID("principal_id", uuid.UUID{}).
			Unique().
			Immutable().
			Comment("Parent Principal ID"),
		field.String("client_id").
			NotEmpty().
			Unique().
			Comment("OAuth2 client_id"),
		field.String("client_secret_hash").
			Sensitive().
			Comment("Hashed client secret"),
		field.Strings("redirect_uris").
			Comment("Allowed OAuth2 redirect URIs"),
		field.Strings("grant_types").
			Default([]string{"authorization_code", "refresh_token"}).
			Comment("Allowed OAuth2 grant types"),
		field.Strings("response_types").
			Default([]string{"code"}).
			Comment("Allowed OAuth2 response types"),
		field.Bool("confidential").
			Default(true).
			Comment("Whether client can keep secrets (server vs public client)"),
		field.String("logo_url").
			Optional().
			Nillable().
			Comment("Application logo URL"),
		field.String("homepage_url").
			Optional().
			Nillable().
			Comment("Application homepage URL"),
		field.String("privacy_policy_url").
			Optional().
			Nillable().
			Comment("Privacy policy URL"),
		field.String("terms_of_service_url").
			Optional().
			Nillable().
			Comment("Terms of service URL"),
	}
	return append(baseFields, appFields...)
}

// Indexes returns indexes for the Application entity.
func (ApplicationMixin) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("client_id").Unique(),
		index.Fields("principal_id").Unique(),
	}
}

// AgentMixin provides fields for the Agent entity (AI agents).
// Agent extends Principal with AI agent-specific data.
// Use this mixin for AI agents that act on behalf of humans or organizations.
type AgentMixin struct {
	mixin.Schema
}

// Fields returns the Agent fields.
func (AgentMixin) Fields() []ent.Field {
	baseFields := BaseMixin{}.Fields()
	agentFields := []ent.Field{
		field.UUID("principal_id", uuid.UUID{}).
			Unique().
			Immutable().
			Comment("Parent Principal ID"),
		field.UUID("owner_principal_id", uuid.UUID{}).
			Optional().
			Nillable().
			Comment("Human or organization that owns this agent"),
		field.String("model").
			Optional().
			Comment("AI model identifier (e.g., claude-3-opus)"),
		field.String("system_prompt").
			Optional().
			Comment("System prompt for the agent"),
		field.JSON("tools", []string{}).
			Optional().
			Comment("Tools/capabilities the agent can use"),
		field.JSON("constraints", map[string]any{}).
			Optional().
			Comment("Operational constraints (rate limits, scope limits)"),
		field.Time("last_active_at").
			Optional().
			Nillable().
			Comment("Last activity timestamp"),
	}
	return append(baseFields, agentFields...)
}

// Indexes returns indexes for the Agent entity.
func (AgentMixin) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("principal_id").Unique(),
		index.Fields("owner_principal_id"),
	}
}

// ServicePrincipalMixin provides fields for the ServicePrincipal entity.
// ServicePrincipal extends Principal for system service accounts.
// Use this mixin for background jobs, cron tasks, and system processes.
type ServicePrincipalMixin struct {
	mixin.Schema
}

// Fields returns the ServicePrincipal fields.
func (ServicePrincipalMixin) Fields() []ent.Field {
	baseFields := BaseMixin{}.Fields()
	serviceFields := []ent.Field{
		field.UUID("principal_id", uuid.UUID{}).
			Unique().
			Immutable().
			Comment("Parent Principal ID"),
		field.String("service_name").
			NotEmpty().
			Unique().
			Comment("Unique service identifier"),
		field.String("description").
			Optional().
			Comment("Description of the service's purpose"),
		field.String("api_key_hash").
			Optional().
			Sensitive().
			Comment("Hashed API key for authentication"),
		field.Time("api_key_last_rotated").
			Optional().
			Nillable().
			Comment("When the API key was last rotated"),
		field.Strings("allowed_ips").
			Optional().
			Comment("IP allowlist for service authentication"),
		field.Time("last_used_at").
			Optional().
			Nillable().
			Comment("Last time the service authenticated"),
	}
	return append(baseFields, serviceFields...)
}

// Indexes returns indexes for the ServicePrincipal entity.
func (ServicePrincipalMixin) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("principal_id").Unique(),
		index.Fields("service_name").Unique(),
	}
}
