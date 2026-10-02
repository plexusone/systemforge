package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// OAuthApp holds the schema definition for OAuth 2.0 applications/clients.
type OAuthApp struct {
	ent.Schema
}

// Annotations of the OAuthApp.
func (OAuthApp) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_oauth_apps"},
	}
}

// Fields of the OAuthApp.
func (OAuthApp) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),

		// Client identification
		field.String("client_id").
			Unique().
			Immutable().
			NotEmpty().
			Comment("Public client identifier"),

		field.String("name").
			NotEmpty().
			MaxLen(255).
			Comment("Human-readable app name"),

		field.String("description").
			Optional().
			MaxLen(1000),

		field.String("logo_url").
			Optional(),

		// App type determines allowed grants and security requirements
		field.Enum("app_type").
			Values("web", "spa", "native", "service", "machine").
			Default("web").
			Comment("web=confidential, spa/native=public+PKCE, service/machine=client_credentials"),

		// Ownership
		field.UUID("owner_id", uuid.UUID{}).
			Comment("User who created this app"),

		field.UUID("organization_id", uuid.UUID{}).
			Optional().
			Nillable().
			Comment("Organization scope (optional)"),

		// OAuth configuration
		field.JSON("redirect_uris", []string{}).
			Default([]string{}).
			Comment("Allowed redirect URIs"),

		field.JSON("allowed_scopes", []string{}).
			Default([]string{}).
			Comment("Scopes this app can request"),

		field.JSON("allowed_grants", []string{}).
			Default([]string{"authorization_code", "refresh_token"}).
			Comment("Allowed grant types"),

		field.JSON("allowed_response_types", []string{}).
			Default([]string{"code"}).
			Comment("Allowed response types"),

		// Token configuration
		field.Int("access_token_ttl").
			Default(900).
			Comment("Access token TTL in seconds (default 15 min)"),

		field.Int("refresh_token_ttl").
			Default(604800).
			Comment("Refresh token TTL in seconds (default 7 days)"),

		field.Bool("refresh_token_rotation").
			Default(true).
			Comment("Rotate refresh tokens on use"),

		// Flags
		field.Bool("first_party").
			Default(false).
			Comment("First-party apps skip consent screen"),

		field.Bool("public").
			Default(false).
			Comment("Public clients cannot keep secrets"),

		field.Bool("active").
			Default(true),

		field.Time("revoked_at").
			Optional().
			Nillable(),

		// Metadata
		field.JSON("metadata", map[string]string{}).
			Optional().
			Comment("Custom metadata"),

		// Timestamps
		field.Time("created_at").
			Default(time.Now).
			Immutable(),

		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}

// Edges of the OAuthApp.
func (OAuthApp) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("owner", User.Type).
			Ref("oauth_apps").
			Field("owner_id").
			Required().
			Unique(),

		edge.From("organization", Organization.Type).
			Ref("oauth_apps").
			Field("organization_id").
			Unique(),

		edge.To("secrets", OAuthAppSecret.Type),
		edge.To("tokens", OAuthToken.Type),
		edge.To("auth_codes", OAuthAuthCode.Type),
		edge.To("consents", OAuthConsent.Type),
	}
}

// Indexes of the OAuthApp.
func (OAuthApp) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("client_id").Unique(),
		index.Fields("owner_id"),
		index.Fields("organization_id"),
		index.Fields("active"),
	}
}
