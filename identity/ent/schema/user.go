package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// User holds the schema definition for the User entity.
type User struct {
	ent.Schema
}

// Annotations of the User.
func (User) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "cf_users"},
	}
}

// Mixin of the User.
func (User) Mixin() []ent.Mixin {
	return []ent.Mixin{
		BaseMixin{},
	}
}

// Fields of the User.
func (User) Fields() []ent.Field {
	return []ent.Field{
		field.String("email").
			NotEmpty().
			Unique(),
		field.String("name").
			NotEmpty(),
		field.String("avatar_url").
			Optional().
			Nillable(),
		field.String("password_hash").
			Optional().
			Sensitive(),
		field.Bool("is_platform_admin").
			Default(false).
			Comment("Cross-organization admin access"),
		field.Bool("active").
			Default(true),
		field.Time("last_login_at").
			Optional().
			Nillable(),
		field.UUID("federation_id", uuid.UUID{}).
			Optional().
			Nillable().
			Unique().
			Comment("SystemAuth global identity ID for federated users"),
	}
}

// Edges of the User.
func (User) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("memberships", Membership.Type),
		edge.To("oauth_accounts", OAuthAccount.Type),
		edge.To("refresh_tokens", RefreshToken.Type),
		edge.To("api_keys", APIKey.Type),

		// OAuth 2.0 edges
		edge.To("oauth_apps", OAuthApp.Type),
		edge.To("oauth_tokens", OAuthToken.Type),
		edge.To("oauth_auth_codes", OAuthAuthCode.Type),
		edge.To("oauth_consents", OAuthConsent.Type),
		edge.To("created_service_accounts", ServiceAccount.Type),
	}
}

// Indexes of the User.
func (User) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("email").
			Unique(),
		index.Fields("active"),
		index.Fields("federation_id").
			Unique(),
	}
}
