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

// OAuthAccount holds the schema definition for the OAuthAccount entity.
// It stores OAuth provider connections for users, supporting multiple providers per user.
type OAuthAccount struct {
	ent.Schema
}

// Annotations of the OAuthAccount.
func (OAuthAccount) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_oauth_accounts"},
	}
}

// Mixin of the OAuthAccount.
func (OAuthAccount) Mixin() []ent.Mixin {
	return []ent.Mixin{
		BaseMixin{},
	}
}

// Fields of the OAuthAccount.
func (OAuthAccount) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("user_id", uuid.UUID{}),
		field.String("provider").
			NotEmpty().
			Comment("OAuth provider name (e.g., github, google)"),
		field.String("provider_user_id").
			NotEmpty().
			Comment("User ID from the OAuth provider"),
		field.String("access_token").
			Optional().
			Sensitive().
			Comment("Encrypted OAuth access token"),
		field.String("refresh_token").
			Optional().
			Sensitive().
			Comment("Encrypted OAuth refresh token"),
		field.Time("token_expires_at").
			Optional().
			Nillable().
			Comment("Access token expiration time"),
	}
}

// Edges of the OAuthAccount.
func (OAuthAccount) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("oauth_accounts").
			Field("user_id").
			Required().
			Unique(),
	}
}

// Indexes of the OAuthAccount.
func (OAuthAccount) Indexes() []ent.Index {
	return []ent.Index{
		// One account per provider per external user
		index.Fields("provider", "provider_user_id").
			Unique(),
		index.Fields("user_id"),
		index.Fields("provider"),
	}
}
