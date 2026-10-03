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

// OAuthAppSecret holds client secrets for OAuth apps.
// Multiple secrets can exist for rotation purposes.
type OAuthAppSecret struct {
	ent.Schema
}

// Annotations of the OAuthAppSecret.
func (OAuthAppSecret) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_oauth_app_secrets"},
	}
}

// Fields of the OAuthAppSecret.
func (OAuthAppSecret) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),

		field.UUID("app_id", uuid.UUID{}).
			Comment("OAuth app this secret belongs to"),

		// Secret is hashed with Argon2id
		field.String("secret_hash").
			Sensitive().
			NotEmpty().
			Comment("Argon2id hash of the secret"),

		// Prefix for identification (first 8 chars of original secret)
		field.String("secret_prefix").
			MaxLen(12).
			Comment("First few chars for identification"),

		// Lifecycle
		field.Time("expires_at").
			Optional().
			Nillable().
			Comment("When this secret expires"),

		field.Time("last_used_at").
			Optional().
			Nillable(),

		field.Bool("revoked").
			Default(false),

		field.Time("revoked_at").
			Optional().
			Nillable(),

		field.Time("created_at").
			Default(time.Now).
			Immutable(),
	}
}

// Edges of the OAuthAppSecret.
func (OAuthAppSecret) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("app", OAuthApp.Type).
			Ref("secrets").
			Field("app_id").
			Required().
			Unique(),
	}
}

// Indexes of the OAuthAppSecret.
func (OAuthAppSecret) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("app_id"),
		index.Fields("app_id", "revoked"),
	}
}
