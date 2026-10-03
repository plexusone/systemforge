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

// RefreshToken holds the schema definition for the RefreshToken entity.
// It tracks JWT refresh tokens for token rotation and revocation.
type RefreshToken struct {
	ent.Schema
}

// Annotations of the RefreshToken.
func (RefreshToken) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_refresh_tokens"},
	}
}

// Mixin of the RefreshToken.
func (RefreshToken) Mixin() []ent.Mixin {
	return []ent.Mixin{
		BaseMixin{},
	}
}

// Fields of the RefreshToken.
func (RefreshToken) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("user_id", uuid.UUID{}),
		field.String("token").
			NotEmpty().
			Unique().
			Sensitive().
			Comment("Opaque refresh token value"),
		field.String("family").
			NotEmpty().
			Comment("Token family for rotation tracking"),
		field.Time("expires_at").
			Comment("Token expiration time"),
		field.Bool("revoked").
			Default(false).
			Comment("Whether the token has been revoked"),
		field.String("user_agent").
			Optional().
			Comment("Client user agent for audit"),
		field.String("ip_address").
			Optional().
			Comment("Client IP address for audit"),
	}
}

// Edges of the RefreshToken.
func (RefreshToken) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("refresh_tokens").
			Field("user_id").
			Required().
			Unique(),
	}
}

// Indexes of the RefreshToken.
func (RefreshToken) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("token").
			Unique(),
		index.Fields("user_id"),
		index.Fields("family"),
		index.Fields("expires_at"),
		index.Fields("revoked"),
	}
}
