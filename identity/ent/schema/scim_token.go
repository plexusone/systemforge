package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// ScimToken is a bearer token a tenant organization's identity provider
// presents to the SCIM API. Only a SHA-256 hash of the token is stored; the
// plaintext is shown once, when the token is issued.
//
// Tokens of one organization are numbered by generation. The unique
// (organization_id, generation) index makes concurrent rotations of one
// organization conflict, so at most one of them commits.
type ScimToken struct {
	ent.Schema
}

// Annotations of the ScimToken.
func (ScimToken) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_scim_tokens"},
	}
}

// Mixin of the ScimToken.
func (ScimToken) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeOrderedUUIDMixin{},
	}
}

// Fields of the ScimToken.
func (ScimToken) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("organization_id", uuid.UUID{}).
			Immutable().
			Comment("Tenant organization the token provisions"),

		field.Int("generation").
			Positive().
			Immutable().
			Comment("Issue order within the organization, starting at 1"),

		field.String("token_prefix").
			NotEmpty().
			MaxLen(32).
			Immutable().
			Comment("Leading characters of the token, not secret, for display"),

		field.String("token_hash").
			NotEmpty().
			Sensitive().
			Unique().
			Immutable().
			Comment("Hex SHA-256 of the token"),

		field.String("description").
			Optional().
			MaxLen(255),

		field.UUID("created_by", uuid.UUID{}).
			Optional().
			Nillable().
			Immutable().
			Comment("Principal that issued the token"),

		field.Time("created_at").
			Default(time.Now).
			Immutable(),

		field.Time("last_used_at").
			Optional().
			Nillable().
			Comment("Last successful authentication, recorded at most once a minute"),

		field.Time("expires_at").
			Optional().
			Nillable().
			Immutable(),

		field.Time("revoked_at").
			Optional().
			Nillable(),

		field.UUID("revoked_by", uuid.UUID{}).
			Optional().
			Nillable().
			Comment("Principal that revoked the token; empty when a rotation did"),
	}
}

// Indexes of the ScimToken.
func (ScimToken) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("organization_id", "generation").Unique(),
		index.Fields("organization_id", "revoked_at"),
	}
}
