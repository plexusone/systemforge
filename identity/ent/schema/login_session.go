package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// LoginSession holds SystemAuth browser login sessions (the __Host-sf_login
// cookie). Only a SHA-256 hash of the opaque session token is stored.
type LoginSession struct {
	ent.Schema
}

// Annotations of the LoginSession.
func (LoginSession) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_login_sessions"},
	}
}

// Fields of the LoginSession.
func (LoginSession) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),

		field.String("token_hash").
			Unique().
			Immutable().
			Comment("Hex SHA-256 of the session token; the token itself is never stored"),

		field.UUID("principal_id", uuid.UUID{}).
			Immutable().
			Comment("Authenticated principal"),

		field.String("provider").
			Optional().
			Immutable().
			Comment("Upstream provider used to sign in"),

		field.Time("created_at").
			Immutable().
			Comment("When the session was established"),

		field.Time("expires_at").
			Immutable().
			Comment("Absolute session expiry"),
	}
}

// Indexes of the LoginSession.
func (LoginSession) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("principal_id"),
		index.Fields("expires_at"),
	}
}
