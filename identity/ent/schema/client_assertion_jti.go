package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// ClientAssertionJTI records the JWT IDs of client assertions that have been
// used, so a signed assertion cannot be replayed before it expires
// (RFC 7523 section 3, as required by Fosite's client manager).
type ClientAssertionJTI struct {
	ent.Schema
}

// Annotations of the ClientAssertionJTI.
func (ClientAssertionJTI) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_client_assertion_jtis"},
	}
}

// Mixin of the ClientAssertionJTI.
func (ClientAssertionJTI) Mixin() []ent.Mixin {
	return []ent.Mixin{
		BaseMixin{},
	}
}

// Fields of the ClientAssertionJTI.
func (ClientAssertionJTI) Fields() []ent.Field {
	return []ent.Field{
		field.String("jti").
			NotEmpty().
			Unique().
			Immutable().
			Comment("JWT ID of a used client assertion"),

		field.Time("expires_at").
			Immutable().
			Comment("When the assertion expires; the JTI can be forgotten after this"),
	}
}

// Indexes of the ClientAssertionJTI.
func (ClientAssertionJTI) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("expires_at"),
	}
}
