package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// VerificationToken holds SystemAuth's email verification tokens (ADR-003):
// single-use, purpose-scoped and short-lived. Only a SHA-256 hash of the
// token is stored; the token itself exists only in the link that was
// mailed.
type VerificationToken struct {
	ent.Schema
}

// Annotations of the VerificationToken.
func (VerificationToken) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_verification_tokens"},
	}
}

// Fields of the VerificationToken.
func (VerificationToken) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),

		field.String("token_hash").
			Unique().
			Immutable().
			Comment("Hex SHA-256 of the verification token; the token itself is never stored"),

		field.Enum("purpose").
			Values("verify_email", "email_change").
			Immutable().
			Comment("What the token may be used for; a token is never accepted for another purpose"),

		field.String("email").
			NotEmpty().
			Immutable().
			Comment("Address the token was mailed to and verifies"),

		field.UUID("principal_id", uuid.UUID{}).
			Optional().
			Nillable().
			Immutable().
			Comment("Principal the token acts for (email change); null for a pending sign-in"),

		field.String("binding").
			NotEmpty().
			Immutable().
			Comment("What a confirmation must present: a hash of the pending sign-in's browser cookie, or the principal"),

		field.Bytes("data").
			Optional().
			Immutable().
			Sensitive().
			Comment("Purpose-specific payload, such as the pending sign-in"),

		field.Time("created_at").
			Immutable().
			Comment("When the token was issued"),

		field.Time("expires_at").
			Immutable().
			Comment("When the token stops being accepted"),

		field.Time("consumed_at").
			Optional().
			Nillable().
			Comment("When the token was used or revoked; a consumed token is never accepted again"),
	}
}

// Indexes of the VerificationToken.
func (VerificationToken) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("purpose", "binding"),
		index.Fields("expires_at"),
	}
}
