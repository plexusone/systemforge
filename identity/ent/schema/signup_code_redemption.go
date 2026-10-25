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

// SignupCodeRedemption holds the schema definition for an account created
// with a sign-up code. It records which code admitted which principal, so a
// deployment can tell which cohort or member each account came from.
type SignupCodeRedemption struct {
	ent.Schema
}

// Annotations of the SignupCodeRedemption.
func (SignupCodeRedemption) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_signup_code_redemptions"},
	}
}

// Mixin of the SignupCodeRedemption.
func (SignupCodeRedemption) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeOrderedUUIDMixin{},
	}
}

// Fields of the SignupCodeRedemption.
func (SignupCodeRedemption) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("code_id", uuid.UUID{}).
			Immutable().
			Comment("The code that admitted the account"),
		field.UUID("principal_id", uuid.UUID{}).
			Immutable().
			Comment("The principal created with the code; not a foreign key, so it survives deletion"),
		field.String("email").
			NotEmpty().
			Immutable().
			Comment("Verified email of the account when it was created, lower-case"),
		field.Time("created_at").
			Default(time.Now).
			Immutable().
			Comment("When the account was created"),
	}
}

// Edges of the SignupCodeRedemption.
func (SignupCodeRedemption) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("code", SignupCode.Type).
			Ref("redemptions").
			Field("code_id").
			Required().
			Unique().
			Immutable(),
	}
}

// Indexes of the SignupCodeRedemption.
func (SignupCodeRedemption) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("code_id"),
		index.Fields("principal_id"),
		index.Fields("created_at"),
	}
}
