package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// SignupAllowance holds the schema definition for how many people a member
// may invite while a deployment is invite-only. A member without a row, or
// whose row has no granted value, has the deployment's default allowance.
// The member's codes that are redeemed, or neither revoked nor expired,
// count against it. Creating a member code locks the member's row, so
// concurrent requests cannot exceed the allowance.
type SignupAllowance struct {
	ent.Schema
}

// Annotations of the SignupAllowance.
func (SignupAllowance) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_signup_allowances"},
	}
}

// Mixin of the SignupAllowance.
func (SignupAllowance) Mixin() []ent.Mixin {
	return []ent.Mixin{
		BaseMixin{},
	}
}

// Fields of the SignupAllowance.
func (SignupAllowance) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("principal_id", uuid.UUID{}).
			Unique().
			Immutable().
			Comment("The member; not a foreign key, so it survives deletion"),
		field.Int("granted").
			Optional().
			Nillable().
			NonNegative().
			Comment("How many invite codes the member may hold; nil means the deployment's default"),
		field.String("note").
			Optional().
			MaxLen(500).
			Comment("Free-text context for operators"),
		field.UUID("set_by_principal_id", uuid.UUID{}).
			Optional().
			Nillable().
			Comment("The operator who last set the allowance"),
	}
}
