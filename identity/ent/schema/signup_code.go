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

// SignupCode holds the schema definition for a platform sign-up invite
// code: a shareable code that lets up to max_uses people create an account
// while a deployment is invite-only. Unlike a SignupInvite it is not tied to
// an email address. Only a hash of the code is stored; the code itself is
// shown once, when it is created.
//
// An operator code may admit many people and carries a label naming the
// cohort. A member code is created by a member from their allowance
// (SignupAllowance) and admits one person.
type SignupCode struct {
	ent.Schema
}

// Annotations of the SignupCode.
func (SignupCode) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_signup_codes"},
	}
}

// Mixin of the SignupCode.
func (SignupCode) Mixin() []ent.Mixin {
	return []ent.Mixin{
		BaseMixin{},
	}
}

// Fields of the SignupCode.
func (SignupCode) Fields() []ent.Field {
	return []ent.Field{
		field.String("code_hash").
			NotEmpty().
			Unique().
			Immutable().
			Sensitive().
			Comment("Hex SHA-256 of the normalized code"),
		field.String("code_hint").
			MaxLen(4).
			Immutable().
			Comment("Last four characters of the code, to tell codes apart in lists"),
		field.Enum("kind").
			Values("operator", "member").
			Immutable().
			Comment("operator: created by an operator; member: created by a member from their allowance"),
		field.String("label").
			Optional().
			MaxLen(100).
			Comment("Cohort name, such as launch-week"),
		field.String("note").
			Optional().
			MaxLen(500).
			Comment("Free-text context for operators"),
		field.UUID("created_by_principal_id", uuid.UUID{}).
			Optional().
			Nillable().
			Immutable().
			Comment("The principal that created the code; not a foreign key, so it survives deletion"),
		field.String("created_by_label").
			Optional().
			MaxLen(255).
			Immutable().
			Comment("Operator label, for codes created from the command line"),
		field.Int("max_uses").
			Positive().
			Comment("How many accounts the code may create"),
		field.Int("use_count").
			NonNegative().
			Default(0).
			Comment("Uses reserved or redeemed; never more than max_uses"),
		field.Time("expires_at").
			Optional().
			Nillable().
			Comment("When the code stops working; nil means it does not expire"),
		field.Time("revoked_at").
			Optional().
			Nillable().
			Comment("When the code was revoked"),
	}
}

// Edges of the SignupCode.
func (SignupCode) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("redemptions", SignupCodeRedemption.Type),
	}
}

// Indexes of the SignupCode.
func (SignupCode) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("created_by_principal_id"),
		index.Fields("label"),
		index.Fields("expires_at"),
	}
}
