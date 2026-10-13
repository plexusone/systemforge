package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// SignupInvite holds the schema definition for a platform sign-up invite: a
// verified email address that may create an account while a deployment is
// invite-only. It is not an organization invite (Invite), which adds a
// person to an organization; a SignupInvite lets a person into the
// deployment at all.
//
// The email is stored lower-case, and an invite is consumed by the first
// account created with it.
type SignupInvite struct {
	ent.Schema
}

// Annotations of the SignupInvite.
func (SignupInvite) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_signup_invites"},
	}
}

// Mixin of the SignupInvite.
func (SignupInvite) Mixin() []ent.Mixin {
	return []ent.Mixin{
		BaseMixin{},
	}
}

// Fields of the SignupInvite.
func (SignupInvite) Fields() []ent.Field {
	return []ent.Field{
		field.String("email").
			NotEmpty().
			Unique().
			Comment("Invited email address, lower-case; matched against the verified email of the upstream login"),
		field.String("note").
			Optional().
			MaxLen(500).
			Comment("Free-text context for operators, such as who asked for the invite"),
		field.String("invited_by").
			Optional().
			MaxLen(255).
			Comment("Operator label that created the invite"),
		field.Time("expires_at").
			Optional().
			Nillable().
			Comment("When the invite stops working; nil means it does not expire"),
		field.Time("redeemed_at").
			Optional().
			Nillable().
			Comment("When an account was created with the invite"),
		field.UUID("redeemed_by", uuid.UUID{}).
			Optional().
			Nillable().
			Comment("The principal created with the invite; not a foreign key, so it survives deletion"),
	}
}

// Indexes of the SignupInvite.
func (SignupInvite) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("redeemed_at"),
		index.Fields("expires_at"),
	}
}
