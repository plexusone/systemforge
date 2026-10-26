package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
)

// SignupWaitlistEntry holds the schema definition for an address that asked
// to be told when sign-up opens, while a deployment is invite-only. It
// records the consent text the person saw and its version, so an operator
// can show what they agreed to. The email is stored lower-case, once.
type SignupWaitlistEntry struct {
	ent.Schema
}

// Annotations of the SignupWaitlistEntry.
func (SignupWaitlistEntry) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_signup_waitlist"},
	}
}

// Mixin of the SignupWaitlistEntry.
func (SignupWaitlistEntry) Mixin() []ent.Mixin {
	return []ent.Mixin{
		BaseMixin{},
	}
}

// Fields of the SignupWaitlistEntry.
func (SignupWaitlistEntry) Fields() []ent.Field {
	return []ent.Field{
		field.String("email").
			NotEmpty().
			Unique().
			MaxLen(320).
			Comment("Address to notify, lower-case"),
		field.String("consent_version").
			MaxLen(64).
			Comment("Version of the consent text shown when the address was last submitted"),
		field.String("consent_text").
			MaxLen(2000).
			Comment("The consent text shown when the address was last submitted"),
		field.Time("invited_at").
			Optional().
			Nillable().
			Comment("When an operator invited the address from the waitlist"),
	}
}
