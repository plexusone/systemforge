package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// BillingDispute is a buyer's dispute of a charge with their bank. While
// one is open, or once it is lost, what the charge bought is suspended.
// Events can arrive out of order, so a closed dispute stays closed.
type BillingDispute struct {
	ent.Schema
}

// Annotations of the BillingDispute.
func (BillingDispute) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_billing_disputes"},
	}
}

// Mixin of the BillingDispute.
func (BillingDispute) Mixin() []ent.Mixin {
	return []ent.Mixin{
		BaseMixin{},
	}
}

// Fields of the BillingDispute.
func (BillingDispute) Fields() []ent.Field {
	return []ent.Field{
		field.String("dispute_id").
			NotEmpty().
			MaxLen(255).
			Unique().
			Immutable(),
		field.String("charge_id").
			Optional().
			MaxLen(255),
		field.String("payment_intent").
			Optional().
			MaxLen(255),
		field.Bool("closed").
			Default(false),
		field.Bool("lost").
			Default(false),
	}
}

// Indexes of the BillingDispute.
func (BillingDispute) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("payment_intent"),
	}
}
