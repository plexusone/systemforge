package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// BillingRefund keeps the highest refunded total seen for a charge, and
// whether it was refunded in full. Refund events can arrive out of order
// and before the checkout they refund, so the state is kept apart from
// the order and only ever grows.
type BillingRefund struct {
	ent.Schema
}

// Annotations of the BillingRefund.
func (BillingRefund) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_billing_refunds"},
	}
}

// Mixin of the BillingRefund.
func (BillingRefund) Mixin() []ent.Mixin {
	return []ent.Mixin{
		BaseMixin{},
	}
}

// Fields of the BillingRefund.
func (BillingRefund) Fields() []ent.Field {
	return []ent.Field{
		field.String("charge_id").
			NotEmpty().
			MaxLen(255).
			Unique().
			Immutable(),
		field.String("payment_intent").
			Optional().
			MaxLen(255),
		field.Int64("refunded_cents").
			Default(0),
		field.Bool("full").
			Default(false),
	}
}

// Indexes of the BillingRefund.
func (BillingRefund) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("payment_intent"),
	}
}
