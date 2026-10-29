package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
)

// BillingEvent records a payment provider webhook event that has been
// processed, so a redelivered event is applied once. The unique event_id
// is what makes processing once hold across instances.
type BillingEvent struct {
	ent.Schema
}

// Annotations of the BillingEvent.
func (BillingEvent) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_billing_events"},
	}
}

// Mixin of the BillingEvent.
func (BillingEvent) Mixin() []ent.Mixin {
	return []ent.Mixin{
		BaseMixin{},
	}
}

// Fields of the BillingEvent.
func (BillingEvent) Fields() []ent.Field {
	return []ent.Field{
		field.String("event_id").
			NotEmpty().
			MaxLen(255).
			Unique().
			Immutable().
			Comment("The payment provider's event ID"),
	}
}
