package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// BillingOrder records a one-time checkout for a marketplace listing when
// the checkout is created, so the paid checkout and any later refund are
// matched to the listing, organization and purchaser from this record
// rather than from metadata the provider sends back.
type BillingOrder struct {
	ent.Schema
}

// Annotations of the BillingOrder.
func (BillingOrder) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_billing_orders"},
	}
}

// Mixin of the BillingOrder.
func (BillingOrder) Mixin() []ent.Mixin {
	return []ent.Mixin{
		BaseMixin{},
	}
}

// Fields of the BillingOrder.
func (BillingOrder) Fields() []ent.Field {
	return []ent.Field{
		field.String("session_id").
			NotEmpty().
			MaxLen(255).
			Unique().
			Immutable().
			Comment("The provider's checkout session ID"),
		field.UUID("listing_id", uuid.UUID{}).
			Immutable(),
		field.UUID("organization_id", uuid.UUID{}).
			Immutable().
			Comment("The buying organization"),
		field.UUID("purchaser_id", uuid.UUID{}).
			Immutable().
			Comment("The principal who started the checkout"),
		field.Int64("amount_cents").
			Immutable(),
		field.Enum("status").
			Values("pending", "paid", "refunded").
			Default("pending"),
		field.String("payment_intent").
			Optional().
			Nillable().
			MaxLen(255).
			Comment("The provider's payment, recorded when the checkout is paid"),
		field.UUID("license_id", uuid.UUID{}).
			Optional().
			Nillable().
			Comment("The license the paid order granted"),
	}
}

// Indexes of the BillingOrder.
func (BillingOrder) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("payment_intent"),
		index.Fields("listing_id", "organization_id"),
	}
}
