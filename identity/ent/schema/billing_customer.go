package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// BillingCustomer maps a payment provider customer to the organization
// that pays through it. Each organization has at most one customer, and a
// customer belongs to one organization.
type BillingCustomer struct {
	ent.Schema
}

// Annotations of the BillingCustomer.
func (BillingCustomer) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_billing_customers"},
	}
}

// Mixin of the BillingCustomer.
func (BillingCustomer) Mixin() []ent.Mixin {
	return []ent.Mixin{
		BaseMixin{},
	}
}

// Fields of the BillingCustomer.
func (BillingCustomer) Fields() []ent.Field {
	return []ent.Field{
		field.String("customer_id").
			NotEmpty().
			MaxLen(255).
			Unique().
			Comment("The payment provider's customer ID"),
		field.UUID("organization_id", uuid.UUID{}).
			Unique().
			Comment("The organization that pays through the customer"),
	}
}
