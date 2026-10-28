package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// BillingSeller is a selling organization's connected payment account and
// what the provider last said it may do. A seller's paid listings can be
// published and bought only while charges_enabled.
type BillingSeller struct {
	ent.Schema
}

// Annotations of the BillingSeller.
func (BillingSeller) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_billing_sellers"},
	}
}

// Mixin of the BillingSeller.
func (BillingSeller) Mixin() []ent.Mixin {
	return []ent.Mixin{
		BaseMixin{},
	}
}

// Fields of the BillingSeller.
func (BillingSeller) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("organization_id", uuid.UUID{}).
			Unique().
			Comment("The selling organization"),
		field.String("account_id").
			NotEmpty().
			MaxLen(255).
			Unique().
			Comment("The provider's connected account ID"),
		field.Bool("charges_enabled").
			Default(false),
		field.Bool("payouts_enabled").
			Default(false),
		field.Bool("details_submitted").
			Default(false),
	}
}
