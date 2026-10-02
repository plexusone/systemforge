package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/index"

	"github.com/plexusone/systemforge/identity/ent/mixin"
)

// License holds the schema definition for a marketplace license entitlement.
type License struct {
	ent.Schema
}

// Annotations of the License.
func (License) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_licenses"},
	}
}

// Mixin of the License.
func (License) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.LicenseMixin{},
	}
}

// Fields of the License.
func (License) Fields() []ent.Field {
	// All fields provided by LicenseMixin
	return nil
}

// Edges of the License.
func (License) Edges() []ent.Edge {
	return []ent.Edge{
		// Listing this license is for
		edge.From("listing", Listing.Type).
			Ref("licenses").
			Field("listing_id").
			Required().
			Unique().
			Comment("The marketplace listing this license grants access to"),

		// Organization that holds this license
		edge.From("organization", Organization.Type).
			Ref("licenses").
			Field("organization_id").
			Required().
			Unique().
			Comment("Organization that holds this license"),

		// Principal who purchased
		edge.From("purchaser", Principal.Type).
			Ref("purchased_licenses").
			Field("purchased_by").
			Required().
			Unique().
			Comment("Principal who purchased this license"),

		// Seat assignments
		edge.To("seat_assignments", SeatAssignment.Type).
			Comment("Seats assigned from this license"),
	}
}

// Indexes of the License.
func (License) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("listing_id"),
		index.Fields("organization_id"),
		index.Fields("purchased_by"),
		index.Fields("license_type"),
		index.Fields("valid_from", "valid_until"),
		index.Fields("stripe_subscription_id"),
		// Unique constraint: one license per listing per org
		index.Fields("listing_id", "organization_id").
			Unique(),
	}
}
