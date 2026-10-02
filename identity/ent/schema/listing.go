package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/index"

	"github.com/plexusone/systemforge/identity/ent/mixin"
)

// Listing holds the schema definition for a marketplace product listing.
type Listing struct {
	ent.Schema
}

// Annotations of the Listing.
func (Listing) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_listings"},
	}
}

// Mixin of the Listing.
func (Listing) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.ListingMixin{},
	}
}

// Fields of the Listing.
func (Listing) Fields() []ent.Field {
	// All fields provided by ListingMixin
	return nil
}

// Edges of the Listing.
func (Listing) Edges() []ent.Edge {
	return []ent.Edge{
		// Creator organization
		edge.From("creator_org", Organization.Type).
			Ref("listings").
			Field("creator_org_id").
			Required().
			Unique().
			Comment("Organization that created this listing"),

		// Owner principal
		edge.From("owner", Principal.Type).
			Ref("owned_listings").
			Field("owner_id").
			Required().
			Unique().
			Comment("Principal who owns this listing"),

		// Licenses granted from this listing
		edge.To("licenses", License.Type).
			Comment("Licenses granted from this listing"),
	}
}

// Indexes of the Listing.
func (Listing) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("creator_org_id"),
		index.Fields("owner_id"),
		index.Fields("status"),
		index.Fields("pricing_model"),
		index.Fields("product_type"),
		index.Fields("product_type", "product_id"),
		index.Fields("status", "created_at"),
	}
}
