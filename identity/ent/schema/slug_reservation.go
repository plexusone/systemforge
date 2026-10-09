package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// SlugReservation holds the schema definition for a slug an organization
// gave up. For the cooling-off period the slug resolves to the organization
// that released it, and only the principal who released it (or an
// organization that principal owns) may take it again (ADR-006).
type SlugReservation struct {
	ent.Schema
}

// Annotations of the SlugReservation.
func (SlugReservation) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_slug_reservations"},
	}
}

// Mixin of the SlugReservation.
func (SlugReservation) Mixin() []ent.Mixin {
	return []ent.Mixin{
		BaseMixin{},
	}
}

// Fields of the SlugReservation.
func (SlugReservation) Fields() []ent.Field {
	return []ent.Field{
		field.String("slug").
			NotEmpty().
			Unique().
			Comment("The reserved slug"),
		field.UUID("released_by_principal_id", uuid.UUID{}).
			Comment("The principal who released the slug; may reclaim it"),
		field.UUID("released_from_organization_id", uuid.UUID{}).
			Optional().
			Nillable().
			Comment("The organization that held the slug; the slug resolves to it until expiry"),
		field.Time("released_at").
			Default(time.Now).
			Comment("When the slug was released"),
		field.Time("expires_at").
			Comment("When the reservation ends"),
	}
}

// Edges of the SlugReservation.
func (SlugReservation) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("released_by", Principal.Type).
			Field("released_by_principal_id").
			Required().
			Unique().
			Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.To("released_from", Organization.Type).
			Field("released_from_organization_id").
			Unique().
			Annotations(entsql.OnDelete(entsql.SetNull)),
	}
}

// Indexes of the SlugReservation.
func (SlugReservation) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("expires_at"),
	}
}
