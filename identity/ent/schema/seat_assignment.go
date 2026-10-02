package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/index"

	"github.com/plexusone/systemforge/identity/ent/mixin"
)

// SeatAssignment holds the schema definition for a license seat assignment.
type SeatAssignment struct {
	ent.Schema
}

// Annotations of the SeatAssignment.
func (SeatAssignment) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_seat_assignments"},
	}
}

// Mixin of the SeatAssignment.
func (SeatAssignment) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.SeatAssignmentMixin{},
	}
}

// Fields of the SeatAssignment.
func (SeatAssignment) Fields() []ent.Field {
	// All fields provided by SeatAssignmentMixin
	return nil
}

// Edges of the SeatAssignment.
func (SeatAssignment) Edges() []ent.Edge {
	return []ent.Edge{
		// License this seat belongs to
		edge.From("license", License.Type).
			Ref("seat_assignments").
			Field("license_id").
			Required().
			Unique().
			Comment("The license this seat belongs to"),

		// Principal assigned to this seat
		edge.From("principal", Principal.Type).
			Ref("seat_assignments").
			Field("principal_id").
			Required().
			Unique().
			Comment("The principal assigned to this seat"),

		// Principal who made the assignment
		edge.From("assigner", Principal.Type).
			Ref("assigned_seats").
			Field("assigned_by").
			Required().
			Unique().
			Comment("Principal who made this assignment"),
	}
}

// Indexes of the SeatAssignment.
func (SeatAssignment) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("license_id"),
		index.Fields("principal_id"),
		index.Fields("assigned_by"),
		// Unique: one principal per license
		index.Fields("license_id", "principal_id").
			Unique(),
	}
}
