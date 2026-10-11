package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// AccessChange holds the schema definition for a record that a
// principal's access was reduced or ended (ADR-010). Relying parties
// refuse tokens issued before a recorded change, so the record outlives
// the change only for as long as such a token could exist; rows older than
// that are pruned (accesschange.Prune).
//
// The principal and organization are plain identifiers, not edges: a row
// is written in the transaction that deletes or deactivates the thing it
// describes, and must survive it.
type AccessChange struct {
	ent.Schema
}

// Annotations of the AccessChange.
func (AccessChange) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_access_changes"},
	}
}

// Mixin of the AccessChange.
func (AccessChange) Mixin() []ent.Mixin {
	return []ent.Mixin{
		// Rows are read back oldest first; v7 IDs keep that order when
		// changed_at ties on a coarse clock.
		TimeOrderedUUIDMixin{},
	}
}

// Fields of the AccessChange.
func (AccessChange) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("principal_id", uuid.UUID{}).
			Immutable().
			Comment("The principal whose access changed"),
		field.UUID("organization_id", uuid.UUID{}).
			Optional().
			Nillable().
			Immutable().
			Comment("The organization the change is scoped to; null means every organization"),
		field.Time("changed_at").
			Default(time.Now).
			Immutable().
			Comment("When the change was recorded, on the server clock"),
		// A string rather than an enum so that adding a reason is a code
		// change only. The reasons are the registry in
		// identity/accesschange, which accesschange.Record enforces.
		field.String("reason").
			NotEmpty().
			MaxLen(64).
			Immutable().
			Comment("Why access changed; a reason from the identity/accesschange registry"),
	}
}

// Indexes of the AccessChange.
func (AccessChange) Indexes() []ent.Index {
	return []ent.Index{
		// Pollers and replay read the rows newer than a timestamp.
		index.Fields("changed_at"),
	}
}
