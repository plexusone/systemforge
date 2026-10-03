package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// Membership holds the schema definition for the Membership entity.
// It represents a user's membership in an organization with a specific role.
type Membership struct {
	ent.Schema
}

// Annotations of the Membership.
func (Membership) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_memberships"},
	}
}

// Mixin of the Membership.
func (Membership) Mixin() []ent.Mixin {
	return []ent.Mixin{
		BaseMixin{},
	}
}

// Fields of the Membership.
func (Membership) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("user_id", uuid.UUID{}),
		field.UUID("organization_id", uuid.UUID{}),
		field.String("role").
			NotEmpty().
			Comment("App-defined role (e.g., owner, admin, member, student, instructor)"),
		field.JSON("permissions", []string{}).
			Optional().
			Comment("Optional fine-grained permissions"),
	}
}

// Edges of the Membership.
func (Membership) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("memberships").
			Field("user_id").
			Required().
			Unique(),
		edge.From("organization", Organization.Type).
			Ref("memberships").
			Field("organization_id").
			Required().
			Unique(),
	}
}

// Indexes of the Membership.
func (Membership) Indexes() []ent.Index {
	return []ent.Index{
		// One membership per user per organization
		index.Fields("user_id", "organization_id").
			Unique(),
		index.Fields("user_id"),
		index.Fields("organization_id"),
		index.Fields("role"),
	}
}
