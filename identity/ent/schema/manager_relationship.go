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

// ManagerRelationship records that one human principal manages another
// (ADR-005). A managed principal, a human without an email, always has at
// least one active manager, and a manager is a human with an email.
type ManagerRelationship struct {
	ent.Schema
}

// Annotations of the ManagerRelationship.
func (ManagerRelationship) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_manager_relationships"},
	}
}

// Mixin of the ManagerRelationship.
func (ManagerRelationship) Mixin() []ent.Mixin {
	return []ent.Mixin{
		BaseMixin{},
	}
}

// Fields of the ManagerRelationship.
func (ManagerRelationship) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("managed_principal_id", uuid.UUID{}).
			Immutable().
			Comment("The principal being managed"),

		field.UUID("manager_principal_id", uuid.UUID{}).
			Immutable().
			Comment("The managing principal"),

		field.String("role").
			NotEmpty().
			Immutable().
			Comment("Manager role, such as guardian or educator"),

		field.Bool("active").
			Default(true).
			Comment("Whether the relationship is in effect"),

		field.UUID("created_by", uuid.UUID{}).
			Optional().
			Nillable().
			Immutable().
			Comment("Principal that established the relationship"),
	}
}

// Edges of the ManagerRelationship.
func (ManagerRelationship) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("managed", Principal.Type).
			Ref("managers").
			Field("managed_principal_id").
			Required().
			Unique().
			Immutable(),

		edge.From("manager", Principal.Type).
			Ref("managing").
			Field("manager_principal_id").
			Required().
			Unique().
			Immutable(),
	}
}

// Indexes of the ManagerRelationship.
func (ManagerRelationship) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("managed_principal_id", "manager_principal_id", "role").Unique(),
		index.Fields("manager_principal_id"),
	}
}
