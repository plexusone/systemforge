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

// PrincipalMembership holds the schema definition for principal-organization memberships.
// This extends the existing Membership concept to support all principal types.
type PrincipalMembership struct {
	ent.Schema
}

// Annotations of the PrincipalMembership.
func (PrincipalMembership) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_principal_memberships"},
	}
}

// Mixin of the PrincipalMembership.
func (PrincipalMembership) Mixin() []ent.Mixin {
	return []ent.Mixin{
		BaseMixin{},
	}
}

// Fields of the PrincipalMembership.
func (PrincipalMembership) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("principal_id", uuid.UUID{}),
		field.UUID("organization_id", uuid.UUID{}),

		field.String("role").
			NotEmpty().
			Comment("App-defined role (e.g., owner, admin, member)"),

		field.JSON("permissions", []string{}).
			Optional().
			Comment("Optional fine-grained permissions"),

		// Active status for soft-delete
		field.Bool("active").
			Default(true).
			Comment("Whether this membership is active"),
	}
}

// Edges of the PrincipalMembership.
func (PrincipalMembership) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("principal", Principal.Type).
			Ref("principal_memberships").
			Field("principal_id").
			Required().
			Unique(),

		edge.From("organization", Organization.Type).
			Ref("principal_memberships").
			Field("organization_id").
			Required().
			Unique(),
	}
}

// Indexes of the PrincipalMembership.
func (PrincipalMembership) Indexes() []ent.Index {
	return []ent.Index{
		// One membership per principal per organization
		index.Fields("principal_id", "organization_id").
			Unique(),
		index.Fields("principal_id"),
		index.Fields("organization_id"),
		index.Fields("role"),
		index.Fields("active"),
	}
}
