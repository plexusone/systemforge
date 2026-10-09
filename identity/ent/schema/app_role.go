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

// AppRole holds the schema definition for a principal's role in one
// application of an organization. The role is one of the roles the
// application declares in its authz.AppVocabulary; the service validates
// it, so the column is free text and new application roles need no
// migration.
type AppRole struct {
	ent.Schema
}

// Annotations of the AppRole.
func (AppRole) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_app_roles"},
	}
}

// Mixin of the AppRole.
func (AppRole) Mixin() []ent.Mixin {
	return []ent.Mixin{
		BaseMixin{},
	}
}

// Fields of the AppRole.
func (AppRole) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("principal_id", uuid.UUID{}).
			Comment("The principal holding the role"),
		field.UUID("organization_id", uuid.UUID{}).
			Comment("The organization the role is held in"),
		field.String("application").
			NotEmpty().
			Comment("Application identifier as registered in authz.VocabularyRegistry"),
		field.String("role").
			NotEmpty().
			Comment("A role from the application's AppVocabulary"),
		field.UUID("assigned_by", uuid.UUID{}).
			Optional().
			Nillable().
			Comment("Principal who made the assignment"),
	}
}

// Edges of the AppRole.
func (AppRole) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("principal", Principal.Type).
			Field("principal_id").
			Required().
			Unique().
			Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.To("organization", Organization.Type).
			Field("organization_id").
			Required().
			Unique().
			Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.To("assigner", Principal.Type).
			Field("assigned_by").
			Unique().
			Annotations(entsql.OnDelete(entsql.SetNull)),
	}
}

// Indexes of the AppRole.
func (AppRole) Indexes() []ent.Index {
	return []ent.Index{
		// One role per principal per application per organization.
		index.Fields("principal_id", "organization_id", "application").
			Unique(),
		// Listing an organization's roles and counting an application's.
		index.Fields("organization_id", "application"),
	}
}
