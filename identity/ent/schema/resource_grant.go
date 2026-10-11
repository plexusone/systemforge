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

// ResourceGrant holds the schema definition for a principal's role on one
// resource of an organization (ADR-008). A grant gives access to that
// resource without organization-wide access: a principal who is not a
// member of the organization holds a "collaborator" membership while it
// has any grant there.
//
// The resource type is the application's definition name, "{app}_{type}",
// and the resource identifier is the application's own string, so the
// substrate stores grants for resources it knows nothing else about. The
// role is one of the resource roles viewer, contributor and maintainer
// (authz.ResourceRoles); the service validates it, so the column is free
// text and a new resource role needs no migration.
type ResourceGrant struct {
	ent.Schema
}

// Annotations of the ResourceGrant.
func (ResourceGrant) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_resource_grants"},
	}
}

// Mixin of the ResourceGrant.
func (ResourceGrant) Mixin() []ent.Mixin {
	return []ent.Mixin{
		BaseMixin{},
	}
}

// Fields of the ResourceGrant.
func (ResourceGrant) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("principal_id", uuid.UUID{}).
			Comment("The principal holding the role"),
		field.UUID("organization_id", uuid.UUID{}).
			Comment("The resource's organization"),
		field.String("resource_type").
			NotEmpty().
			MaxLen(128).
			Comment("The resource's definition name, {app}_{type}, as declared in the application's vocabulary"),
		field.String("resource_id").
			NotEmpty().
			MaxLen(1024).
			Comment("The application's identifier of the resource"),
		field.String("role").
			NotEmpty().
			Comment("A resource role: viewer, contributor or maintainer"),
		field.UUID("granted_by", uuid.UUID{}).
			Optional().
			Nillable().
			Comment("Principal who made the grant"),
	}
}

// Edges of the ResourceGrant.
func (ResourceGrant) Edges() []ent.Edge {
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
		edge.To("granter", Principal.Type).
			Field("granted_by").
			Unique().
			Annotations(entsql.OnDelete(entsql.SetNull)),
	}
}

// Indexes of the ResourceGrant.
func (ResourceGrant) Indexes() []ent.Index {
	return []ent.Index{
		// One role per principal per resource.
		index.Fields("principal_id", "resource_type", "resource_id").
			Unique(),
		// A principal's grants in an organization: the last-grant test and
		// the collaborator listing.
		index.Fields("organization_id", "principal_id"),
		// ListResources for a type.
		index.Fields("resource_type", "principal_id"),
		// ListResourceGrants for one resource.
		index.Fields("resource_type", "resource_id"),
	}
}
