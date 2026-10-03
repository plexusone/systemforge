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

// ServicePrincipal holds the schema definition for backend service-specific principal data.
// This is a one-to-one extension of Principal where type="service".
type ServicePrincipal struct {
	ent.Schema
}

// Annotations of the ServicePrincipal.
func (ServicePrincipal) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_service_principals"},
	}
}

// Mixin of the ServicePrincipal.
func (ServicePrincipal) Mixin() []ent.Mixin {
	return []ent.Mixin{
		BaseMixin{},
	}
}

// Fields of the ServicePrincipal.
func (ServicePrincipal) Fields() []ent.Field {
	return []ent.Field{
		// Foreign key to Principal
		field.UUID("principal_id", uuid.UUID{}).
			Unique().
			Immutable().
			Comment("Reference to parent Principal"),

		// Service identification
		field.String("service_type").
			NotEmpty().
			Comment("Type of service (e.g., backend, worker, gateway)"),

		field.String("description").
			Optional().
			MaxLen(1000).
			Comment("Service description"),

		// Audit
		field.UUID("created_by", uuid.UUID{}).
			Optional().
			Nillable().
			Comment("Principal who created this service account"),

		field.Time("last_used_at").
			Optional().
			Nillable().
			Comment("Last time this service account was used"),

		// Network restrictions
		field.JSON("allowed_ips", []string{}).
			Default([]string{}).
			Comment("IP addresses/CIDRs allowed to use this service account"),
	}
}

// Edges of the ServicePrincipal.
func (ServicePrincipal) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("principal", Principal.Type).
			Ref("service_principal").
			Field("principal_id").
			Required().
			Unique().
			Immutable(),

		// The principal who created this service account
		edge.To("creator", Principal.Type).
			Field("created_by").
			Unique().
			Comment("Principal who created this service account"),
	}
}

// Indexes of the ServicePrincipal.
func (ServicePrincipal) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("principal_id").Unique(),
		index.Fields("service_type"),
		index.Fields("created_by"),
	}
}
