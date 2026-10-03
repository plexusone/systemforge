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

// Human holds the schema definition for human-specific principal data.
// This is a one-to-one extension of Principal where type="human".
type Human struct {
	ent.Schema
}

// Annotations of the Human.
func (Human) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_humans"},
	}
}

// Mixin of the Human.
func (Human) Mixin() []ent.Mixin {
	return []ent.Mixin{
		BaseMixin{},
	}
}

// Fields of the Human.
func (Human) Fields() []ent.Field {
	return []ent.Field{
		// Foreign key to Principal
		field.UUID("principal_id", uuid.UUID{}).
			Unique().
			Immutable().
			Comment("Reference to parent Principal"),

		// Core identity fields
		field.String("email").
			NotEmpty().
			Unique().
			Comment("Primary email address"),

		field.String("given_name").
			Optional().
			Comment("First/given name"),

		field.String("family_name").
			Optional().
			Comment("Last/family name"),

		field.String("avatar_url").
			Optional().
			Nillable().
			Comment("Profile picture URL"),

		// Localization
		field.String("locale").
			Optional().
			Default("en").
			Comment("Preferred locale (e.g., en-US)"),

		field.String("timezone").
			Optional().
			Default("UTC").
			Comment("Preferred timezone (e.g., America/Los_Angeles)"),

		// Administrative flags
		field.Bool("is_platform_admin").
			Default(false).
			Comment("Cross-organization admin access"),

		// Authentication tracking
		field.Time("last_login_at").
			Optional().
			Nillable().
			Comment("Last successful login timestamp"),

		field.Time("email_verified_at").
			Optional().
			Nillable().
			Comment("When email was verified"),
	}
}

// Edges of the Human.
func (Human) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("principal", Principal.Type).
			Ref("human").
			Field("principal_id").
			Required().
			Unique().
			Immutable(),
	}
}

// Indexes of the Human.
func (Human) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("principal_id").Unique(),
		index.Fields("email").Unique(),
		index.Fields("is_platform_admin"),
	}
}
