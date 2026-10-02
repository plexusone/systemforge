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

// ServiceAccount represents a non-human identity for server-to-server OAuth.
// Used with JWT Bearer grant (RFC 7523) for machine-to-machine authentication.
type ServiceAccount struct {
	ent.Schema
}

// Annotations of the ServiceAccount.
func (ServiceAccount) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_service_accounts"},
	}
}

// Fields of the ServiceAccount.
func (ServiceAccount) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),

		// Identification
		field.String("name").
			NotEmpty().
			MaxLen(255).
			Comment("Human-readable name"),

		field.String("description").
			Optional().
			MaxLen(1000),

		// Unique email-like identifier for JWT "sub" claim
		field.String("email").
			Unique().
			NotEmpty().
			Comment("Unique identifier (e.g., mybot@myorg.serviceaccount.local)"),

		// Ownership
		field.UUID("organization_id", uuid.UUID{}).
			Comment("Organization this service account belongs to"),

		field.UUID("created_by", uuid.UUID{}).
			Comment("User who created this service account"),

		// What this SA can do
		field.JSON("allowed_scopes", []string{}).
			Default([]string{}).
			Comment("Scopes this SA can request"),

		// Lifecycle
		field.Bool("active").
			Default(true),

		field.Time("last_used_at").
			Optional().
			Nillable(),

		// Timestamps
		field.Time("created_at").
			Default(time.Now).
			Immutable(),

		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}

// Edges of the ServiceAccount.
func (ServiceAccount) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("organization", Organization.Type).
			Ref("service_accounts").
			Field("organization_id").
			Required().
			Unique(),

		edge.From("creator", User.Type).
			Ref("created_service_accounts").
			Field("created_by").
			Required().
			Unique(),

		edge.To("key_pairs", ServiceAccountKeyPair.Type),
	}
}

// Indexes of the ServiceAccount.
func (ServiceAccount) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("email").Unique(),
		index.Fields("organization_id"),
		index.Fields("active"),
	}
}
