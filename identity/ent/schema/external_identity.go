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

// ExternalIdentity links a Principal to an upstream login identity
// (e.g. a GitHub or Google account). The (provider, subject) pair is the
// stable key used to find the principal on every social login; email is
// recorded for information and verified-email linking only.
type ExternalIdentity struct {
	ent.Schema
}

// Annotations of the ExternalIdentity.
func (ExternalIdentity) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_external_identities"},
	}
}

// Mixin of the ExternalIdentity.
func (ExternalIdentity) Mixin() []ent.Mixin {
	return []ent.Mixin{
		BaseMixin{},
	}
}

// Fields of the ExternalIdentity.
func (ExternalIdentity) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("principal_id", uuid.UUID{}).
			Comment("Principal this upstream identity is linked to"),
		field.String("provider").
			NotEmpty().
			Immutable().
			Comment("Upstream provider name (e.g., github, google)"),
		field.String("subject").
			NotEmpty().
			Immutable().
			Comment("Stable user ID at the provider (GitHub numeric id, Google sub)"),
		field.String("email").
			Optional().
			Comment("Email last reported by the provider"),
		field.Bool("email_verified").
			Default(false).
			Comment("Whether the provider asserted the email is verified"),
		field.Time("last_login_at").
			Optional().
			Nillable().
			Comment("Last successful login through this identity"),
	}
}

// Edges of the ExternalIdentity.
func (ExternalIdentity) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("principal", Principal.Type).
			Ref("external_identities").
			Field("principal_id").
			Required().
			Unique(),
	}
}

// Indexes of the ExternalIdentity.
func (ExternalIdentity) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("provider", "subject").Unique(),
		index.Fields("principal_id"),
	}
}
