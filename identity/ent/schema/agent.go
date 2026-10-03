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

// Agent holds the schema definition for AI agent-specific principal data.
// This is a one-to-one extension of Principal where type="agent".
type Agent struct {
	ent.Schema
}

// Annotations of the Agent.
func (Agent) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_agents"},
	}
}

// Mixin of the Agent.
func (Agent) Mixin() []ent.Mixin {
	return []ent.Mixin{
		BaseMixin{},
	}
}

// Fields of the Agent.
func (Agent) Fields() []ent.Field {
	return []ent.Field{
		// Foreign key to Principal
		field.UUID("principal_id", uuid.UUID{}).
			Unique().
			Immutable().
			Comment("Reference to parent Principal"),

		// Agent identification
		field.String("model_id").
			NotEmpty().
			Comment("AI model identifier (e.g., claude-3-opus)"),

		field.String("version").
			Optional().
			Comment("Agent version"),

		// Delegation - who authorized this agent
		field.UUID("delegating_principal_id", uuid.UUID{}).
			Optional().
			Nillable().
			Comment("Principal who delegated authority to this agent"),

		// Constraints on what the agent can do
		field.JSON("capability_constraints", []string{}).
			Default([]string{}).
			Comment("Capabilities this agent is constrained to"),

		field.JSON("resource_constraints", []string{}).
			Default([]string{}).
			Comment("Resources this agent can access"),

		// Token lifetime limits
		field.Int("max_token_lifetime").
			Default(3600).
			Comment("Maximum token lifetime in seconds (default 1 hour)"),

		// Session tracking
		field.String("session_id").
			Optional().
			Nillable().
			Comment("Current session identifier"),

		// Approval requirements
		field.Bool("requires_confirmation").
			Default(true).
			Comment("Whether actions require human confirmation"),
	}
}

// Edges of the Agent.
func (Agent) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("principal", Principal.Type).
			Ref("agent").
			Field("principal_id").
			Required().
			Unique().
			Immutable(),

		// The principal who delegated authority (self-reference through Principal)
		edge.To("delegating_principal", Principal.Type).
			Field("delegating_principal_id").
			Unique().
			Comment("Principal who authorized this agent"),
	}
}

// Indexes of the Agent.
func (Agent) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("principal_id").Unique(),
		index.Fields("model_id"),
		index.Fields("delegating_principal_id"),
		index.Fields("session_id"),
		index.Fields("requires_confirmation"),
	}
}
