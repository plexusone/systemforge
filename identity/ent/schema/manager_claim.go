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

// ManagerClaim is a single-use code a manager issues so that a human with
// an email can become guardian of a managed principal (ADR-005). Claims
// are kept apart from credentials so a claim code can never sign anyone
// in.
type ManagerClaim struct {
	ent.Schema
}

// Annotations of the ManagerClaim.
func (ManagerClaim) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_manager_claims"},
	}
}

// Fields of the ManagerClaim.
func (ManagerClaim) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),

		field.UUID("managed_principal_id", uuid.UUID{}).
			Immutable().
			Comment("The principal the claim grants guardianship of"),

		field.String("code_prefix").
			Unique().
			Immutable().
			Comment("Displayable prefix of the code, used to look it up"),

		field.String("code_hash").
			Sensitive().
			Immutable().
			Comment("SHA-256 of the code"),

		field.UUID("issued_by", uuid.UUID{}).
			Immutable().
			Comment("Manager that issued the claim"),

		field.Time("expires_at").
			Immutable(),

		field.Time("redeemed_at").
			Optional().
			Nillable(),

		field.UUID("redeemed_by", uuid.UUID{}).
			Optional().
			Nillable().
			Comment("Human that became guardian by redeeming the claim"),

		field.Time("created_at").
			Default(time.Now).
			Immutable(),
	}
}

// Edges of the ManagerClaim.
func (ManagerClaim) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("managed", Principal.Type).
			Ref("manager_claims").
			Field("managed_principal_id").
			Required().
			Unique().
			Immutable(),
	}
}

// Indexes of the ManagerClaim.
func (ManagerClaim) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("managed_principal_id"),
	}
}
