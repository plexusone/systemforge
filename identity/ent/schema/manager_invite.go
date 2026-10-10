package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// ManagerInvite is a single-use invitation with which a human with a
// verified email offers to manage a self-managed human, who enters
// management only by accepting it while signed in (ADR-009). It is kept
// apart from organization invites, which grant membership, not authority
// over a person.
type ManagerInvite struct {
	ent.Schema
}

// Annotations of the ManagerInvite.
func (ManagerInvite) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_manager_invites"},
	}
}

// Fields of the ManagerInvite.
func (ManagerInvite) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),

		field.UUID("manager_principal_id", uuid.UUID{}).
			Immutable().
			Comment("The human that becomes a manager when the invite is accepted"),

		field.String("email").
			NotEmpty().
			Immutable().
			Comment("Verified email of the human invited to be managed"),

		field.String("role").
			NotEmpty().
			Immutable().
			Comment("Manager role granted on acceptance"),

		field.String("token_prefix").
			Unique().
			Immutable().
			Comment("Displayable prefix of the token, used to look it up"),

		field.String("token_hash").
			Sensitive().
			Immutable().
			Comment("SHA-256 of the token"),

		field.Time("expires_at").
			Immutable(),

		field.Time("accepted_at").
			Optional().
			Nillable(),

		field.UUID("accepted_by", uuid.UUID{}).
			Optional().
			Nillable().
			Comment("Human that entered management by accepting the invite"),

		field.Time("revoked_at").
			Optional().
			Nillable(),

		field.Time("declined_at").
			Optional().
			Nillable().
			Comment("When the invitee declined the invitation"),

		field.UUID("declined_by", uuid.UUID{}).
			Optional().
			Nillable().
			Comment("Human that declined the invitation"),

		field.Time("created_at").
			Default(time.Now).
			Immutable(),
	}
}

// Indexes of the ManagerInvite.
func (ManagerInvite) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("manager_principal_id"),
		index.Fields("email"),
	}
}
