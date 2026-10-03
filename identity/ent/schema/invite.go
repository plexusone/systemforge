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

// Invite holds the schema definition for organization invitations.
// Invites allow existing members to invite new users to join an organization.
type Invite struct {
	ent.Schema
}

// Annotations of the Invite.
func (Invite) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_invites"},
	}
}

// Mixin of the Invite.
func (Invite) Mixin() []ent.Mixin {
	return []ent.Mixin{
		BaseMixin{},
	}
}

// Fields of the Invite.
func (Invite) Fields() []ent.Field {
	return []ent.Field{
		// Organization being invited to
		field.UUID("organization_id", uuid.UUID{}).
			Comment("Organization the invite is for"),

		// Who sent the invite
		field.UUID("inviter_principal_id", uuid.UUID{}).
			Comment("Principal who created the invite"),

		// Invitee email (may not exist as a user yet)
		field.String("email").
			NotEmpty().
			Comment("Email address of the invitee"),

		// Role to assign when accepted
		field.String("role").
			NotEmpty().
			Default("member").
			Comment("Role to assign when invite is accepted"),

		// Secure token for invite link
		field.String("token").
			NotEmpty().
			Unique().
			Sensitive().
			Comment("Secure token for invite URL"),

		// Invite status
		field.Enum("status").
			Values("pending", "accepted", "declined", "expired", "revoked").
			Default("pending").
			Comment("Current status of the invite"),

		// Optional personal message
		field.Text("message").
			Optional().
			Nillable().
			Comment("Personal message from inviter"),

		// Expiration
		field.Time("expires_at").
			Comment("When this invite expires"),

		// Acceptance tracking
		field.Time("accepted_at").
			Optional().
			Nillable().
			Comment("When the invite was accepted"),

		// Who accepted (may be different from email if user already exists)
		field.UUID("accepted_by_principal_id", uuid.UUID{}).
			Optional().
			Nillable().
			Comment("Principal who accepted the invite"),

		// For resend tracking
		field.Int("resend_count").
			Default(0).
			Comment("Number of times invite was resent"),

		field.Time("last_sent_at").
			Default(time.Now).
			Comment("When invite was last sent/resent"),
	}
}

// Edges of the Invite.
func (Invite) Edges() []ent.Edge {
	return []ent.Edge{
		// Organization relationship
		edge.From("organization", Organization.Type).
			Ref("invites").
			Field("organization_id").
			Required().
			Unique(),

		// Inviter relationship
		edge.From("inviter", Principal.Type).
			Ref("sent_invites").
			Field("inviter_principal_id").
			Required().
			Unique(),
	}
}

// Indexes of the Invite.
func (Invite) Indexes() []ent.Index {
	return []ent.Index{
		// Fast lookup by token
		index.Fields("token").Unique(),

		// Find invites by email
		index.Fields("email"),

		// Find invites for an organization
		index.Fields("organization_id"),

		// Find pending invites for an org
		index.Fields("organization_id", "status"),

		// Find invites by email and org (to prevent duplicates)
		index.Fields("organization_id", "email", "status"),

		// Find invites sent by a principal
		index.Fields("inviter_principal_id"),

		// Cleanup expired invites
		index.Fields("status", "expires_at"),
	}
}
