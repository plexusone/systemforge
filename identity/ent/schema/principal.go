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

// Principal holds the schema definition for the Principal entity.
// Principal is the unified identity root representing any type of actor:
// human, application, agent, or service.
type Principal struct {
	ent.Schema
}

// Annotations of the Principal.
func (Principal) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_principals"},
	}
}

// Mixin of the Principal.
func (Principal) Mixin() []ent.Mixin {
	return []ent.Mixin{
		BaseMixin{},
	}
}

// Fields of the Principal.
func (Principal) Fields() []ent.Field {
	return []ent.Field{
		// Principal type determines which extension table is used
		field.Enum("type").
			Values("human", "application", "agent", "service").
			Immutable().
			Comment("Type of principal: human, application, agent, service"),

		// Unique identifier for this principal
		// For humans: email address
		// For applications: client_id
		// For agents: agent identifier
		// For services: service@org identifier
		field.String("identifier").
			NotEmpty().
			Unique().
			Comment("Unique identifier (email, client_id, service@org)"),

		field.String("display_name").
			NotEmpty().
			Comment("Human-readable display name"),

		// Optional organization scope
		field.UUID("organization_id", uuid.UUID{}).
			Optional().
			Nillable().
			Comment("Organization this principal belongs to"),

		field.Bool("active").
			Default(true).
			Comment("Whether the principal is active"),

		// Capabilities define what this principal can do
		field.JSON("capabilities", map[string]bool{}).
			Default(map[string]bool{}).
			Comment("Principal capabilities (can_access_ui, can_delegate, etc.)"),

		// Scopes this principal is allowed to request
		field.JSON("allowed_scopes", []string{}).
			Default([]string{}).
			Comment("Scopes this principal can request"),

		// Arbitrary metadata
		field.JSON("metadata", map[string]any{}).
			Optional().
			Comment("Custom metadata"),
	}
}

// Edges of the Principal.
func (Principal) Edges() []ent.Edge {
	return []ent.Edge{
		// Organization relationship
		edge.From("organization", Organization.Type).
			Ref("principals").
			Field("organization_id").
			Unique(),

		// Type-specific extensions (one-to-one)
		edge.To("human", Human.Type).
			Unique().
			Comment("Human extension (when type=human)"),

		edge.To("application", Application.Type).
			Unique().
			Comment("Application extension (when type=application)"),

		edge.To("agent", Agent.Type).
			Unique().
			Comment("Agent extension (when type=agent)"),

		edge.To("service_principal", ServicePrincipal.Type).
			Unique().
			Comment("Service extension (when type=service)"),

		// Credentials owned by this principal
		edge.To("credentials", Credential.Type).
			Comment("Credentials for authentication"),

		// Tokens issued to this principal
		edge.To("principal_tokens", PrincipalToken.Type).
			Comment("Tokens issued to this principal"),

		// Memberships in organizations
		edge.To("principal_memberships", PrincipalMembership.Type).
			Comment("Organization memberships"),

		// Personal organizations owned by this principal
		edge.To("owned_organizations", Organization.Type).
			Comment("Personal organizations owned by this principal"),

		// Invites sent by this principal
		edge.To("sent_invites", Invite.Type).
			Comment("Invitations sent by this principal"),

		// Marketplace: Listings owned by this principal
		edge.To("owned_listings", Listing.Type).
			Comment("Marketplace listings owned by this principal"),

		// Marketplace: Licenses purchased by this principal
		edge.To("purchased_licenses", License.Type).
			Comment("Licenses purchased by this principal"),

		// Marketplace: Seat assignments for this principal
		edge.To("seat_assignments", SeatAssignment.Type).
			Comment("License seats assigned to this principal"),

		// Marketplace: Seats assigned by this principal
		edge.To("assigned_seats", SeatAssignment.Type).
			Comment("License seats assigned by this principal"),
	}
}

// Indexes of the Principal.
func (Principal) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("identifier").Unique(),
		index.Fields("type"),
		index.Fields("organization_id"),
		index.Fields("active"),
		index.Fields("type", "active"),
		index.Fields("organization_id", "type"),
	}
}
