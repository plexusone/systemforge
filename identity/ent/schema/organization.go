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

// Organization holds the schema definition for the Organization entity.
type Organization struct {
	ent.Schema
}

// Annotations of the Organization.
func (Organization) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_organizations"},
	}
}

// Mixin of the Organization.
func (Organization) Mixin() []ent.Mixin {
	return []ent.Mixin{
		BaseMixin{},
	}
}

// Fields of the Organization.
func (Organization) Fields() []ent.Field {
	return []ent.Field{
		field.String("name").
			NotEmpty(),
		field.String("slug").
			NotEmpty().
			Unique().
			Comment("URL-safe identifier"),

		// Organization type: personal (auto-created for users), team, or enterprise
		field.Enum("org_type").
			Values("personal", "team", "enterprise").
			Default("team").
			Comment("personal=user namespace, team=shared org, enterprise=large org"),

		// Owner principal for personal orgs (the user who owns this namespace)
		field.UUID("owner_principal_id", uuid.UUID{}).
			Optional().
			Nillable().
			Comment("For personal orgs, the principal who owns this namespace"),

		field.String("logo_url").
			Optional().
			Nillable(),
		field.String("description").
			Optional().
			Nillable().
			Comment("Organization description"),
		field.String("website_url").
			Optional().
			Nillable().
			Comment("Organization website"),
		field.JSON("settings", map[string]any{}).
			Optional().
			Comment("App-specific configuration"),
		field.Enum("plan").
			Values("free", "starter", "pro", "enterprise").
			Default("free"),
		field.Bool("active").
			Default(true),
	}
}

// Edges of the Organization.
func (Organization) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("memberships", Membership.Type),
		edge.To("api_keys", APIKey.Type),

		// OAuth 2.0 edges
		edge.To("oauth_apps", OAuthApp.Type),
		edge.To("service_accounts", ServiceAccount.Type),

		// Principal-centric edges
		edge.To("principals", Principal.Type),
		edge.To("principal_memberships", PrincipalMembership.Type),

		// Owner edge for personal orgs
		edge.From("owner", Principal.Type).
			Ref("owned_organizations").
			Field("owner_principal_id").
			Unique().
			Comment("Owner principal for personal organizations"),

		// Invites to this organization
		edge.To("invites", Invite.Type).
			Comment("Pending invitations to join this organization"),

		// Marketplace: Listings created by this organization
		edge.To("listings", Listing.Type).
			Comment("Marketplace listings created by this organization"),

		// Marketplace: Licenses held by this organization
		edge.To("licenses", License.Type).
			Comment("Marketplace licenses held by this organization"),

		// Marketplace: Platform subscription for this organization
		edge.To("subscription", Subscription.Type).
			Unique().
			Comment("Platform subscription for this organization"),
	}
}

// Indexes of the Organization.
func (Organization) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("slug").
			Unique(),
		index.Fields("active"),
		index.Fields("org_type"),
		index.Fields("owner_principal_id"),
		index.Fields("org_type", "active"),
	}
}
