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

// OAuthConsent tracks user consent for OAuth apps.
// First-party apps skip consent; third-party apps require explicit approval.
type OAuthConsent struct {
	ent.Schema
}

// Annotations of the OAuthConsent.
func (OAuthConsent) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_oauth_consents"},
	}
}

// Fields of the OAuthConsent.
func (OAuthConsent) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),

		field.UUID("user_id", uuid.UUID{}).
			Comment("User who granted consent"),

		field.UUID("app_id", uuid.UUID{}).
			Comment("OAuth app that received consent"),

		// What was granted
		field.JSON("scopes", []string{}).
			Default([]string{}).
			Comment("Scopes the user consented to"),

		// Consent status
		field.Bool("granted").
			Default(true).
			Comment("Whether consent is currently active"),

		field.Time("granted_at").
			Default(time.Now).
			Comment("When consent was first granted"),

		field.Time("last_used_at").
			Optional().
			Nillable().
			Comment("Last time this consent was used for authorization"),

		// Revocation
		field.Bool("revoked").
			Default(false),

		field.Time("revoked_at").
			Optional().
			Nillable(),

		field.String("revoked_reason").
			Optional().
			Comment("user_initiated, admin_revoked, app_deleted, etc."),

		// Timestamps
		field.Time("created_at").
			Default(time.Now).
			Immutable(),

		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}

// Edges of the OAuthConsent.
func (OAuthConsent) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("oauth_consents").
			Field("user_id").
			Required().
			Unique(),

		edge.From("app", OAuthApp.Type).
			Ref("consents").
			Field("app_id").
			Required().
			Unique(),
	}
}

// Indexes of the OAuthConsent.
func (OAuthConsent) Indexes() []ent.Index {
	return []ent.Index{
		// One consent record per user-app pair
		index.Fields("user_id", "app_id").Unique(),
		index.Fields("user_id"),
		index.Fields("app_id"),
		index.Fields("granted"),
		index.Fields("revoked"),
	}
}
