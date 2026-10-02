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

// OAuthToken holds OAuth 2.0 access and refresh tokens.
type OAuthToken struct {
	ent.Schema
}

// Annotations of the OAuthToken.
func (OAuthToken) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_oauth_tokens"},
	}
}

// Fields of the OAuthToken.
func (OAuthToken) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),

		// What issued this token
		field.UUID("app_id", uuid.UUID{}).
			Comment("OAuth app that issued this token"),

		// Who this token represents
		field.UUID("user_id", uuid.UUID{}).
			Optional().
			Nillable().
			Comment("User this token represents (nil for client_credentials)"),

		field.UUID("service_account_id", uuid.UUID{}).
			Optional().
			Nillable().
			Comment("Service account (for JWT bearer grant)"),

		// Token signatures (hashed for lookup)
		field.String("access_token_signature").
			Unique().
			Comment("SHA256 signature of access token"),

		field.String("refresh_token_signature").
			Optional().
			Unique().
			Nillable().
			Comment("SHA256 signature of refresh token"),

		// Token family for rotation tracking
		field.UUID("family_id", uuid.UUID{}).
			Default(uuid.New).
			Comment("Token family for refresh rotation"),

		// What's granted
		field.JSON("scopes", []string{}).
			Default([]string{}).
			Comment("Granted scopes"),

		field.JSON("audience", []string{}).
			Default([]string{}).
			Comment("Token audience"),

		// Session binding
		field.String("session_id").
			Optional().
			Comment("BFF session ID if applicable"),

		// Fosite request data (serialized)
		field.Text("request_data").
			Optional().
			Comment("Serialized Fosite request for introspection"),

		// Lifecycle
		field.Time("access_expires_at").
			Comment("When access token expires"),

		field.Time("refresh_expires_at").
			Optional().
			Nillable().
			Comment("When refresh token expires"),

		field.Bool("revoked").
			Default(false),

		field.Time("revoked_at").
			Optional().
			Nillable(),

		field.String("revoked_reason").
			Optional(),

		// Tracking
		field.String("client_ip").
			Optional(),

		field.String("user_agent").
			Optional(),

		field.Time("last_used_at").
			Optional().
			Nillable(),

		field.Time("created_at").
			Default(time.Now).
			Immutable(),
	}
}

// Edges of the OAuthToken.
func (OAuthToken) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("app", OAuthApp.Type).
			Ref("tokens").
			Field("app_id").
			Required().
			Unique(),

		edge.From("user", User.Type).
			Ref("oauth_tokens").
			Field("user_id").
			Unique(),
	}
}

// Indexes of the OAuthToken.
func (OAuthToken) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("access_token_signature").Unique(),
		index.Fields("refresh_token_signature").Unique(),
		index.Fields("app_id"),
		index.Fields("user_id"),
		index.Fields("family_id"),
		index.Fields("revoked"),
		index.Fields("access_expires_at"),
	}
}
