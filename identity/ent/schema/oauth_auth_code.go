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

// OAuthAuthCode holds OAuth 2.0 authorization codes.
type OAuthAuthCode struct {
	ent.Schema
}

// Annotations of the OAuthAuthCode.
func (OAuthAuthCode) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_oauth_auth_codes"},
	}
}

// Fields of the OAuthAuthCode.
func (OAuthAuthCode) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),

		// Code signature (hashed for lookup)
		field.String("code_signature").
			Unique().
			Comment("SHA256 signature of the authorization code"),

		// Who/what
		field.UUID("app_id", uuid.UUID{}).
			Comment("OAuth app this code was issued to"),

		field.UUID("user_id", uuid.UUID{}).
			Comment("User who authorized"),

		// PKCE
		field.String("code_challenge").
			Optional().
			Comment("PKCE code challenge"),

		field.String("code_challenge_method").
			Optional().
			Default("S256").
			Comment("PKCE challenge method (S256)"),

		// Request parameters (for verification on exchange)
		field.String("redirect_uri").
			Comment("Redirect URI from authorization request"),

		field.JSON("scopes", []string{}).
			Default([]string{}).
			Comment("Requested scopes"),

		field.String("state").
			Optional().
			Comment("State parameter from request"),

		field.String("nonce").
			Optional().
			Comment("OIDC nonce"),

		// Fosite request data (serialized)
		field.Text("request_data").
			Optional().
			Comment("Serialized Fosite request"),

		// Lifecycle
		field.Time("expires_at").
			Comment("When this code expires (short-lived, ~10 min)"),

		field.Bool("used").
			Default(false).
			Comment("Whether code has been exchanged"),

		field.Time("used_at").
			Optional().
			Nillable(),

		// Tracking
		field.String("client_ip").
			Optional(),

		field.String("user_agent").
			Optional(),

		field.Time("created_at").
			Default(time.Now).
			Immutable(),
	}
}

// Edges of the OAuthAuthCode.
func (OAuthAuthCode) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("app", OAuthApp.Type).
			Ref("auth_codes").
			Field("app_id").
			Required().
			Unique(),

		edge.From("user", User.Type).
			Ref("oauth_auth_codes").
			Field("user_id").
			Required().
			Unique(),
	}
}

// Indexes of the OAuthAuthCode.
func (OAuthAuthCode) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("code_signature").Unique(),
		index.Fields("app_id"),
		index.Fields("user_id"),
		index.Fields("expires_at"),
		index.Fields("used"),
	}
}
