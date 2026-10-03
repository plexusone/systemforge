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

// Application holds the schema definition for OAuth application-specific principal data.
// This is a one-to-one extension of Principal where type="application".
type Application struct {
	ent.Schema
}

// Annotations of the Application.
func (Application) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_applications"},
	}
}

// Mixin of the Application.
func (Application) Mixin() []ent.Mixin {
	return []ent.Mixin{
		BaseMixin{},
	}
}

// Fields of the Application.
func (Application) Fields() []ent.Field {
	return []ent.Field{
		// Foreign key to Principal
		field.UUID("principal_id", uuid.UUID{}).
			Unique().
			Immutable().
			Comment("Reference to parent Principal"),

		// Client identification
		field.String("client_id").
			Unique().
			Immutable().
			NotEmpty().
			Comment("Public OAuth client identifier"),

		field.String("description").
			Optional().
			MaxLen(1000).
			Comment("Application description"),

		field.String("logo_url").
			Optional().
			Comment("Application logo URL"),

		// App type determines allowed grants and security requirements
		field.Enum("app_type").
			Values("web", "spa", "native", "machine").
			Default("web").
			Comment("web=confidential, spa/native=public+PKCE, machine=client_credentials"),

		// OAuth configuration
		field.JSON("redirect_uris", []string{}).
			Default([]string{}).
			Comment("Allowed redirect URIs"),

		field.JSON("allowed_grants", []string{}).
			Default([]string{"authorization_code", "refresh_token"}).
			Comment("Allowed grant types"),

		field.JSON("allowed_response_types", []string{}).
			Default([]string{"code"}).
			Comment("Allowed response types"),

		// Token configuration
		field.Int("access_token_ttl").
			Default(900).
			Comment("Access token TTL in seconds (default 15 min)"),

		field.Int("refresh_token_ttl").
			Default(604800).
			Comment("Refresh token TTL in seconds (default 7 days)"),

		field.Bool("refresh_token_rotation").
			Default(true).
			Comment("Rotate refresh tokens on use"),

		// Flags
		field.Bool("first_party").
			Default(false).
			Comment("First-party apps skip consent screen"),

		field.Bool("public").
			Default(false).
			Comment("Public clients cannot keep secrets"),
	}
}

// Edges of the Application.
func (Application) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("principal", Principal.Type).
			Ref("application").
			Field("principal_id").
			Required().
			Unique().
			Immutable(),

		// Tokens issued by this application
		edge.To("issued_tokens", PrincipalToken.Type).
			Comment("Tokens issued by this application"),
	}
}

// Indexes of the Application.
func (Application) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("principal_id").Unique(),
		index.Fields("client_id").Unique(),
		index.Fields("app_type"),
		index.Fields("first_party"),
	}
}
