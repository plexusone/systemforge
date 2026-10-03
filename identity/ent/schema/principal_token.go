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

// PrincipalToken holds OAuth 2.0 access and refresh tokens for principals.
// This replaces OAuthToken with principal-centric token management.
type PrincipalToken struct {
	ent.Schema
}

// Annotations of the PrincipalToken.
func (PrincipalToken) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_principal_tokens"},
	}
}

// Fields of the PrincipalToken.
func (PrincipalToken) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),

		// Who this token represents
		field.UUID("principal_id", uuid.UUID{}).
			Comment("Principal this token represents"),

		field.Enum("principal_type").
			Values("human", "application", "agent", "service").
			Comment("Type of the principal (denormalized for fast lookup)"),

		// What application issued this token
		field.UUID("issued_by_app_id", uuid.UUID{}).
			Optional().
			Nillable().
			Comment("Application principal that issued this token"),

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

		// Parent token for delegation chains
		field.UUID("parent_token_id", uuid.UUID{}).
			Optional().
			Nillable().
			Comment("Parent token ID (for delegated tokens)"),

		// What's granted
		field.JSON("scopes", []string{}).
			Default([]string{}).
			Comment("Granted scopes"),

		field.JSON("audience", []string{}).
			Default([]string{}).
			Comment("Token audience"),

		// Principal capabilities at time of issuance
		field.JSON("capabilities", map[string]bool{}).
			Default(map[string]bool{}).
			Comment("Capabilities granted to this token"),

		// Delegation chain for agent tokens
		field.JSON("delegation_chain", []string{}).
			Default([]string{}).
			Comment("Chain of principal IDs in delegation (root to current)"),

		// DPoP binding (RFC 9449)
		field.String("dpop_jkt").
			Optional().
			Comment("DPoP JWK thumbprint for proof-of-possession"),

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

// Edges of the PrincipalToken.
func (PrincipalToken) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("principal", Principal.Type).
			Ref("principal_tokens").
			Field("principal_id").
			Required().
			Unique(),

		edge.From("issued_by_app", Application.Type).
			Ref("issued_tokens").
			Field("issued_by_app_id").
			Unique(),

		// Self-referential for delegation chains
		edge.To("child_tokens", PrincipalToken.Type).
			From("parent_token").
			Field("parent_token_id").
			Unique(),
	}
}

// Indexes of the PrincipalToken.
func (PrincipalToken) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("access_token_signature").Unique(),
		index.Fields("refresh_token_signature").Unique(),
		index.Fields("principal_id"),
		index.Fields("principal_type"),
		index.Fields("issued_by_app_id"),
		index.Fields("family_id"),
		index.Fields("parent_token_id"),
		index.Fields("revoked"),
		index.Fields("access_expires_at"),
		index.Fields("session_id"),
	}
}
