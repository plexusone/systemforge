package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// LoginState holds in-flight upstream OAuth logins started by SystemAuth
// social login. Rows are single-use and short-lived; only a SHA-256 hash of
// the OAuth state value is stored.
type LoginState struct {
	ent.Schema
}

// Annotations of the LoginState.
func (LoginState) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_login_states"},
	}
}

// Fields of the LoginState.
func (LoginState) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),

		field.String("state_hash").
			Unique().
			Immutable().
			Comment("Hex SHA-256 of the OAuth state value"),

		field.String("provider").
			Immutable().
			Comment("Upstream provider the flow was started for"),

		field.Text("redirect_url").
			Optional().
			Immutable().
			Comment("Validated post-login destination"),

		field.String("nonce").
			Optional().
			Immutable().
			Sensitive().
			Comment("OpenID Connect nonce"),

		field.String("pkce_verifier").
			Optional().
			Immutable().
			Sensitive().
			Comment("PKCE code verifier for the upstream token exchange"),

		field.Time("expires_at").
			Immutable().
			Comment("When the in-flight login expires"),
	}
}

// Indexes of the LoginState.
func (LoginState) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("expires_at"),
	}
}
