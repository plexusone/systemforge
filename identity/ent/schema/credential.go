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

// Credential holds the schema definition for unified credentials.
// Credentials can be passwords, API keys, keypairs, WebAuthn credentials, or TOTP secrets.
type Credential struct {
	ent.Schema
}

// Annotations of the Credential.
func (Credential) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_credentials"},
	}
}

// Fields of the Credential.
func (Credential) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),

		// Owner
		field.UUID("principal_id", uuid.UUID{}).
			Comment("Principal that owns this credential"),

		// Credential type
		field.Enum("type").
			Values("password", "api_key", "keypair", "webauthn", "totp", "client_secret").
			Comment("Type of credential"),

		// Unique identifier within type (e.g., key prefix for API keys)
		field.String("identifier").
			Optional().
			Comment("Unique identifier for this credential (e.g., key prefix)"),

		// Secret storage (hashed)
		field.String("secret_hash").
			Optional().
			Sensitive().
			Comment("Hashed secret (Argon2id for passwords/secrets, SHA256 for tokens)"),

		// For keypairs
		field.Text("public_key").
			Optional().
			Comment("Public key (PEM format) for keypair credentials"),

		field.String("key_algorithm").
			Optional().
			Comment("Key algorithm (RS256, ES256, etc.)"),

		field.String("key_id").
			Optional().
			Unique().
			Nillable().
			Comment("Key ID for keypair credentials (used in JWT kid header)"),

		// For WebAuthn
		field.Bytes("webauthn_credential_id").
			Optional().
			Comment("WebAuthn credential ID"),

		field.Bytes("webauthn_public_key").
			Optional().
			Comment("WebAuthn public key (COSE format)"),

		field.String("webauthn_aaguid").
			Optional().
			Comment("WebAuthn authenticator AAGUID"),

		field.Uint32("webauthn_sign_count").
			Optional().
			Default(0).
			Comment("WebAuthn signature counter"),

		// What this credential can access
		field.JSON("scopes", []string{}).
			Default([]string{}).
			Comment("Scopes this credential grants"),

		// Lifecycle
		field.Bool("active").
			Default(true).
			Comment("Whether this credential is active"),

		field.Time("expires_at").
			Optional().
			Nillable().
			Comment("When this credential expires (nil = never)"),

		field.Bool("revoked").
			Default(false).
			Comment("Whether this credential has been revoked"),

		field.Time("revoked_at").
			Optional().
			Nillable().
			Comment("When this credential was revoked"),

		field.String("revoked_reason").
			Optional().
			Comment("Reason for revocation"),

		// Audit
		field.Time("last_used_at").
			Optional().
			Nillable().
			Comment("Last time this credential was used"),

		field.String("last_used_ip").
			Optional().
			Comment("IP address of last use"),

		// Metadata
		field.String("name").
			Optional().
			Comment("Human-readable name for this credential"),

		field.JSON("metadata", map[string]any{}).
			Optional().
			Comment("Custom metadata"),

		// Timestamps
		field.Time("created_at").
			Default(time.Now).
			Immutable(),

		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}

// Edges of the Credential.
func (Credential) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("principal", Principal.Type).
			Ref("credentials").
			Field("principal_id").
			Required().
			Unique(),
	}
}

// Indexes of the Credential.
func (Credential) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("principal_id"),
		index.Fields("principal_id", "type"),
		index.Fields("type"),
		index.Fields("identifier"),
		index.Fields("active"),
		index.Fields("revoked"),
		index.Fields("expires_at"),
		// For API key lookup by prefix
		index.Fields("type", "identifier").
			Unique(),
	}
}
