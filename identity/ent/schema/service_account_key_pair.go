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

// ServiceAccountKeyPair holds RSA/EC key pairs for JWT Bearer authentication.
// Multiple keys can exist for rotation purposes.
type ServiceAccountKeyPair struct {
	ent.Schema
}

// Annotations of the ServiceAccountKeyPair.
func (ServiceAccountKeyPair) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_service_account_key_pairs"},
	}
}

// Fields of the ServiceAccountKeyPair.
func (ServiceAccountKeyPair) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),

		field.UUID("service_account_id", uuid.UUID{}).
			Comment("Service account this key belongs to"),

		// Key identification
		field.String("key_id").
			NotEmpty().
			Comment("Key ID for JWK 'kid' claim"),

		// Key type and algorithm
		field.Enum("key_type").
			Values("rsa", "ec").
			Default("rsa").
			Comment("Key type: RSA or EC"),

		field.Enum("algorithm").
			Values("RS256", "RS384", "RS512", "ES256", "ES384", "ES512").
			Default("RS256").
			Comment("JWT signing algorithm"),

		// Public key (PEM encoded) - stored for signature verification
		field.Text("public_key_pem").
			NotEmpty().
			Comment("PEM-encoded public key for signature verification"),

		// Private key is NOT stored server-side
		// The client generates and keeps the private key
		// Only the public key is uploaded for verification

		// Lifecycle
		field.Time("expires_at").
			Optional().
			Nillable().
			Comment("When this key expires"),

		field.Bool("active").
			Default(true),

		field.Time("last_used_at").
			Optional().
			Nillable(),

		field.Bool("revoked").
			Default(false),

		field.Time("revoked_at").
			Optional().
			Nillable(),

		// Timestamps
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
	}
}

// Edges of the ServiceAccountKeyPair.
func (ServiceAccountKeyPair) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("service_account", ServiceAccount.Type).
			Ref("key_pairs").
			Field("service_account_id").
			Required().
			Unique(),
	}
}

// Indexes of the ServiceAccountKeyPair.
func (ServiceAccountKeyPair) Indexes() []ent.Index {
	return []ent.Index{
		// Key ID must be unique per service account
		index.Fields("service_account_id", "key_id").Unique(),
		index.Fields("service_account_id"),
		index.Fields("active"),
		index.Fields("revoked"),
	}
}
