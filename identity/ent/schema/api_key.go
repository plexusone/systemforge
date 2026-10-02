package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// APIKey holds the schema definition for the APIKey entity.
// API keys provide server-to-server authentication without user interaction.
type APIKey struct {
	ent.Schema
}

// Annotations of the APIKey.
func (APIKey) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_api_keys"},
	}
}

// Mixin of the APIKey.
func (APIKey) Mixin() []ent.Mixin {
	return []ent.Mixin{
		BaseMixin{},
	}
}

// Fields of the APIKey.
func (APIKey) Fields() []ent.Field {
	return []ent.Field{
		// Name is a human-readable identifier for the key.
		field.String("name").
			NotEmpty().
			Comment("Human-readable name for the API key"),

		// Prefix is the visible portion of the key (e.g., "cf_live_abc123").
		// This is safe to display and helps identify keys.
		field.String("prefix").
			NotEmpty().
			Unique().
			Comment("Visible prefix of the API key (e.g., cf_live_abc123)"),

		// KeyHash is the SHA-256 hash of the full API key.
		// The actual key is only shown once at creation time.
		field.String("key_hash").
			NotEmpty().
			Sensitive().
			Comment("SHA-256 hash of the full API key"),

		// Scopes is a JSON array of permission scopes.
		// Example: ["read:users", "write:projects"]
		field.JSON("scopes", []string{}).
			Optional().
			Comment("Permission scopes granted to this key"),

		// Description is an optional note about the key's purpose.
		field.String("description").
			Optional().
			Nillable().
			Comment("Optional description of the key's purpose"),

		// ExpiresAt is when the key expires (nil = never).
		field.Time("expires_at").
			Optional().
			Nillable().
			Comment("When the key expires (nil = never)"),

		// LastUsedAt tracks when the key was last used.
		field.Time("last_used_at").
			Optional().
			Nillable().
			Comment("When the key was last used"),

		// LastUsedIP tracks the IP that last used the key.
		field.String("last_used_ip").
			Optional().
			Nillable().
			Comment("IP address that last used the key"),

		// Revoked indicates if the key has been revoked.
		field.Bool("revoked").
			Default(false).
			Comment("Whether the key has been revoked"),

		// RevokedAt is when the key was revoked.
		field.Time("revoked_at").
			Optional().
			Nillable().
			Comment("When the key was revoked"),

		// RevokedReason is why the key was revoked.
		field.String("revoked_reason").
			Optional().
			Nillable().
			Comment("Reason for revocation"),

		// Environment distinguishes live vs test keys.
		// Values: "live", "test"
		field.Enum("environment").
			Values("live", "test").
			Default("live").
			Comment("Environment: live or test"),

		// Metadata stores additional key-value data.
		field.JSON("metadata", map[string]string{}).
			Optional().
			Comment("Additional metadata"),
	}
}

// Edges of the APIKey.
func (APIKey) Edges() []ent.Edge {
	return []ent.Edge{
		// Owner is the user who owns this API key.
		edge.From("owner", User.Type).
			Ref("api_keys").
			Required().
			Unique().
			Comment("User who owns this API key"),

		// Organization is the org this key belongs to (optional).
		// If set, the key can only access resources in this org.
		edge.From("organization", Organization.Type).
			Ref("api_keys").
			Unique().
			Comment("Organization this key is scoped to (optional)"),
	}
}

// Indexes of the APIKey.
func (APIKey) Indexes() []ent.Index {
	return []ent.Index{
		// Fast lookup by prefix for key validation.
		index.Fields("prefix").
			Unique(),

		// Find all keys for a user.
		index.Edges("owner"),

		// Find all keys for an organization.
		index.Edges("organization"),

		// Find non-revoked, non-expired keys.
		index.Fields("revoked", "expires_at"),

		// Find keys by environment.
		index.Fields("environment"),
	}
}
