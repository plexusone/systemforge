package mixin

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"entgo.io/ent/schema/mixin"
	"github.com/google/uuid"
)

// APIKey provides common fields for API key entities.
// Apps use this mixin in their Ent schema and implement EntClientInterface
// to connect SystemForge's EntStore to their generated Ent client.
//
// Example usage in app schema:
//
//	func (APIKey) Mixin() []ent.Mixin {
//	    return []ent.Mixin{
//	        mixin.APIKey{},
//	    }
//	}
type APIKey struct {
	mixin.Schema
}

// Fields of the APIKey mixin.
func (APIKey) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),

		field.String("name").
			NotEmpty().
			MaxLen(100).
			Comment("User-provided name for identification"),

		field.String("prefix").
			NotEmpty().
			MaxLen(20).
			Comment("Visible prefix for identification (e.g., sf_live_xxxx)"),

		field.String("key_hash").
			NotEmpty().
			MaxLen(64).
			Sensitive().
			Comment("SHA-256 hash of the full key"),

		field.UUID("owner_id", uuid.UUID{}).
			Comment("User who owns this key"),

		field.UUID("organization_id", uuid.UUID{}).
			Optional().
			Nillable().
			Comment("Organization scope (optional)"),

		field.Strings("scopes").
			Default([]string{}).
			Comment("Granted permission scopes"),

		field.String("description").
			Optional().
			MaxLen(500).
			Comment("User-provided description"),

		field.Enum("environment").
			Values("live", "test").
			Default("live").
			Comment("Key environment"),

		field.Time("expires_at").
			Optional().
			Nillable().
			Comment("When the key expires (NULL = never)"),

		field.Time("last_used_at").
			Optional().
			Nillable().
			Comment("When the key was last used"),

		field.String("last_used_ip").
			Optional().
			MaxLen(45).
			Comment("IP that last used the key"),

		field.Bool("revoked").
			Default(false).
			Comment("Whether the key is revoked"),

		field.Time("revoked_at").
			Optional().
			Nillable().
			Comment("When the key was revoked"),

		field.String("revoked_reason").
			Optional().
			MaxLen(500).
			Comment("Why the key was revoked"),

		field.JSON("metadata", map[string]string{}).
			Optional().
			Comment("Additional key metadata"),

		field.Time("created_at").
			Default(time.Now).
			Immutable(),

		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}

// Indexes of the APIKey mixin.
func (APIKey) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("owner_id"),
		index.Fields("organization_id"),
		index.Fields("prefix"),
		index.Fields("key_hash").Unique(),
		index.Fields("environment"),
	}
}
