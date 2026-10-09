// Package mixin provides Ent mixins for composing SystemForge identity fields
// into application schemas.
package mixin

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/mixin"
	"github.com/google/uuid"
)

// UUIDMixin provides a UUID primary key field.
// Use this when you want UUID-based primary keys in your schema.
type UUIDMixin struct {
	mixin.Schema
}

// Fields returns the UUID id field.
func (UUIDMixin) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),
	}
}

// TimestampMixin provides created_at and updated_at timestamp fields.
// Use this for automatic timestamp tracking in your schema.
type TimestampMixin struct {
	mixin.Schema
}

// Fields returns the timestamp fields.
func (TimestampMixin) Fields() []ent.Field {
	return []ent.Field{
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}

// BaseMixin combines UUID and Timestamp mixins for convenience.
// This is the most commonly used mixin for SystemForge-compatible entities.
type BaseMixin struct {
	mixin.Schema
}

// Fields returns combined UUID and timestamp fields.
func (BaseMixin) Fields() []ent.Field {
	fields := make([]ent.Field, 0, 3)
	fields = append(fields, UUIDMixin{}.Fields()...)
	fields = append(fields, TimestampMixin{}.Fields()...)
	return fields
}

// OrganizationBase provides the core organization fields for composition.
// Apps can use this mixin to get SystemForge-compatible organization fields
// while adding their own custom fields or renaming to match their domain
// (e.g., Team, Tenant, Workspace).
type OrganizationBase struct {
	mixin.Schema
}

// Fields returns the core organization fields.
func (OrganizationBase) Fields() []ent.Field {
	baseFields := BaseMixin{}.Fields()
	orgFields := []ent.Field{
		field.String("name").
			NotEmpty(),
		field.String("slug").
			NotEmpty().
			Unique().
			Comment("URL-safe identifier"),
		field.String("logo_url").
			Optional().
			Nillable(),
		field.JSON("settings", map[string]any{}).
			Optional().
			Comment("App-specific configuration"),
		field.Bool("active").
			Default(true),
		// Public profile fields
		field.String("tagline").
			Optional().
			Nillable().
			MaxLen(200).
			Comment("Short tagline for public display"),
		field.Text("description").
			Optional().
			Nillable().
			Comment("Full public description (Markdown supported)"),
		field.String("website_url").
			Optional().
			Nillable().
			Comment("External website URL"),
		field.JSON("social_links", []string{}).
			Optional().
			Comment("Social media URLs (LinkedIn, Twitter, etc.)"),
		field.Bool("public_listing").
			Default(false).
			Comment("Whether org appears in public directory"),
	}
	return append(baseFields, orgFields...)
}
