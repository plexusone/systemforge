// Package schema provides Ent schema definitions for SystemForge identity management.
package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/mixin"
	"github.com/google/uuid"
)

// UUIDMixin provides a UUID primary key field.
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

// TimeOrderedUUIDMixin provides a UUIDv7 primary key field. Unlike
// UUIDMixin's random v4 IDs, v7 IDs sort in creation order, so ordering by
// (timestamp, id) is deterministic when timestamps tie, as they do on
// platforms with a coarse clock such as Windows. Use it on append-only
// records that are read back in the order they were written.
type TimeOrderedUUIDMixin struct {
	mixin.Schema
}

// Fields returns the UUIDv7 id field.
func (TimeOrderedUUIDMixin) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(newTimeOrderedUUID).
			Immutable(),
	}
}

// newTimeOrderedUUID returns a UUIDv7. It fails only if the system random
// source does, which is an unrecoverable invariant violation.
func newTimeOrderedUUID() uuid.UUID {
	return uuid.Must(uuid.NewV7())
}

// TimestampMixin provides created_at and updated_at timestamp fields.
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
