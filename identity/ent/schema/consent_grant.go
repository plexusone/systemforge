package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// ConsentGrant records one scope a principal granted to an OAuth client on
// the SystemAuth consent page. One row per (principal, client, scope) keeps
// concurrent grants race-free without read-modify-write.
type ConsentGrant struct {
	ent.Schema
}

// Annotations of the ConsentGrant.
func (ConsentGrant) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_consent_grants"},
	}
}

// Fields of the ConsentGrant.
func (ConsentGrant) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),

		field.String("principal_id").
			Immutable().
			Comment("Principal that granted consent"),

		field.String("client_id").
			Immutable().
			Comment("OAuth client ID that received consent"),

		field.String("scope").
			Immutable().
			Comment("Granted scope"),

		field.Time("granted_at").
			Default(time.Now).
			Immutable(),
	}
}

// Indexes of the ConsentGrant.
func (ConsentGrant) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("principal_id", "client_id", "scope").Unique(),
		index.Fields("client_id"),
	}
}
