package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/index"

	"github.com/plexusone/systemforge/identity/ent/mixin"
)

// Subscription holds the schema definition for a platform subscription.
type Subscription struct {
	ent.Schema
}

// Annotations of the Subscription.
func (Subscription) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "sf_subscriptions"},
	}
}

// Mixin of the Subscription.
func (Subscription) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.SubscriptionMixin{},
	}
}

// Fields of the Subscription.
func (Subscription) Fields() []ent.Field {
	// All fields provided by SubscriptionMixin
	return nil
}

// Edges of the Subscription.
func (Subscription) Edges() []ent.Edge {
	return []ent.Edge{
		// Organization this subscription belongs to
		edge.From("organization", Organization.Type).
			Ref("subscriptions").
			Field("organization_id").
			Required().
			Unique().
			Comment("The subscribing organization"),
	}
}

// Indexes of the Subscription.
func (Subscription) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("organization_id"),
		// One subscription per listing, and one platform-wide
		// subscription (null listing), per organization.
		index.Fields("organization_id", "listing_id").
			Unique(),
		index.Fields("organization_id").
			Unique().
			Annotations(entsql.IndexAnnotation{Where: "listing_id IS NULL"}).
			StorageKey("subscription_platform_per_org"),
		index.Fields("listing_id"),
		index.Fields("status"),
		index.Fields("plan_tier"),
		index.Fields("stripe_subscription_id"),
		index.Fields("stripe_customer_id"),
		index.Fields("current_period_end"),
		index.Fields("status", "current_period_end"),
	}
}
