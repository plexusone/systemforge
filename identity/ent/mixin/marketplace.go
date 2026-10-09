// Package mixin provides Ent mixins for composing SystemForge fields into application schemas.
package mixin

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/mixin"
	"github.com/google/uuid"
)

// ListingMixin provides the core fields for marketplace listings.
// Apps can use this mixin to create their own Listing schema while
// adding app-specific fields and edges.
//
// Example usage:
//
//	type Listing struct {
//	    ent.Schema
//	}
//
//	func (Listing) Mixin() []ent.Mixin {
//	    return []ent.Mixin{
//	        mixin.ListingMixin{},
//	    }
//	}
//
//	func (Listing) Fields() []ent.Field {
//	    return []ent.Field{
//	        // App-specific fields
//	        field.UUID("course_id", uuid.UUID{}).Optional(),
//	    }
//	}
type ListingMixin struct {
	mixin.Schema
}

// Fields returns the core listing fields.
func (ListingMixin) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),

		// Ownership
		field.UUID("creator_org_id", uuid.UUID{}).
			Comment("Organization that created this listing"),
		field.UUID("owner_id", uuid.UUID{}).
			Comment("Principal who owns this listing"),

		// Product reference (app defines the actual product entity)
		field.String("product_type").
			NotEmpty().
			Comment("Type of product: course, dashboard_template, etc."),
		field.UUID("product_id", uuid.UUID{}).
			Optional().
			Nillable().
			Comment("Reference to the actual product (optional for drafts)"),
		field.String("application").
			Optional().
			Nillable().
			Comment("Application identifier, as registered in the authz vocabulary registry, that holding this listing entitles an organization to"),

		// Display
		field.String("title").
			NotEmpty().
			MaxLen(200),
		field.Text("description").
			Optional(),

		// Pricing
		field.Enum("pricing_model").
			Values("free", "one_time", "subscription", "per_seat").
			Default("free"),
		field.Int64("price_cents").
			Default(0).
			Comment("Price in cents (0 for free)"),
		field.String("currency").
			Default("USD").
			MaxLen(3).
			Comment("ISO 4217 currency code"),

		// Status
		field.Enum("status").
			Values("draft", "pending_review", "published", "archived").
			Default("draft"),

		// Metadata
		field.JSON("metadata", map[string]any{}).
			Optional().
			Comment("App-specific metadata"),

		// Timestamps
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
		field.Time("published_at").
			Optional().
			Nillable().
			Comment("When the listing was published"),
	}
}

// LicenseMixin provides the core fields for marketplace licenses.
// Apps can use this mixin to create their own License schema while
// adding app-specific fields and edges.
type LicenseMixin struct {
	mixin.Schema
}

// Fields returns the core license fields.
func (LicenseMixin) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),

		// References
		field.UUID("listing_id", uuid.UUID{}).
			Comment("The marketplace listing this license grants access to"),
		field.UUID("organization_id", uuid.UUID{}).
			Comment("The organization that holds this license"),
		field.UUID("purchased_by", uuid.UUID{}).
			Comment("Principal who purchased this license"),

		// License type
		field.Enum("license_type").
			Values("seat_based", "team", "unlimited").
			Default("unlimited"),

		// Seats (for seat-based licenses)
		field.Int("seats").
			Optional().
			Nillable().
			Comment("Number of seats (nil for unlimited)"),
		field.Int("used_seats").
			Default(0).
			Comment("Currently assigned seats"),

		// Validity
		field.Time("valid_from").
			Default(time.Now).
			Comment("When the license becomes active"),
		field.Time("valid_until").
			Optional().
			Nillable().
			Comment("When the license expires (nil for perpetual)"),

		// Stripe integration
		field.String("stripe_subscription_id").
			Optional().
			Nillable().
			Comment("Stripe subscription ID for recurring licenses"),

		// Timestamps
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}

// SeatAssignmentMixin provides the core fields for license seat assignments.
// Apps can use this mixin to track which principals are assigned to license seats.
type SeatAssignmentMixin struct {
	mixin.Schema
}

// Fields returns the seat assignment fields.
func (SeatAssignmentMixin) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),

		field.UUID("license_id", uuid.UUID{}).
			Comment("The license this seat belongs to"),
		field.UUID("principal_id", uuid.UUID{}).
			Comment("The principal assigned to this seat"),
		field.UUID("assigned_by", uuid.UUID{}).
			Comment("Principal who made this assignment"),

		field.Time("assigned_at").
			Default(time.Now).
			Immutable(),
	}
}

// SubscriptionMixin provides the core fields for platform subscriptions.
// Apps can use this mixin to create their own Subscription schema for
// tracking organization-level platform access.
type SubscriptionMixin struct {
	mixin.Schema
}

// Fields returns the core subscription fields.
func (SubscriptionMixin) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),

		// Organization reference
		field.UUID("organization_id", uuid.UUID{}).
			Comment("The subscribing organization"),

		// The listing this subscription is for. A subscription without one
		// is the organization-wide platform subscription, of which an
		// organization has at most one.
		field.UUID("listing_id", uuid.UUID{}).
			Optional().
			Nillable().
			Comment("Listing this subscription is for; null for the platform subscription"),

		// Plan
		field.String("plan_tier").
			NotEmpty().
			Default("free").
			Comment("Plan name: free, starter, pro, enterprise"),

		// Status
		field.Enum("status").
			Values("active", "trialing", "past_due", "canceled", "unpaid").
			Default("active"),

		// Billing period
		field.Time("current_period_start").
			Default(time.Now),
		field.Time("current_period_end"),

		// Stripe integration
		field.String("stripe_subscription_id").
			Unique().
			Optional().
			Nillable(),
		field.String("stripe_customer_id").
			Optional().
			Nillable(),

		// Cancellation
		field.Bool("cancel_at_period_end").
			Default(false),

		// Timestamps
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}

// CreatorOrgMixin provides fields for creator/publisher organizations.
// Use this mixin for organizations that create and sell products on the marketplace.
// This is separate from OrganizationBase which is for consumer organizations.
type CreatorOrgMixin struct {
	mixin.Schema
}

// Fields returns the creator organization fields.
func (CreatorOrgMixin) Fields() []ent.Field {
	baseFields := BaseMixin{}.Fields()
	creatorFields := []ent.Field{
		field.String("name").
			NotEmpty(),
		field.String("slug").
			NotEmpty().
			Unique().
			Comment("URL-safe identifier"),
		field.String("logo_url").
			Optional().
			Nillable(),
		field.Text("description").
			Optional().
			Comment("Publisher description for marketplace"),
		field.String("website_url").
			Optional().
			Nillable(),
		field.JSON("settings", map[string]any{}).
			Optional().
			Comment("Publisher-specific settings"),
		field.Bool("verified").
			Default(false).
			Comment("Platform-verified publisher"),
		field.Bool("active").
			Default(true),

		// Stripe Connect for payouts
		field.String("stripe_connect_id").
			Optional().
			Nillable().
			Comment("Stripe Connect account ID for payouts"),
		field.Bool("stripe_onboarding_complete").
			Default(false),

		// Revenue share override (if different from platform default)
		field.Int("revenue_share_percent").
			Optional().
			Nillable().
			Comment("Creator's revenue share percentage (nil = platform default)"),
	}
	return append(baseFields, creatorFields...)
}
