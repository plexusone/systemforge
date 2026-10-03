// Package stripe provides Stripe integration for the marketplace.
package stripe

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/stripe/stripe-go/v84"
	"github.com/stripe/stripe-go/v84/checkout/session"

	"github.com/plexusone/systemforge/marketplace"
)

// Config holds Stripe configuration.
type Config struct {
	// SecretKey is the Stripe secret API key.
	SecretKey string

	// WebhookSecret is the Stripe webhook signing secret.
	WebhookSecret string

	// ConnectAccountID is the Stripe Connect account ID (optional, for platforms).
	ConnectAccountID string
}

// CheckoutService implements marketplace.CheckoutService using Stripe.
type CheckoutService struct {
	config    Config
	listings  marketplace.ListingService
	licenses  marketplace.LicenseService
	authzSync marketplace.AuthzSyncer
}

// NewCheckoutService creates a new Stripe checkout service.
func NewCheckoutService(cfg Config, listings marketplace.ListingService, licenses marketplace.LicenseService, authzSync marketplace.AuthzSyncer) *CheckoutService {
	stripe.Key = cfg.SecretKey
	return &CheckoutService{
		config:    cfg,
		listings:  listings,
		licenses:  licenses,
		authzSync: authzSync,
	}
}

// CreateCheckoutSession creates a Stripe checkout session for a listing.
func (s *CheckoutService) CreateCheckoutSession(ctx context.Context, req marketplace.CheckoutRequest) (*marketplace.CheckoutSession, error) {
	// Get the listing
	listing, err := s.listings.Get(ctx, req.ListingID)
	if err != nil {
		return nil, fmt.Errorf("failed to get listing: %w", err)
	}

	if !listing.IsPublished() {
		return nil, fmt.Errorf("listing is not published")
	}

	// Build line items
	lineItems, err := s.buildLineItems(listing, req.Seats)
	if err != nil {
		return nil, err
	}

	// Determine mode based on pricing model
	mode := stripe.CheckoutSessionModePayment
	if listing.PricingModel == marketplace.PricingSubscription {
		mode = stripe.CheckoutSessionModeSubscription
	}

	// Create checkout session params
	params := &stripe.CheckoutSessionParams{
		Mode:       stripe.String(string(mode)),
		LineItems:  lineItems,
		SuccessURL: stripe.String(req.SuccessURL + "?session_id={CHECKOUT_SESSION_ID}"),
		CancelURL:  stripe.String(req.CancelURL),
		Metadata: map[string]string{
			"listing_id":      req.ListingID.String(),
			"organization_id": req.OrganizationID.String(),
			"purchaser_id":    req.PurchaserID.String(),
		},
		ClientReferenceID: stripe.String(fmt.Sprintf("%s:%s", req.OrganizationID.String(), req.ListingID.String())),
	}

	if req.Seats != nil {
		params.Metadata["seats"] = fmt.Sprintf("%d", *req.Seats)
	}

	// Create the session
	sess, err := session.New(params)
	if err != nil {
		return nil, fmt.Errorf("failed to create checkout session: %w", err)
	}

	return &marketplace.CheckoutSession{
		SessionID: sess.ID,
		URL:       sess.URL,
	}, nil
}

// buildLineItems builds Stripe line items from a listing.
func (s *CheckoutService) buildLineItems(listing *marketplace.Listing, seats *int) ([]*stripe.CheckoutSessionLineItemParams, error) {
	quantity := int64(1)
	if seats != nil && *seats > 0 {
		quantity = int64(*seats)
	}

	// For free listings, we don't need Stripe
	if listing.IsFree() {
		return nil, fmt.Errorf("cannot create checkout for free listing")
	}

	var priceData *stripe.CheckoutSessionLineItemPriceDataParams

	switch listing.PricingModel {
	case marketplace.PricingOneTime:
		priceData = &stripe.CheckoutSessionLineItemPriceDataParams{
			Currency:   stripe.String(listing.Currency),
			UnitAmount: stripe.Int64(listing.PriceCents),
			ProductData: &stripe.CheckoutSessionLineItemPriceDataProductDataParams{
				Name:        stripe.String(listing.Title),
				Description: stripe.String(listing.Description),
			},
		}

	case marketplace.PricingSubscription:
		priceData = &stripe.CheckoutSessionLineItemPriceDataParams{
			Currency:   stripe.String(listing.Currency),
			UnitAmount: stripe.Int64(listing.PriceCents),
			Recurring: &stripe.CheckoutSessionLineItemPriceDataRecurringParams{
				Interval: stripe.String(string(stripe.PriceRecurringIntervalMonth)),
			},
			ProductData: &stripe.CheckoutSessionLineItemPriceDataProductDataParams{
				Name:        stripe.String(listing.Title),
				Description: stripe.String(listing.Description),
			},
		}

	case marketplace.PricingPerSeat:
		priceData = &stripe.CheckoutSessionLineItemPriceDataParams{
			Currency:   stripe.String(listing.Currency),
			UnitAmount: stripe.Int64(listing.PriceCents),
			Recurring: &stripe.CheckoutSessionLineItemPriceDataRecurringParams{
				Interval: stripe.String(string(stripe.PriceRecurringIntervalMonth)),
			},
			ProductData: &stripe.CheckoutSessionLineItemPriceDataProductDataParams{
				Name:        stripe.String(listing.Title + " (per seat)"),
				Description: stripe.String(listing.Description),
			},
		}

	default:
		return nil, fmt.Errorf("unsupported pricing model: %s", listing.PricingModel)
	}

	return []*stripe.CheckoutSessionLineItemParams{
		{
			PriceData: priceData,
			Quantity:  stripe.Int64(quantity),
		},
	}, nil
}

// ProcessWebhook handles Stripe webhook events.
func (s *CheckoutService) ProcessWebhook(ctx context.Context, payload []byte, signature string) error {
	event, err := VerifyWebhook(payload, signature, s.config.WebhookSecret)
	if err != nil {
		return fmt.Errorf("invalid webhook signature: %w", err)
	}

	switch event.Type {
	case "checkout.session.completed":
		return s.handleCheckoutCompleted(ctx, event)
	case "customer.subscription.created":
		return s.handleSubscriptionCreated(ctx, event)
	case "customer.subscription.updated":
		return s.handleSubscriptionUpdated(ctx, event)
	case "customer.subscription.deleted":
		return s.handleSubscriptionDeleted(ctx, event)
	case "invoice.paid":
		return s.handleInvoicePaid(ctx, event)
	case "invoice.payment_failed":
		return s.handleInvoicePaymentFailed(ctx, event)
	default:
		// Ignore unhandled event types
		return nil
	}
}

// handleCheckoutCompleted grants a license after successful checkout.
func (s *CheckoutService) handleCheckoutCompleted(ctx context.Context, event *stripe.Event) error {
	sess, err := parseCheckoutSession(event)
	if err != nil {
		return err
	}

	// Extract metadata
	listingID, err := uuid.Parse(sess.Metadata["listing_id"])
	if err != nil {
		return fmt.Errorf("invalid listing_id in metadata: %w", err)
	}
	orgID, err := uuid.Parse(sess.Metadata["organization_id"])
	if err != nil {
		return fmt.Errorf("invalid organization_id in metadata: %w", err)
	}
	purchaserID, err := uuid.Parse(sess.Metadata["purchaser_id"])
	if err != nil {
		return fmt.Errorf("invalid purchaser_id in metadata: %w", err)
	}

	// Get listing to determine license type
	listing, err := s.listings.Get(ctx, listingID)
	if err != nil {
		return fmt.Errorf("failed to get listing: %w", err)
	}

	// Determine license type and seats
	licenseType := marketplace.LicenseUnlimited
	var seats *int
	if listing.PricingModel == marketplace.PricingPerSeat {
		licenseType = marketplace.LicenseSeatBased
		if seatsStr, ok := sess.Metadata["seats"]; ok {
			var s int
			if _, err := fmt.Sscanf(seatsStr, "%d", &s); err == nil {
				seats = &s
			}
		}
	}

	// Create the license
	license := &marketplace.License{
		ID:             uuid.New(),
		ListingID:      listingID,
		OrganizationID: orgID,
		LicenseType:    licenseType,
		Seats:          seats,
		ValidFrom:      time.Now(),
		PurchasedBy:    purchaserID,
	}

	// For subscriptions, set the Stripe subscription ID
	if sess.Subscription != nil {
		subID := sess.Subscription.ID
		license.StripeSubscriptionID = &subID
	}

	if err := s.licenses.Grant(ctx, license); err != nil {
		// Check if already licensed (idempotency)
		if err == marketplace.ErrAlreadyLicensed {
			return nil
		}
		return fmt.Errorf("failed to grant license: %w", err)
	}

	return nil
}

// handleSubscriptionCreated handles new subscription creation.
func (s *CheckoutService) handleSubscriptionCreated(ctx context.Context, event *stripe.Event) error {
	// Subscription creation is typically handled by checkout.session.completed
	// This handler can be used for subscriptions created outside of checkout
	return nil
}

// handleSubscriptionUpdated handles subscription updates.
func (s *CheckoutService) handleSubscriptionUpdated(_ context.Context, event *stripe.Event) error {
	sub, err := parseSubscription(event)
	if err != nil {
		return err
	}

	// Find the license by Stripe subscription ID and update it
	// This would require adding a method to find license by Stripe subscription ID
	_ = sub // TODO: Implement license update based on subscription status
	return nil
}

// handleSubscriptionDeleted handles subscription cancellation.
func (s *CheckoutService) handleSubscriptionDeleted(_ context.Context, event *stripe.Event) error {
	sub, err := parseSubscription(event)
	if err != nil {
		return err
	}

	// Find and revoke the license
	// This would require adding a method to find license by Stripe subscription ID
	_ = sub // TODO: Implement license revocation
	return nil
}

// handleInvoicePaid handles successful invoice payment.
func (s *CheckoutService) handleInvoicePaid(ctx context.Context, event *stripe.Event) error {
	// Extend license validity if needed
	return nil
}

// handleInvoicePaymentFailed handles failed invoice payment.
func (s *CheckoutService) handleInvoicePaymentFailed(ctx context.Context, event *stripe.Event) error {
	// Mark license as past_due or revoke after grace period
	return nil
}

// Ensure CheckoutService implements marketplace.CheckoutService.
var _ marketplace.CheckoutService = (*CheckoutService)(nil)
