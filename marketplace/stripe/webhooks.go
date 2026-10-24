package stripe

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/stripe/stripe-go/v84"
	"github.com/stripe/stripe-go/v84/webhook"
)

// ErrWebhookSecretRequired is returned when a webhook is verified without
// a signing secret. An empty secret would accept a signature anyone can
// compute, so verification fails closed.
var ErrWebhookSecretRequired = errors.New("stripe: webhook signing secret is required")

// VerifyWebhook verifies the Stripe webhook signature and returns the parsed
// event. It returns ErrWebhookSecretRequired when secret is empty.
func VerifyWebhook(payload []byte, signature, secret string) (*stripe.Event, error) {
	if secret == "" {
		return nil, ErrWebhookSecretRequired
	}
	event, err := webhook.ConstructEvent(payload, signature, secret)
	if err != nil {
		return nil, fmt.Errorf("webhook verification failed: %w", err)
	}
	return &event, nil
}

// parseCheckoutSession extracts a checkout session from an event.
func parseCheckoutSession(event *stripe.Event) (*stripe.CheckoutSession, error) {
	var sess stripe.CheckoutSession
	if err := json.Unmarshal(event.Data.Raw, &sess); err != nil {
		return nil, fmt.Errorf("failed to parse checkout session: %w", err)
	}
	return &sess, nil
}

// parseSubscription extracts a subscription from an event.
//
//nolint:unparam // Subscription return value will be used when handlers are implemented
func parseSubscription(event *stripe.Event) (*stripe.Subscription, error) {
	var sub stripe.Subscription
	if err := json.Unmarshal(event.Data.Raw, &sub); err != nil {
		return nil, fmt.Errorf("failed to parse subscription: %w", err)
	}
	return &sub, nil
}

// parseInvoice extracts an invoice from an event.
//
//nolint:unused // Will be used when invoice handlers are implemented
func parseInvoice(event *stripe.Event) (*stripe.Invoice, error) {
	var inv stripe.Invoice
	if err := json.Unmarshal(event.Data.Raw, &inv); err != nil {
		return nil, fmt.Errorf("failed to parse invoice: %w", err)
	}
	return &inv, nil
}

// parseAccount extracts a Connect account from an event.
//
//nolint:unused // Will be used when Connect account handlers are implemented
func parseAccount(event *stripe.Event) (*stripe.Account, error) {
	var acct stripe.Account
	if err := json.Unmarshal(event.Data.Raw, &acct); err != nil {
		return nil, fmt.Errorf("failed to parse account: %w", err)
	}
	return &acct, nil
}

// WebhookEventTypes lists the Stripe event types we handle.
var WebhookEventTypes = []string{
	"checkout.session.completed",
	"checkout.session.async_payment_succeeded",
	"customer.subscription.created",
	"customer.subscription.updated",
	"customer.subscription.deleted",
	"invoice.paid",
	"invoice.payment_failed",
	"account.updated", // Stripe Connect
}
