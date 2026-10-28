package billing

import (
	"errors"
	"fmt"

	"github.com/plexusone/payforge"
	payforgestripe "github.com/plexusone/payforge/stripe"
	"github.com/plexusone/systemspec-pricingpackaging/pricingspec"
)

// StripeConfig is what NewStripe needs. It holds secrets: do not log it.
type StripeConfig struct {
	// SecretKey is the Stripe secret key. Its mode (test or live) is the
	// mode webhook events must match.
	SecretKey string
	// WebhookSecrets are the signing secrets of the webhook endpoints: one,
	// and a second for connected-account events when the spec has a
	// marketplace.
	WebhookSecrets []string
	// AllowedURLHosts are the hosts redirect URLs may name. Required; give
	// CheckoutConfig.AllowedURLHosts the same list.
	AllowedURLHosts []string
	// Locker is held per organization around a plan checkout. Required;
	// give the lifecycle and CheckoutConfig the same Locker.
	Locker payforge.Locker
}

// NewStripe checks the configuration as payforge.CheckStartup does, and
// returns the Stripe client and the webhook reader, with the reader's mode
// set from the key so events of the other mode are acknowledged and not
// applied. It fails with payforge.ErrNotConfigured when there is no key:
// use payforge.Disabled for free mode then.
func NewStripe(spec *pricingspec.Spec, cfg StripeConfig) (*payforgestripe.Client, payforgestripe.Webhook, error) {
	if cfg.SecretKey == "" {
		return nil, payforgestripe.Webhook{}, payforge.ErrNotConfigured
	}
	if err := payforge.CheckStartup(spec, payforge.ProviderConfig{SecretKey: cfg.SecretKey, WebhookSecrets: cfg.WebhookSecrets}); err != nil {
		return nil, payforgestripe.Webhook{}, err
	}
	if len(cfg.AllowedURLHosts) == 0 {
		return nil, payforgestripe.Webhook{}, errors.New("billing: AllowedURLHosts is required")
	}
	if cfg.Locker == nil {
		return nil, payforgestripe.Webhook{}, errors.New("billing: a Locker is required")
	}
	client, err := payforgestripe.New(spec, payforgestripe.Config{
		SecretKey: cfg.SecretKey, AllowedURLHosts: cfg.AllowedURLHosts, Locker: cfg.Locker,
	})
	if err != nil {
		return nil, payforgestripe.Webhook{}, fmt.Errorf("billing: stripe client: %w", err)
	}
	return client, payforgestripe.Webhook{Mode: client.Mode(), Secrets: cfg.WebhookSecrets}, nil
}
