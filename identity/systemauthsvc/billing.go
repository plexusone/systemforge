package systemauthsvc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/plexusone/payforge"
	payforgestripe "github.com/plexusone/payforge/stripe"
	"github.com/plexusone/systemspec-pricingpackaging/pricingspec"

	"github.com/plexusone/systemforge/billing"
	"github.com/plexusone/systemforge/billing/pglock"
	"github.com/plexusone/systemforge/console"
)

// BillingWebhookPath is where the payment provider posts events, on the
// SystemAuth host (ADR-021).
const BillingWebhookPath = "/billing/webhook"

// Where the payment provider sends a buyer back to: the organization's
// billing page in the console.
const (
	billingPage     = console.Prefix + "/orgs/" + billing.OrganizationPlaceholder + "/billing"
	billingSuccess  = billingPage + "?checkout=success"
	billingCanceled = billingPage + "?checkout=canceled"
)

// ErrBillingNotConfigured is returned by billing operations in free mode.
var ErrBillingNotConfigured = errors.New("systemauthsvc: billing has no payment provider (free mode)")

// billingService is billing as the configuration enables it. client is nil
// in free mode.
type billingService struct {
	spec     *pricingspec.Spec
	client   *payforgestripe.Client
	webhook  http.Handler
	checkout *billing.CheckoutConfig
}

// openBilling builds billing from the configuration's billing section and
// mounts the webhook. The console's section is mounted with the console.
func (s *Service) openBilling(c *Config, opts Options) error {
	if c.Billing == nil {
		return nil
	}
	if opts.Pricing == nil {
		return errors.New("systemauthsvc: the configuration has billing, which needs Options.Pricing")
	}
	if s.client == nil {
		return errors.New("systemauthsvc: billing needs a database")
	}
	b := &billingService{spec: opts.Pricing}
	s.billing = b
	if !c.Billing.Configured() {
		s.logger.Warn("billing has no secret key: free mode, every organization is on the default plan",
			"default_plan", opts.Pricing.PlanOrDefault("").ID)
		return nil
	}

	issuer, err := url.Parse(c.Issuer)
	if err != nil || issuer.Host == "" {
		return fmt.Errorf("systemauthsvc: billing needs an absolute issuer URL: %q", c.Issuer)
	}
	hosts := []string{issuer.Hostname()}
	var locker payforge.Locker = &payforge.MemoryLocker{}
	if s.dialect == "postgres" && s.db != nil {
		locker = pglock.New(s.db, s.logger)
	} else {
		s.logger.Warn("billing holds its locks in memory, which suits one instance only", "storage", s.storageName)
	}
	client, reader, err := billing.NewStripe(opts.Pricing, billing.StripeConfig{
		SecretKey: c.Billing.StripeSecretKey, WebhookSecrets: c.Billing.WebhookSecrets(),
		AllowedURLHosts: hosts, Locker: locker,
	})
	if err != nil {
		return fmt.Errorf("systemauthsvc: billing: %w", err)
	}
	store := billing.NewStore(s.client)
	sinkOpts := []billing.SinkOption{billing.WithSinkLogger(s.logger)}
	if opts.OnPlanChange != nil {
		sinkOpts = append(sinkOpts, billing.OnEntitlement(opts.OnPlanChange))
	}
	sink := billing.NewSink(s.client, sinkOpts...)
	life := &payforge.Lifecycle{
		Spec: opts.Pricing, Store: store, Sink: sink, Provider: client, Locker: locker,
	}
	hook, err := billing.NewWebhookHandler(billing.WebhookConfig{
		Reader: reader, Lifecycle: life, Store: store, Locker: locker, Logger: s.logger,
	})
	if err != nil {
		return fmt.Errorf("systemauthsvc: billing: %w", err)
	}
	base := strings.TrimRight(c.Issuer, "/")
	b.client, b.webhook = client, hook
	b.checkout = &billing.CheckoutConfig{
		Billing: client, Spec: opts.Pricing, Store: store, DB: s.client, Locker: locker,
		URLs: billing.RedirectURLs{
			PlanSuccess: base + billingSuccess, PlanCancel: base + billingCanceled, PortalReturn: base + billingPage,
		},
		AllowedURLHosts: hosts, Logger: s.logger,
	}
	s.server.Router().Post(BillingWebhookPath, hook.ServeHTTP)
	s.logger.Info("billing enabled", "provider", "stripe", "mode", client.Mode(), "webhook", BillingWebhookPath)
	return nil
}

// billingConsole is the console's billing section, or nil when billing is
// not configured.
func (s *Service) billingConsole() (http.Handler, error) {
	if s.billing == nil {
		return nil, nil
	}
	cfg := billing.ConsoleConfig{
		Spec: s.billing.spec, DB: s.client, Checkout: s.billing.checkout,
		Principal:      s.consolePrincipal,
		WriteAuthError: s.writeBillingAuthError,
		Role:           s.organizationRole,
		Logger:         s.logger,
	}
	if s.billing.client != nil {
		cfg.Mode = string(s.billing.client.Mode())
	}
	h, err := billing.NewConsole(cfg)
	if err != nil {
		return nil, fmt.Errorf("systemauthsvc: %w", err)
	}
	return h, nil
}

// organizationRole is the person's organization role, or "" when they are
// not a member, as the orgs claim reports it.
func (s *Service) organizationRole(ctx context.Context, principal, org uuid.UUID) (string, error) {
	orgs, err := s.consoleOrganizations(ctx, principal)
	if err != nil {
		return "", err
	}
	for _, o := range orgs {
		if o.ID == org.String() {
			return o.Role, nil
		}
	}
	return "", nil
}

// writeBillingAuthError answers a billing request without a usable login
// session, as the console's other sections do.
func (s *Service) writeBillingAuthError(w http.ResponseWriter, err error) {
	status, msg := http.StatusUnauthorized, "sign in required"
	if !errors.Is(err, console.ErrNoSession) {
		s.logger.Error("billing: reading the login session", "error", err)
		status, msg = http.StatusInternalServerError, "internal error"
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(map[string]string{"error": msg}); err != nil {
		s.logger.Debug("billing: writing a response", "error", err)
	}
}

// OrganizationPlan is the plan an organization is on, for the host's
// limits and features: its subscription's plan while the subscription
// grants it, and the spec's default plan otherwise, which is every
// organization's plan in free mode. It needs billing in the configuration.
func (s *Service) OrganizationPlan(ctx context.Context, org uuid.UUID) (pricingspec.Plan, error) {
	if s.billing == nil {
		return pricingspec.Plan{}, errors.New("systemauthsvc: the configuration has no billing section")
	}
	plan, _, err := billing.OrganizationPlan(ctx, s.client, s.billing.spec, org)
	return plan, err
}

// SyncPrices creates or updates the payment provider's products and prices
// from the pricing spec, or with dryRun reports what it would change. It
// reads only the configuration's Stripe key, so it runs without starting
// the service, and fails with ErrBillingNotConfigured when there is none.
func SyncPrices(ctx context.Context, cfg *Config, spec *pricingspec.Spec, dryRun bool) (payforgestripe.SyncReport, error) {
	if cfg == nil || !cfg.Billing.Configured() {
		return payforgestripe.SyncReport{}, ErrBillingNotConfigured
	}
	if spec == nil {
		return payforgestripe.SyncReport{}, errors.New("systemauthsvc: syncing prices needs a pricing spec")
	}
	client, err := payforgestripe.New(spec, payforgestripe.Config{SecretKey: cfg.Billing.StripeSecretKey})
	if err != nil {
		return payforgestripe.SyncReport{}, fmt.Errorf("systemauthsvc: billing: %w", err)
	}
	return client.Sync(ctx, dryRun)
}
