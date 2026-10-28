# Billing

Package `billing` takes payments through
[payforge](https://github.com/plexusone/payforge). The products and prices
come from a pricing spec; payforge creates them at Stripe, starts checkout and
the customer portal, and turns what Stripe reports into entitlements. `billing`
supplies the storage and the endpoints, on the SystemForge database.

The organization pays. A person starts a checkout or opens the portal on behalf
of an organization they may manage, and the plan or license belongs to the
organization.

## What it does

| Stripe reports | SystemForge stores |
|----------------|--------------------|
| A subscription to a plan of the spec, created, changed or ended | The organization's platform subscription (`sf_subscriptions` row with no listing): `plan_tier` is the plan the organization is on, the spec's default plan when nothing grants |
| A paid one-time checkout for a listing | A license for the buying organization |
| A full refund of that checkout | The license suspended, for good |
| A dispute of that payment | The license suspended while the dispute is open or once it is lost; restored when it is won |
| A seller's connected account changing | Whether the seller can take payments, which decides whether its paid listings can be published |

Every change writes the authorization graph again, whether or not the database
changed, so a graph write that failed is repaired when Stripe redelivers the
event. Events are recorded once processed (`sf_billing_events`), so a
redelivered event applies once. Events of another app sharing the Stripe
account, of the other mode (test or live), or from a seller's own account are
acknowledged and not applied.

## Wiring

```go
import (
    "github.com/plexusone/payforge"

    "github.com/plexusone/systemforge/billing"
    "github.com/plexusone/systemforge/billing/pglock"
    "github.com/plexusone/systemforge/marketplace"
)

spec, err := pricingspec.Load(specFile)

// One lock per organization, held across instances. On a single instance,
// &payforge.MemoryLocker{} also works.
locker := pglock.New(sqlDB, logger)

store := billing.NewStore(entClient)
sink := billing.NewSink(entClient,
    billing.WithAuthzSyncer(marketplace.NewSpiceDBSyncer(spice)),
    billing.OnEntitlement(func(ctx context.Context, c billing.PlanChange) error {
        return nil // update state of your own that follows the plan
    }))

client, reader, err := billing.NewStripe(spec, billing.StripeConfig{
    SecretKey:       os.Getenv("STRIPE_SECRET_KEY"),
    WebhookSecrets:  []string{platformSecret, connectSecret},
    AllowedURLHosts: []string{"app.example.com"},
    Locker:          locker,
})

life := &payforge.Lifecycle{
    Spec: spec, Store: store, Sink: sink,
    Sales: sink, Sellers: sink, Disputes: sink,
    Provider: client, Accounts: client, Locker: locker,
}
hook, err := billing.NewWebhookHandler(billing.WebhookConfig{
    Reader: reader, Lifecycle: life, Store: store, Checkouts: sink, Logger: logger,
})
mux.Handle("POST /billing/webhook", hook)

co, err := billing.NewCheckout(billing.CheckoutConfig{
    Billing: client, Connect: client, Spec: spec, Store: store, DB: entClient,
    Listings: svc.Listings(), ListingProduct: "listing",
    Purchases: marketplace.OrgRolePurchaseAuthorizer(orgAuthorizer),
    Locker:    locker,
    URLs: billing.RedirectURLs{
        PlanSuccess:    "https://app.example.com/billing/done",
        PlanCancel:     "https://app.example.com/pricing",
        ListingSuccess: "https://app.example.com/market/done",
        ListingCancel:  "https://app.example.com/market",
        PortalReturn:   "https://app.example.com/billing",
    },
    AllowedURLHosts: []string{"app.example.com"},
    Logger:          logger,
})
co.Register(mux, "/billing")

// Paid listings can be published only by sellers that can take payments.
svc := marketplace.NewEntService(entClient, syncer).WithPublishGate(billing.NewSellerGate(store))
```

Without a Stripe key, use `payforge.Disabled(spec)`: every organization is on
the spec's default plan and checkout answers 501.

Before taking payments, sync the catalog to Stripe once with the client's
`Sync` (see payforge's catalog guide), and register the webhook endpoint for
the events payforge reads.

### Endpoints

| Endpoint | Body | Answer |
|----------|------|--------|
| `POST /billing/checkout/plan` | `{"plan": "pro", "interval": "month"}` | `{"url": ...}` of the checkout |
| `POST /billing/checkout/listing` | `{"listing_id": "..."}` | `{"url": ...}` of the checkout |
| `POST /billing/portal` | none | `{"url": ...}` of the customer portal |
| `POST /billing/webhook` | Stripe's event | `ok` |

- **The organization** comes from the caller's credential
  (`requestprincipal.RequestPrincipal.Organization`); set
  `CheckoutConfig.Organization` to resolve it another way.
- **The caller** must pass `Purchases` for the organization.
  `NewCheckout` refuses a configuration without one.
- **The Stripe customer** is found from the organization, never from the
  request, and created the first time.
- **Redirect URLs** are configured, never taken from the request, and must be
  https on a host in `AllowedURLHosts`. With a test-mode Stripe key, localhost
  and other loopback hosts also pass, over http too, for local development;
  with a live key they are refused when the checkout is built.
- **Errors** are fixed messages, `{"error": ...}`; causes are logged.

The webhook answers 400 to a signature that does not verify, 413 to a body over
1 MiB, 500 when handling failed so Stripe redelivers, and 200 otherwise.

### Listings

Only one-time listings are sold through checkout: payforge sells subscriptions
to the spec's plans, not to individual listings. A listing is sold as the
spec's seller-set product named by `ListingProduct`, at the listing's price.
With a `marketplace` section in the spec, the sale goes to the seller's
connected account and the platform keeps its fee; record the account with
`store.LinkSeller` after payforge's `Connect.CreateAccount`. The checkout is
recorded (`sf_billing_orders`) before the buyer sees it, and its payment,
refunds and disputes are matched through that record.

## Tables

Created by the Ent schema migration (`systemauth migrate`, or
`Schema.Create`); no SQL migration is needed.

| Table | Holds |
|-------|-------|
| `sf_billing_events` | Processed event IDs; prune with `Store.PruneEvents` |
| `sf_billing_customers` | Stripe customer of each organization |
| `sf_billing_orders` | Listing checkouts and the license each granted |
| `sf_billing_refunds` | Highest refunded total per charge |
| `sf_billing_disputes` | Disputes of charges |
| `sf_billing_sellers` | Sellers' connected accounts |

## Upgrading from `marketplace/stripe`

`marketplace/stripe`, `marketplace.CheckoutService` and the marketplace API's
`POST /checkout` endpoint are removed, with the dependency on
`github.com/stripe/stripe-go/v84`.

1. Write a pricing spec for the plans and products you sell, and sync it to
   Stripe. Prices are found by lookup key; a price created by hand before the
   spec grants nothing unless listed in `payforge.Lifecycle.LegacyPrices`.
2. Replace `stripe.NewCheckoutService` and `EntService.WithCheckout` with the
   wiring above, and mount `billing`'s endpoints. Remove
   `marketplace.WithPurchaseAuthorizer`; pass the authorizer as
   `CheckoutConfig.Purchases`.
3. Clients call `POST /billing/checkout/listing` with `listing_id` only, in
   place of `POST /checkout`. The organization comes from the credential, and
   `success_url` and `cancel_url` are configured on the server.
4. Point the Stripe webhook endpoint at the new handler; there was none before.
   Add the events payforge reads: `checkout.session.completed`,
   `checkout.session.async_payment_succeeded`,
   `checkout.session.async_payment_failed`, `customer.subscription.*`,
   `charge.refunded`, `charge.dispute.created`, `charge.dispute.closed`, and,
   with a marketplace, `account.updated` on the Connect endpoint.
5. Run the schema migration to create the `sf_billing_*` tables.
6. Listings sold by subscription or per seat cannot be bought through the new
   checkout. Licenses granted for them earlier are unchanged; sell
   subscriptions as plans of the spec.
