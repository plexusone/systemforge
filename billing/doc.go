// Package billing connects SystemForge to payforge
// (github.com/plexusone/payforge), which turns a pricing spec into products
// and prices at a payment provider and a paid subscription into an
// entitlement. It supplies the ports payforge leaves to the host, backed by
// the SystemForge Ent client, and the HTTP handlers an application mounts.
//
// It is a package of its own, not part of marketplace, because it serves
// both the organization's platform plan and marketplace listings, and
// because marketplace stays free of any payment provider: billing depends
// on marketplace, never the reverse.
//
// # The subject
//
// The subject payforge bills is the buying organization: payforge's
// Subject.ID and Entitlement.Subject are an organization ID. A person pays
// on behalf of an organization they may manage.
//
// # Pieces
//
//   - [Store] is payforge's Store: processed event IDs, kept with a unique
//     constraint so an event is applied once across instances, and the
//     mapping from a provider customer to an organization. It also records
//     listing orders and sellers' connected accounts.
//   - billing/pglock is a payforge.Locker that holds across instances with
//     a PostgreSQL advisory lock; payforge.MemoryLocker holds within one
//     process. Give the same Locker to the lifecycle, the Stripe client and
//     billing's configs.
//   - [Sink] is payforge's EntitlementSink, SaleSink, SellerSink and
//     DisputeSink: a plan becomes the organization's platform subscription,
//     a paid listing checkout a license, a full refund or a dispute the
//     license's suspension, and a seller's connected account whether its
//     paid listings can be published ([SellerGate]). Every apply writes the
//     authorization graph again, so a sync that failed is repaired by the
//     provider's redelivery.
//   - [NewWebhookHandler] is the webhook endpoint.
//   - [Checkout] holds the checkout and customer-portal endpoints.
//   - [NewStripe] builds the payforge Stripe client and webhook reader with
//     the settings production needs.
//
// # Wiring
//
//	locker := pglock.New(sqlDB, logger) // &payforge.MemoryLocker{} on one instance
//	store := billing.NewStore(entClient)
//	sink := billing.NewSink(entClient,
//	    billing.WithAuthzSyncer(marketplace.NewSpiceDBSyncer(spice)))
//	client, reader, err := billing.NewStripe(spec, billing.StripeConfig{
//	    SecretKey: key, WebhookSecrets: secrets,
//	    AllowedURLHosts: []string{"app.example.com"}, Locker: locker})
//	life := &payforge.Lifecycle{Spec: spec, Store: store, Sink: sink,
//	    Sales: sink, Sellers: sink, Disputes: sink,
//	    Provider: client, Accounts: client, Locker: locker}
//	hook, err := billing.NewWebhookHandler(billing.WebhookConfig{
//	    Reader: reader, Lifecycle: life, Store: store, Checkouts: sink,
//	    Logger: logger})
//	mux.Handle("POST /billing/webhook", hook)
//
//	co, err := billing.NewCheckout(billing.CheckoutConfig{
//	    Billing: client, Connect: client, Spec: spec, Store: store,
//	    DB: entClient, Listings: svc.Listings(), ListingProduct: "listing",
//	    Purchases: marketplace.OrgRolePurchaseAuthorizer(orgAuthz),
//	    Locker: locker, URLs: billing.RedirectURLs{...},
//	    AllowedURLHosts: []string{"app.example.com"}, Logger: logger})
//	co.Register(mux, "/billing")
//
//	svc.WithPublishGate(billing.NewSellerGate(store))
//
// The tables are created by the Ent schema migration (Schema.Create, or
// systemauth migrate); no SQL migration is needed.
//
// # Decisions
//
// Redirect URLs are configured on the server and never read from a
// request. Responses carry fixed messages; causes are logged. Only one-time
// listings are sold through [Checkout]: payforge sells subscriptions to the
// pricing spec's plans, not to individual listings. Once billing is wired,
// it owns the organization's platform subscription: an entitlement sets its
// plan, so a plan set by hand is replaced by the next subscription event
// for the organization.
package billing
