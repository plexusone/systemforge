# Selling Plans from the Console

A deployment that sells plans gives SystemAuth a pricing spec and a
`billing` section in its configuration. Organizations then choose and pay
for a plan in the [organization console](console.md), through Stripe
Checkout, and change or cancel it in Stripe's customer portal. Every
application of the deployment reads the organization's plan from
SystemForge. The design is
[ADR-021](../design/adrs/ADR-021-billing-in-the-organization-console.md),
and plans set by hand are
[ADR-022](../design/adrs/ADR-022-plans-set-by-the-operator.md).

This guide is for a host that runs SystemAuth through `systemauthsvc`. A
host that wires the `billing` package itself, for example to sell
marketplace listings, follows [Billing](../marketplace/billing.md).

## What you need

- **The console,** since organizations buy there. Billing refuses to start
  without a `console` section.
- **A database.** Either `database` in the configuration or a storage
  client the host passes in; the check runs once storage is open, so an
  injected client counts.
- **A pricing spec**
  ([systemspec-pricingpackaging](https://github.com/plexusone/systemspec-pricingpackaging)),
  supplied by the host as `Options.Pricing`.
- **For payments,** a Stripe secret key and the signing secret of a webhook
  endpoint. Without them the deployment runs in free mode.

## The pricing spec

The spec lists the plans, their prices and what each grants. Two fields
decide which plan an organization falls back to and which plans are sold:

- **`defaultPlan`** is the plan of every organization nothing else puts on a
  plan, and the plan an unknown or removed plan ID resolves to
  (`Spec.PlanOrDefault`).
- **`"internal": true`** on a plan keeps it out of the pricing view and out
  of checkout. Only an operator can put an organization on it (see
  [Plans set by the operator](#plans-set-by-the-operator)).

The host loads the spec, usually embedded in its binary, and passes it in:

```go
spec, err := pricingspec.Parse(pricingJSON) // or pricingspec.Load(reader)
if err != nil {
    return err
}
svc, err := systemauthsvc.New(ctx, cfg, systemauthsvc.Options{
    Pricing: spec,
    // Optional: keep state of your own in step with the plan.
    OnPlanChange: func(ctx context.Context, c billing.PlanChange) error {
        return nil
    },
})
```

A configuration with a `billing` section and no `Options.Pricing` fails at
startup.

## Free mode first

A `billing` section without a key is valid. It runs the deployment in free
mode:

```yaml
console:
  web_dir: /opt/myapp/web/console
billing: {}
```

- Every organization is on the spec's default plan, unless an operator has
  set its plan. A host that builds `marketplace.EntitlementSource` over the
  platform subscription passes `marketplace.WithoutPayments()` when
  `Service.TakesPayments()` is false, so a paid plan stored from an earlier
  configuration grants nothing there either.
- The console's billing section shows the plans, with `configured: false`
  and `canManage: false`, and starts no checkout (`409`).
- No webhook route is mounted.

This lets a deployment ship its plans and limits before it takes payments.

## Turning payments on

Name the secrets as references, so setting them turns payments on without
changing the file:

```yaml
billing:
  stripe_secret_key: ${STRIPE_SECRET_KEY}
  stripe_webhook_secrets: ["${STRIPE_WEBHOOK_SECRET}"]
```

| Key | Meaning |
|---|---|
| `stripe_secret_key` | A Stripe secret key, or a restricted key with write access to products, prices, customers, Checkout sessions and the customer portal. Its mode, test or live, is the deployment's. Empty means free mode |
| `stripe_webhook_secrets` | Signing secrets of the webhook endpoint. Several are accepted while one is rotated; empty entries, such as an unset variable, are ignored. At least one is required with a key |

Quote a reference inside a YAML list: `[${VAR}]` is not valid YAML.

Then, once per Stripe account and mode:

1. **Add a webhook endpoint** for `https://<SystemAuth host>/billing/webhook`
   with these events: `checkout.session.completed`,
   `checkout.session.async_payment_succeeded`,
   `checkout.session.async_payment_failed`,
   `customer.subscription.created`, `customer.subscription.updated`,
   `customer.subscription.deleted`, `invoice.paid` and
   `invoice.payment_failed`.
2. **Create the products and prices** from the spec with `billing sync`
   (see [The host's billing command](#the-hosts-billing-command)). Prices are
   found by lookup key, so running it again changes only what differs.
3. **Turn on the customer portal** in the Stripe Dashboard, allowing plan
   changes between the synced prices, cancellation and payment method
   updates.

On PostgreSQL, billing holds its locks in the database, so several
instances can serve the webhook. On another database the locks are in
memory, which suits one instance only.

### Locally, in test mode

With a test key, checkout accepts return addresses on loopback hosts over
http, including names under `localhost` such as `auth.localhost`
(RFC 6761). A live key refuses them. Forward Stripe's events with the
Stripe CLI, logged in to the same account or sandbox as the key:

```bash
stripe listen --forward-to http://auth.localhost:8080/billing/webhook \
  --events checkout.session.completed,checkout.session.async_payment_succeeded,checkout.session.async_payment_failed,customer.subscription.created,customer.subscription.updated,customer.subscription.deleted,invoice.paid,invoice.payment_failed
```

It prints the signing secret to use as `STRIPE_WEBHOOK_SECRET`. Pay with the
test card `4242 4242 4242 4242`.

## The console's billing section

The console serves billing under
`/console/api/v1/organizations/{org}/billing`, signed in with the login
session:

| Call | Who | Does |
|---|---|---|
| `GET …/billing` | Any member | The organization's plan, its subscription, the spec's pricing view, `mode` (`test` or `live`), `configured`, `canManage` and `setByOperator` |
| `POST …/billing/checkout` | Owners and admins | Starts a checkout for `{"plan": "builder", "interval": "month"}` and answers `{"url": …}` |
| `POST …/billing/portal` | Owners and admins | Opens the customer portal and answers `{"url": …}` |

- A person outside the organization gets `404`, and a member who is not an
  owner or admin gets `403` for checkout and the portal.
- Checkout answers `409` in free mode, while an operator's plan is set, and
  when the organization already has a subscription, which it changes in the
  portal.
- Checkout and the portal return the buyer to
  `/console/orgs/{org}/billing`, with `?checkout=success` or
  `?checkout=canceled` after checkout. The addresses are fixed on the
  server; nothing in the request changes them.

This release serves the billing API only. The billing page of
`@plexusone/console` comes in a later systemforge-web release, which will
enable it with `createConsoleApp({ billing: true })`; until then a host
builds its own page on the API.

## Which plan an organization is on

`Service.OrganizationPlan(ctx, org)` returns the plan an application
should enforce, looked up from the spec at the moment of the check:

1. **The operator's plan,** when one is set, whatever the subscription's
   status and also in free mode.
2. **The subscription's plan,** while payments are on and the subscription
   is active, in a trial or past due.
3. **The spec's default plan** otherwise.

Billing events never change the operator's plan. They keep updating the
subscription underneath, so a paid plan takes effect again when the
operator's plan is cleared. Applications read the plan from SystemForge and
keep no copy of their own.

## Plans set by the operator

An operator puts an organization on any plan of the spec by hand: an
internal plan for the deployment's own accounts, or a plan given by
agreement. While it is set, the organization stays on it through any
billing activity, plan checkout is refused, and the console reports
`setByOperator`. The note is kept for operators and not shown to members.

## The host's billing command

`billingcmd.Command` adds `billing` to the host's Cobra CLI. It needs a
function that loads the host's SystemAuth configuration and pricing spec:

```go
import "github.com/plexusone/systemforge/billing/billingcmd"

root.AddCommand(billingcmd.Command(func(ctx context.Context) (*systemauthsvc.Config, *pricingspec.Spec, error) {
    cfg, err := systemauthsvc.LoadConfig(configPath)
    if err != nil {
        return nil, nil, err
    }
    spec, err := pricingspec.Parse(pricingJSON)
    return cfg, spec, err
}))
```

It provides:

```bash
myapp billing sync --dry-run                       # what would change at Stripe
myapp billing sync                                 # create or update products and prices
myapp billing plan list                            # every organization with an operator's plan
myapp billing plan show <organization>
myapp billing plan set <organization> <plan> --note "partner pilot"
myapp billing plan clear <organization>
```

An organization is named by its slug, its ID, or its owner's email address.
A note is at most 200 characters. `sync` reads only the Stripe key, so it
runs without starting the service.

## Upgrading a database

The tables and the operator's plan columns of `sf_subscriptions` are
created by the Ent schema migration (`systemauth migrate`, or
`Schema.Create`). Every deployment runs it on upgrading, with or without
billing, since every query of subscriptions reads those columns. No SQL
migration is needed.
