# ADR-021: Billing in the Organization Console

**Status:** Proposed
**Deciders:** @grokify
**Relates to:** ADR-018 (the console this extends), INIT-SYSTEMFORGE-015
(the `billing` package over payforge, which this puts to use).

## Context

The `billing` package turns a pricing spec into Stripe prices, takes payment
through Stripe Checkout, opens Stripe's customer portal, and stores a paid
subscription as the organization's plan. It is tested, but every host had to
wire it: build the Stripe client, the store, the sink, the lifecycle and the
webhook, mount the routes, and build screens for choosing a plan. Each
deployment that sells plans needs the same wiring and the same screens.

An organization's plan is not an application's. It is chosen once for the
organization, by the people who manage it, which is the console's audience
(ADR-018).

## Decision

1. **SystemAuth wires billing from configuration.** A `billing` section
   holds the Stripe secret key and the webhook signing secrets, as secret
   references. The host passes its pricing spec as `Options.Pricing`, and
   may pass `Options.OnPlanChange` for state of its own that follows the
   plan.
2. **Free mode is the absence of a key.** With a `billing` section and no
   key, every organization is on the spec's default plan, the console shows
   the plans without a way to buy, and no webhook is served. A deployment
   can name `${STRIPE_SECRET_KEY}` in its configuration and turn payments on
   by setting the secret.
3. **The webhook is on the SystemAuth host**, at `/billing/webhook`.
4. **The console has a billing section.** Under
   `/console/api/v1/organizations/{org}/billing`: the organization's plan,
   its subscription and the spec's pricing view (any member); checkout and
   the customer portal (owners and admins). The console's pages show it at
   `/console/orgs/{org}/billing`.
5. **Return addresses are fixed on the server.** Checkout and the portal
   return the buyer to the organization's billing page. A configured URL
   may name `{organization}`, filled with the organization the caller was
   authorized for, never with anything else from the request.
6. **Names under `localhost` are loopback** (RFC 6761) for the test-mode
   redirect rules, so a local setup on `auth.localhost` can complete a
   test checkout. A live key still refuses every loopback host.
7. **Applications read the plan; they do not store it.**
   `Service.OrganizationPlan` returns the plan for limits and features,
   looked up from the spec at the moment of a check.

## Consequences

- A host that sells plans supplies a pricing spec and two secrets, and
  syncs its prices with `Service.SyncPrices`.
- Buying is in one place for every application of a deployment.
- The console's billing section has no listing (marketplace) checkout; a
  deployment that sells listings still mounts `billing.Checkout` itself.
