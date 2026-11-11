# ADR-022: Plans Set by the Operator

**Status:** Proposed
**Deciders:** @grokify
**Relates to:** ADR-021 (billing, whose events store the plan this
overrides), and the internal plans of the pricing spec.

## Context

An organization's plan is its platform subscription's `plan_tier`, which
billing events write. Some organizations need a plan nobody pays for:

- the deployment's own accounts, which run and test the service and should
  meet no limits;
- a customer given a plan by agreement, such as a partner, a pilot or a
  replacement for a plan sold elsewhere.

A pricing spec can now mark a plan **internal**: never sold, left out of the
pricing view, with no price. Something still has to put an organization on
it. Writing `plan_tier` by hand does not last: the next subscription event
for the organization writes it again. Each application could keep a plan of
its own, but then every application of a deployment needs the same
override, and the console, the authorization graph and the entitlements in
tokens would all disagree with it.

## Decision

1. **The platform subscription holds an operator's plan**, beside the plan
   billing stores: `operator_plan`, with `operator_note` (why, at most 200
   characters) and `operator_set_at`. A null `operator_plan` means there is
   none.
2. **It wins while it is set.** `Subscription.GrantedPlan` returns the
   operator's plan whatever the subscription's status, and otherwise the
   subscription's plan while it is active, in a trial or past due.
   `billing.OrganizationPlan`, `Service.OrganizationPlan`, the
   entitlements, and `GetPlanTier` (the seller's plan for marketplace fees)
   all use it. The entitlement it grants has no end date. It applies in
   free mode too, where a paid subscription grants nothing, so a deployment
   that takes no payments can still put its own accounts on an internal
   plan.
3. **Billing never writes it.** Subscription events keep updating
   `plan_tier`, the status and the period, so a paid subscription is kept
   accurately underneath and takes effect again when the operator's plan is
   cleared.
4. **Checkout does not sell over it.** While it is set, plan checkout is
   refused with 409, since the organization would pay for a plan it would
   not be on. The customer portal still opens, to manage or cancel a paid
   subscription. The console reports `setByOperator`; the note is for
   operators and is not shown to members.
5. **Any plan of the spec may be set**, internal or not. A plan that is not
   in the spec is refused when it is set; one later removed from the spec
   resolves to the default plan, like any stored plan.
6. **Operators set it with a command**, `billing plan list|show|set|clear`
   in `billingcmd`, which a host adds to its CLI. An organization is named by
   its slug, its ID, or its owner's email address.

## Consequences

- A deployment's own accounts go on an internal plan with one command, and
  stay on it through any billing activity.
- Every reader of the plan agrees, so an application reads the plan from
  SystemForge and keeps no copy of its own.
- An operator's plan has no expiry; it lasts until it is cleared. A
  time-limited grant would need an end date of its own.
- Setting it is not an audited event; the note and the time are kept on the
  row, and `billing plan list` shows every organization that has one.
