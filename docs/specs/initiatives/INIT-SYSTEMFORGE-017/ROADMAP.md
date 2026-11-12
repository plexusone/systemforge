# ROADMAP — Billing in the Organization Console

**Initiative:** `INIT-SYSTEMFORGE-017`
**Repository:** `github.com/plexusone/systemforge`

Let a deployment sell its plans with configuration alone: SystemAuth wires
the `billing` package from a `billing` section and the host's pricing spec,
and the organization console shows the plan and takes payment
([ADR-021](../../../design/adrs/ADR-021-billing-in-the-organization-console.md)).
Commits implementing an item carry `Refs: RMI-SYSTEMFORGE-<NNN>`.

## Phase 1 — Billing from Configuration

**Theme:** A host turns on payments with a pricing spec and two secrets

- [x] `RMI-SYSTEMFORGE-240` The `billing` configuration section: the Stripe key and webhook secrets as secret references, validated, with free mode when there is no key
- [x] `RMI-SYSTEMFORGE-241` SystemAuth builds billing from the section and `Options.Pricing`: the webhook route, a lock across instances on PostgreSQL, `OrganizationPlan` and `SyncPrices`
  - Depends on: `RMI-SYSTEMFORGE-240`
- [x] `RMI-SYSTEMFORGE-242` The console's billing API: the plan, the subscription and the pricing view for members, and checkout and the portal for owners and admins
  - Depends on: `RMI-SYSTEMFORGE-241`
- [x] `RMI-SYSTEMFORGE-243` Return addresses for the caller's organization, and names under `localhost` as loopback hosts for test-mode checkout
- [ ] `RMI-SYSTEMFORGE-244` The billing page in `@plexusone/console` (systemforge-web)
  - Depends on: `RMI-SYSTEMFORGE-242`
- [ ] `RMI-SYSTEMFORGE-245` Proven in production by a first host: a live subscription bought, changed in the portal and canceled
  - Depends on: `RMI-SYSTEMFORGE-244`

## Phase 2 — Plans Set by the Operator

**Theme:** An operator puts an organization on a plan nobody pays for, and billing leaves it there ([ADR-022](../../../design/adrs/ADR-022-plans-set-by-the-operator.md))

- [x] `RMI-SYSTEMFORGE-246` The operator's plan on the platform subscription, which `GrantedPlan`, `OrganizationPlan`, the entitlements and `GetPlanTier` honor and billing events never write
- [x] `RMI-SYSTEMFORGE-247` Plan checkout refused while an operator's plan is set, and `setByOperator` in the console's billing status
  - Depends on: `RMI-SYSTEMFORGE-246`
- [x] `RMI-SYSTEMFORGE-248` `billing plan list|show|set|clear` in `billingcmd`, naming an organization by slug, ID or owner's email
  - Depends on: `RMI-SYSTEMFORGE-246`
- [ ] `RMI-SYSTEMFORGE-249` The console's billing page says when the operator set the plan and offers no checkout (systemforge-web)
  - Depends on: `RMI-SYSTEMFORGE-247`
- [ ] `RMI-SYSTEMFORGE-250` A first host reads its plan from SystemForge, with its own accounts on an internal plan
  - Depends on: `RMI-SYSTEMFORGE-248`
