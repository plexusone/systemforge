# ROADMAP — Production Hardening and Billing on PayForge

**Initiative:** `INIT-SYSTEMFORGE-015`
**Repository:** `github.com/plexusone/systemforge`

Make SystemAuth and the relying-party stack safe to run for outside users,
and move billing onto `github.com/plexusone/payforge`, which reads plans from
a pricing spec, in place of the marketplace's own Stripe code. Commits
implementing an item carry `Refs: RMI-SYSTEMFORGE-<NNN>`.

## Phase 1 — Sign-In and Token Integrity

**Theme:** A code, a refresh token and an email address each grant access once, to the right person

- [x] `RMI-SYSTEMFORGE-200` An authorization code is exchanged once: invalidation is conditional on the code being unused, so two concurrent exchanges cannot both succeed
- [x] `RMI-SYSTEMFORGE-201` A refresh token is rotated once: rotation is conditional on that token being active, and a second use revokes the family
- [x] `RMI-SYSTEMFORGE-202` A social sign-in links to an existing account by email only when the provider is authoritative for the address, and GitHub sign-in uses the primary email only
- [x] `RMI-SYSTEMFORGE-203` Production checks that fail closed, each with a named opt-out logged at startup: the token HMAC secret, the client-credentials grant with a shared secret, clients exempt from DPoP, and a per-instance replay cache without an explicit single-instance setting
- [x] `RMI-SYSTEMFORGE-204` Security headers on every HTML page SystemAuth serves: a content security policy with `frame-ancestors 'none'`, `X-Content-Type-Options`, `Referrer-Policy`, and HSTS when the issuer is https

## Phase 2 — Billing on PayForge

**Theme:** A paid subscription becomes an entitlement through one tested path

- [x] `RMI-SYSTEMFORGE-205` `billing` storage: a Postgres store for processed events and customers, and a per-account lock that holds across instances
- [x] `RMI-SYSTEMFORGE-206` The webhook handler: verified, size-limited, idempotent, with no error detail in responses
  - Depends on: `RMI-SYSTEMFORGE-205`
- [x] `RMI-SYSTEMFORGE-207` Sinks from PayForge entitlements, refunds and seller accounts onto the marketplace's licenses, with the authorization graph re-synced on every apply
  - Depends on: `RMI-SYSTEMFORGE-205`
- [x] `RMI-SYSTEMFORGE-208` Checkout and customer-portal handlers: the organization from the caller's session, an organization-manage check, and the customer found server-side
  - Depends on: `RMI-SYSTEMFORGE-207`
- [x] `RMI-SYSTEMFORGE-209` Remove `marketplace/stripe`, with an upgrade guide
  - Depends on: `RMI-SYSTEMFORGE-206`, `RMI-SYSTEMFORGE-208`

## Phase 3 — Security Process and Release

**Theme:** Operators know how to run it and researchers know how to report

- [x] `RMI-SYSTEMFORGE-210` `SECURITY.md`: the reporting channel, response targets and supported versions
- [x] `RMI-SYSTEMFORGE-211` The production checklist: keys and secrets, the replay cache, the edge and origin, backups, monitoring
- [x] `RMI-SYSTEMFORGE-212` v0.27.0 release notes, changelog and upgrade guide
  - Depends on: `RMI-SYSTEMFORGE-200`, `RMI-SYSTEMFORGE-201`, `RMI-SYSTEMFORGE-202`, `RMI-SYSTEMFORGE-203`, `RMI-SYSTEMFORGE-204`, `RMI-SYSTEMFORGE-209`, `RMI-SYSTEMFORGE-210`, `RMI-SYSTEMFORGE-211`

## Phase 4 — Limits, Logs and the Threat Model

**Theme:** Abuse is slowed, incidents are traceable and the risks are written down

- [ ] `RMI-SYSTEMFORGE-213` One client-address rule, configured with trusted proxy networks and the header to read, used by SystemAuth, the BFF, `appauth` and rate limits
- [ ] `RMI-SYSTEMFORGE-214` Rate limiting in layers: a default per-IP limit, route policies for the token, login and sign-up paths, limits for signed-in callers, and `RateLimit-*` headers
  - Depends on: `RMI-SYSTEMFORGE-213`
- [ ] `RMI-SYSTEMFORGE-215` Logs fit for incidents: no stack traces for client errors, no tokens or secrets (with a test), and a structured security-event log through `contract/audit`
- [ ] `RMI-SYSTEMFORGE-216` No internal error text in API responses: known errors map to fixed messages, the rest are logged
- [ ] `RMI-SYSTEMFORGE-217` The threat model, and removal of API keys from `appauth` and `relyingparty`

## Phase 5 — Remaining Review Findings and Release

**Theme:** The smaller findings from the launch review are closed

- [ ] `RMI-SYSTEMFORGE-218` The BFF session cookie refuses `SameSite=None`, so a configuration cannot weaken the origin check
- [ ] `RMI-SYSTEMFORGE-219` `EmbeddedOAuthProvider.Revoke` revokes the token it is given, or reports why it cannot
- [ ] `RMI-SYSTEMFORGE-220` Every HTTP server systemforge builds sets `ReadHeaderTimeout`
- [ ] `RMI-SYSTEMFORGE-221` v0.28.0 release notes, changelog and upgrade guide
  - Depends on: `RMI-SYSTEMFORGE-213`, `RMI-SYSTEMFORGE-214`, `RMI-SYSTEMFORGE-215`, `RMI-SYSTEMFORGE-216`, `RMI-SYSTEMFORGE-217`, `RMI-SYSTEMFORGE-218`, `RMI-SYSTEMFORGE-219`, `RMI-SYSTEMFORGE-220`
