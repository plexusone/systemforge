# ROADMAP — Centralized Social Login — GitHub/Google via SystemAuth

**Initiative:** `INIT-SYSTEMFORGE-005`
**Repository:** `github.com/plexusone/systemforge`

Builds the central "log in with GitHub/Google" capability that downstream
relying-party applications have long referenced as `RMI-SYSTEMFORGE-001` but
which was never specced or built here (the roadmaps start at
`RMI-SYSTEMFORGE-003`; the OAuth server PRD deferred social login as "handled
separately"). Full rationale and the architecture decision — IdP-centralized in
SystemAuth, not a per-app library — are in ADR-002; RMI titles below are
summaries.

> These RMIs are **defined but not yet claimed or scheduled** — they are the
> design of record for a later execution session. Commits implementing an item
> will carry the trailer `Refs: RMI-SYSTEMFORGE-<NNN>`; none exist yet. Phase
> status derives from member-RMI status.

The identity substrate is ready: `sf_principal_id` is defined once in the shared
`identity/ent/mixin.PrincipalMixin` (ADR-001) and relying parties link upstream
identities to it. What this initiative adds is the login **surface** and a
single sanctioned place to build it.

## Phase 1 — SystemAuth Social Login (core)

**Theme:** One place speaks to GitHub/Google; SystemAuth owns the login

- [ ] `RMI-SYSTEMFORGE-075` Consolidate the two duplicate social-login primitive packages (`session/oauth`, `identity/oauthclient`) into one sanctioned package; retire the dead one
- [ ] `RMI-SYSTEMFORGE-001` Mount GitHub/Google login on the SystemAuth server: login-start + callback routes, `Principal` upsert keyed by provider subject with verified-email linking fallback, `__Host-sf_login` session establishment
  - Depends on: `RMI-SYSTEMFORGE-075`
- [ ] `RMI-SYSTEMFORGE-076` Harden the login flow: allowlist-validated post-login redirect with no token in the URL, real refresh-token rotation (reuse detection, absolute expiry), real logout with session + token revocation
  - Depends on: `RMI-SYSTEMFORGE-001`

## Phase 2 — Relying-Party Federation Contract

**Theme:** Consumers federate; nobody reimplements the callback

- [ ] `RMI-SYSTEMFORGE-077` Serve `/oauth/userinfo` (advertised in discovery but unmounted) so the relying-party callback has a stable profile endpoint
  - Depends on: `RMI-SYSTEMFORGE-001`
- [ ] `RMI-SYSTEMFORGE-081` Reusable relying-party OIDC-client callback + middleware (sub → `sf_principal_id` find-or-create, verified-email linking) and the `/bff/*` cookie-session surface the shared frontend expects; programmatic clients keep bearer/API-key access
  - Depends on: `RMI-SYSTEMFORGE-001`
  - Depends on: `RMI-SYSTEMFORGE-077`

## Phase 3 — Consumer Convergence & Lock

**Theme:** Every consumer onto central login; prevent per-app drift

Downstream consumers retire app-local GitHub/Google login and adopt the
relying-party federation contract (`RMI-SYSTEMFORGE-081`), linking by
`sf_principal_id`. These per-consumer items are tracked in the initiative and
intentionally not enumerated here, matching INIT-SYSTEMFORGE-004.

- [ ] `RMI-SYSTEMFORGE-078` CI gate + conformance: block new direct github.com/google.com OAuth wiring outside the sanctioned package; conformance check that relying parties key by `sf_principal_id`
  - Depends on: `RMI-SYSTEMFORGE-081`
