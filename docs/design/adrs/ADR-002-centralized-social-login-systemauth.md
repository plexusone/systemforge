# ADR-002: Centralized Social Login (GitHub/Google) via SystemAuth

**Status:** Accepted
**Deciders:** @grokify
**Relates to:** ADR-001 (the `SystemAuth` / `sf_` / `sf_principal_id` naming this
ADR keys its account-linking on), the OAuth server PRD (`docs/design/FEAT_OAUTH_PRD.md`,
which listed "social login providers (handled separately)" as a non-goal — this
ADR is where that deferred work lands), and the authentication PRD
(`docs/design/FEAT_AUTHN_PRD.md`, US-1: "sign in via OAuth (GitHub, Google)").
Executed by INIT-SYSTEMFORGE-005. Consumed by downstream relying-party
applications, which depend on this capability as `RMI-SYSTEMFORGE-001`.

## Context

Downstream relying-party applications have referenced a central login
capability — `RMI-SYSTEMFORGE-001`, "log in with GitHub/Google, built once
centrally" — as a dependency. That capability was never actually specced or
built in this repo: the roadmaps start at `RMI-SYSTEMFORGE-003`, and the OAuth
server PRD explicitly deferred social login. What exists today is three
disconnected pieces, none of which is a mounted, principal-upserting,
session-establishing social-login server:

- **`session/oauth`** — a complete GitHub/Google OAuth-dance library
  (`AuthorizationURL` → `HandleCallback` → fetch user profile via raw HTTP
  against `api.github.com` / `googleapis.com`). It returns a `*UserInfo` and
  does **no** persistence. It is **dead code**: zero import sites across the
  repo.
- **`identity/oauthclient`** — a *second*, parallel GitHub/Google user-fetch
  helper (`FetchGitHubUser`, `FetchGoogleUser`, `GenerateState`,
  `StateManager`, provider configs). This is the one a reference consumer
  actually imports. So the repo ships **two** overlapping social-login
  primitive packages.
- **The SystemAuth server (`cmd/systemauth`, `identity/systemauth`)** is a
  Fosite OAuth2/OIDC **authorization server** — it issues tokens to downstream
  clients (`/oauth/authorize`, `/oauth/token`, `/oauth/introspect`,
  `/oauth/revoke`, `/.well-known/*`). It has **no** "log in with GitHub/Google"
  routes. Its `federation.go` / `federation_handlers.go` are SystemAuth↔app
  SSO federation between our own apps, **not** upstream social login.

The only working end-to-end GitHub/Google flow lives **inside a reference
consumer application**, reimplemented locally. That reference pattern carries
three defects we must not propagate by copy-paste:

1. **Unvalidated post-login redirect that leaks the access token** — the target
   is taken straight from the query string with no allowlist, and the access
   token is appended as `?access_token=...`, landing it in browser history,
   proxy logs, and `Referer` headers.
2. **Stubbed refresh tokens** — the refresh handler returns
   "not implemented; please re-authenticate."
3. **No-op logout** — logout is a bare `204` with no session/token revocation.

It also has **two inconsistent account-linking models** in the same file: the
direct GitHub/Google path keys the local principal **by email only** and never
records a stable identity id; the SystemAuth-federation path keys by the OIDC
`sub` → `sf_principal_id` (with verified-email as a *linking fallback*). The
second is correct and stable; the first silently merges distinct upstream
identities that happen to share an email and breaks if an email changes.

The identity substrate is ready: `sf_principal_id` is defined once in the
shared `identity/ent/mixin.PrincipalMixin` (ADR-001) and is already used
consistently by downstream principal schemas. What is missing is the login
**surface** and a single sanctioned place to build it.

## Decision

**Make SystemAuth the single identity provider for GitHub/Google login.**
Relying-party applications do not implement social login themselves; they
federate to SystemAuth as OIDC clients and link the returned identity by
`sf_principal_id`. GitHub/Google client credentials live only in the SystemAuth
deployment — one upstream OAuth app registration per provider, not one per
relying party.

### Where the login lives

- **Mount GitHub/Google login on the SystemAuth server.** Add login-start and
  callback routes to `cmd/systemauth` / `identity/systemauth`. On callback,
  SystemAuth upserts its own `Principal` and establishes the hardened
  `__Host-sf_login` session, then returns the user to the relying party through
  the OIDC authorization-code flow it already serves.
- **Account-linking model (canonical):** upsert the SystemAuth `Principal`
  keyed by the **upstream provider identity** (`provider` + provider subject),
  recorded as the stable principal identity. A **verified** upstream email may
  *link* an incoming login to an existing principal, but email is never the
  primary key. This is the stable path generalized from the reference
  consumer's SystemAuth-federation handler; the email-only keying is rejected.
- **Relying parties link by `sf_principal_id`.** A relying party's callback
  find-or-creates its local principal by the OIDC `sub` (the SystemAuth
  principal UUID) → `sf_principal_id`, with verified email as a linking
  fallback — the one model, provided as a reusable helper so no app
  reimplements it.

### Consolidate the primitives

- Collapse `session/oauth` and `identity/oauthclient` into **one** sanctioned
  social-login primitives package that the SystemAuth server consumes; retire
  the duplicate. There is exactly one place that speaks to github.com /
  google.com.

### Fix the three gaps centrally

Because the flow is built once, the reference-pattern defects are fixed once:

- **Allowlist-validated post-login redirect**, and **never** place tokens in a
  redirect URL — the session is a cookie; the authorization code / tokens flow
  through the OIDC exchange, not the query string.
- **Real refresh-token rotation** (reuse-detection, absolute expiry) — the
  Fosite server already issues refresh tokens; the login/session layer must use
  them rather than stub them.
- **Real logout** — session revocation plus token revocation via the existing
  `/oauth/revoke`.

### Relying-party contract

- Provide the reusable **OIDC-client callback + middleware** helper (sub →
  `sf_principal_id` find-or-create, verified-email linking) and the **`/bff/*`
  cookie-session surface** the shared frontend expects, so the browser path is
  a cookie/BFF contract while programmatic clients (CLI/MCP) use bearer tokens
  (SystemAuth sessions / per-user API keys) directly against the API.
- **Serve `/oauth/userinfo`.** Discovery advertises a `userinfo_endpoint` but
  no route is mounted; the relying-party callback needs it (or must fall back
  to the ID token + JWKS). Mounting it is the cleaner contract and is scoped as
  an execution item.

### Rejected alternative: shared library each app mounts in-process

Extract the reference pattern into one shared Go package that each app mounts
to do its **own** GitHub/Google login and upsert its **own** principal. This
needs no running SystemAuth and is the smaller change, but it does not deliver
one login / one session across apps (the shell-composition goal), forces every
app to register its own upstream OAuth apps and hold those secrets, and leaves
N copies of the callback/upsert logic to drift. Rejected in favor of the
IdP-centralized model, consistent with the "built once centrally, every relying
party consumes it" intent that downstream consumers already depend on.

## Consequences

- Relying-party applications gain a hard dependency on a **running SystemAuth
  instance** for interactive login (programmatic bearer/API-key access is
  unaffected). This is the deliberate cost of one-login-across-apps.
- The two duplicate primitive packages (`session/oauth`, `identity/oauthclient`)
  collapse to one; the retired import path is a breaking change for any
  consumer on the old one, carried in the same coordinated pass as the other
  identity breaking changes (pre-1.0 semver).
- The three reference-pattern defects are fixed once, in SystemAuth, instead of
  being copied into each consumer.
- Carried cautions (from the identity integration review): the default JWKS has
  a single non-rotating key id; the OAuth state store defaults to in-memory
  (single-instance only) and needs a shared store under horizontal scaling;
  DPoP is bindable but not enforced; upstream is GitHub/Google only (no generic
  OIDC/SAML yet). These bound the first release and are tracked, not resolved
  here.
- Per-consumer migration off app-local social login is **tracked in
  INIT-SYSTEMFORGE-005 and intentionally not enumerated in this repo**, matching
  the convention ADR-001 / INIT-SYSTEMFORGE-004 established.

## References

- ADR-001 (`SystemAuth` / `sf_` / `sf_principal_id` — the linking identity).
- `docs/design/FEAT_OAUTH_PRD.md` (social login deferred as "handled
  separately"); `docs/design/FEAT_AUTHN_PRD.md` US-1 (the requirement).
- INIT-SYSTEMFORGE-005 ROADMAP (the execution RMIs).
- Affected surfaces: `session/oauth`, `identity/oauthclient` (consolidate);
  `cmd/systemauth`, `identity/systemauth/server.go`,
  `identity/systemauth/handler_discovery.go` (login + userinfo routes,
  session); `identity/ent/mixin.PrincipalMixin` (`sf_principal_id`).
