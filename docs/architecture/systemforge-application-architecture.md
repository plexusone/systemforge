# SystemForge Application Architecture

**Status:** Normative convention (v1)
**Applies to:** every Go service built on SystemForge

SystemForge is not only a library collection — it is an opinionated way to
build production Go services. This document is the convention: where code
lives, how capabilities cross boundaries, how identity is modeled, and how a
service is composed for deployment. Think of it as the "Rails for Go"
application guide — convention over configuration, adapted to Go and to an
AI-assisted, multi-service world.

The single most important property this architecture delivers:

> **A capability is a code boundary. A service is a deployment boundary. An
> application is a composition boundary. These are three different things,
> and deployment topology is reversible without changing business logic.**

A SystemForge application starts as a modular monolith, can extract any
capability into its own service when scaling or ownership demands it, and can
recombine services back into one binary — all without rewriting the
capabilities themselves. Monolith and microservices are not a one-time
architectural commitment; they are per-deployment composition choices, and
different deployments of the same codebase may make opposite choices at the
same time.

## Principles

1. **Convention over configuration.** There is a preferred way to build a
   SystemForge application; follow it unless you have a concrete reason not
   to.
2. **Vertical slices over global technical layers.** Product functionality
   lives under `internal/feature/<slug>`, not in global `handlers/`,
   `services/`, `repositories/` trees.
3. **Foundation is singular; platform and feature are per-deployment.**
   Identity/authn/authz is one shared system of record everywhere; other
   infrastructure and all features are instantiated per deployment.
4. **Contracts cross boundaries.** Features and applications interact through
   explicit Go interfaces, never by reaching into each other's internals.
5. **Local-first composition.** Use ordinary typed Go calls when components
   share a process; an API is a deployment adapter, not the default seam.
6. **Modular monolith first.** Start with one deployable; extract a service
   only when operations or scaling justify it.
7. **Deployment topology is reversible.** Splitting or recombining services
   must not alter core business logic.
8. **Secure and multi-tenant by default.** Identity, authorization, tenancy,
   and observability come from SystemForge, not per-app reinvention.
9. **Product lines are separable.** Data is partitioned so a product line can
   be cleanly separated onto its own instance — and later re-merged — without
   re-architecture (see [Product-line separability](#product-line-separability-and-data-portability)).
10. **Architecture is machine-validatable.** The dependency and structural
    rules here are intended to be lintable, not just documented.

## The three layers

```text
internal/
├── foundation/   identity, org/tenancy, authn, authz, sessions
│                 — ALWAYS a single shared system of record (see Foundation)
├── platform/      db, observability, config, jobs, events
│                 — reusable infrastructure, instantiated per deployment
└── feature/        product capability verticals (see Feature slices)
    ├── dashboard/
    ├── query/
    └── notebook/

app/               public composition entrypoint (see Composition) — NOT internal
cmd/               deployment entrypoints (see Deployment topologies)
```

`foundation` differs from `platform` in exactly one way: a `platform`
capability may reasonably have one instance per deployment (each application
can run its own job queue), whereas `foundation` is always a single shared
identity / org system of record across every deployment. Foundation is the
one layer that never gets a "local copy per app."

> The `dashboard` / `query` / `notebook` names above are illustrative
> capability examples used throughout this document. They are not prescribed
> features.

### Dependency rules (normative)

```text
feature   → platform      allowed
feature   → foundation    allowed   (e.g. an authz check in a handler)
platform  → foundation    allowed
platform  → feature       DENIED
foundation → platform     DENIED
foundation → feature      DENIED
feature A  → feature B     only through feature B's contract.go
```

These rules are intended to be enforced by a dependency lint in CI, in the
same spirit as the org's existing dependency-policy tooling. Until then they
are enforced by review.

## Feature slices

A feature owns its transport, application logic, domain types, and
persistence. Conventional files — use the name where the responsibility
exists; a small feature may have only two of them:

```text
internal/feature/<slug>/
├── feature.go       construction / registration (implements compose.Feature)
├── contract.go      exported Go interface(s) other features/apps depend on
├── routes.go        route registration
├── handler.go       HTTP / Huma transport
├── service.go       application / orchestration logic
├── repository.go    persistence boundary
├── model.go         feature-local domain / data types
└── client.go        remote implementation of contract.go, when the
                     capability is consumed out-of-process
```

Rules:

- **Files are conventional, not mandatory.** Do not create empty files for
  ceremony. A `health` feature may be just `feature.go` + `handler.go`.
- **Split by responsibility before splitting into subdirectories.** Prefer
  `create.go` / `update.go` / `publish.go` in one package over a premature
  `handler/`, `service/`, `repository/` subtree. Introduce subdirectories
  only when a feature grows independent sub-capabilities (e.g.
  `dashboard/widget/`, `dashboard/sharing/`).
- **Distinguish API DTOs from domain types.** A handler translates the wire
  request into an application command; the HTTP JSON struct is not the
  internal model.
- **`internal/feature/*` is private.** Cross-feature access goes through the
  other feature's `contract.go`, never a deep import of its internals.

### Persistence and the shared ORM client

`repository.go` is a persistence **boundary**, not necessarily a private
database. A generated ORM (Ent) emits a single client and a single model
package for the whole schema, so the physical data layer **cannot** be
partitioned one-client-per-feature. This is a deliberate, accepted carve-out
from strict per-feature encapsulation:

- The generated client is **shared platform infrastructure**
  (`internal/platform/db`), instantiated once per deployment.
- Each feature defines a narrow `repository.go` interface over that shared
  client, exposing only the entities and queries that feature owns. Logical
  ownership is enforced by the repository interface and by review/lint, even
  though the client is physically shared.
- **Foundation identity entities** (`Principal`, `Organization`,
  `Membership`, …) live in the same generated client but are **owned by
  foundation**. Features read them through foundation contracts; a feature
  must not mutate identity tables directly. This is exactly the kind of
  cross-layer access the dependency lint should flag.

The rule of thumb: the client may be shared, but the **queries a feature is
allowed to run** are scoped by its repository interface — a feature reaching
into another feature's or foundation's tables directly is a violation even
though the compiler permits it.

## Contracts: in-process and remote

Every capability that another capability consumes exposes a **Go interface**
in `contract.go`. That interface is the boundary — the same one whether the
provider is in-process or across the network.

```go
// internal/feature/query/contract.go
type Executor interface {
    Execute(ctx context.Context, req Request) (Result, error)
}
```

A consumer depends only on the interface:

```go
// internal/feature/dashboard/service.go
type Service struct {
    query query.Executor   // never *query.Service directly
}
```

Two implementations satisfy it. The local one is an ordinary Go type:

```go
var _ query.Executor = (*query.Service)(nil)      // in-process
```

The remote one calls an API and implements the identical interface:

```go
var _ query.Executor = (*queryclient.Client)(nil) // over HTTP/API
```

The consumer's code never changes; only construction (which implementation
is injected) changes.

**A Go interface contract and an API contract are related but not identical.**
The Go interface expresses in-process semantics; the API/OpenAPI contract
expresses wire semantics (authn, scopes, status mapping, rate limits,
idempotency, versioning). Keep them semantically aligned, but do not
mechanically generate one from the other. The remote `Client` is an *adapter*
from the wire contract to the Go capability contract.

**Rejected: a generic invocation bus.** We deliberately do not adopt a
`system.Invoke("query.execute", ...)`-style bus. It trades Go's compile-time
checking, IDE navigation, explicit dependencies, and refactoring safety for
uniform-looking calls that are not uniform in failure mode. Every contract
stays a typed Go interface.

## Composition runtime

SystemForge owns the composition contract so every repo implements the same
seam instead of inventing its own. A small package in SystemForge defines:

```go
// Feature is one registrable capability — a feature slice or a whole app.
type Feature interface {
    Name() string                      // canonical slug (see Canonical slugs)
    RegisterRoutes(r Registrar) error
    Start(ctx context.Context) error   // no-op allowed
    Stop(ctx context.Context) error    // no-op allowed
}

// Registrar abstracts the HTTP layer (Huma today) so features do not bind
// to a concrete server type at the contract level.
type Registrar interface { /* route-group registration surface */ }
```

A monolith is then just one composition of features:

```go
app := systemforge.NewApp(cfg)
app.Register(
    dashboard.New(deps),
    query.New(deps),
    notebook.New(deps),
)
app.Run()
```

Crucially, **an app is itself a `Feature`** (it aggregates its internal
features and re-exposes them under one `Name()`). That is what makes
composition recursive: a host registers a whole application exactly the way
an application registers one of its own features.

## Horizontal and vertical applications

Whether an application is "horizontal" or "vertical" is a **go-to-market
classification, not a structural fork**. Every SystemForge repo has the same
internal shape. What differs is only who composes it and how.

- A **horizontal capability application** is a repo whose feature contracts
  get embedded by other applications *and* which also composes its own
  features into a standalone deployment via its own `cmd/`. Embedded mode
  (its capabilities mounted inside another product) and standalone mode (its
  own product) are the same feature contracts consumed by two different
  composers — one of them being the repo's own binary.
- A **vertical product application** is a repo that composes its own features
  plus imported horizontal capabilities into one product.

Some applications are offered both ways; that is a licensing/packaging
decision, not a second codebase.

### The public `app/` package

`internal/feature/*` stays private, but each repo's composition entrypoint
must be **public**, because it is the seam other repos compose against:

```text
<module>/app        // NOT internal/app
    func New(cfg Config) (*App, error)     // *App implements compose.Feature
```

- A horizontal capability's own `cmd/` calls `app.New` to run standalone.
- A vertical product imports the horizontal capability's `app` package (or
  individual feature packages plus their `contract.go`) to embed those
  capabilities inside its own binary.
- A composition repo does the same one level up: import two vertical
  products' `app` packages and register both into one binary — mechanically
  no different from a vertical product importing a horizontal capability.

Go's `internal/` visibility is exactly why the composition entrypoint lives
at `app/` and not `internal/app/`: an external module cannot import another
module's `internal/` tree. Wiring that is genuinely private to a repo
(foundation+platform+feature assembly detail) may still live under
`internal/`; only the composition surface is public.

## Wiring mechanism (normative)

**Composition is compile-time; selection is startup-time.** Both the local
implementation and the remote client may be compiled into the same binary,
and the deployment's startup configuration decides which is constructed.
There is no runtime re-wiring of a live process and no dynamic plugin
loading.

Distinct topologies are normally expressed as distinct `cmd/` entrypoints —
a monolith `cmd/<app>` and per-capability `cmd/<capability>-service`
binaries — each reading the same config shape:

```json
{
  "capabilities": {
    "query":    { "deployment": "local" },
    "notebook": { "deployment": "remote", "endpoint": "https://notebook.internal" }
  }
}
```

We do not (initially) make this dynamic at runtime. Compile-time composition
with explicit entrypoints is simpler and safer; the architecture model
understands the local/remote distinction, which is what matters.

## Canonical feature slugs

One slug per feature drives every surface. Given the slug `dashboard`:

| Surface           | Value                                  |
| ----------------- | -------------------------------------- |
| Go package        | `internal/feature/dashboard`           |
| TypeScript        | `web/src/features/dashboard`           |
| UI route          | `/dashboards`                          |
| BFF API           | `/api/dashboards`                      |
| REST API          | `/api/v1/dashboards`                   |
| OpenAPI tag       | `dashboard`                            |
| Permission prefix | `dashboard.*`                          |
| OAuth scope       | `dashboard:{resource}:{verb}` (see [authz conventions](../authz-conventions.md)) |
| Telemetry         | `dashboard.*`                          |

The identity is the **singular slug** (`dashboard`); URLs may use the
conventional plural resource form (`/dashboards`). Do not let each surface
independently invent names (`dashboard`, `dashboards`, `dash`,
`dashboard-manager`) — the inconsistency is expensive for humans, code
generators, the policy engine, observability, and AI agents alike.

### BFF vs. public REST

BFF and public REST **share the same capability request/response schemas and
application contract by default**, differing only in authentication,
throttling, and exposure policy — not semantics:

```text
        Dashboard capability (one application contract)
                        │
          ┌─────────────┴─────────────┐
        BFF API                    REST API
   session cookie auth          OAuth / API token
   browser throttling           API throttling
   CSRF / origin                token scopes
          └─────────────┬─────────────┘
                        │
                dashboard.Service
```

The BFF must not become a second backend: it handles authentication
translation, session/cookie handling, CSRF, browser policy, and rate
limiting — not duplicated business logic. The BFF *may* additionally expose
**UI-composition endpoints** (e.g. `GET /api/ui/dashboard-page/123`
aggregating several capabilities for one screen). Those are explicitly not
part of the public REST contract and must not pollute it.

Authentication provenance stays out of the request schema. The same
application method serves a browser (session → user principal), an API
client (OAuth token → API principal), and a service (workload token →
service principal); the feature does not care how the principal arrived.

## Foundation: the identity model

Foundation is the one always-shared layer. Its model is built on
SystemForge's `identity` package (a `Principal` unified root with
`Human`/`Application`/`Agent`/`ServicePrincipal` extensions,
`PrincipalMembership`, and `Organization`), extended for multi-product and
product-separability concerns.

### Principal vs. Organization

- **`Principal`** is the global identity of a person or workload. Human-type
  principals are global by construction (no single-org scope); org access is
  expressed exclusively through `PrincipalMembership`.
- **`Organization`** carries an **`app_id`** naming the *product line* it
  belongs to — the unit that is deployed, billed, and (if ever) separated as
  a whole.

**`app_id` names a product line, never a horizontal capability.** When a
product embeds horizontal capabilities, there is still exactly one
Organization for that product; the embedded capabilities are entitlements
*within* that org, expressed through the [authorization
conventions](../authz-conventions.md)'s per-app vocabularies, roles, and
scopes. A composed multi-product binary still has per-product Organizations;
the app switcher spans them.

### One principal ≠ access to every product

A `Principal` existing does not imply access to every product. The UI app
switcher queries the principal's memberships, groups by `Organization.app_id`,
and shows only the products the principal actually has a membership in. SSO
covers authentication (one principal, one session); it never implies
authorization to a different product.

### Email and identity linking

A principal may hold **multiple email addresses** (one `PrincipalEmail` row
each). Each address is verified or not:

- A **verified** email is globally unique within a foundation instance and is
  valid identity evidence.
- An **unverified** email is user-supplied text and **MUST NOT be used as an
  identity-linking signal anywhere in SystemForge** — not for merge, not for
  account linking, not for "is this the same user" heuristics. Anyone can
  claim any address they do not control.

This rule governs every account-linking flow (OAuth-provider linking, SSO,
and instance merge), not only one case.

### Product-line separability and data portability

Because every `Organization`/`Membership` row is partitioned by `app_id`, a
product line's identity and org data can be **cleanly separated onto its own
foundation instance** — a filtered export of the `Principal` rows referenced
by that product's memberships plus all rows for that `app_id` — without
re-architecting anything. This is a deliberate design goal: product lines are
data-portable and independently operable, not welded together by a shared
schema.

The separation preserves each `Principal.id` and stamps the new instance with
`forked_from` / `forked_at` provenance, so two instances that shared an
ancestor can later be **reconciled/merged**. Merge is a verified-email-only,
step-up-confirmed reconciliation — never a silent auto-merge. The data model
makes both directions possible; the export/merge *tooling* is built when a
concrete need for it exists.

## Token profiles (target convention)

The following is the **target** SystemForge credential model. It is
documented here as convention; its full implementation is progressive.

| Profile              | Representation                         | Use                        |
| -------------------- | -------------------------------------- | -------------------------- |
| `web-session`        | opaque / encrypted HttpOnly cookie     | Browser ↔ BFF              |
| `access-token`       | minimal signed JWT (JWS)               | BFF / API / service calls  |
| `confidential-token` | encrypted JWT (JWE)                    | Claims needing confidentiality |

Rules:

- **Browsers get an opaque/encrypted HttpOnly session cookie, not a reusable
  OAuth bearer token.** OAuth begins at the BFF/API boundary. JavaScript
  never reads the credential.
- The BFF **statelessly** exchanges validated web-session claims for
  short-lived, audience- and scope-restricted API tokens. Neither the browser
  session nor the API token should require persistent per-token storage for
  normal validation; centralized state is reserved for authorization policy,
  key management, and exceptional revocation (`Principal.security_epoch`).
- **Minimize claims.** No sensitive or unnecessary information belongs in a
  plaintext signed JWT merely because it is signed — signing protects
  integrity, not confidentiality. Prefer opaque identifiers and minimal
  routing/validation claims; resolve richer authorization from foundation
  when needed.
- Use browser/device fingerprint or DPoP (RFC 9449) for **adaptive risk /
  anti-replay**, not as the primary authorization mechanism. Unverified
  fingerprints are a signal, never a credential.

## Deployment topologies

The same codebase supports a progression, and different deployments may sit
at different points simultaneously:

```text
Stage 1  One binary — all features + platform (+ shared foundation)
Stage 2  Feature extraction — monolith + selected feature services
Stage 3  Platform extraction — feature services + platform services
Stage 4  Mixed topology — whatever combination makes operational sense
```

Stage 4 is expected to be the normal mature state, not "everything becomes a
microservice." Some capabilities benefit from independent scaling or trust
boundaries; many are cheaper and more reliable in-process. Foundation remains
one shared identity system of record across all of them.

## Frontend alignment

The TypeScript frontend mirrors the **conceptual** feature boundaries, not
the exact filesystem:

```text
web/src/
├── app/          composition, routing, providers
├── features/     product capabilities (aligned slugs with the backend)
│   ├── dashboard/  { api.ts, hooks.ts, components/, pages/, index.ts }
│   ├── query/
│   └── notebook/
├── platform/     cross-cutting frontend infra (auth, api client, telemetry)
└── design-system/ generic UI primitives
```

Rules:

- **Aligned slugs.** `features/dashboard` ↔ `internal/feature/dashboard`.
  Frontend directories may be plural; backend Go packages are singular.
- **A feature owns its UI.** Do not scatter one capability across global
  `pages/`, `hooks/`, `api/` trees.
- **Public feature surface via `index.ts`** — the TypeScript analogue of
  Go's `contract.go`. Cross-feature imports go through it, not deep paths.
- **Not every backend feature has a frontend feature** (audit, jobs,
  webhooks are API-only), and some frontend features (home, admin,
  onboarding) orchestrate several backend capabilities.
- Frontend dependency rules mirror the backend: `app → features → platform /
  design-system`; `platform`/`design-system` never import `features`;
  cross-feature is default-deny.

## Related conventions

- [Authorization conventions](../authz-conventions.md) — the `AppVocabulary`
  contract, app-namespaced resource types, `{app}:{resource}:{verb}` scopes,
  the two-gate model, and the shared SpiceDB base schema. This architecture's
  `feature → foundation` authz calls and per-app entitlement model build on
  it.
