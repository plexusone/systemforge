# ADR-016: External Connections

**Status:** Proposed
**Deciders:** @grokify
**Relates to:** ADR-013 (credentials are encrypted under keys it manages),
ADR-008 (resource-scoped grants), ADR-015 (connections are keyed by
organization ID, never by slug), ADR-002 (social sign-in identities, which
this ADR keeps separate).
**Builds on:** [connectionforge](https://github.com/plexusone/connectionforge),
the generic connection-management library whose
[specifications](https://github.com/plexusone/connectionforge/tree/main/docs/specs)
define the mechanism.
**Updates:** a new `docs/design/architecture/connections.md`.

## Context

Applications on SystemForge integrate with services their customers already
use: a code host, a CDN, product analytics, monitoring, payments. Each
integration needs an organization to authorize access to an account at that
service and the application to use that authorization later, often from a
background job. Without a shared mechanism every application stores its own
tokens, in its own tables, with its own refresh logic and no common way to
test, revoke or audit them.

The needs are the same across applications and providers:

- **One inventory per organization** of what it has connected, shown in one
  place, reusable by every application the organization uses.
- **Credentials encrypted under managed keys,** with tenant isolation as
  strong as the rest of the platform's data.
- **Connections that are tested,** so a revoked token is found by a check,
  not by a failed feature.
- **Refresh and rotation that are safe** when several processes use one
  connection.
- **Authorization and audit** consistent with the platform's: who may use,
  share or disconnect a connection, and a record of each.

None of this is specific to identity, so the mechanism is its own module,
connectionforge, usable outside SystemForge. Its primary consumer is
SystemForge, and this ADR records how the platform adopts it, in the same way
ADR-013 records the adoption of keyforge.

There are already credentials in SystemForge, and they are a different
thing. `identity/credential` holds what a principal uses to sign **in**
(passwords, API keys, WebAuthn); `external_identity` links a principal to a
social sign-in account. A connection is what the platform uses to reach
**out** to a third-party service on an organization's behalf.

## Decision

1. **SystemForge adopts connectionforge as its one mechanism for outbound
   connections to external services.** Applications do not store
   third-party tokens themselves. SystemForge provides a thin `connections`
   package that composes connectionforge with the platform, as `keys` does
   for keyforge (ADR-013 decision 1).
2. **connectionforge owns the connection domain, including its schema.**
   SystemForge imports its Ent-backed `sqlstore`, runs its migration on the
   platform database and does not copy, regenerate or merge the schema into
   SystemForge's Ent client. The two share the database, not code
   generation. connectionforge's tables are prefixed `connectionforge_`.
3. **The import direction is one way.** SystemForge imports connectionforge,
   keyforge and omnivault. connectionforge imports none of them, nor any
   application. The `connections` package holds the adapters between them:

   | connectionforge port | SystemForge implementation |
   |---|---|
   | `Cryptographer` | keyforge client, purpose `connectionforge.credential` (ADR-013) |
   | Stores and `Leaser` | connectionforge `sqlstore` on the platform database |
   | `Authorizer` | `authz.Authorizer`, with connections as resources (decision 6) |
   | `Auditor` | the platform audit trail (`contract/audit`) |
   | `SecretSource` | omnivault, for platform-held secrets (decision 8) |
   | Tenant transaction hook | `rls`, setting the organization for each transaction |

4. **Connections belong to an organization.** The connectionforge owner is
   the organization ID, stored as text in `owner_id` (ADR-015: never a slug).
   A personal organization (ADR-006) can hold connections like any other.
5. **Tenant isolation holds twice.** `sqlstore` filters every query by owner
   in code. On PostgreSQL, SystemForge also enables row-level security on
   every table `sqlstore` reports, with an `rls` migrator configured for the
   `owner_id` column, and primes each connectionforge transaction through its
   hook so `SET LOCAL` applies. A bug in either layer alone does not expose
   another organization's connections.
6. **Connections are authorization resources.** A connection is a resource of
   type `connection` in the platform's authorization, with the actions
   `view`, `use`, `manage`, `share` and `disconnect`.
   - Organization owners and admins may manage, share and disconnect every
     connection in the organization.
   - The principal who created a connection manages it.
   - Members may view connections; collaborators (ADR-008) see none unless a
     connection is granted to them. Using a connection requires a grant,
     given to a principal, a service principal or an agent, through the
     resource-scoped grants of ADR-008.
   - Every broker call checks `use` against current authorization; a saved
     job or an agent is re-checked when it runs, not only when it was set up.
7. **Applications reach a connection through SystemForge, not through
   connectionforge directly.** SystemForge exposes the connection operations
   in its API and SDK:

   ```text
   GET    /api/v1/connections
   POST   /api/v1/connections
   GET    /api/v1/connections/{id}
   PATCH  /api/v1/connections/{id}
   POST   /api/v1/connections/{id}/test
   POST   /api/v1/connections/{id}/authorize
   GET    /api/v1/connections/callback
   POST   /api/v1/connections/{id}/credential
   DELETE /api/v1/connections/{id}
   GET    /api/v1/providers
   ```

   In process, an application asks the `connections` package for an
   authenticated `*http.Client` and hands it to the provider's SDK. No API
   response, log or audit event contains a secret, and no browser code ever
   receives one.
8. **Provider registration is the application's; platform secrets are the
   deployment's.** An application registers the providers it needs, with
   their manifests and adapters, at startup. Secrets that belong to the
   deployment rather than to an organization, such as an OAuth client secret
   or a GitHub App private key, are read through omnivault and never stored in
   connectionforge's tables. A GitHub App connection stores only the
   installation ID.
9. **Sign-in and connections stay separate even when one provider serves
   both.** The same GitHub App may be used for social sign-in (ADR-002) and
   for repository access. Signing in creates an `external_identity` for a
   principal; installing the app for an organization creates a connection.
   Neither implies the other, and disconnecting one does not affect the other.
10. **Bindings make dependencies visible.** An application records a binding
    when a feature starts depending on a connection. Disconnecting shows the
    bindings that would stop working, and requires confirmation when any
    exist.
11. **Connection management is mounted in process.** Like SystemAuth and the
    keyforge control plane (ADR-013 decision 1), it runs in the platform
    process; validation and refresh run as platform jobs. It is split out
    only when another process needs it.
12. **The user interface is shared.** Connection pages and widgets are built
    once, over the SystemForge API, so every application can embed a
    connection picker or a full settings section instead of building its own.
    Their component library is decided separately.

## Consequences

- **One inventory and one audit trail** for every organization's external
  connections, across applications.
- **Applications stop holding third-party tokens.** They receive an
  authenticated client, which removes most of the ways a token leaks.
- **A dependency on keyforge in production.** Credentials cannot be read
  without it; a connection whose credential cannot be decrypted is not used.
  This makes ADR-013's wiring a prerequisite, and keyforge's release v0.1.0
  is the minimum version.
- **More tables in the platform database,** owned and migrated by another
  module. A connectionforge upgrade can change the schema; it is applied by
  SystemForge's migrate command with the rest.
- **Row-level security covers tables SystemForge did not define,** using a
  tenant column name other than its default. The `rls` migrator runs a
  second configuration for them.
- **Background jobs need an organization context** to use a connection, so
  jobs run with the organization set, as requests do.
- **Provider coverage is the applications' work.** SystemForge ships no
  provider-specific code beyond what connectionforge provides.

## Alternatives considered

- **Each application stores its own tokens.** Rejected: duplicated refresh
  and audit logic, no shared inventory, and every application becomes a
  place secrets can leak.
- **Build the mechanism inside SystemForge.** Rejected for the same reasons
  as keyforge (ADR-013): it is not specific to identity, it deserves its own
  review, and other products can use it.
- **Extend `identity/credential`.** Rejected: those credentials authenticate
  principals to the platform; outbound connections have a different owner
  (an organization), lifecycle (refresh, provider revocation, health) and
  threat model.
- **Generate connectionforge's schema into SystemForge's Ent client.**
  Rejected: it couples the two modules' code generation and Ent versions,
  and makes connectionforge's schema changes SystemForge edits.
- **Store connection secrets in omnivault.** Rejected for per-organization
  credentials: omnivault holds deployment secrets and returns plaintext;
  per-organization credentials need tenant isolation, versioning and
  envelope encryption bound to the connection.
- **A separate connection service on the data path.** Deferred: in process
  is simpler and faster; the port boundaries let it move out later.

## Open questions

- Whether usage is recorded as counters per connection and period, or as
  sampled events.
- Whether an organization can share a connection with another organization
  (for example an agency and its client), and how that interacts with
  row-level security.
- How agent-delegated authorization is expressed in grants when it is added.
- Which roles, beyond owner and admin, may connect a new provider, and
  whether connecting a provider is gated by the organization's entitlements.
