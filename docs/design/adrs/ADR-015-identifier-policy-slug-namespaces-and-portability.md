# ADR-015: Identifier Policy, Slug Namespaces and Portability Across Deployments

**Status:** Proposed
**Deciders:** @grokify
**Relates to:** ADR-006 (organization lifecycle, slugs, cooling-off),
ADR-007 (memberships and entitlements as claims; decision 4 stands),
ADR-014 (application roles).
**Updates:** `docs/design/architecture/organizations.md` (identifiers and
slugs).

## Context

Several applications run on one SystemForge deployment and share a single
sign-in and organization model, so one person sees one set of organizations
across them. Three questions have come up that ADR-006 and ADR-007 do not
answer on their own:

- **Which identifier is safe to show customers?** Identifiers appear in
  tokens, URLs, exports and logs. Platforms sold to security teams are
  reviewed for metadata disclosure, and a time-ordered identifier carries
  the creation time of the thing it names.
- **What may an application key its data by?** Today an application can key
  tenant rows by organization slug. A slug can be released, reserved for
  seven days and then taken by someone else (ADR-006), so data keyed by it
  can follow the name to a different owner.
- **Can an application leave a deployment, or another deployment join one?**
  Splitting an application off, or merging a deployment in after an
  acquisition, must not depend on names that two deployments may both have
  claimed.

## Decision

1. **Identifier classes.** Every identifier SystemForge issues belongs to
   one class, and the class fixes how it is generated.

   | Class | Examples | Generator |
   |---|---|---|
   | Identity and tenancy entities | principal, organization, membership, client, credential, application and customer-facing resource IDs | UUIDv4 (random) |
   | Append-only records whose own time is already visible | access changes, audit and activity events, request evidence | UUIDv7 (time-ordered) |
   | Credentials and secrets | API keys, session cookies, invite tokens, OAuth state and nonces | CSPRNG bytes, stored hashed where possible; never a UUID |

   - **The test** is whether the creation time is itself sensitive. An
     account's or organization's creation time is metadata a customer did
     not choose to publish, so those IDs are random. An event already
     carries its time, so a time-ordered ID discloses nothing new and keeps
     insertion local in the database.
   - **A UUID never authorizes.** RFC 9562 section 8 says UUIDs must not be
     used as security capabilities and should not be assumed hard to guess.
     Authorization is checked on every request whatever the ID looks like.
   - **The choice of v4 for identity entities is conservative, not
     mandated.** The RFC describes the timestamp in a v7 UUID as a very
     small attack surface; the platform avoids it because it costs nothing
     and shortens security review.
   - **One identifier per entity.** There is no separate public and internal
     ID. A table that truly needs both time-ordered inserts and a random
     external ID may add a second column only by amending this ADR with the
     measured problem, because an internal ID that leaks through logs,
     joins and exports defeats the purpose.
   - **In code:** `UUIDMixin` and `BaseMixin` generate v4; `TimeOrderedUUIDMixin`
     generates v7 and is opt-in.

2. **Applications key tenant data by organization ID, never by slug.** The
   slug is a label resolved from the memberships the person already holds
   (the orgs claim, ADR-007). A rename, a conversion to a team organization
   or a released slug changes the label and nothing else.

3. **SystemForge owns slugs.** One slug registry per deployment serves every
   application, so one organization slug opens all of them in a single
   experience. Applications do not store, validate or reserve organization
   slugs themselves; they ask SystemForge.

4. **Slugs live in namespaces.** A slug is unique within a namespace, stored
   as `(namespace, slug)`.

   - **`org`:** organization slugs, shared by personal and team
     organizations as ADR-006 decision 4 requires.
   - **`app:<application-id>`:** slugs of resources an application owns
     (for example a published site or a shared dashboard). Two applications
     may use the same slug without conflict, and a slug an application owns
     moves with that application.
   - **Cooling-off applies per namespace** with the same seven days and the
     same claim rule as ADR-006 decision 5.
   - **Schema** (not part of this ADR's first implementation): the unique
     indexes on `sf_organizations.slug` and `sf_slug_reservations.slug`
     become unique on the namespace and slug together, with the namespace
     defaulting to `org`.

5. **Portability: split and merge.** Organization and principal IDs are
   random UUIDs, so they do not collide across deployments and are kept as
   they are.

   - **Splitting an application off** takes its data, which is keyed by
     organization ID, together with the organizations and principals that
     data references and the application's namespace of slugs.
   - **Merging a deployment in** imports organizations and principals with
     their IDs. A slug that is already taken is not overwritten: the
     importing deployment applies a declared policy, either renaming the
     incoming slug or reserving it, and the old name resolves as an alias
     for a cooling-off period.
   - **Principal subject continuity** across an issuer change is an open
     question below.

6. **Probing is bounded.** Slug availability and alias resolution are rate
   limited, and a resource the caller may not see returns the same response
   as one that does not exist.

7. **Customer-defined roles remain out of scope.** ADR-007 decision 4
   stands: roles are the ones an application declares. Customer-defined
   roles, permission bundles and teams matter for larger organizations and
   are deferred to a later tier; the first audience is individual builders
   and small teams. This ADR does not change the role model.

## Consequences

- **Account and organization metadata does not leak through IDs,** which
  keeps penetration-test and questionnaire answers short.
- **Data stays with the organization through renames and conversions,**
  and a freed slug cannot inherit another tenant's data.
- **Applications written against slugs must change** to key by organization
  ID. Existing rows keyed by a slug are attached to the organization's ID
  by an operator step before the key is switched.
- **Event tables keep cheap, ordered inserts** without a mapping layer.
- **Splitting or merging is a data-and-registry operation,** not a
  re-identification of every row.
- **The slug registry becomes a shared dependency** of every application,
  so its availability and rate limits matter.

## Alternatives considered

- **UUIDv7 for every table.** Rejected: it discloses account and
  organization creation time for a gain that is negligible at identity-table
  volumes.
- **UUIDv4 for every table.** Rejected: append-only tables take most of the
  writes and benefit from ordered inserts, and their IDs disclose nothing
  their rows do not.
- **A private v7 key plus a public v4 key on every table.** Rejected as the
  default: extra column, index and mapping for a benefit identity tables do
  not need (decision 1).
- **Encrypting or obfuscating identifiers.** Rejected: it adds key
  management and loses ordering, and protects nothing that slugs and error
  responses do not already show. Identifiers are not secrets.
- **Keep keying tenants by slug.** Rejected: a released slug can pass to a
  new owner after the cooling-off period.
- **A separate slug namespace for every application's organizations.**
  Rejected: it breaks the single, shared experience across applications.
- **Pairwise subject identifiers per application.** Not adopted now: it
  prevents cross-application correlation, which a single shared experience
  does not want. Reconsider if a deployment must isolate applications from
  each other.

## Open questions

- **Subject continuity on a split:** an application that leaves keeps
  principal IDs, but the token issuer and `sub` it trusts change. Whether a
  deployment issues tokens under both issuers for a transition, or the
  application maps old subjects to new, is undecided.
- **Namespace of a deployment:** whether the `org` namespace also needs a
  deployment qualifier so two deployments' registries can be merged without
  a policy, or whether the import policy is enough.
- **Which application-owned resources get slugs in the registry,** and
  whether an application may keep its own slug table with only the
  namespace reservation held by SystemForge.
- **Rate limits for probing,** their values, and whether availability
  checks require a signed-in caller.
