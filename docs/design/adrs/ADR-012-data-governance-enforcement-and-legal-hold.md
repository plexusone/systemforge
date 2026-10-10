# ADR-012: Data Governance Catalog, Legal Holds and Enforcement

**Status:** Proposed
**Deciders:** @grokify
**Relates to:** ADR-011 (lifecycle states, data classification and privacy
rights; this ADR defines the catalog, holds and enforcement behind them;
it replaces ADR-011's single erasure flag with holds), ADR-007 (roles),
ADR-010 (access changes).
**Updates:** a new `docs/design/architecture/data-governance.md`.

## Context

ADR-011 defines a classification registry, lifecycle states, access and
erasure operations, and an erasure hold. It leaves two questions open:

- **What does a hold preserve?** A mailbox hold works because email is
  immutable once sent: "preserve" means "do not delete". A row in a CRUD
  database is overwritten by an update, and the earlier state is often the
  evidence. Preserving only against deletion would let the data be altered
  instead.
- **How is any of it enforced in applications?** Each product keeps its own
  data in its own schema and database. Governance that only covers
  SystemForge's tables protects little, and routing every product's queries
  through a SystemForge data service would make the platform the data layer
  for all of them, contradicting the modular monolith (a product must be
  able to split out) and adding latency for rare operations. It would not
  even enforce anything: a holder of a database credential bypasses any
  interface.

Governance that spans products is what makes the platform valuable to a
product team: classification, privacy rights and holds that work for their
data without each team building them. The design below delivers that
without taking over their data access.

## Decision

### The data catalog

1. **The classification registry is a central data catalog.** Each
   registered entity and field is described once, and the catalog is the
   answer to "what data do we hold and what rules apply to it". Per entity
   it records: the owner (product or platform), the data subject key,
   whether it is subject to access and erasure requests (GDPR scope),
   whether it can be placed under hold, whether it is `versioned`, its
   retention note and its eraser. Per field it records the class (`public`,
   `pii`, `secret`), the erasure strategy and the export flag.
2. **The catalog is queryable and published.** It is available through an
   API and a command, and rendered as a documentation page from the same
   source, so a data protection review, a customer questionnaire and the
   enforcement code read one definition. Products' entries appear in it when
   they register (decision 14).

### Legal holds

3. **A hold means preserve, and preservation covers alteration as well as
   deletion.** A subject covered by a hold has its data preserved as of the
   hold and protected from change.
4. **A hold is an object, and a subject may be on several at once.** A hold
   has an identifier, a name, an optional external reference (a matter
   number that the platform stores and does not interpret), a reason, a
   state (`active` or `released`), its placing and releasing actors, and a
   set of **custodians**: the subjects it covers. A subject is held while at
   least one active hold covers it. Releasing one hold never clears
   another; the subject becomes erasable only when no active hold remains.
5. **Custodians are subjects, grouped by the hold.** A hold lists its
   custodians explicitly. As a convenience a hold may be placed on an
   organization, which adds the organization's members at that time and
   records the hold against the organization. Whether members who join
   later are also added is chosen when the hold is placed
   (`include_future_members`), and defaults to no. The setting is recorded
   with the hold and changing it is an audited change by the legal manager.
   The platform understands the grouping (which subjects a hold covers, and
   which holds cover a subject) and nothing about the matter itself.
6. **Placing a hold snapshots each custodian.** For every custodian the
   platform runs the same `Export` operation (ADR-011, decision 9) and
   stores the result as a sealed, immutable artifact with a digest, time,
   actor and hold. The snapshot answers "what did it say when the hold
   began". A subject added to a hold later is snapshotted at that moment.
7. **While any hold covers a subject:**
   - erasure, deletion and purge of its records are refused with `ErrHeld`;
   - edits to `pii` fields are refused with `ErrHeld`, so the snapshot
     remains the true state, except for `versioned` entities (decision 9);
   - archive remains allowed (it destroys nothing) and is how a subject is
     hidden from customers during a dispute;
   - operational writes continue: sign-in bookkeeping, session and token
     records, credential rotation and membership or role changes, each of
     which is already an auditable access change (ADR-010).
   The refusal names the holds, to administrators and to the legal manager
   only.
8. **Refusals are recorded.** A refused erasure, deletion or correction is
   an audit event, so the deferral of a data subject's request is
   evidenced.
9. **Versioned entities keep every before-image.** An entity registered as
   `versioned` allows edits under a hold and stores each previous state
   (all fields, not only `pii`) in an append-only history. Such entities are
   marked in the catalog, and their history is subject to the hold: it is
   not purged while any hold covers the subject. The platform's own identity
   tables use the freeze (decision 7), not versioning.

### Roles and notification

10. **Two platform roles, with privacy under legal.** Organizations place
    privacy inside legal, so the roles are separate in permission and nested
    in default assignment:
    - `privacy_manager` handles data subject requests: the catalog (read),
      access and portability exports, restriction (archive), and erasure
      and deletion requests, which are refused while a hold applies.
    - `legal_manager` places, changes and releases holds, decides whether a
      hold is disclosed, and holds every `privacy_manager` permission. A
      hold overrides erasure, so the role that can place one must be able to
      see the requests it defers.
    Both are platform-level roles in the SystemForge vocabulary (ADR-007),
    separate from platform administration, so that placing a hold or
    erasing a person is not available to everyone who can administer
    accounts. Permissions are named (`privacy.request.manage`,
    `privacy.catalog.read`, `legal.hold.manage`, `legal.hold.disclose`,
    `audit.read`) so a deployment whose privacy office sits outside legal
    can assign them differently. Holds and snapshots are readable only to
    `legal_manager` and to administrators with `audit.read`.
11. **A hold is marked internally, and notification is the legal manager's
    decision.** The marker is visible to staff in admin tooling. Whether
    and how the person is told is set per hold: not at all, in the
    application (a notice the product renders from a claim or an API field),
    or out of band (a message the legal team sends). The default is not to
    notify, so a hold is not disclosed to a subject by accident. A subject
    whose erasure request is deferred is told only that the request is
    pending review, unless the legal manager has chosen to disclose.

### Snapshot storage

12. **The snapshot location is configurable.** Two stores are supported
    behind one interface: the database (a sealed, encrypted record, the
    default and the one used at first, since the volume is expected to be
    small) and an S3-compatible object store, with the snapshot written as a
    file (Parquet for tabular exports) and referenced from the database by
    location and digest. Moving to the object store is a configuration
    change; existing snapshots remain readable through their recorded
    location.
13. **Snapshots are personal data.** They carry the classification of their
    contents, are encrypted at rest, are excluded from ordinary exports, and
    are removed only when every hold covering the subject has been released
    and the subject's own erasure has proceeded.

### Enforcement in applications

14. **Applications reach their own data directly.** SystemForge does not sit
    between a product and its database. Identity and organization data stays
    behind SystemForge's services, because it owns them; product data goes
    through the product's own access layer.
15. **Registration is mandatory and verified.** A product annotates its Ent
    entities with classification (ADR-011, decision 7) and registers them in
    the catalog. `dataclass.Verify` runs at startup and fails in production,
    and warns in development, when a registered field has no classification
    or an entity with personal data has no subject key and eraser.
16. **SystemForge ships the enforcement as an Ent hook.** A mutation hook
    consults the catalog and the holds covering the subject and refuses the
    writes that decision 7 forbids; for versioned entities it writes the
    before-image. A product installs it once on its client, so enforcement
    sits in the write path without a data service.
17. **A conformance test is provided.** It fails in CI when a registered
    entity can be mutated without the hook installed, which catches a second
    client or a bulk path that skips it.
18. **Where tables share a database with SystemForge,** a trigger or
    row-level-security policy may back the hook as defense in depth. This is
    optional and engine-specific, and it lives in the engine-specific
    packages, not in the portable core.
19. **What this does not stop is stated.** Raw SQL, a bulk import script or a
    direct console session bypasses an ORM hook. The mitigations are
    operational and documented: lint rules against raw SQL in product code,
    `guardsql` for query paths, and control over who holds a database
    credential. The platform promises what a library can promise.

## Consequences

- **A hold is meaningful for mutable data.** The sealed snapshot plus the
  freeze answers "what did it say then" without a history store on every
  table, and versioned entities cover records that must stay editable.
- **Several matters can cover one person.** Release of one matter leaves the
  others in force, and the platform can answer "which holds cover this
  person" and "who is on this hold".
- **Placing and disclosing a hold are separate decisions held by a legal
  role**, not by whoever administers accounts.
- **Products get governance by registering, not by building it.** The
  catalog makes the platform's coverage inspectable and auditable.
- **The platform stays out of product data paths.** No added hop, and a
  product can still split out. The cost is that enforcement is by
  convention, hook and test, and not by a mandatory interface.
- **Annotating entities is real work** for each product; the startup check
  makes omissions loud.
- **The platform now models holds and custodians.** It still does not model
  matters, deadlines, counsel or discovery; those stay in the legal team's
  systems, referenced by the external reference.

## Alternatives considered

- **A single hold flag per subject.** Rejected: it cannot express several
  matters, and releasing one would clear the rest.
- **All application data access through SystemForge.** Rejected: makes the
  platform the data layer for every product, couples their schemas and
  deployment, adds latency, and still does not stop a credential holder.
- **Preserve against deletion only.** Rejected: alteration defeats the
  purpose of a hold on mutable data.
- **Freeze every write under hold.** Rejected: breaks sign-in, rotation and
  membership operations; the account must stay usable and secure.
- **Versioning everywhere by default.** Deferred: a history store on every
  classified table is heavy for a first version; kept as a per-entity
  option and recorded in the catalog.

## Open questions

- How a data subject access request interacts with a hold the subject must
  not be told about (decision 11 defaults to "pending review").
- Whether `legal_manager` and `privacy_manager` are also available per
  organization for enterprise tenants (they are platform-level to start).
- Whether erasure by a `privacy_manager` needs a second approver
  (separation of duties) for subjects with an active deferred request.
- Snapshot encryption keys: per hold, per subject, or platform-wide.
