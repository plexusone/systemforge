# ADR-012: Data Governance Catalog, Legal Holds and Enforcement

**Status:** Proposed
**Deciders:** @grokify
**Relates to:** ADR-011 (lifecycle states, data classification and privacy
rights; this ADR defines the catalog, holds and enforcement behind them;
it replaces ADR-011's single erasure flag with holds), ADR-007 (roles),
ADR-010 (access changes), ADR-013 (key management, which owns snapshot
encryption).
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
   registered entity and field is described once, in the model of
   `github.com/grokify/datacatalog` (ADR-011, decisions 6 and 7), and the
   catalog is the answer to "what data do we hold and what rules apply to
   it". Per entity it records: the owner (product or platform), the data
   subject key, whether it is subject to access and erasure requests (GDPR
   scope), whether it can be placed under hold, whether it is `versioned`,
   its structured retention (`keep`, then `purge` or `offload`; ADR-011,
   decision 24) and its eraser. Per field it records the visibility
   (`public` or `internal`), the `pii` and `secret` tags, the erasure
   strategy and the export flag. Per relationship to another registered
   entity it records the purge disposition (`cascade`, `detach` or
   `restrict`; ADR-011, decision 21).
2. **The catalog is queryable and published.** It is available through an
   API and a command, and rendered as a documentation page from the same
   source, so a data protection review, a customer questionnaire and the
   enforcement code read one definition. Products' entries appear in it when
   they register (decision 16).

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
   - erasure, deletion and purge of its records are refused with `ErrHeld`,
     and a dependent row covered by a hold blocks the purge of the subject it
     references (decision 22);
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

10. **Two platform roles for privacy and legal, with privacy under legal.**
    (A third, `trust_safety_manager`, for purging abusive accounts, is
    defined in decision 24.) Organizations place
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
    `legal_manager` and to administrators with `audit.read`. The roles and
    permissions are part of the platform so every product gets the same
    generic capability; an application may extend them with its own roles or
    narrower permissions in its vocabulary, but may not weaken the platform's
    refusals (a hold still blocks erasure).
11. **Destructive and disclosing actions are requests.** Erasure,
    deletion, hold release and disclosure run as a request with states
    `requested`, `approved`, `executed` or `cancelled`, so there is one
    audited path whatever the policy. A deployment sets a policy per action:
    - `none`: the requester's authority is enough and the request executes
      at once. This is the default, since many businesses start with one
      person who holds every role.
    - `delay`: the request executes after a configurable period, during
      which it can be cancelled and the stated notification is sent. This
      protects a single operator from a mistake without needing a second
      person.
    - `approval`: a second principal holding the permission, different from
      the requester, must approve. The approver cannot be the requester or
      the subject, and an unapproved request expires.
    The policy can be tightened without a code change as the business grows.

12. **A hold is marked internally, and notification is the legal manager's
    decision.** The marker is visible to staff in admin tooling. Whether
    and how the person is told is set per hold: not at all, in the
    application (a notice the product renders from a claim or an API field),
    or out of band (a message the legal team sends). The default is not to
    notify, so a hold is not disclosed to a subject by accident. A subject
    whose erasure request is deferred is told only that the request is
    pending review, unless the legal manager has chosen to disclose.

### Snapshot storage

13. **The snapshot location is configurable.** Two stores are supported
    behind one interface: the database (a sealed, encrypted record, the
    default and the one used at first, since the volume is expected to be
    small) and an S3-compatible object store, with the snapshot written as a
    file (Parquet for tabular exports) and referenced from the database by
    location and digest. Moving to the object store is a configuration
    change; existing snapshots remain readable through their recorded
    location. The same store, with the same manifest, holds data offloaded
    from the primary database under ADR-011, decision 25.
14. **Snapshots are personal data.** They carry the classification of their
    contents, are encrypted at rest under keys managed as ADR-013 decides,
    are excluded from ordinary exports, and are removed only when every hold
    covering the subject has been released and the subject's own erasure has
    proceeded. The key hierarchy (per hold, per subject or platform-wide) is
    ADR-013's decision, not this one's.

### Enforcement in applications

15. **Applications reach their own data directly.** SystemForge does not sit
    between a product and its database. Identity and organization data stays
    behind SystemForge's services, because it owns them; product data goes
    through the product's own access layer.
16. **Registration is mandatory and verified.** A product annotates its Ent
    entities with classification (ADR-011, decision 7) and registers them in
    the catalog. `dataclass.Verify` runs at startup and fails in production,
    and warns in development, when a registered field has no classification
    or an entity with personal data has no subject key and eraser.
17. **SystemForge ships the enforcement as an Ent hook.** A mutation hook
    consults the catalog and the holds covering the subject and refuses the
    writes that decision 7 forbids; for versioned entities it writes the
    before-image; for a subject marked `purging` it refuses new dependent
    writes (decision 22). A product installs it once on its client, so
    enforcement sits in the write path without a data service.
18. **A conformance test is provided.** It fails in CI when a registered
    entity can be mutated without the hook installed, which catches a second
    client or a bulk path that skips it.
19. **Where tables share a database with SystemForge,** a trigger or
    row-level-security policy may back the hook as defense in depth. This is
    optional and engine-specific, and it lives in the engine-specific
    packages, not in the portable core.
20. **What this does not stop is stated.** Raw SQL, a bulk import script or a
    direct console session bypasses an ORM hook. The mitigations are
    operational and documented: lint rules against raw SQL in product code,
    `guardsql` for query paths, and control over who holds a database
    credential. The platform promises what a library can promise.

### Purge

21. **Purge planning is a walk of the catalog's relationships.** Given a
    subject, the platform follows its registered entities and their edges,
    counts the rows each would remove, and classifies each dependent: it
    cascades (owned by the subject), it detaches (reference cleared), or it
    blocks. Anything that blocks produces the dependency report of ADR-011,
    decision 20: a row of another subject, a `restrict` edge with rows
    present, a row covered by a hold, an edge in the Ent schema that the
    catalog does not declare. The same walk is the dry run. The report holds
    entity names, counts and reasons and never row contents, and is shown only
    to a holder of the permission in decision 24.
22. **Execution runs through the hook, in the platform, not in the
    database.** The plan is executed as ADR-011, decision 22 says: the subject
    is marked `purging`, new dependent writes are refused by the hook,
    dependents are removed leaf first in resumable batches, each batch is
    re-checked against the holds at the moment it runs (a hold placed
    mid-purge stops it with `ErrHeld`, and the rows removed so far are
    recorded), and the subject is removed last. Database cascades are not
    used on registered entities: they run inside the engine and skip the
    hook, so they would bypass hold checks, before-images and audit. Foreign
    keys stay `RESTRICT`.
23. **The catalog's relationships are verified against the schema.** A
    registration check and the conformance test compare every edge of a
    registered Ent entity with the catalog and fail on an undeclared edge or
    a foreign key that is not `RESTRICT`. An entity added without a
    disposition cannot ship, as a field without a classification cannot.
24. **Purge is a separate permission and role.** `account.purge.plan` runs
    the dry run and reads the dependency report; `account.purge` executes.
    They belong to a platform role, `trust_safety_manager`, separate from
    `privacy_manager` and `legal_manager`, because removing spam at volume is
    an abuse-handling duty and carries none of their authority over holds
    and data subject requests. Purge is a destructive request under decision
    11, and its policy can differ by origin: expiry of provisional accounts is
    system-initiated and uses `none`, a single purge by an operator uses the
    deployment's policy, and a bulk purge by criteria (signup window, email
    domain, network range) always starts with a dry run and, above a
    configurable row threshold, requires `approval` where a second principal
    exists.

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
- **Purge is safe because it is planned and refused.** A subject with
  dependents the catalog does not mark as owned cannot be removed, and the
  reason is reported, like a cloud provider's dependency violation.
- **Dependency edges are one more thing a product declares**, and the
  verification step keeps that list from rotting.

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
- **Rely on `ON DELETE CASCADE` for purge.** Rejected: cascades run inside
  the database and bypass the hook, so held rows could be removed, before-
  images skipped and no audit written.
- **Hard delete as the ordinary delete.** Rejected: references to a deleted
  principal would break or cascade; the tombstone stays the default and purge
  is the narrow exception.
- **Tombstone everything, including spam.** Rejected: it keeps a row, and an
  identifier, for each junk account at free-tier volumes, and retains data the
  platform has no reason to keep.
- **Versioning everywhere by default.** Deferred: a history store on every
  classified table is heavy for a first version; kept as a per-entity
  option and recorded in the catalog.

## Open questions

- How a data subject access request interacts with a hold the subject must
  not be told about (decision 12 defaults to "pending review").
- The default delay period for the `delay` policy.
- Whether a deployment with one principal can satisfy `approval` through an
  external approver (for example a named advisor with a scoped, temporary
  role), or must stay on `none` or `delay`.
- The row threshold above which a bulk purge requires approval, and whether
  it differs for provisional accounts.
- Whether a hold placed during a long purge should roll back the rows already
  removed (it cannot) or only stop and report, which is what decision 22
  specifies.
