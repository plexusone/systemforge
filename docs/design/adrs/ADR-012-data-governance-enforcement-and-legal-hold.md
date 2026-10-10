# ADR-012: Data Governance Enforcement and Legal Hold

**Status:** Proposed
**Deciders:** @grokify
**Relates to:** ADR-011 (lifecycle states, data classification and privacy
rights; this ADR defines how those are enforced and what a hold means),
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

### Legal hold semantics

1. **A hold means preserve, and preservation covers alteration as well as
   deletion.** A subject under hold has its data preserved as of the hold
   and protected from change, in two parts.
2. **Placing a hold takes a sealed snapshot.** The platform runs the same
   `Export` operation (ADR-011, decision 9) for the subject and stores the
   result as an immutable artifact with a digest, the time, the actor and
   the reason. The snapshot answers "what did it say when the hold began".
3. **While the hold is set:**
   - erasure, deletion and purge of the subject's records are refused with
     `ErrHeld`;
   - edits to fields classified `pii` are refused with `ErrHeld`, so the
     snapshot remains the true state;
   - archive remains allowed (it destroys nothing) and is how a subject is
     hidden from customers during a dispute;
   - operational writes continue: sign-in bookkeeping, session and token
     records, credential rotation and membership or role changes, each of
     which is already an auditable access change (ADR-010).
4. **Refusals are recorded.** A refused erasure or correction is an audit
   event, so the deferral of a data subject's request is evidenced.
5. **Setting and clearing a hold is administrator-only** and recorded; it
   carries a reason and an optional external reference (a matter number)
   that the platform stores and does not interpret.
6. **Versioning is an extension, not the baseline.** An entity may register
   as `versioned`, in which case edits are allowed under a hold and each
   before-image is kept. A product whose records must stay editable (a
   profile the person actively maintains) uses this; the platform's own
   identity tables use the freeze.

### Enforcement in applications

7. **Applications reach their own data directly.** SystemForge does not sit
   between a product and its database. Identity and organization data stays
   behind SystemForge's services, because it owns them; product data goes
   through the product's own access layer.
8. **Registration is mandatory and verified.** A product annotates its Ent
   entities with classification (ADR-011, decision 7) and registers them.
   `dataclass.Verify` runs at startup and fails in production, and warns in
   development, when a registered field has no classification or an entity
   with personal data has no registered subject key and eraser.
9. **SystemForge ships the enforcement as an Ent hook.** A mutation hook
   consults the registry and the hold flag and refuses writes that the hold
   forbids. A product installs it once on its client. Enforcement therefore
   sits in the write path without a data service, and it follows the
   standard ORM rather than a new abstraction.
10. **A conformance test is provided.** It fails in CI when a registered
    entity can be mutated without the hook installed, which catches the
    common mistake of a second client or a bulk path that skips it.
11. **Where tables share a database with SystemForge,** a database trigger
    or row-level-security policy may back the hook as defense in depth. This
    is optional and engine-specific, and it lives in the engine-specific
    packages, not in the portable core.
12. **What this does not stop is stated.** Raw SQL, a bulk import script or
    a direct console session bypasses an ORM hook. The mitigations are
    operational and are documented: lint rules against raw SQL in product
    code, `guardsql` for any analytics or ad hoc query path, and control over
    who holds a database credential. The platform promises what a library
    can promise, and says where it stops.

## Consequences

- **A hold is meaningful for mutable data.** The sealed snapshot plus the
  freeze answers "what did it say then" without a history store on every
  table; versioned entities cover the cases that need edits.
- **Products get governance by registering, not by building it:**
  classification, export, erasure, holds and an audit trail work across
  their data through one mechanism.
- **The platform stays out of product data paths.** No added hop, and a
  product can still split out. The cost is that enforcement is by
  convention, hook and test, and not by a mandatory interface.
- **Annotating entities is real work** for each product, and the startup
  check makes omissions loud.
- **The snapshot is itself personal data.** It is stored under the same
  classification, erased when the hold is cleared and the subject's erasure
  proceeds, and excluded from ordinary exports.

## Alternatives considered

- **All application data access through SystemForge.** Rejected: makes the
  platform the data layer for every product, couples their schemas and
  deployment, adds latency, and still does not stop a credential holder.
- **Preserve against deletion only.** Rejected: alteration defeats the
  purpose of a hold on mutable data.
- **Freeze every write under hold.** Rejected: breaks sign-in, rotation and
  membership operations; the account must stay usable and secure.
- **Versioning everywhere by default.** Deferred: a history store on every
  classified table is heavy for a first version; kept as a per-entity
  option.

## Open questions

- Snapshot storage: in the database as a sealed blob, or in an object store
  referenced by digest.
- Whether `versioned` entities keep before-images for all fields or only
  `pii` ones.
- How a hold on an organization relates to holds on its members.
