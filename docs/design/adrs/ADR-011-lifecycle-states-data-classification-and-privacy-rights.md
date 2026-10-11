# ADR-011: Lifecycle States, Data Classification and Privacy Rights

**Status:** Proposed
**Deciders:** @grokify
**Relates to:** ADR-005 and ADR-009 (managed principals; this ADR amends the
release decision of ADR-009), ADR-006 (organization lifecycle), ADR-010
(access changes), ADR-012 (enforcement and the semantics of a hold).
**Updates:** `docs/design/architecture/managed-principals.md`,
`docs/design/architecture/organizations.md`, a new
`docs/design/architecture/data-governance.md`.

## Context

SystemForge holds personal data for every product built on it, and several
decisions so far assumed an account either exists or is "deactivated". Four
needs do not fit that:

- **Hiding without destroying.** An account that should disappear from
  customer-facing applications, such as a departed member or a closed
  profile, while staff can still see it and restore it.
- **Deleting without breaking references.** Principals are referenced by
  memberships, audit records, work items and grants. Deleting the row would
  either cascade through those or fail on foreign keys.
- **Privacy rights.** GDPR and similar regimes give a data subject access,
  portability, rectification, restriction and erasure. These are
  cross-cutting: every product stores data about the same person. They
  belong in the platform layer so each product does not reimplement them,
  and so there is one place that knows which columns hold personal data.
- **Dead and unwanted accounts at scale.** A free tier accumulates accounts
  that were abandoned and accounts created by spammers. Soft deleting every
  one and keeping a tombstone is the wrong answer for spam, which should
  leave no personal data and no row behind, and abandoned accounts should not
  be kept indefinitely, which the storage-limitation principle also requires.
  Versioned entities, whose history grows with every edit, add unbounded
  growth of their own.

Managed principals add a related question. ADR-009 says releasing a
principal removes its managers at once. In practice the end of a management
arrangement is a process: the manager may need to finish handover, and the
record of the arrangement should be editable and, like a release object on a
code host, correctable or removable before it is final.

## Decision

### Lifecycle states

1. **A principal and an organization have a lifecycle state:**
   `provisional`, `active`, `archived` or `deleted`. Transitions:
   provisional → active (graduation, decision 19), active ⇄ archived, and
   active or archived → deleted. Deleted is terminal. A subject may also be
   purged (decision 20), which removes it and is not a state it stays in.
2. **Archived** is reversible and means "not for customers to see":
   - it is excluded from listings, search, mentions and pickers in
     customer-facing applications;
   - platform administrators and the owners' admin tooling can still list,
     read and restore it;
   - it cannot sign in at all, so that "archived" has one clear meaning,
     and its sessions are revoked when it is archived (an access change,
     ADR-010); an archived organization's members lose access to it through
     their claims; data export for an archived subject is performed by an
     administrator;
   - memberships, grants and history are preserved.
3. **Deleted is a soft delete.** The row stays so references hold, and every
   column classified as personal data (below) is erased according to its
   erasure strategy. The identifier is replaced by a non-reversible
   tombstone, credentials, external identities, sessions, consents and
   claims are removed, and memberships and relationships are deactivated.
   Deletion of personal data is irreversible; the tombstone is not.
4. **The delete transition never removes the row.** `deleted` keeps a
   tombstone so references hold. Removing rows is a separate operation,
   `purge` (decision 20), allowed only where nothing depends on them and
   nothing forbids it. An application that must remove tombstoned rows after
   a retention period does so through the platform's purge, not its own job.
5. **Transitions require authority and are recorded:** an actor with the
   account-management permission (or a platform administrator), an
   access-change reason for each transition (ADR-010), and an audit record
   that holds no personal data.

### Data classification

6. **Every persisted field is classified, on two independent axes.**
   - **Visibility** is `public` or `internal`. `public` may be shown to
     application users, subject to the application's own authorization.
     `internal` is system data not shown to application users: flags,
     counters, security stamps, internal references and operational state.
   - **Tags**, each on or off: `pii` (personal data about an identifiable
     person) and `secret` (credentials, tokens, keys, anything whose
     disclosure grants access).
   The axes are independent: a display name is `public` and `pii`; a login
   record's IP address is `internal` and `pii`; a password hash is
   `internal` and `secret`. One rule ties them: `secret` implies `internal`,
   and validation rejects a secret field marked `public`. Visibility is
   never defaulted: an unclassified field is an error, not a public one.
   A field also carries optional attributes: an **erasure strategy**
   (`clear`, `tombstone`, `hash`, `delete_row`, `shred` or `retain` with a
   stated reason) and an **export** flag. An entity carries the **subject
   key** (how a row maps to a data subject), whether it is in privacy scope,
   whether it can be placed under hold, whether it is versioned, and a
   **retention** note.
7. **The model is a separate, generic module, and the classification is
   metadata in Go next to the schema.** The catalog model, its validation
   and its audience filtering live in `github.com/grokify/datacatalog`, a
   public, dependency-free module that other tools (a query guard such as
   `guardsql`, documentation generators, a future management application)
   consume without depending on SystemForge or on an ORM. SystemForge adds
   the pieces that are specific to it: Ent annotations on each field of its
   own schemas, collected into a catalog by a small `dataclass` package, and
   the orchestration of export, erasure and holds. Applications annotate
   their own entities the same way and register them. A test fails when a
   field has no classification, so a new column cannot ship unclassified.
8. **The catalog is the single source for governance tooling.** It drives
   export and erasure (below), log redaction, response filtering (a
   serialization helper omits every `internal` field unless the caller asks
   for a staff or system view), and query gating: a query guard such as
   `guardsql` blocks `internal` and `secret` columns for customer queries
   always, and `pii` columns unless the profile allows them. The guard adopts
   the catalog's own predicate, so there is one definition of what a
   customer query may touch.

### Privacy rights

9. **SystemForge provides the operations; applications decide policy.**
   - **Access and portability:** `Export(subject)` returns the subject's
     records from every registered entity where `export` is set, in a
     structured, machine-readable form.
   - **Erasure:** `Erase(subject)` is the delete transition above, applied
     to the subject's rows in every registered entity per their strategies,
     reporting which entities were erased and which retained rows (with the
     retention reason).
   - **Restriction:** archiving a subject, plus a flag that processing is
     restricted for the applications that need to honor it.
   - **Rectification:** ordinary edits.
10. **Erasure is orchestrated, not assumed.** Products store their own data;
    each registers an eraser for its entities (or relies on annotations for
    simple cases). `Erase` runs them, records per-entity results without
    personal data, and can be resumed after a partial failure.
11. **Retention is a policy input, not a platform constant.** SystemForge
    records retention per field and per entity (decision 24) and runs the
    purge, dormancy and offload operations below, but does not fix periods:
    they follow the product's tier and packaging, which the application
    configures.
12. **Erasure can be held.** A subject may be covered by one or more legal
    holds (ADR-012). While any hold covers it, `Erase`, the delete
    transition, purge and edits to `pii` fields refuse with `ErrHeld`, and
    archive remains available. Holds are placed and released by a legal manager,
    not by a platform administrator acting alone. ADR-012 defines holds,
    what they preserve, and how they are enforced. SystemForge models the
    hold and its custodians; legal case management stays outside it.
13. **The audit log is exportable.** Lifecycle transitions, erasure results
    and hold changes are recorded without personal data, and an
    administrator can export them (by organization and time range), so a
    customer can evidence what was erased, when and under whose authority.
    This is independent of the hold: the export serves accountability, the
    hold serves refusal.
14. **Managed principals are covered.** A managed subject's request is made
    by an authorized manager, and the audit record names that manager's
    authority; once released, the principal acts for itself.
15. **A request is verified before it is honored.** Verification of the
    requester's identity is the application's responsibility; SystemForge
    exposes the operations behind the authorization checks of decision 5.

### Release of a managed principal (amends ADR-009, decision 3)

16. **Release is a record with a state, not an instant.** Releasing a
    principal creates a release record in state `open`. While it is open:
    - the principal is self-managed: it may act for itself, and the managers'
      authority over it is suspended (`managed` is false);
    - the manager relationships are retained, dormant, so a mistaken release
      can be reversed;
    - the record may be edited (for example its note and effective details)
      and may be deleted, which restores the management arrangement.
17. **Closing a release is the formal end of management.** Closing removes
    the manager relationships and cannot be undone by a manager. After a
    release is closed only a platform administrator may change or reopen
    it.
18. **ADR-009's other rules stand:** a principal without a verified email
    must have a manager, so release still requires a verified email, and
    email remains independent of management.

### Dead accounts, purge and storage tiering

19. **An account that has not proven itself is `provisional`.** A principal
    created by a signup that has not yet verified an email or taken a first
    meaningful action is `provisional`. A deployment sets the graduation
    criterion and a short time to live. A provisional account that does not
    graduate within it is purged (decision 20), with no tombstone. Spam that
    never graduates therefore never becomes an identity record that other
    records reference. A deployment may further restrict what a provisional account can do (for
    example, it holds no roles and is not referenced as an author), so that
    graduation is the point at which other records begin to depend on it.
20. **`purge` removes a subject's rows when everything that depends on them
    can also be removed.** It differs from `deleted` in that no row, and no
    personal data, remains. A subject is purgeable when every record that
    references it, directly or transitively, is itself purgeable: it belongs
    to the same subject, is declared `cascade` (below), and is not covered by a
    hold. Otherwise the purge is refused with a **dependency report** and the
    caller may fall back to the ordinary delete, which keeps a tombstone. The
    report names the entity, the count and the reason for each blocker and
    never the contents of another subject's rows.
21. **Relationships carry a purge disposition in the catalog.** Each edge
    between registered entities is declared:

    | Disposition | Meaning | Example |
    |---|---|---|
    | `cascade` | The dependent is owned by the subject and is purged with it | Sessions, API keys, preferences, memberships of the subject's personal organization |
    | `detach` | The dependent stays and its reference is cleared or replaced by a placeholder | A comment authored in another organization's workspace |
    | `restrict` | The dependent blocks the purge | Billing records, a membership in an organization that still exists, another subject's data |

    An edge without a disposition is an error at registration, as an
    unclassified field is. Where a deployment's product has content shared
    with other subjects, which of `restrict` and `detach` applies is the
    product's decision.
22. **Purge is orchestrated by the platform, not by database cascades.**
    Executing a purge marks the subject `purging`, which the enforcement
    hook (ADR-012) uses to refuse new dependent writes, then removes
    dependents leaf first in batches that can be resumed, and finally the
    subject. Foreign keys on registered entities stay `RESTRICT`, as a
    safety net that makes an undeclared dependency fail loudly. Every step
    runs through the same hook, so hold checks, before-images and audit
    apply; the audit record carries counts and no personal data. A
    `versioned` entity's before-images are part of the closure and are purged
    with it unless a hold covers the subject.
23. **Purge leaves an abuse fingerprint, not personal data.** So a purged
    account is not simply recreated, the platform may retain a keyed hash of
    the verified email (and, if the deployment chooses, network indicators)
    under a key managed as ADR-013 decides. The fingerprint cannot be
    reversed, is classified in the catalog, has its own retention period, and
    is used only to block re-registration and to measure abuse. The lawful
    basis and the period are the deployment's decision and need review for
    its jurisdictions.
24. **Dormant accounts follow a ladder, and retention is structured.**
    - An account records when it was last active, updated at most once a
      day so activity does not become a write on every request.
    - A deployment sets, per tier, a dormancy period after which the owner
      is notified, then the account is archived (decision 2), then deleted
      after a further period, and purged where decision 20 allows.
    - Accounts with active billing, a covering hold, or the sole ownership of
      an organization that has other members are excluded until that is
      resolved.
    - The notice tells the owner how to keep the account: signing in before
      archive resets the period, and an archived account is restored on
      request.
    - Retention in the catalog is structured as `keep` (a duration) and
      `then` (`purge` or `offload`), per entity, with the periods supplied by
      configuration (decision 11).
25. **Archive in storage terms is "offload", and it is a separate tier.**
    `archived` (decision 2) is a visibility state and stays in the database.
    Moving rows out of the primary database is **offload**, defined as:
    - Data eligible for offload is historical and cold: tombstones past
      their period, before-images of `versioned` entities, snapshots whose
      holds were released, and old audit records.
    - Offloaded rows are written to the snapshot store (ADR-012, decision
      13), a database table set or an S3-compatible object store with
      Parquet files, with a manifest recording the catalog version, row
      counts and digest, and a stub left where a reference requires one.
    - Before-image and audit storage is **partitioned by time** from the
      first version, so that cold partitions can be detached, exported and
      purged without rewriting live tables. Hot queries use partial indexes
      and default scopes that exclude `archived` and `deleted` rows.
    - Offload is not destruction, so it is allowed under a hold, but it is a
      custody change and is audited. Offloaded data stays reachable by
      subject for export, erasure and hold: encryption under per-subject keys
      (ADR-013) lets erasure destroy a subject's key and cover the offloaded
      copy without rewriting files.
    - **Purge is the only deletion.** It is explicit, retention-driven and
      hold-aware.

## Consequences

- **Accounts can be hidden without losing history**, and an administrator
  can restore them.
- **Deletion never breaks references**, and the personal data in a deleted
  row is gone by construction rather than by convention.
- **One registry answers "where do we keep personal data?"** for the
  platform and for every product built on it, and CI keeps it complete.
- **Products take on work:** annotate their entities and register erasers.
  The cost is small for simple tables and explicit for the rest.
- **Release becomes reversible until it is closed.** The cost is a second
  state and a dormant-relationship rule that every authority check must
  honor, including the `managed` claim.
- **ADR-009's "release removes managers" becomes "closing removes
  managers".** Code and docs that equate release with removal change.
- **Spam and abandoned accounts do not accumulate.** Provisional accounts
  expire without a trace, the dormancy ladder reclaims the rest, and purge is
  safe because it refuses whatever still has dependents.
- **Every relationship needs a disposition.** Adding an edge between
  registered entities now carries a decision, which is the same discipline as
  classifying a field and is enforced the same way.
- **Large histories have somewhere to go.** Time-partitioned history and the
  offload tier bound the growth of the primary database, at the cost of a
  second place to look when data is subject to a request or a hold.
- **ADR-011's earlier "no hard delete" is withdrawn.** Row removal exists, as
  `purge`, but only where the dependency rule allows it.

## Open questions

- Retention periods, which follow product tier and packaging decisions.
- Whether organizations get the same `Erase` semantics for their member
  data, or only archive and delete of the organization record.
- The shape of the export format (one archive per subject, with a manifest).
- What counts as graduating from `provisional`: a verified email, a first
  meaningful action, or either.
- The retention period and lawful basis for the abuse fingerprint, which
  need legal review per jurisdiction.
- Whether an account under investigation needs a `suspended` state between
  `active` and purge, or whether archive covers it.
- The default disposition for content shared with other subjects, `restrict`
  or `detach`, per product.
- The dormancy periods per tier, which follow packaging.

## References

- `guardsql`: the `pii` and `secret` data classes.
- GDPR Articles 15–18 and 20 (access, rectification, erasure, restriction,
  portability).
