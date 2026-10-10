# ADR-011: Lifecycle States, Data Classification and Privacy Rights

**Status:** Proposed
**Deciders:** @grokify
**Relates to:** ADR-005 and ADR-009 (managed principals; this ADR amends the
release decision of ADR-009), ADR-006 (organization lifecycle), ADR-010
(access changes).
**Updates:** `docs/design/architecture/managed-principals.md`,
`docs/design/architecture/organizations.md`, a new
`docs/design/architecture/data-governance.md`.

## Context

SystemForge holds personal data for every product built on it, and several
decisions so far assumed an account either exists or is "deactivated". Three
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

Managed principals add a related question. ADR-009 says releasing a
principal removes its managers at once. In practice the end of a management
arrangement is a process: the manager may need to finish handover, and the
record of the arrangement should be editable and, like a release object on a
code host, correctable or removable before it is final.

## Decision

### Lifecycle states

1. **A principal and an organization have a lifecycle state:** `active`,
   `archived` or `deleted`. Transitions: active ⇄ archived, and
   active or archived → deleted. Deleted is terminal.
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
4. **There is no hard delete in the platform.** An application that must
   purge rows after a retention period does so on tombstoned rows through
   its own job.
5. **Transitions require authority and are recorded:** an actor with the
   account-management permission (or a platform administrator), an
   access-change reason for each transition (ADR-010), and an audit record
   that holds no personal data.

### Data classification

6. **Every persisted field is classified.** The vocabulary is small and
   deliberately matches existing tooling:
   - `public` (the default, written explicitly);
   - `pii` — personal data about an identifiable person;
   - `secret` — credentials, tokens, keys and anything whose disclosure
     grants access.
   A field also carries optional attributes: the **subject key** (how the
   row maps to a data subject), an **erasure strategy** (`clear`,
   `tombstone`, `hash`, `delete_row` or `retain` with a stated reason), an
   **export** flag, and a **retention** note.
7. **The classification is metadata in Go, next to the schema.** It is an
   Ent annotation on each field in SystemForge's own schemas, collected into
   a registry by a small `dataclass` package. Applications annotate their
   own entities the same way and register them, so a product's tables are
   covered by the same mechanism. A test fails when a field has no
   classification, so a new column cannot ship unclassified.
8. **The registry is the single source for governance tooling.** It drives
   export and erasure (below), log redaction, and, as an optional adapter,
   a `guardsql` schema so analytics queries exclude `pii` and `secret`
   columns by default. The vocabulary (`pii`, `secret`) is the one
   `guardsql` already uses; the richer attributes are SystemForge's own, so
   the adapter maps down and does not make `guardsql` a dependency of the
   platform.

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
    records a retention note per field and exposes a purge hook, but does
    not fix periods: they follow the product's tier and packaging, which the
    application configures.
12. **Erasure can be held, minimally.** A subject may carry an *erasure
    hold*: a flag with a reason, set and cleared only by a platform
    administrator and recorded as an access-controlled audit event. While it
    is set, `Erase` and the delete transition refuse with `ErrHeld`, and
    archive remains available. SystemForge does not model legal cases,
    scopes or expiry; an application that needs them keeps them and sets the
    flag.
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

## Open questions

- Retention periods, which follow product tier and packaging decisions.
- Whether organizations get the same `Erase` semantics for their member
  data, or only archive and delete of the organization record.
- The shape of the export format (one archive per subject, with a manifest).

## References

- `guardsql`: the `pii` and `secret` data classes.
- GDPR Articles 15–18 and 20 (access, rectification, erasure, restriction,
  portability).
