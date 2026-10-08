# ADR-009: Management Is a Relationship, Not the Absence of an Email

**Status:** Accepted
**Deciders:** @grokify
**Relates to:** ADR-005 (managed principals; this ADR amends its definition
and its invariant 4), ADR-003 (verified email), ADR-006 (organization
lifecycle: slugs for managed principals).
**Updates:** `docs/design/architecture/managed-principals.md`.

## Context

ADR-005 introduced managed principals for humans who cannot hold an email or
their own credentials, with the motivating case of young children in a
learning application. It defined the state by the email:

- a managed principal is "a `Principal(type=human)` whose `Human.email` is
  null";
- a managed principal that later attaches a verified email "is an ordinary
  human", after which its managers may be removed;
- `managedprincipal.IsManaged` tests `Human.email IS NULL`.

Two consumer cases do not fit that definition:

- **Children who have an email.** Many elementary-school students have a
  school-issued address. They still need a guardian or educator in control
  of their account: creating it, issuing sign-in, seeing activity, revoking
  and deleting. Under ADR-005 such a child cannot be created as managed at
  all, because the email makes them "ordinary".
- **Adults whose account is managed by arrangement.** A matchmaking
  application in which a family member manages a profile on an adult's
  behalf, with that adult's agreement. The adult has an email and may sign
  in themselves, and the manager's authority comes from the relationship
  they both accept, not from an email gap.

In both, the email and the relationship are independent facts. The email
answers "can this person be contacted and verified"; the relationship
answers "who may act for this person". ADR-005 conflated them because its
first consumer had neither.

## Decision

1. **A managed principal is a human with at least one active manager
   relationship.** Management is derived from the relationships, not from
   the email. While managed, `CanManageProfile` and `CanDelegate` are
   false, as ADR-005 specifies.
2. **Email is independent of management.** A managed principal may have an
   email (attached at creation or later, verified per ADR-003) and keep its
   managers. Attaching an email changes nothing about management.
3. **Email still decides whether management may end.** ADR-005's invariant
   1 stands: a human without an email must have a manager at all times. The
   last manager of a principal can be removed only when the principal has a
   verified email; that removal **releases** the principal, which becomes
   self-managed. This is the only rule in which email matters.
4. **A managed principal may hold its own credentials when a manager allows
   it:** a password, a social login linked to its email, or login tokens.
   The manager role's authority (consent, deletion, credential revocation,
   session revocation) is unchanged by the principal signing in itself.
5. **A self-managed human may enter management by consent.** A manager
   relationship with an existing self-managed principal is created only by
   that principal accepting a manager invitation, since it gives up control
   of its own profile. Creation by a manager (ADR-005) remains the path for
   principals the manager creates.
6. **Managers are unchanged:** an active human with a verified email that is
   not itself managed.
7. **What a managed principal may do for itself is the application's
   decision**, expressed in its authorization vocabulary: a learning
   application may let a child do nothing to the account; a matchmaking
   application may let the adult read and the manager edit, or the reverse.
   The platform supplies the relationship, the roles, and the `managed`
   claim; it does not fix the split.

### Changes to the implementation

- `IsManaged` answers from active manager relationships; `ErrNotManaged`
  means "has no active manager", not "has an email".
- `ErrLastManager` keeps its meaning (the last manager of a principal
  without a verified email cannot be removed) and its wording changes to
  say so.
- Creating a managed principal accepts an optional email, verified like any
  other (ADR-003) before it counts for release.
- A `release` operation removes the last manager of a principal with a
  verified email and clears the managed state in the same transaction.
- Manager invitations to existing principals: a new invite kind carrying
  the manager role, accepted by the signed-in principal.
- The `managed` session claim is derived from relationships.
- Slugs for managed principals (ADR-006) keep the manager-entered or
  generated form whether or not an email exists; an email's local part is
  not used for a managed principal, so a manager never exposes a child's
  address through a handle.

## Consequences

- **Students with school email addresses are supported**, and a child's
  account need not lose its guardian when the school issues an address.
- **Adults can be managed by arrangement**, with their consent recorded as
  the accepted invitation.
- **Release is an explicit event**, auditable, instead of a side effect of
  attaching an email.
- **Code that used the email as a proxy for management must change**:
  `IsManaged`, the `managed` claim, and any application that inferred
  management from a missing `email`.
- **No change for ADR-005's original consumer**: a child created without an
  email behaves exactly as before.
