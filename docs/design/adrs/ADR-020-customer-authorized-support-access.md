# ADR-020: Customer-Authorized Support Access

**Status:** Proposed
**Deciders:** @grokify
**Relates to:** ADR-011 (data classification, whose `pii` tag drives
masking), ADR-012 (platform roles, approval and delay policies, and the
audit trail), ADR-007 (organization roles), ADR-008 (resource-scoped
grants), ADR-010 (access changes), ADR-018 (the organization console, where
customers grant and review access), ADR-019 (support requests, which are
where a grant is usually asked for).

## Context

The operator of an application needs to look into a customer's data to
answer a support request, investigate a fault or confirm a bill. Platform
administrators today either see everything or nothing, and both are wrong:

- **Seeing everything by default** means every person with an administrative
  role can read every customer's personal data, which is more access than the
  work needs, and more than customers expect.
- **Seeing nothing** means a support request that needs a look at the
  customer's workspace cannot be answered.

The common practice is for staff to work without personal data by default,
and for the customer to authorize fuller access for a limited time when a
request needs it. The platform already has the pieces:

- the data catalog tags every field `pii` or not (ADR-011);
- the serialization helper and query guard filter fields by the catalog;
- ADR-012 separates privacy and legal permissions from platform
  administration, and defines approval and delay policies for sensitive
  actions.

What is missing is the grant itself, and the rule for what staff see without
one.

## Decision

### Default staff access

1. **Staff see customer data with personal data masked.** Platform
   administrators and `support_agent` holders see accounts, organizations,
   lifecycle states, entitlements, configuration, counts and health. Every
   field the catalog tags `pii` is masked in their responses and refused in
   their queries, through the same catalog predicate that customer queries
   use. Masking happens in the platform's serialization and query guard, so
   an application gets it for its own entities by registering them.
2. **A support request's own text is not masked for support staff.** A
   requester writes to the operator in order to be answered. `support_agent`
   holders read the requests addressed to the operator (ADR-019) without a
   grant. A grant is for the customer's application data, not for the message
   they sent.

### Customer authorization

3. **A support access grant is a record, created by the customer.**
   - **Who grants it:** an organization owner or admin, or the principal
     themselves for a personal organization.
   - **Its scope:** one organization, optionally narrowed to one application
     or to named resources.
   - **Its level:** `view`. A level that lets staff act on the customer's
     behalf is a separate, later decision (see Alternatives).
   - **Its window:** 8 hours by default. The customer may choose a custom
     window up to a maximum of 7 days, and a deployment may lower the
     maximum.
   - **What it records:** the reason, the support request reference when
     there is one, who granted it, when, its expiry, and who may use it.
     That is any `support_agent` by default, or named staff.
4. **A grant can be asked for, but only the customer creates it.** Staff may
   send a request for access from a support request. The customer sees what
   is asked, for how long and why, and approves, shortens or declines.
   Approving creates the grant. Staff cannot create one.
5. **Under a grant, masking is lifted for that scope only.** Every read under
   a grant is checked against the grant on each request, so expiry or
   revocation applies at once (ADR-010). Writes are refused at the `view`
   level.
6. **The customer can always see and end it.** The organization console
   (ADR-018) lists active and past grants, with their audit trail. Owners and
   admins can revoke a grant at any time. A grant ends at its expiry with no
   action needed, and is never extended. A new grant is created instead.
7. **Every use is audited.** Each read under a grant is an audit event with
   the staff principal, the grant, the resource and the time, and without the
   personal data read. The customer can export the events for their
   organization.

### Emergency access

8. **Access without a grant is possible, and costly.** For a security
   incident, a legal obligation or a service outage, staff with the
   `support.access.emergency` permission may open emergency access.
   - It needs a stated reason, and passes through ADR-012's request policy
     with `approval` as the default: a second principal holding the
     permission approves.
   - Its window is at most 8 hours.
   - It is audited like a grant, and the organization's owners are told
     after the fact, unless a legal hold's disclosure decision (ADR-012
     decision 12) says otherwise.

### Permissions

9. **Named permissions, in the vocabulary of ADR-012:**
   - `support.request.read` for reading support requests;
   - `support.access.request` for asking a customer for access;
   - `support.access.use` for using an active grant;
   - `support.access.emergency` for opening emergency access;
   - `support.access.grant` for customers: held by organization owners and
     admins.

   The platform role `support_agent` holds the first three. Emergency access
   is held by no role by default.

## Consequences

- **Staff can do most support work without personal data,** and customers
  know when their data was opened, by whom and why.
- **Every application gets masking for free,** as long as its entities are
  classified, which ADR-011 already requires.
- **Some support takes longer.** A request that needs a look at a workspace
  waits for the customer to approve. The request form can ask for access
  up front to save a round trip.
- **Masked views must still be useful.** Screens built for staff show masked
  values as masked, never blank. The organization, state and counts stay
  visible.
- **The help desk is outside this.** A vendor inbox shows a support message to
  whoever has access there. Staff meant to work masked do not get a seat in
  the vendor's inbox.

## Alternatives considered

- **Administrators see everything.** Rejected: more access than the work
  needs, and no record a customer can check.
- **A grant for acting as the user now.** Deferred: acting as a user changes
  data under the customer's name, needs its own consent wording, a visible
  banner and a stronger audit. It is decided when an application needs it.
- **Staff create grants with a reason, without the customer.** Rejected as the
  normal path: it is emergency access by another name. Emergency access keeps
  its approval and notification costs.
- **Unlimited or renewable windows.** Rejected: a forgotten grant becomes
  standing access. A short default, a hard maximum and no extension keep each
  grant tied to one piece of work.
