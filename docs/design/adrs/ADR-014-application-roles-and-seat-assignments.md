# ADR-014: Application Roles and Marketplace Seat Assignments Are Separate Records

**Status:** Proposed
**Deciders:** @grokify
**Relates to:** ADR-007 (memberships and entitlements as claims; this ADR
amends its decision 8), ADR-008 (resource-scoped collaborators).
**Updates:** `docs/design/architecture/organizations.md` (seat accounting)
and `docs/design/architecture/authorization.md` (application roles). Both
already describe the behavior below; they are not changed by this ADR.

## Context

ADR-007 decision 8 says that application roles are stored in `sf_app_roles`,
"which replaces seat assignments as the record of who may use what", and
that a seat-licensed application counts its rows against the license. The
initiative's TRD went further and planned for `SeatAssignment` to become a
view derived from `sf_app_roles`, kept for one release and then removed.

The implementation does the second half of the sentence and not the first:

- **Seat limits are enforced on application roles.** The seat limit of an
  application is the sum of the seats of its valid `seat_based` licenses;
  `approle` counts `sf_app_roles` rows for (organization, application)
  against it and refuses with `ErrNoSeats`. There is no limit when any
  entitlement for the application is not seat-limited.
- **Seat assignments were not replaced.** `sf_seat_assignments`, the
  marketplace seat endpoints, `License.used_seats`, `CheckPrincipal` and the
  SpiceDB `seat_holder` relation (`license#use`) all remain, and none of
  them is derived from application roles. Assigning a role creates no seat
  assignment, and assigning a seat grants no role.

Replacing one record with the other would not be a rename, because they
describe different things:

| | Application role | Seat assignment |
|---|---|---|
| Keyed by | (principal, organization, application) | (license, principal) |
| Answers | What may this person do inside the application? | Does this person hold a seat of this license? |
| Needs an application | Yes, a registered `AppVocabulary` | No: a listing need not name an application |
| Carries a level | Yes, a role from the vocabulary | No |
| Counted by | `approle`, per application | `used_seats`, per license |

A listing that names no application (a template, a dataset, a service sold
without an in-product role) has seats and no application roles. An
application entitled through several licenses, a subscription and a
default has one set of roles and several license records.

Leaving the ADR as written means a reader looking for "who may use
application X" finds two answers, and the architecture pages already say
that the marketplace's seat assignments remain a separate record while ADR-007
says they were replaced.

## Decision

1. **Application roles are the record of who may act inside an
   application.** Applications decide access from the `orgs` claim's `apps`
   map and never from seat assignments. This confirms ADR-007's decision 1
   and the first clause of decision 8.
2. **Seat assignments remain the marketplace's record of who holds a seat
   of a particular license.** They are not replaced, not derived from
   application roles and not required for application access. ADR-007
   decision 8 is amended: `sf_app_roles` does not replace seat assignments.
3. **Seat limits for an application are enforced on application roles**, as
   implemented: a principal holding a role in a seat-licensed application
   consumes one seat for that application, whether or not a seat assignment
   exists. Owners' implicit roles hold no seat.
4. **The two counters are different numbers.** `License.used_seats` counts
   seat assignments of one license. The number of seats an application is
   using is the count of its application roles
   (`approle.Service.ListForOrganization(org, application)`). Interfaces
   that show seat usage for an application must use the second, and the
   marketplace response is not a substitute for it.
5. **A listing that names an application is entitled through the
   marketplace, and its access is granted by application role.** For such
   a listing the seat endpoints are legacy. They keep working, so existing
   integrations are not broken, and they do not grant application access.
   For a listing with no application, seat assignments are the only
   per-person record and keep their present behavior.

## Consequences

- **ADR-007's text is wrong on one point and this ADR corrects it**, so the
  record matches the architecture pages and the code. ADR-007's status line
  gains "decision 8 amended by ADR-014" when this ADR is accepted.
- **No code changes.** The behavior this ADR records is the behavior of
  the code; the TRD's derived-view plan is withdrawn.
- **A deployment can show a principal with a role and no seat assignment**,
  or the reverse, and both are valid states. Support and billing tooling
  should not treat a mismatch as an error.
- **Two ways to give someone a seat remain** for listings that name an
  application. This is the cost of keeping the marketplace's licensing
  record intact, and it is accepted until decision 5's open question is
  settled.

## Alternatives considered

- **Derive seat assignments from application roles**, as the TRD planned.
  Rejected: it cannot cover a listing with no application, loses the
  per-license attribution that a customer with several licenses of one
  product needs, and breaks the marketplace seat API for no gain in
  access control.
- **Make application roles require a seat assignment.** Rejected: it makes
  the licensing record an access gate, so changing a license changes
  access invisibly, and it forces a seat per person even for applications
  the deployment grants to everyone.
- **Remove seat assignments and keep only application roles.** Rejected
  for the same reason as deriving them; it also drops the `seat_holder`
  relation that the relationship-based provider reads for license `use`.

## Open questions

- Whether the seat endpoints should refuse, or be marked deprecated in the
  API schema, for a listing that names an application, so there is one way
  to give a person a seat of such an application.
- Whether a seat-based license that names an application should report
  `used_seats` from application roles instead of seat assignments, which
  would make decision 4's two numbers one for that case.
