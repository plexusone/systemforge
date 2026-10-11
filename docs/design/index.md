# Design

Design documentation for SystemForge lives in two folders with different
rules.

| Folder | Holds | Rule |
|---|---|---|
| [`architecture/`](architecture/organizations.md) | How the system is: one page per area, describing the implementation as it stands | Edited in place; a page is rewritten as the code changes |
| [`adrs/`](adrs/index.md) | Why it is that way: architecture decision records with their context and consequences | Append-only; a later ADR amends or supersedes an earlier one and says so, and the earlier one is never rewritten |

An architecture page lists the ADRs that decide its area in a
**Decisions** line. When an ADR is implemented, the page is edited to
describe the implementation and the ADR is unchanged.

## Architecture

| Page | Scope |
|---|---|
| [Organizations and Membership](architecture/organizations.md) | Organization types, memberships and roles, invites, ownership transfer, slugs, why there is no `plan`, application roles, marketplace entitlements, how relying parties get memberships, claims, token freshness |
| [Managed Principals and Manager Relationships](architecture/managed-principals.md) | Managed principals, invariants, guardian and educator roles, login tokens and their exchange, claims, sessions and manager visibility, attaching an email |
| [Authorization](architecture/authorization.md) | The two-gate model, application vocabularies, the base schema, the role-based and relationship-based providers and what each can answer, conformance, syncing |

## Decisions

[Architecture Decision Records](adrs/index.md) lists every ADR with its
status. ADR-001 to ADR-010 are Accepted; the architecture pages above
describe their implementation.

### Proposed

These ADRs are drafts under review. They are design proposals only: nothing
in them is implemented, and the architecture pages and release notes do not
describe them as features.

| ADR | Proposal |
|---|---|
| [ADR-011](adrs/ADR-011-lifecycle-states-data-classification-and-privacy-rights.md) | Lifecycle states, data classification and privacy rights (would amend ADR-009) |
| [ADR-012](adrs/ADR-012-data-governance-enforcement-and-legal-hold.md) | Data governance catalog, legal holds and enforcement |
| [ADR-013](adrs/ADR-013-key-management.md) | Key management |

## Guides

How-to guides for the implemented behavior are under
[Guides](../guides/invites.md): invites, application roles and entitlements,
collaborators and resource grants, organization slugs, personal-to-team
conversion, access-change invalidation and the authorization mode.
