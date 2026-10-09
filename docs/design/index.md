# Design

Design documentation for SystemForge lives in two folders with different
rules.

| Folder | Holds | Rule |
|---|---|---|
| [`architecture/`](architecture/organizations.md) | How the system is: one page per area, describing the implementation as it stands, with a "Planned changes" section for accepted decisions not yet built | Edited in place; a page is rewritten as the code changes |
| [`adrs/`](adrs/index.md) | Why it is that way: architecture decision records with their context and consequences | Append-only; a later ADR amends or supersedes an earlier one and says so, and the earlier one is never rewritten |

An architecture page lists the ADRs that decide its area in a
**Decisions** line. When an ADR is implemented, the page's "Planned
changes" entry moves up into the page body and the ADR is unchanged.

## Architecture

| Page | Scope |
|---|---|
| [Organizations and Membership](architecture/organizations.md) | Organization types, memberships and roles, invites, ownership transfer, slugs, why there is no `plan`, marketplace entitlements, how relying parties get memberships, claims, token freshness |
| [Managed Principals and Manager Relationships](architecture/managed-principals.md) | Managed principals, invariants, guardian and educator roles, login tokens and their exchange, claims, sessions and manager visibility, attaching an email |
| [Authorization](architecture/authorization.md) | The two-gate model, application vocabularies, the base schema, the role-based and relationship-based providers and what each can answer, conformance, syncing |

## Decisions

[Architecture Decision Records](adrs/index.md) lists every ADR with its
status.
