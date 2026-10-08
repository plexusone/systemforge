# Architecture Decision Records

Decisions about how SystemForge behaves, each with its context and
consequences. ADRs are long-lived: a later ADR may amend or supersede an
earlier one, and says so. Initiative specs (PRD, TRD, PLAN, ROADMAP) live
under `docs/specs/` and execute these decisions.

| ADR | Decision | Status |
|---|---|---|
| [ADR-001](ADR-001-core-era-naming-cleanup-systemauth.md) | Core-era Naming Cleanup — SystemAuth, `sf_` Prefix, Unified Principal-Link Field | Accepted |
| [ADR-002](ADR-002-centralized-social-login-systemauth.md) | Centralized Social Login (GitHub/Google) via SystemAuth | Accepted |
| [ADR-003](ADR-003-verified-email-via-systemauth-and-omnimail.md) | Verified Email in SystemAuth, Delivered Through omnimail | Accepted |
| [ADR-004](ADR-004-retire-legacy-user-principal-sole-identity-root.md) | Retire Legacy `User` — Principal as the Sole Identity Root | Accepted |
| [ADR-005](ADR-005-managed-principals-and-manager-relationships.md) | Managed Principals and Manager Relationships | Accepted, amended by ADR-009 |
| [ADR-006](ADR-006-organization-lifecycle-personal-team-slugs.md) | Organization Lifecycle — Signup, Personal and Team Organizations, Slugs | Proposed |
| [ADR-007](ADR-007-memberships-and-entitlements-as-claims.md) | Organization Memberships and Entitlements as Claims | Accepted |
| [ADR-008](ADR-008-resource-scoped-collaborators.md) | Resource-Scoped Collaborators on the Authorization Substrate | Accepted |
| [ADR-009](ADR-009-management-is-a-relationship.md) | Management Is a Relationship, Not the Absence of an Email (amends ADR-005) | Accepted |

## Statuses

- **Proposed:** written and under review.
- **Accepted:** decided; implementation follows or is complete.
- **Deferred:** recorded so other decisions do not rule it out; not scheduled.
- **Superseded:** replaced by a later ADR, which it links to.
