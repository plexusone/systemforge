# PRD — SystemForge Learner Accounts — Optional Email, QR Login, Guardian and Educator Relationships

**Initiative:** `INIT-SYSTEMFORGE-007`
**Status:** Draft
**Home repo:** `github.com/plexusone/systemforge`
**Design of record:** [ADR-005](../../../design/adrs/ADR-005-managed-principals-and-manager-relationships.md)
**Depends on:** INIT-SYSTEMFORGE-008 (single `Principal` root; this initiative
touches one human model, not two)

## Problem

SystemForge requires every human to have a unique email and to hold their
own credentials. Learning applications built on it need humans who cannot:
children whose accounts are created by a parent or teacher, who sign in by
scanning a code, and whose data a responsible adult must be able to see,
revoke, and delete. Today the only options are a fake email (which corrupts
mail, SCIM, audit, and recovery flows) or an application-local table (which
gives the child no platform identity and splits authorization). Neither is
acceptable for a product that must pass a privacy review before the first
classroom uses it.

At the same time, no existing consumer wants email to become optional for
its users, and recovery, compliance, and deliverability for ordinary accounts
should not get harder.

## Goals

1. **Email stays required by default.** Nothing changes for an application
   that does not opt in.
2. **Managed principals.** An opted-in application can create a human
   without an email, provided at least one manager with an email exists.
3. **Two built-in manager roles**, `guardian` (full authority) and
   `educator` (operational authority), usable by learning and non-learning
   applications alike.
4. **Manager-issued sign-in** via a `login_token` credential that
   applications render as a QR code, printed card, or link.
5. **Manager visibility and control** over a managed principal's tokens and
   sessions.
6. **A path from managed to ordinary**: attaching a verified email later.

## Non-Goals

- Parent, child, student, or teacher concepts in SystemForge. Applications
  map those onto managed principals and manager roles.
- Recording consent, ages, or regulatory evidence. SystemForge supplies a
  manager with authority to consent; the application records that it did.
- Application permissions over a managed principal's data (progress,
  certificates, limits). Those are application facets on the base schema.
- Changing how ordinary humans sign in or recover accounts.

## Users and Stakeholders

| Who | Needs |
|---|---|
| Learning application (first consumer) | Create child accounts from a teacher or parent, issue QR logins, let a parent claim a teacher-created child, revoke and delete |
| Other SystemForge consumers | No behavior change unless they opt in; `Email` becomes optional in Go types and claims |
| SystemAuth operators | A deployment-level switch, default off; audit of who issued and revoked each token |
| Platform administrators | Ability to see manager relationships and act on a managed principal when no manager can |

## Requirements

### Functional

- **F1.** `Human.email` is optional. A human without an email is a managed
  principal with `CanManageProfile = false` and `CanDelegate = false`.
- **F2.** Managed principals can be created only when the deployment setting
  and the requesting OAuth client's `managed_principals_enabled` flag are
  both on.
- **F3.** Creating a managed principal requires at least one manager in the
  same transaction. Removing the last manager is refused; deactivation or
  deletion must be used instead.
- **F4.** A manager must be an active human with an email. Managed
  principals cannot be managers.
- **F5.** Built-in manager roles are `guardian` and `educator`, with the
  platform authority described in ADR-005. Applications may register
  additional roles through the authorization vocabulary.
- **F6.** A `login_token` credential type: manager-issued, hashed at rest,
  expiring, revocable, reusable by default with a single-use option.
  Lifetime resolves as: explicit request value, else the `Application`'s
  configured default, else the platform default (30 days); never above the
  platform ceiling. Single-use tokens default to 20 minutes.
- **F7.** SystemAuth exchanges a `login_token` for a session whose claims
  identify the subject as managed; the exchange is rate-limited and returns
  the same response for unknown, expired, and revoked tokens.
- **F8.** Managers can list a managed principal's `login_token` credentials
  and active sessions, and revoke any of them.
- **F9.** An `educator` can issue a claim that lets a human with an email
  become `guardian` of the managed principal; a `guardian` can add or remove
  other managers directly.
- **F10.** A managed principal can attach an email, verified through the
  INIT-SYSTEMFORGE-006 flow, after which it is an ordinary human and may
  hold its own credentials; existing manager relationships persist until
  removed.
- **F11.** `Principal.identifier` is the email when present, otherwise
  `human:<principal-id>`; attaching an email updates it.
- **F12.** The base SpiceDB schema gains `guardian` and `educator` relations
  on `principal` with `manage_account`, `manage_credentials`, and
  `view_profile` permissions.
- **F13.** Every path that assumed an email handles its absence: social
  login linking, invitations, signup, SCIM, `userinfo` and ID-token claims,
  relying-party principal views, and marketplace purchasing (managed
  principals cannot purchase).

### Non-Functional

- **N1.** With both flags off, existing conformance suites pass unchanged
  apart from the `Email` type change.
- **N2.** Every manager action on a managed principal (create, issue, revoke,
  add or remove manager, delete) is audited with the acting principal.
- **N3.** `golangci-lint` reports no findings.
- **N4.** Documentation describes managed principals as a platform
  primitive with a learning application as the worked example, not as a
  children's feature.

## Success Criteria

- A learning application can: create a managed principal from an `educator`
  account, issue a `login_token`, sign the managed principal in with it, have
  a `guardian` claim it, and have the `guardian` revoke the token and delete
  the principal, with each step authorized and audited.
- An application that has not opted in cannot create a human without an
  email, and its existing tests pass.
- A managed principal who attaches a verified email can then set a password
  and sign in without any manager involvement.

## Risks

| Risk | Mitigation |
|---|---|
| A reusable token is password-equivalent | Reduced capabilities on managed sessions, rate-limited exchange, expiry, manager visibility and revocation, single-use option |
| An email-assuming path is missed | F13 audit is its own roadmap item with a checklist derived from a repository-wide search; conformance suites gain no-email cases |
| Database uniqueness with null email | Verify that the target database permits multiple nulls under the unique index before changing the schema |
| Scope creep into consent and age handling | Explicit non-goal; the application owns these |

## Decisions

- **`login_token` lifetime.** The platform default is **30 days**, a
  conservative posture suited to a general SaaS identity platform.
  Applications that opt into managed principals may override it per
  `Application` (a learning application will typically choose a school
  year), bounded by a platform ceiling. Single-use tokens are short-lived by
  default (20 minutes), matching the "backup code" pattern common in
  classroom login systems. Comparable products sit between 90 days and one
  year for reusable codes and void them on an annual cycle.
- **`educator` may not delete a managed principal**, including one that
  never received a `guardian`. Deletion is a `guardian` or platform
  administrator action. Start strict; revisit only if orphaned accounts
  accumulate in practice. The intent is to keep learners in the system, not
  to make removal easy.
