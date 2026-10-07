# PRD — Retire Legacy User — Principal as the Sole Identity Root

**Initiative:** `INIT-SYSTEMFORGE-008`
**Status:** Draft
**Home repo:** `github.com/plexusone/systemforge`
**Design of record:** [ADR-004](../../adrs/ADR-004-retire-legacy-user-principal-sole-identity-root.md)

## Problem

SystemForge has two tables that each claim to be "the human user":
`sf_users` (legacy `User`) and `sf_principals` + `sf_humans` (`Principal`
with the `Human` extension). The platform was designed to converge on
`Principal` as the single root for humans, applications, agents, and
services, and most code has moved. The remainder is small but sits on the
most important paths:

- Password login and the SystemAuth user store read `sf_users`.
- Social login writes `sf_principals` and never reads `sf_users`.
- SCIM provisioning writes `sf_users` and `sf_memberships`.
- The bootstrap creates a synthetic human in `sf_users` to own OAuth clients.

The result is that the same email address can exist as two unrelated
identities depending on how the person first arrived, and features that look
up "the human with this email" disagree with each other. This is a defect
that will surface the first time a real organization mixes sign-in methods,
which is the normal case for any school, team, or family.

No consumer application has shipped against these tables, and the first
launches are near. This is the last point at which the fix is a schema
deletion rather than a production data migration.

## Goals

1. **One identity record per human.** Every sign-in method (password, social,
   federation sync, SCIM) resolves to the same `Principal` + `Human`.
2. **Remove `sf_users` and the tables that exist only to support it**, with
   no compatibility layer.
3. **Ship a breaking release (v0.14.0)** before any consumer depends on the
   legacy tables.
4. **Leave INIT-SYSTEMFORGE-007 (learner accounts) a single model to extend.**

## Non-Goals

- Making email optional, QR login, or guardian/educator relationships. Those
  are INIT-SYSTEMFORGE-007 and depend on this initiative.
- Changing the `identity/apikey` interface that applications implement.
- Changing the authorization vocabulary or SpiceDB schema
  (INIT-SYSTEMFORGE-001).
- Any production data migration; none exists.

## Users and Stakeholders

| Who | Impact |
|---|---|
| Application developers on SystemForge | One identity API; `identity/ent/user` and `identity/ent/membership` disappear and code importing them fails to compile |
| SystemAuth operators | Bootstrap owner becomes a service principal; dev databases run one drop migration |
| Identity-provider admins using SCIM | Provisioned users are principals, visible to every other sign-in method |
| INIT-SYSTEMFORGE-007 | Unblocked; single table to make email optional on |

## Requirements

### Functional

- **F1.** Password login looks up the human by `Human.email` and verifies
  against a `sf_credentials` row of type `password`.
- **F2.** The federation identity-sync API (create/update/delete by
  federation ID) operates on `Principal` + `Human`, recording the federation
  as an `ExternalIdentity` (provider + subject). Its request and response
  contract in `contract/` is unchanged.
- **F3.** SCIM user and group/membership operations run on `Principal`,
  `Human`, and `PrincipalMembership` with the same SCIM wire behavior as
  today, including filtering and pagination.
- **F4.** Statically configured OAuth clients are owned by a
  `Principal(type=service)`; `OAuthApp.owner` references `Principal`.
- **F5.** OAuth tokens, authorization codes, and consents carry the subject
  as a principal ID and have no `user` edge.
- **F6.** The `User`, `Membership`, `OAuthAccount`, `RefreshToken`, and
  `APIKey` Ent schemas and their tables are removed. `ServiceAccount` and
  `ServiceAccountKeyPair` are removed if the RFC 7523 path is confirmed to
  run on `ServicePrincipal` plus keypair credentials; otherwise their creator
  edge is repointed to `Principal`.
- **F7.** A migration drops the retired tables.
- **F8.** A CI gate fails on new references to `sf_users`, `ent.User`,
  `identity/ent/user`, `identity/ent/membership`, or `cf_`.

### Non-Functional

- **N1.** Hard cutover: no dual-write, no shim, no deprecation period.
- **N2.** All existing tests pass or are rewritten against the new model; the
  two test files that touch legacy `User` are updated, not deleted.
- **N3.** `golangci-lint` reports no findings.
- **N4.** Documentation under `docs/identity/` describes only the surviving
  model.

## Success Criteria

- A human who signs in with Google and then sets a password, or who is
  SCIM-provisioned and then signs in with Google, has exactly one principal.
- `grep -r 'sf_users\|ent\.User\b' --include='*.go' .` returns nothing
  outside the CI gate itself.
- v0.14.0 is tagged with a BREAKING CHANGE note and CI green.
- INIT-SYSTEMFORGE-007 can begin against one table.

## Risks

| Risk | Mitigation |
|---|---|
| A code path that reads `sf_users` is missed | The CI gate plus Ent regeneration make any remaining import a compile error |
| SCIM wire behavior drifts during the rewrite | Keep the existing SCIM tests as the contract; add cases for filtering and memberships before rewriting |
| RFC 7523 service accounts turn out to depend on `sf_service_accounts` | Confirm the path first; if it does, repoint the creator edge and defer table removal to a follow-on rather than block the release |
| Downstream code imports a removed Ent package | Intended: it fails at compile time; downstream products link through `relyingparty` and were verified not to read the legacy tables |

## Open Questions

- Does the service-account JWT-bearer flow already run on `ServicePrincipal`
  + keypair credentials, or on `sf_service_accounts`? Decides the scope of F6.
- Should the bootstrap service principal's identifier be fixed (as the system
  user's UUID was) so repeated bootstraps are idempotent across instances?
  Default: yes, keep a fixed well-known ID.
