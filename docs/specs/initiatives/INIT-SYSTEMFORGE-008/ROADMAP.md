# ROADMAP — Retire Legacy User — Principal as the Sole Identity Root

**Initiative:** `INIT-SYSTEMFORGE-008`
**Repository:** `github.com/plexusone/systemforge`

Design of record: [ADR-004](../../adrs/ADR-004-retire-legacy-user-principal-sole-identity-root.md).
Hard cutover, no compatibility window; tagged as breaking v0.14.0. Commits
implementing an item carry `Refs: RMI-SYSTEMFORGE-<NNN>`.

## Phase 1 — SystemAuth on Principal

**Theme:** Every sign-in method resolves to one `Principal` + `Human`

- [x] `RMI-SYSTEMFORGE-093` Bootstrap owner as service principal: replace the synthetic system user with a fixed-ID `Principal(type=service)` and repoint `OAuthApp.owner` to `Principal`
- [x] `RMI-SYSTEMFORGE-094` Drop `user` edges on OAuthToken, OAuthAuthCode, and OAuthConsent; remove `legacyUserID`; subjects are principal IDs
  - Depends on: `RMI-SYSTEMFORGE-093`
  - Delivered: also moved the `identity/oauth` Fosite storage onto the `subject` column (it had dropped non-UUID subjects), and made `CreateClient` report only genuine duplicates as `ErrClientExists`.
- [x] `RMI-SYSTEMFORGE-095` SystemAuth storage on Principal/Human: merge `User` and `LoginPrincipal` into one `HumanPrincipal` DTO, rename storage methods to `*Human*`, reimplement over `Principal` + `Human` in Ent and memory storage, password login verified through `sf_credentials`
  - Depends on: `RMI-SYSTEMFORGE-094`
  - Delivered together with 096: removing the federation-ID lookup from storage left the federation handlers without a way to resolve identities, so both items landed in one change. Password login needs no new code: `credential.Service.VerifyPassword` matches the injectable verifier signature once identity IDs are principal IDs. Email uniqueness is enforced case-insensitively on writes, matching lookups.
- [x] `RMI-SYSTEMFORGE-096` Federation sync as external identities: create/update/delete resolve through `ExternalIdentity(provider, subject)`; drop `federation_id`; wire contract unchanged
  - Depends on: `RMI-SYSTEMFORGE-095`
  - Delivered: `create` adopts an existing principal with the same email and links the federation identity, so later updates and deletes resolve to it; `delete` reports synced only for an identity that was never linked.

## Phase 2 — SCIM and Service Accounts

**Theme:** Provisioning and non-human identities on the same root

- [x] `RMI-SYSTEMFORGE-097` SCIM store on principals: pin wire behavior with filter, pagination, and membership tests, then rewrite the store over `Principal`, `Human`, and `PrincipalMembership`
  - Depends on: `RMI-SYSTEMFORGE-095`
  - Delivered: the store had no tests; pinning them exposed a panic on every ascending list sort, fixed before the rewrite. The pinning suite passed unchanged against the rewrite. Intentional changes: `userName` is not case-exact (RFC 7643), deleting a group member works, and memberships honor the `active` flag. SCIM-provisioned emails are not marked verified, so social login refuses to auto-link them rather than duplicating.
- [ ] `RMI-SYSTEMFORGE-098` Service accounts: confirm the RFC 7523 path runs on `ServicePrincipal` + keypair credentials; retire `sf_service_accounts` if so, otherwise repoint `creator` to `Principal`
  - Depends on: `RMI-SYSTEMFORGE-093`

## Phase 3 — Removal and Release

**Theme:** Delete the legacy model and lock it out

- [ ] `RMI-SYSTEMFORGE-099` Remove User, Membership, OAuthAccount, RefreshToken, and APIKey schemas (plus service-account schemas per 098); regenerate Ent; add migration `0002` dropping the tables
  - Depends on: `RMI-SYSTEMFORGE-096`
  - Depends on: `RMI-SYSTEMFORGE-097`
  - Depends on: `RMI-SYSTEMFORGE-098`
- [ ] `RMI-SYSTEMFORGE-100` Documentation: rewrite `docs/identity/{users,memberships,api-keys}.md` and README identity bullets around the principal model; fix the stale `cf_memberships` reference in `rls/testing.go`
  - Depends on: `RMI-SYSTEMFORGE-099`
- [ ] `RMI-SYSTEMFORGE-101` CI grep gate for `sf_users`, `ent.User`, and removed Ent packages; changelog entry and breaking tag v0.14.0; record the release
  - Depends on: `RMI-SYSTEMFORGE-100`
