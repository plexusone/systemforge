# ROADMAP — Post-Cutover Identity Follow-Ups

**Initiative:** `INIT-SYSTEMFORGE-009`
**Repository:** `github.com/plexusone/systemforge`

Fixes and hygiene found while retiring the legacy User model
(INIT-SYSTEMFORGE-008, ADR-004). The RFC 7523 JWT-bearer grant is tracked
as its own feature initiative. Commits implementing an item carry
`Refs: RMI-SYSTEMFORGE-<NNN>`.

## Phase 1 — Correctness

**Theme:** Behavior that is wrong or inconsistent today

- [ ] `RMI-SYSTEMFORGE-112` Fix `identity/oauth.NewProvider`, which panics on construction because its storage does not implement `fosite.Storage` (`ClientAssertionJWTValid` is missing); add a construction test
- [ ] `RMI-SYSTEMFORGE-113` Rename the Core-era default BFF session cookie `cf_session` to `sf_session`, with a release note that existing sessions sign in again
- [ ] `RMI-SYSTEMFORGE-114` Membership listing excludes inactive memberships by default, with an option to include them, matching the SCIM store
- [ ] `RMI-SYSTEMFORGE-115` Opt-in configuration to treat SCIM-provisioned emails as verified, default off, so a later social login can link automatically when a deployment trusts its identity provider

## Phase 2 — Integrity and Model Hygiene

**Theme:** Close the remaining gaps the cutover left

- [ ] `RMI-SYSTEMFORGE-116` PostgreSQL case-insensitive unique index on `sf_humans` email, created by the migrate step with the dialect passed in, so concurrent creates cannot race past the transactional check
- [ ] `RMI-SYSTEMFORGE-117` Retire or realign the legacy-shaped mixins in `identity/ent/mixin` (`UserBase`, `MembershipBase`, `OAuthAccountMixin`, `RefreshTokenMixin`, and `HumanMixin` fields absent from `sf_humans`) after inventorying their consumers
  - Depends on: `RMI-SYSTEMFORGE-114`
