# ROADMAP — Post-Cutover Identity Follow-Ups

**Initiative:** `INIT-SYSTEMFORGE-009`
**Repository:** `github.com/plexusone/systemforge`

Fixes and hygiene found while retiring the legacy User model
(INIT-SYSTEMFORGE-008, ADR-004). The RFC 7523 JWT-bearer grant is tracked
as its own feature initiative. Commits implementing an item carry
`Refs: RMI-SYSTEMFORGE-<NNN>`.

## Phase 1 — Correctness

**Theme:** Behavior that is wrong or inconsistent today

- [x] `RMI-SYSTEMFORGE-112` Fix `identity/oauth.NewProvider`, which panics on construction because its storage does not implement `fosite.Storage` (`ClientAssertionJWTValid` is missing); add a construction test
  - Delivered: storage now satisfies every Fosite interface the provider composes, enforced by compile-time assertions. Also fixed: SystemAuth recorded client-assertion JTIs as auth-code rows with a nil app ID, so private_key_jwt authentication failed and replay was never detected (now a dedicated `sf_client_assertion_jtis` store shared by both); and `identity/oauth` never recorded a token family, so revocation matched nothing.
- [x] `RMI-SYSTEMFORGE-113` Rename the Core-era default BFF session cookie `cf_session` to `sf_session`, with a release note that existing sessions sign in again
  - Delivered: a single `DefaultCookieName` constant now feeds both the cookie manager and the OpenAPI security scheme. No application hardcoded the old name. The last `cf_` table names in current docs were also corrected.
- [x] `RMI-SYSTEMFORGE-114` Membership listing excludes inactive memberships by default, with an option to include them, matching the SCIM store
  - Delivered: `IncludeInactive()` option and an `includeInactive` query parameter on the members endpoint; signup keeps reporting the stored owner membership.
- [x] `RMI-SYSTEMFORGE-115` Opt-in configuration to treat SCIM-provisioned emails as verified, default off, so a later social login can link automatically when a deployment trusts its identity provider
  - Delivered: `store.Config.TrustProvisionedEmail`. Also fixed: changing an email through SCIM kept the previous address's verification.

## Phase 2 — Integrity and Model Hygiene

**Theme:** Close the remaining gaps the cutover left

- [x] `RMI-SYSTEMFORGE-116` PostgreSQL case-insensitive unique index on `sf_humans` email, created by the migrate step with the dialect passed in, so concurrent creates cannot race past the transactional check
  - Delivered: `identity/pgschema` holds PostgreSQL-only DDL, applied by the migrate step; the dialect is recorded for configured, injected-pool, and injected-client storage. Ent's exec-query feature is enabled so an injected client can apply it.
- [x] `RMI-SYSTEMFORGE-117` Retire or realign the legacy-shaped mixins in `identity/ent/mixin` (`UserBase`, `MembershipBase`, `OAuthAccountMixin`, `RefreshTokenMixin`, and `HumanMixin` fields absent from `sf_humans`) after inventorying their consumers
  - Depends on: `RMI-SYSTEMFORGE-114`
  - Delivered: `UserBase` and `MembershipBase` had no consumers and are removed. `HumanMixin`, `OAuthAccountMixin`, and `RefreshTokenMixin` are deprecated rather than removed, because an application still builds a local identity schema from them; removal follows its move to SystemAuth.
