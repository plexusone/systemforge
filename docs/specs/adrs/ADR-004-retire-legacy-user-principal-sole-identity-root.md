# ADR-004: Retire Legacy `User` — Principal as the Sole Identity Root

**Status:** Accepted
**Deciders:** @grokify
**Relates to:** INIT-SYSTEMFORGE-004 (naming cleanup that established the
`sf_principal_id` link field), INIT-SYSTEMFORGE-008 (the RMIs that execute
this), and INIT-SYSTEMFORGE-007 (learner accounts, which is written against
the single model this decision leaves behind). Sequenced before the first
consumer application ships.

## Context

SystemForge carries two identity models for human users:

- **Legacy `User`** (`sf_users`): email, name, password hash, platform-admin
  flag, `federation_id`, with dependent tables `sf_memberships`,
  `sf_oauth_accounts`, `sf_refresh_tokens`, `sf_api_keys`, and owner/creator
  edges from `sf_oauth_apps`, `sf_oauth_tokens`, `sf_oauth_auth_codes`,
  `sf_oauth_consents`, and `sf_service_accounts`.
- **`Principal`** (`sf_principals`) with per-type extension tables
  (`sf_humans`, `sf_applications`, `sf_agents`, `sf_service_principals`), and
  dependent `sf_credentials`, `sf_external_identities`, `sf_principal_tokens`,
  `sf_principal_memberships`. `Organization.owner` already points at a
  principal.

The newer model was designed as the unified root for humans, applications,
agents, and services, and most of the codebase has moved to it. What remains
on `User` is small but load-bearing:

- **SystemAuth's own storage** (`identity/systemauth/storage_ent.go`): the
  user CRUD methods, `GetUserByEmail` (the password-login lookup),
  `GetUserByFederationID`, and a `legacyUserID` helper that populates the
  optional `user` edge on OAuth tokens when a `User` row happens to exist.
- **The system bootstrap** (`identity/systemauthsvc/database.go`): a fake
  `system@systemauth.local` user in `sf_users` that owns statically configured
  OAuth clients, because `OAuthApp.owner` points at `User`.
- **The SCIM store** (`identity/scim/store/ent.go`): all user and membership
  provisioning on `User` + `Membership`.
- **The federation identity-sync handlers**: create/update/delete of local
  users keyed by `federation_id`.

Meanwhile **social login** (`identity/systemauth/social_directory_ent.go`)
creates a `Principal` + `Human` and never touches `sf_users`.

**The split is a live correctness defect, not a tidiness issue.** A person who
signs in with Google exists only in `sf_principals`; password login
(`GetUserByEmail`) and SCIM cannot see them. A SCIM-provisioned person exists
only in `sf_users`; social login (`FindByVerifiedEmail`) cannot see them and
will create a second identity for the same address. Every feature that keys on
"the human with this email" gives a different answer depending on which table
it reads.

Field-by-field, `Principal` + `Human` already covers `User`: `email`,
`display_name`/`given_name`/`family_name`, `avatar_url`, `is_platform_admin`,
`active`, `last_login_at` all exist; `password_hash` is a `sf_credentials` row
of type `password` (the `identity/credential` service already implements it);
`memberships` → `principal_memberships`; `oauth_accounts` →
`external_identities`; `refresh_tokens` → `principal_tokens`; `api_keys` →
credentials of type `api_key`. The only legacy field with no column
equivalent, `federation_id`, is an upstream subject identifier and maps onto an
`ExternalIdentity` row (`provider` = the federation, `subject` = the federation
ID). No new field is required.

Four legacy tables have **no live callers** in this repository:
`sf_oauth_accounts`, `sf_refresh_tokens`, `sf_api_keys` (the `identity/apikey`
package is an interface that applications implement over their own store),
and `sf_service_accounts` with its key pairs. `sf_memberships` is read only by
the SCIM store. Only two test files exercise the legacy `User` paths.

**Why now.** No consumer application has shipped against these tables.
Downstream products that hold their own user records link to SystemAuth
through `relyingparty` and `sf_principal_id`, not by reading `sf_users`. The
first launches are imminent; after them, every one of these tables acquires
production rows and this becomes a data migration with a compatibility window
instead of a schema deletion.

## Decision

**`Principal` is the sole identity root.** Humans are `Principal(type=human)`
+ `Human`. The legacy `User` entity and every table that exists only to
support it are removed, with no dual-model compatibility layer.

### Model

- **Identity:** `sf_principals` + `sf_humans`. The human's email lives in
  `Human.email` only. (INIT-SYSTEMFORGE-007 later makes it optional under
  application configuration; this ADR does not change its constraints.)
- **Passwords:** `sf_credentials` type `password`, verified through the
  `identity/credential` service. SystemAuth's password login resolves the
  identity by `Human.email` and verifies against the credential row.
- **Upstream identities:** `sf_external_identities` for social providers
  *and* for the legacy federation sync, which becomes an `ExternalIdentity`
  with the federation as provider and the federation ID as subject.
  `federation_id` is dropped from the model.
- **Memberships:** `sf_principal_memberships` everywhere, including SCIM.
- **Ownership edges:** `OAuthApp.owner`, `ServiceAccount.creator` (if the
  table is retained), and any other `→ User` edge are repointed to
  `Principal`. The OAuth token, auth-code, and consent tables carry the
  subject as a principal ID and lose their `user` edge; `legacyUserID` is
  deleted.
- **Bootstrap:** statically configured OAuth clients are owned by a
  `Principal(type=service)`, not a synthetic human user.
- **Removed schemas:** `User`, `Membership`, `OAuthAccount`, `RefreshToken`,
  `APIKey`. `ServiceAccount` and `ServiceAccountKeyPair` are removed as well
  if the RFC 7523 service-account path is confirmed to run on
  `ServicePrincipal` + keypair credentials; otherwise their creator edge is
  repointed and their retirement becomes a follow-on.

### Execution

- **Hard cutover, no deprecation window.** As in ADR-001, this is the single
  advantage of doing it before anything ships, and the reason not to defer.
- **One initiative.** INIT-SYSTEMFORGE-008 converges SystemAuth storage, the
  bootstrap, federation sync, SCIM, schema removal, migration, docs, and the
  CI guard in one pass, so no half-state is tagged.
- **Version:** a breaking minor, **v0.14.0**, documented as breaking (pre-1.0
  semver), matching how v0.10.0 and v0.11.0 carried earlier cutovers.
- **Dev databases** get a one-time migration (`0002`) that drops the retired
  tables. No production data exists to migrate.

## Consequences

- SystemAuth, SCIM, and social login all read and write the same human
  record; the duplicate-identity defect disappears by construction.
- INIT-SYSTEMFORGE-007 (learner accounts) touches one table and one set of
  code paths when it makes email optional and adds the QR credential and
  guardian/educator relationships, instead of auditing two models.
- Ent is regenerated; generated identifiers for the removed entities
  disappear, and any out-of-tree code importing
  `identity/ent/user` or `identity/ent/membership` breaks loudly at compile
  time, which is the intended failure mode.
- `docs/identity/users.md`, `memberships.md`, and `api-keys.md` are rewritten
  around `Principal`/`Human`/`PrincipalMembership`/`Credential`. The stale
  `cf_memberships` reference in `rls/testing.go` is fixed in passing.
- A CI grep gate fails on any new reference to `sf_users`, `ent.User`,
  `cf_`, or the removed Ent packages so the legacy model cannot creep back.
- The `identity/apikey` package's interface contract is unchanged;
  applications keep implementing it over their own store.

## References

- INIT-SYSTEMFORGE-008 ROADMAP (execution RMIs).
- INIT-SYSTEMFORGE-004 ROADMAP and ADR-001 (prior hard cutover; `sf_` prefix
  and `sf_principal_id`).
- INIT-SYSTEMFORGE-007 (learner accounts; depends on this).
- Affected surfaces: `identity/ent/schema/{user,membership,oauth_account,
  refresh_token,api_key,oauth_app,oauth_token,oauth_auth_code,oauth_consent,
  service_account,service_account_key_pair}.go`,
  `identity/systemauth/{storage.go,storage_ent.go,storage_memory.go,
  federation_handlers.go,provider_identity.go}`,
  `identity/systemauthsvc/{database.go,service.go}`,
  `identity/scim/store/ent.go`, `rls/testing.go`, `docs/identity/*`.
