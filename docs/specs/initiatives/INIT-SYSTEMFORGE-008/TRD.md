# TRD — Retire Legacy User — Principal as the Sole Identity Root

**Initiative:** `INIT-SYSTEMFORGE-008`
**Design of record:** [ADR-004](../../adrs/ADR-004-retire-legacy-user-principal-sole-identity-root.md)

## Current State

### Two human models

| Concern | Legacy (`User`) | Target (`Principal` + `Human`) |
|---|---|---|
| Table | `sf_users` | `sf_principals`, `sf_humans` |
| Email | `User.email` (required, unique) | `Human.email` (required, unique) |
| Name | `name` | `Principal.display_name`, `Human.given_name`/`family_name` |
| Password | `User.password_hash` | `sf_credentials` type `password` |
| Platform admin | `is_platform_admin` | `Human.is_platform_admin` |
| Active | `active` | `Principal.active` |
| Upstream identities | `sf_oauth_accounts` | `sf_external_identities` |
| Federation link | `User.federation_id` | none (maps to an `ExternalIdentity`) |
| Memberships | `sf_memberships` | `sf_principal_memberships` |
| Refresh tokens | `sf_refresh_tokens` | `sf_principal_tokens` |
| API keys | `sf_api_keys` (owner → User) | `sf_credentials` type `api_key` |
| Org ownership | — | `Organization.owner_principal_id` (already) |

### Live dependencies on the legacy model

Non-test, non-generated code only:

| Location | What it does |
|---|---|
| `identity/systemauth/storage.go`, `storage_ent.go`, `storage_memory.go` | `CreateUser`, `GetUser`, `GetUserByEmail`, `GetUserByFederationID`, `UpdateUser`, `DeleteUser`; `legacyUserID()` sets the optional `user` edge on OAuth tokens when a `User` row exists |
| `identity/systemauth/provider_identity.go`, `provider_auth.go` | Password login: `GetIdentityByEmail` → `storage.GetUserByEmail` |
| `identity/systemauth/federation_handlers.go` | Identity sync create/update/delete keyed by `federation_id` |
| `identity/systemauthsvc/database.go`, `service.go` | `ensureSystemUser` creates `system@systemauth.local` in `sf_users` as owner of static OAuth clients; health check queries `User` |
| `identity/scim/store/ent.go` | Full SCIM store on `User` + `Membership` |
| `rls/testing.go` | Test helper inserts into `cf_memberships` (stale pre-rename name) |

Legacy schemas with **no live callers**: `OAuthAccount`, `RefreshToken`,
`APIKey`, `ServiceAccount`, `ServiceAccountKeyPair`. `Membership` is used only
by the SCIM store.

Edges from other schemas into `User`: `OAuthApp.owner`, `OAuthToken.user`,
`OAuthAuthCode.user`, `OAuthConsent.user` (all optional), `ServiceAccount.creator`.

Social login (`social_directory_ent.go`) already creates `Principal` +
`Human` + `ExternalIdentity` and is the reference implementation for the
target model.

## Design

### 1. SystemAuth storage on Principal

Replace the `User`-backed methods in `systemauth.Storage` with
`Principal`/`Human`-backed ones, keeping the `systemauth.User` value type as
the storage-layer DTO so callers in `provider_identity.go` and
`federation_handlers.go` change minimally:

- `GetUserByEmail` → query `Human` by `EmailEqualFold`, join `Principal`.
- `GetUser(id)` → `Principal.Get` with `human` edge; non-human principals are
  not users and return not-found.
- `CreateUser` → create `Principal(type=human, identifier=email,
  display_name=name)` + `Human(email, ...)` in one transaction, mirroring
  `social_directory_ent.go`.
- `UpdateUser` / `DeleteUser` → update `Principal.active` and `Human` fields;
  delete cascades through the principal.
- `GetUserByFederationID` → query `ExternalIdentity` by
  `(provider = federation, subject = id)` and return its principal.
- Remove `legacyUserID`; Fosite request subjects are principal IDs and the
  OAuth token/auth-code/consent builders no longer set a user edge.

The memory storage mirrors the same semantics.

Password verification is already injected (`WithProviderPasswordVerifier`);
the default verifier provided by `systemauthsvc` uses
`identity/credential.Service` against `sf_credentials` type `password`.

### 2. Federation sync as external identities

`federation_handlers.go` keeps its wire contract (`contract/` types are
unchanged). Internally:

- `create`: find by email via `GetUserByEmail`; if absent, `CreateUser` and
  record `ExternalIdentity{provider: <federation provider name>, subject:
  req.Identity.ID}`.
- `update` / `delete`: resolve via the external identity, then update
  `Human`/`Principal.active`.

The provider name is a constant exported from `systemauth` so the identity
can be distinguished from social providers.

### 3. Bootstrap owner is a service principal

`ensureSystemUser` becomes `ensureSystemPrincipal`: a
`Principal(type=service)` with a fixed well-known UUID and identifier
`system@systemauth.local`, plus a `ServicePrincipal` extension row.
`OAuthApp.owner` is repointed to `Principal`; the health check in
`service.go` queries `Principal`.

### 4. SCIM store on principals

Rewrite `identity/scim/store/ent.go`:

- Users ↔ `Principal(type=human)` + `Human`. SCIM `userName`/`emails` map to
  `Human.email`; `active` to `Principal.active`; `name` to
  `given_name`/`family_name`/`display_name`.
- Group membership ↔ `PrincipalMembership` (organization + role).
- Filtering and pagination run on the `Human`/`Principal` query with the same
  SCIM filter semantics the existing tests encode.

The SCIM mapper (`identity/scim/mapper`) and schema packages are unchanged
except for type references.

### 5. Service accounts

Confirm whether the RFC 7523 JWT-bearer path (`identity/token`,
`identity/oauthclient`) authenticates against `ServicePrincipal` + keypair
credentials or against `sf_service_accounts`. If the former, remove
`ServiceAccount` and `ServiceAccountKeyPair` with the other legacy schemas. If
the latter, repoint `ServiceAccount.creator` to `Principal` in this
initiative and open a follow-on to migrate the flow.

### 6. Schema removal and migration

Delete `identity/ent/schema/{user,membership,oauth_account,refresh_token,
api_key}.go` (plus service account schemas per §5), remove the corresponding
`edge.From(... User.Type)` declarations, regenerate Ent, and add
`migrations/0002_drop_legacy_user_tables.sql` dropping `sf_users`,
`sf_memberships`, `sf_oauth_accounts`, `sf_refresh_tokens`, `sf_api_keys`
(and service-account tables per §5), including their FK constraints.

### 7. Documentation and guard

- Rewrite `docs/identity/users.md`, `memberships.md`, `api-keys.md` around
  `Principal`, `Human`, `PrincipalMembership`, and `Credential`; remove the
  stale `cf_users` schema table.
- Update the README feature list (Users/Memberships/OAuth Accounts/API Keys
  bullets) to describe the principal model.
- Fix `rls/testing.go` to use `sf_principal_memberships`.
- Extend the existing CI grep gate (from INIT-SYSTEMFORGE-004) to fail on
  `sf_users`, `ent\.User\b`, `identity/ent/user"`, and
  `identity/ent/membership"`.

## Sequencing Constraints

- §1 and §3 share `storage_ent.go` and the bootstrap; land §3 first so the
  OAuth-client owner is valid before `legacyUserID` is removed.
- §4 (SCIM) depends on §1 so it can reuse the same creation helper.
- §6 can only land after §1–§5; it is the point of no return and is followed
  immediately by §7 and the tag.

## Risks

- **SCIM behavior drift.** Mitigate by expanding SCIM tests (filters,
  pagination, membership add/remove) before the rewrite and treating them as
  the contract.
- **Hidden `User` dependency in generated or reflective code** (e.g. RLS
  policies naming `sf_users`). Mitigate with the CI gate and a repo-wide grep
  for table names in SQL and Go string literals, not just Ent identifiers.
- **Service-account scope ambiguity** (§5). Resolve in the first RMI of
  Phase 2 so the schema-removal RMI has a fixed list.

## Testing Strategy

- Keep `identity/systemauth/storetest` and `identity/relyingparty/storetest`
  as conformance suites; extend them with "same email via two sign-in
  methods yields one principal" cases.
- Rewrite the two legacy `User` test files in `identity/systemauth` against
  the principal-backed storage.
- SCIM: add filter/pagination/membership cases first, then rewrite the store
  and keep them green.
- Bootstrap: test idempotent creation of the system service principal across
  two concurrent calls.
- Migration: apply `0001` then `0002` on a fresh dev database and run the
  full suite.
