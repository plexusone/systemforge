# TRD — Retire Legacy User — Principal as the Sole Identity Root

**Initiative:** `INIT-SYSTEMFORGE-008`
**Design of record:** [ADR-004](../../../design/adrs/ADR-004-retire-legacy-user-principal-sole-identity-root.md)

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
`Principal`/`Human`-backed ones, and collapse the package's two human DTOs
into one:

- `systemauth.User` (`federation_handlers.go`; used by storage, password
  login, federation sync) and `systemauth.LoginPrincipal`
  (`social_directory.go`; used by social login) become a single
  **`HumanPrincipal`** value type: `ID`, `Email`, `EmailVerified`,
  `DisplayName`, `GivenName`, `FamilyName`, `AvatarURL`, `Locale`, `Active`,
  `Metadata`. The `Federated` / `FederationID` fields are dropped; federation
  is an `ExternalIdentity` like any other provider.
- Storage methods are renamed with the type: `CreateHuman`, `GetHuman(id)`,
  `GetHumanByEmail`, `GetHumanByExternalIdentity(provider, subject)`,
  `UpdateHuman`, `DeleteHuman`.

Implementations:

- `GetHumanByEmail` → query `Human` by `EmailEqualFold`, join `Principal`.
- `GetHuman(id)` → `Principal.Get` with `human` edge; non-human principals
  return not-found.
- `CreateHuman` → create `Principal(type=human, identifier=email,
  display_name)` + `Human(email, ...)` in one transaction, mirroring what
  `social_directory_ent.go` does today; social login then calls the same
  helper instead of its own.
- `UpdateHuman` / `DeleteHuman` → update `Principal.active` and `Human`
  fields; delete cascades through the principal.
- `GetHumanByExternalIdentity` → query `ExternalIdentity` by
  `(provider, subject)` and return its principal.
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

Rewrite `identity/scim/store/ent.go`. The group side is already on the
target model and does not change:

- **Groups ↔ `Organization`** (by ID, slug, display name, external ID),
  exactly as today.
- **Members ↔ `PrincipalMembership`** replacing `Membership`:
  `AddMemberToGroup` creates `PrincipalMembership(principal_id,
  organization_id, role = config.DefaultRole)` with the same idempotent
  no-op when it exists; `RemoveMemberFromGroup` deletes by
  `(principal_id, organization_id)`; group member listing reads
  `PrincipalMembership` instead of `Membership`.
- **Users ↔ `Principal(type=human)` + `Human`.** SCIM `userName`/`emails`
  map to `Human.email`; `active` to `Principal.active`; `name` to
  `given_name`/`family_name`/`display_name`. User create goes through the
  shared `CreateHuman` helper from §1.
- Filtering and pagination run on the `Human`/`Principal` query with the same
  SCIM filter semantics the existing tests encode.

So the rewrite is a `Membership` → `PrincipalMembership` substitution plus
re-targeting the user CRUD; no SCIM resource changes meaning.

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
- Rewrite `docs/identity/api-keys.md` to state that the `identity/apikey`
  interface is backed by `sf_credentials` type `api_key`, with the
  `identity/credential` service as the reference implementation; note the
  removal of `sf_api_keys` in the v0.14.0 release notes as a consumer-facing
  change.

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
