# ROADMAP — SystemForge Learner Accounts — Optional Email, QR Login, Guardian and Educator Relationships

**Initiative:** `INIT-SYSTEMFORGE-007`
**Repository:** `github.com/plexusone/systemforge`

Design of record: [ADR-005](../../adrs/ADR-005-managed-principals-and-manager-relationships.md).
Email stays required by default; managed principals are an opt-in state that
always has a manager with an email. Builds on INIT-SYSTEMFORGE-008. Commits
implementing an item carry `Refs: RMI-SYSTEMFORGE-<NNN>`.

## Phase 1 — Model and Invariants

**Theme:** A human without an email is a managed principal with a manager

- [x] `RMI-SYSTEMFORGE-102` Optional `Human.email` and identifier rule: nullable unique email, `identifier` = email or `human:<id>`, `HumanPrincipal.Email` optional, null-uniqueness verified on the target database
  - Depends on: `RMI-SYSTEMFORGE-099`
- [x] `RMI-SYSTEMFORGE-103` Enablement switches: the OAuth client's `managed_principals_enabled` and the `managed_principals.enabled` deployment setting, both default off
  - Depends on: `RMI-SYSTEMFORGE-102`
- [x] `RMI-SYSTEMFORGE-104` `ManagerRelationship` schema and `identity/managedprincipal` service: transactional create with required manager, built-in `guardian`/`educator` roles, last-manager refusal, manager validation, audit
  - Depends on: `RMI-SYSTEMFORGE-103`

## Phase 2 — Sign-in and Control

**Theme:** Manager-issued tokens with the mitigations that make them safe

- [x] `RMI-SYSTEMFORGE-105` `login_token` credential type: issue, constant-time verify, revoke, expiry, single-use option; lifetime resolved from request, then per-application `login_token_ttl`, then 30-day platform default, under a platform ceiling
  - Depends on: `RMI-SYSTEMFORGE-104`
- [x] `RMI-SYSTEMFORGE-106` SystemAuth token exchange: endpoint with identical failure responses and rate limiting, `managed` claim, conditional `email` claims in ID token and `userinfo`
  - Depends on: `RMI-SYSTEMFORGE-105`
- [x] `RMI-SYSTEMFORGE-107` Base authorization relations: `guardian` and `educator` on `principal` with `manage_account`, `manage_credentials`, `view_profile`, `manage_managers`; synced from `ManagerRelationship` for both providers
  - Depends on: `RMI-SYSTEMFORGE-104`
- [x] `RMI-SYSTEMFORGE-108` Manager visibility: list and revoke a managed principal's login tokens and active sessions, authorized through `manage_credentials`
  - Depends on: `RMI-SYSTEMFORGE-106`
  - Depends on: `RMI-SYSTEMFORGE-107`

## Phase 3 — Surfaces and Release

**Theme:** Every surface handles a missing email; release

- [x] `RMI-SYSTEMFORGE-109` Email-assuming path audit: social login, invite, signup, SCIM, relying-party views, `session/jwt`, `contract` types, marketplace purchaser check
  - Depends on: `RMI-SYSTEMFORGE-102`
- [x] `RMI-SYSTEMFORGE-110` Claim and attach-email flows: `educator`/`guardian`-issued single-use claim redeemed by an emailed human to become `guardian`; attach a verified email to a managed principal and restore default capabilities
  - Depends on: `RMI-SYSTEMFORGE-104`
  - Depends on: `RMI-SYSTEMFORGE-105`
- [ ] `RMI-SYSTEMFORGE-111` Documentation and release: `docs/identity/managed-principals.md`, updates to users, security, and authorization conventions docs; changelog; tag v0.14.0, released together with INIT-SYSTEMFORGE-008; record the release
  - Depends on: `RMI-SYSTEMFORGE-108`
  - Depends on: `RMI-SYSTEMFORGE-109`
  - Depends on: `RMI-SYSTEMFORGE-110`
