# ROADMAP — Core-era Naming Cleanup — SystemAuth, `sf_` Prefix, Unified Principal-Link Field

**Initiative:** `INIT-SYSTEMFORGE-004`
**Repository:** `github.com/plexusone/systemforge`

Finishes the CoreForge→SystemForge rename that the module-path migration began:
the import path moved, but the Core-era *names* remained (`cf_` table prefix,
`coreauth`/`corecontrol` service names, and a split principal-link field). This
initiative retires them for `SystemAuth` / `sf_` / `sf_principal_id`. Full
rationale and per-item scope are in ADR-001; RMI titles below are summaries.

Because no consumer has shipped, this is a **hard cutover** — no dual-name
compatibility window. Downstream consumers adopt the new names as a coordinated
follow-on; those items are tracked in the initiative and intentionally not
enumerated in this repo.

## Phase 1 — SystemForge Core

**Theme:** Retire `coreauth`/`corecontrol`/`cf_` in the platform repo; tag breaking

- [ ] `RMI-SYSTEMFORGE-069` Rename service coreauth→systemauth and retire corecontrol (package, binary, bootstrap user, JWKS key id, env vars, OIDC metadata)
- [ ] `RMI-SYSTEMFORGE-070` Rename table prefix cf_→sf_ across all 26 identity schemas; regenerate Ent; provide dev-DB rename migration
  - Depends on: `RMI-SYSTEMFORGE-069`
- [ ] `RMI-SYSTEMFORGE-071` Rename API-key visible prefix cf_live_/cf_test_→sf_live_/sf_test_; update parsing and examples
  - Depends on: `RMI-SYSTEMFORGE-070`
- [ ] `RMI-SYSTEMFORGE-072` Unify cross-app principal-link field as sf_principal_id in the shared mixin/contract (replaces core_control/core_auth)
  - Depends on: `RMI-SYSTEMFORGE-069`
- [ ] `RMI-SYSTEMFORGE-073` Tag breaking release v0.11.0 with BREAKING CHANGE note; update README migration note and config examples
  - Depends on: `RMI-SYSTEMFORGE-070`
  - Depends on: `RMI-SYSTEMFORGE-071`
  - Depends on: `RMI-SYSTEMFORGE-072`

## Phase 2 — Consumer Convergence

**Theme:** Every downstream consumer onto `SystemAuth` / `sf_` / `sf_principal_id`

Downstream consumers adopt the new schema prefix, service name, and the unified
`sf_principal_id` link field, then bump to v0.11.0. These per-consumer items are
tracked in the initiative and intentionally not enumerated here.

## Phase 3 — Verify & Lock

**Theme:** Prove convergence; prevent regression

- [ ] `RMI-SYSTEMFORGE-074` CI grep gate blocking cf_/coreauth/corecontrol/core_control/core_auth; cross-consumer sf_principal_id conformance check
  - Depends on: `RMI-SYSTEMFORGE-073`
