# ADR-001: Core-era Naming Cleanup — SystemAuth, `sf_` Prefix, Unified Principal-Link Field

**Status:** Accepted
**Deciders:** @grokify
**Relates to:** INIT-SYSTEMFORGE-002 (module-path migration — this finishes the
rename it began) and INIT-SYSTEMFORGE-004 (the RMIs that execute this). Sequenced
before any downstream identity integration wires against the auth server.

## Context

SystemForge was renamed from **CoreForge**. The module-path migration
(INIT-SYSTEMFORGE-002, v0.10.0) moved the import path but left the Core-era
*names* in place. They are now internally inconsistent, and the inconsistency
has propagated to downstream consumers of the identity contract:

- **Two Core-era names for the auth server inside this repo:** ~165 `coreauth`
  references (the `identity/coreauth` package, `cmd/coreauth` binary,
  `docs/coreauth`, `site/coreauth`, the `system@coreauth.local` bootstrap user,
  the `coreauth-1` JWKS key id) and ~103 `corecontrol` references — two names
  for one server.
- **A `cf_` table prefix** on all 26 identity tables, declared per-schema as
  `entsql.Annotation{Table: "cf_..."}` in `identity/ent/schema/*.go`, plus the
  Ent-generated FK/edge identifiers derived from them.
- **A `cf_live_` / `cf_test_` API-key visible prefix**
  (`identity/ent/mixin/api_key.go`) — user-facing in every issued key.
- **A divergent cross-app link field.** The foreign key that links a downstream
  consumer's local principal to the SystemForge identity is spelled two
  different ways across consumers — `core_control_principal_id` and
  `core_auth_principal_id` — each baked into that consumer's generated Ent code
  and DB columns. This is the cross-service identity contract, currently spelled
  inconsistently.
- **`sf_` is already partially adopted** — the login cookie is `__Host-sf_login`
  and `SF_TEST_SECRET` exists — so the migration is half-started and
  inconsistent.

**Why now.** No consumer application has shipped yet. The cheapest time to
standardize identity naming is before the first production schema and the first
externally-held API keys ossify it. Deferring turns a coordinated dev-only
rename into a customer-facing migration with a mandatory deprecation window. This
is the one window in which a hard cutover is possible.

## Decision

Standardize on **`SystemAuth`** for the auth server and **`sf_`** for physical
identifiers, retiring `coreauth`, `corecontrol`, and `cf_` entirely.

### Names

- **Service:** `coreauth` → `systemauth`. Package `identity/coreauth` →
  `identity/systemauth`; binary `cmd/coreauth` → `cmd/systemauth`; docs/site
  paths; bootstrap user `system@coreauth.local` → `system@systemauth.local`;
  JWKS key id `coreauth-1` → `systemauth-1`. The parallel `corecontrol` name is
  removed in favor of `systemauth`.
  - *Open sub-choice:* the terser `identity/auth` + `cmd/sfauth` is viable since
    the server is already namespaced under `systemforge`. `SystemAuth` is chosen
    as the primary for a clear, brandable IdP name that parallels SystemForge;
    recorded here so the alternative is not silently lost.
- **Tables:** `cf_*` → `sf_*` (all 26), via the `entsql.Annotation` table names;
  regenerate Ent so edge/FK identifiers follow.
- **API-key prefix:** `cf_live_` / `cf_test_` → `sf_live_` / `sf_test_`.
- **Cross-app principal-link field:** one canonical name, **`sf_principal_id`**,
  defined once (in the shared mixin / integration contract) and adopted by every
  downstream consumer, replacing both `core_control_principal_id` and
  `core_auth_principal_id`. *(This is the highest-value item — it is the
  cross-service contract, not cosmetics.)*
- **Env vars:** `COREAUTH_*` / `CORECONTROL_*` → `SYSTEMAUTH_*`.

### Execution

- **Hard cutover, no deprecation window.** Because no consumer has shipped, the
  rename is a coordinated breaking change with no dual-name compatibility layer.
  This is the single advantage of doing it now and the reason not to defer.
- **Cross-repo, same pass.** The auth server and its downstream consumers
  converge on the new names in one initiative (INIT-SYSTEMFORGE-004) so nothing
  is left on a Core-era name.
- **Version:** tag a breaking minor, **v0.11.0**, documented as breaking (pre-1.0
  semver), matching how v0.10.0 carried the module-path migration.
- **Downstream consumers adopt the final names from the outset** — they sequence
  their identity wiring after this lands and never carry the old names.

## Consequences

- A breaking release; downstream consumers update in lockstep within
  INIT-SYSTEMFORGE-004. Dev databases get a one-time rename migration
  (`ALTER TABLE ... RENAME`, column rename for the link field); no production
  data exists to migrate.
- Ent must be regenerated in this repo and in each consumer that embeds the
  identity schema, since table/column names change generated identifiers.
- A CI guard is added (a repo grep gate) failing on any new
  `cf_` / `coreauth` / `corecontrol` / `core_control` / `core_auth` occurrence,
  so the old names cannot creep back.
- Documentation, config examples, and the OIDC/JWKS discovery metadata that
  reference the server name are updated together.

## References

- INIT-SYSTEMFORGE-002 ROADMAP (module-path migration this completes).
- INIT-SYSTEMFORGE-004 ROADMAP (execution RMIs).
- Affected surfaces: `identity/coreauth`, `cmd/coreauth`, `identity/ent/schema/*`
  (`cf_*` annotations), `identity/ent/mixin/api_key.go` (`cf_live_`/`cf_test_`),
  and the divergent consumer link fields `core_control_principal_id` /
  `core_auth_principal_id`.
