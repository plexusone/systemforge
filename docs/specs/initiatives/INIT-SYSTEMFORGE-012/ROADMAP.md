# ROADMAP — Managed Principals for Relying-Party Applications

**Initiative:** `INIT-SYSTEMFORGE-012`
**Repository:** `github.com/plexusone/systemforge`

Design of record:
[ADR-005](../../../design/adrs/ADR-005-managed-principals-and-manager-relationships.md).
SystemAuth serves the manager API that relying parties composed beside it
call with the manager's access token. Builds on INIT-SYSTEMFORGE-007.
Commits implementing an item carry `Refs: RMI-SYSTEMFORGE-<NNN>`.

## Phase 1 — SystemAuth Serves the Manager API

**Theme:** The manager is the caller and the application is the token's client

- [x] `RMI-SYSTEMFORGE-173` Bearer access with the client: `systemauth.Server.BearerAccess` and `BearerAuthenticator`, a `requestprincipal` adapter carrying the token's client, scopes, and token ID
- [x] `RMI-SYSTEMFORGE-174` Relying-party mode for the handler: client from the token, caller as sole initial manager, `GET /` listing the caller's managed principals, `POST /{id}/login-tokens`, and a per-caller rate limit on code redemption
  - Depends on: `RMI-SYSTEMFORGE-173`
- [x] `RMI-SYSTEMFORGE-175` `systemauthsvc` wiring: build the service when managed principals are enabled, mount `/managed-principals` behind the bearer authenticator, audit emitter and rate-limit options, `Service.ManagedPrincipals()`, and an end-to-end test through `POST /login-token`
  - Depends on: `RMI-SYSTEMFORGE-174`

## Phase 2 — Client and Documentation

**Theme:** Relying parties call the API through a typed client

- [x] `RMI-SYSTEMFORGE-176` `identity/managedprincipal/mpclient`: typed client over `http.Client` and a base URL, taking the manager's access token, with typed errors
  - Depends on: `RMI-SYSTEMFORGE-175`
- [x] `RMI-SYSTEMFORGE-177` Documentation: the HTTP API, scope, and `systemauthsvc` configuration in `docs/identity/managed-principals.md`; changelog
  - Depends on: `RMI-SYSTEMFORGE-176`
