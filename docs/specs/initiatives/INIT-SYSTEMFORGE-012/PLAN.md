# PLAN — Managed Principals for Relying-Party Applications

**Initiative:** `INIT-SYSTEMFORGE-012`

## Entry Gate

- INIT-SYSTEMFORGE-007 released: managed principals, login tokens, manager
  relationships, claims, and invitations.
- Attaching a verified email stays in process until SystemAuth verifies
  email itself (INIT-SYSTEMFORGE-006).

## Build Order

### Phase 1 — SystemAuth Serves the Manager API

Add bearer access that carries the token's client and adapt it to
`requestprincipal`; give the handler a relying-party mode, the two missing
routes, and a code rate limit; build and mount the service in
`systemauthsvc`. Exit: a host that enables managed principals serves the API,
and an end-to-end test creates a managed principal with a manager's token and
signs it in through `POST /login-token`.

### Phase 2 — Client and Documentation

Ship the typed client and document the API and its configuration. Exit: the
client covers every route, and the managed-principals guide shows a relying
party in another process using it.

## Risks and Mitigations

- **Behavior change for in-process handler users:** none. Relying-party mode
  is an option; existing `NewHandler(svc)` callers are unchanged.
- **Scope rollout:** clients must be granted `systemforge:managed_principals`.
  The guide shows the client configuration.

## Follow-On

- An HTTP route to attach an email once SystemAuth verifies addresses itself.
- Shared rate-limit storage for multi-instance SystemAuth deployments.
