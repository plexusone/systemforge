# PRD — Managed Principals for Relying-Party Applications

**Initiative:** `INIT-SYSTEMFORGE-012`
**Status:** Draft
**Home repo:** `github.com/plexusone/systemforge`
**Design of record:** [ADR-005](../../../design/adrs/ADR-005-managed-principals-and-manager-relationships.md)
**Depends on:** INIT-SYSTEMFORGE-007 (managed principals, login tokens,
manager relationships)

## Problem

Managed principals exist only in process. `managedprincipal.Service` and
`managedprincipal.NewHandler` need the SystemAuth database and a SystemAuth
server as their gate, so only code running next to SystemAuth can create a
managed principal or issue a login token.

Hosts compose SystemAuth and their products the other way round. SystemAuth
is built once by `systemauthsvc` and owns the one principals table; each
product is a relying party with its own database that refers to people by
their SystemAuth principal ID, and may run in another process. Such a
product cannot create a managed principal, add a manager, or print a login
code without reaching into SystemAuth's database, which would split the
principals table or bypass its invariants.

## Goals

1. **SystemAuth serves the manager API.** A host that enables managed
   principals in its SystemAuth configuration gets the manager-facing HTTP
   API on SystemAuth, with no code of its own.
2. **The manager is the caller.** Every request carries the signed-in
   manager's SystemAuth access token. Authority comes from that manager's
   relationships and permissions (ADR-005), never from the application.
3. **The application is the token's client.** The OAuth client that a
   create or login-token request is checked against is the one the access
   token was issued to, not one the request names.
4. **Complete for a relying party.** Create a managed principal, list the
   caller's managed principals, add and remove managers, issue login tokens,
   list and revoke tokens and sessions, revoke everything, and issue and
   redeem claims.
5. **A typed Go client** that relying parties import instead of writing
   HTTP calls.

## Non-Goals

- **Attaching a verified email over HTTP.** A relying party cannot prove
  that a principal controls an address, and a principal holding an address
  it does not control would be matched to that address's owner. Attaching an
  email waits for SystemAuth's own verification flow (INIT-SYSTEMFORGE-006);
  until then it stays an in-process operation.
- New manager roles, consent records, or age rules. Those stay with the
  application.
- A user interface. Applications render login codes and manager screens.

## Requirements

- **R1.** `systemauthsvc` builds the managed-principal service when the
  configuration enables managed principals and the deployment has a
  database, and mounts the API under `/managed-principals`. With managed
  principals off, the routes do not exist.
- **R2.** Requests authenticate with a bearer access token issued by this
  SystemAuth, active, naming a principal, and granted the scope
  `systemforge:managed_principals`.
- **R3.** Creating a managed principal over the API makes the caller its
  only initial manager, in a role the request names. Further managers join
  through the existing invitation and claim flows, which require their
  consent.
- **R4.** Creating a managed principal and issuing a login token require the
  token's client to allow managed principals; lifetimes follow the
  existing policy (request, client default, deployment default, ceiling).
- **R5.** Claim redemption and invitation acceptance are rate limited per
  caller, in addition to the codes' entropy.
- **R6.** Every write is audited through the deployment's audit emitter when
  one is configured.
- **R7.** `SystemAuth` built by `systemauthsvc` serves `POST /login-token`
  whenever managed principals are enabled.

## Success Criteria

- A relying party in another process creates a managed principal, issues a
  login token, and the token signs the principal in through
  `POST /login-token`, using only its SystemAuth client and the manager's
  access token.
- A token without the scope, from another issuer, or for a non-manager is
  refused, and the refusal does not reveal whether the principal exists.

## Risks

| Risk | Mitigation |
|---|---|
| An application acts for a manager who did not ask | The scope is granted per client and consented to like any other; the manager's own permissions bound every action |
| An application names another client to get its policy | The client is taken from the token; a different `client_id` in the body is refused |
| Enumeration of managed principals | Unknown, unmanaged, and forbidden principals answer alike (404 or 403 as today) |
| Guessing claim or invitation codes | 160-bit codes, single use, expiry, and a per-caller rate limit |
