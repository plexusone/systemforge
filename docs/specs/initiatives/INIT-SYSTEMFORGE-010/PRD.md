# PRD — JWT Bearer Authorization Grant — Service Principals with Keypair Credentials

**Initiative:** `INIT-SYSTEMFORGE-010`
**Status:** Draft
**Home repo:** `github.com/plexusone/systemforge`

## Problem

Machine-to-machine access to SystemAuth today uses the client-credentials
grant: a backend holds a client secret and exchanges it for a token. Shared
secrets have to be distributed, stored, and rotated on both sides, and a
leaked secret is immediately usable by anyone.

The RFC 7523 JWT-bearer grant lets a workload prove its identity with a
private key it never shares: it signs a short-lived assertion, and the
authorization server verifies it with the registered public key. SystemForge
documented this capability as "service accounts" but never implemented it,
and the tables it described have been removed (ADR-004). The building blocks
now exist on the principal model: service principals, keypair credentials,
and a store for used assertion IDs.

## Goals

1. **SystemAuth accepts the JWT-bearer grant** (`grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`)
   at the token endpoint and issues an access token for a service principal.
2. **Keys are keypair credentials** owned by the service principal, with
   their own scopes, expiry, and revocation.
3. **Assertions cannot be replayed**: every assertion carries a `jti`, and a
   used `jti` is rejected until the assertion would have expired.
4. **Least privilege**: a token's scopes are limited to what the key allows,
   the principal allows, and the request asks for.
5. **Documentation and a reference client** so a workload can be set up end
   to end.

## Non-Goals

- Assertions issued by third-party identity providers (`iss` different from
  the principal). This release accepts self-issued assertions only; a
  trusted-issuer registry is a follow-on.
- JWT client authentication (`private_key_jwt`, RFC 7523 section 2.2),
  which Fosite already supports through client keys and the existing
  assertion-ID store.
- Refresh tokens for this grant. Workloads sign a new assertion instead.
- Human principals using this grant.

## Users and Stakeholders

| Who | Needs |
|---|---|
| Platform operators | Register a service principal and its public keys, rotate and revoke keys, see when a key was last used |
| Workload developers | A documented assertion format and a small client to exchange an assertion for a token |
| Security reviewers | Replay protection, short assertion lifetimes, scoped tokens, and an audit trail |

## Requirements

### Functional

- **F1.** The token endpoint accepts the JWT-bearer grant and verifies the
  assertion signature with the keypair credential named by the assertion's
  `kid`.
- **F2.** The assertion's `iss` and `sub` must both equal the service
  principal's identifier, and the key must belong to that principal.
- **F3.** `aud` must name SystemAuth's token endpoint (or issuer); `exp` is
  required, `iat` and `jti` are required, and the assertion's lifetime may
  not exceed a configured maximum (default one hour).
- **F4.** A used `jti` is rejected until the assertion's `exp`.
- **F5.** The key and the principal must be active and unexpired, and the
  key unrevoked; the principal must be of type service.
- **F6.** Granted scopes are the requested scopes intersected with the
  key's scopes and the principal's allowed scopes; requesting no scopes
  grants the intersection of the key's and principal's scopes.
- **F7.** The issued access token's subject is the service principal's ID,
  and no refresh token is issued.
- **F8.** Successful exchanges update the key's last-used time.
- **F9.** Discovery advertises the grant type when it is enabled; it is
  disabled unless configured.

### Non-Functional

- **N1.** The grant uses Fosite's RFC 7523 handler; SystemForge supplies
  storage, not protocol code.
- **N2.** Failures return RFC 6749 errors without revealing whether a key
  or principal exists.
- **N3.** Unit tests cover every rejection rule; an end-to-end test signs
  real assertions with RSA and ECDSA keys.

## Success Criteria

- A service principal with a registered public key obtains a scoped access
  token by signing an assertion, and the token validates at a resource
  server.
- Replaying the same assertion fails; an expired, revoked, or wrong-subject
  key fails; scopes never exceed the key's or principal's.

## Risks

| Risk | Mitigation |
|---|---|
| Long-lived assertions widen the replay window | Required `jti`, bounded maximum lifetime, JTI store |
| Over-broad tokens | Scope intersection across request, key, and principal |
| Key sprawl | Keys carry expiry; last-used time makes unused keys visible |

## Open Questions

- Should the grant require client authentication in addition to the
  assertion? Proposed: no by default, since the signed assertion is the
  credential, with a configuration switch to require it.
- Should agents (principals of type agent) also be allowed to use the
  grant? Proposed: not in this release.
