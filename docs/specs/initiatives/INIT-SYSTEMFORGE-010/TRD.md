# TRD — JWT Bearer Authorization Grant — Service Principals with Keypair Credentials

**Initiative:** `INIT-SYSTEMFORGE-010`

## Current State

- SystemAuth composes Fosite (v0.49) with the authorization-code, client
  credentials, refresh, introspection, revocation, PKCE, and OpenID Connect
  factories. The RFC 7523 factory is not registered.
- Fosite provides `compose.RFC7523AssertionGrantFactory` and the handler in
  `handler/rfc7523`, which needs storage implementing
  `rfc7523.RFC7523KeyStorage`: `GetPublicKey`, `GetPublicKeys`,
  `GetPublicKeyScopes` (each keyed by issuer, subject, and key ID),
  `IsJWTUsed`, and `MarkJWTUsedForTime`.
- Service principals are `Principal(type=service)` with a
  `ServicePrincipal` extension (`identity/principal`).
- Keypair credentials are `sf_credentials` rows of type `keypair` with a
  globally unique `key_id`, `key_algorithm`, PEM public key, scopes,
  expiry, active, and revoked flags (`identity/credential`
  `CreateKeypair`, `GetKeypairByKeyID`, `ListKeypairs`).
- `identity/clientassertion.JTIStore` records used assertion IDs in
  `sf_client_assertion_jtis` with Fosite's replay semantics.

## Design

### 1. Key storage adapter

A new type in `identity/systemauth` implementing `RFC7523KeyStorage` over
Ent:

- `GetPublicKey(ctx, issuer, subject, keyID)`: look up the keypair credential
  by `key_id`; require it active, unrevoked, and unexpired; load its
  principal and require type service, active, and `identifier == subject`;
  require `issuer == subject` (self-issued only). Parse the PEM public key
  into a `jose.JSONWebKey` with the stored algorithm and key ID. Any failure
  returns `fosite.ErrNotFound` so callers cannot distinguish missing from
  rejected keys.
- `GetPublicKeys(ctx, issuer, subject)`: the same checks for the principal,
  returning all of its usable keypair credentials as a JWK set (used when an
  assertion has no `kid`).
- `GetPublicKeyScopes`: the key's scopes intersected with the principal's
  `allowed_scopes`.
- `IsJWTUsed` and `MarkJWTUsedForTime`: delegate to
  `clientassertion.JTIStore` (`Valid` reports used as `ErrJTIKnown`).
- On a successful exchange, update the credential's `last_used_at` and
  `last_used_ip` through the existing credential service.

### 2. Server composition and configuration

- Register `compose.RFC7523AssertionGrantFactory` when
  `oauth.jwt_bearer.enabled` is true (default false).
- Configuration: `max_assertion_lifetime` (default 1h, mapped to Fosite's
  JWT max duration), `require_client_auth` (default false, mapped to the
  inverse of `GrantTypeJWTBearerCanSkipClientAuth`), `token_lifetime`
  (default 1h). `jti` and `iat` are required (Fosite's ID-optional and
  issued-date-optional settings off).
- The audience accepted is SystemAuth's token endpoint URL and issuer.
- Discovery adds the grant type to `grant_types_supported` when enabled.

### 3. Issued tokens

- Subject: the service principal's ID. No refresh token.
- Granted scopes: Fosite intersects requested scopes with
  `GetPublicKeyScopes`; when none are requested, grant all of them.
- Tokens are stored with the existing token storage, so introspection and
  revocation work unchanged.

### 4. Management

Keys are managed with the existing `identity/credential` API
(`CreateKeypair`, `ListKeypairs`, `Revoke`). This initiative documents the
flow rather than adding endpoints; admin endpoints are a follow-on if
needed.

### 5. Reference client

`identity/oauthclient` gains a helper that builds and signs an assertion
(RS256, ES256, EdDSA) from a private key and principal identifier and
exchanges it for a token, so workloads written in Go need no JWT code of
their own.

## Testing Strategy

- Adapter unit tests: unknown key, revoked, expired, inactive key; wrong
  principal type, inactive principal, subject or issuer mismatch; scope
  intersection; JTI delegation.
- End-to-end tests against an embedded SystemAuth: RSA and ECDSA keys
  exchange signed assertions for tokens that introspect as active with the
  expected subject and scopes; replay, expired assertion, overlong
  lifetime, missing `jti`, and wrong audience are rejected.
- Discovery reflects the enabled flag.

## Risks

- Fosite's key lookup is keyed by issuer and subject; enforcing that the
  key belongs to the subject must happen in the adapter, and is tested
  directly.
- PEM parsing of stored keys must accept the formats `CreateKeypair`
  writes; tests round-trip keys created through the credential service.
