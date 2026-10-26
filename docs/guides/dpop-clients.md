# Calling APIs with DPoP

SystemAuth and the `identity/oauth` provider issue DPoP-bound tokens
(RFC 9449) by default, and the SystemForge middlewares accept them only
with a proof by the key they are bound to. This guide is for the people
writing a client: a backend service, a CLI, a mobile app, or anything else
that gets tokens from SystemAuth and calls an API with them. The server
side is in [DPoP Enforcement](../session/dpop.md).

Browser applications behind the [BFF](../bff/overview.md) need nothing: the
BFF holds a key per session and sends the proofs.

## What changes for a client

| Step | With bearer tokens | With DPoP |
|---|---|---|
| Token request | `POST /oauth/token` | The same, plus a `DPoP` header carrying a proof |
| Token response | `token_type: Bearer` | `token_type: DPoP`; the token is bound to the proof's key |
| API call | `Authorization: Bearer <token>` | `Authorization: DPoP <token>` and a new `DPoP` proof on every request |
| Refresh | Refresh token alone | Refresh token and a proof by the same key |

A copied token is useless without the private key, so the key is the
secret to protect.

## Keep one key pair

Generate an elliptic-curve key pair (ES256, ES384 or ES512; discovery lists
them in `dpop_signing_alg_values_supported`) and use it for every request
of a session. Tokens and refresh tokens stay bound to it: a refresh with
another key is refused. Keep the key as long as its refresh token, and
store it with the same care. A new key needs new tokens: sign in or
request them again.

Every instance that shares a session (for example, replicas of a backend
that store tokens in a shared database) needs the same key.

## Build a proof

A proof is a JWT signed with the private key, sent in the `DPoP` header.

| Part | Value |
|---|---|
| Header `typ` | `dpop+jwt` |
| Header `alg` | `ES256` (or `ES384`, `ES512`) |
| Header `jwk` | The public key only; a proof whose `jwk` carries a private key is refused |
| `jti` | A new random identifier for every proof; a reused one is refused |
| `htm` | The request method, such as `POST` |
| `htu` | The request URL without query or fragment |
| `iat` | Now; a proof older than 5 minutes by default is refused |
| `ath` | Base64url SHA-256 of the access token, on API calls (not on the token request) |
| `nonce` | The server's nonce, when it asked for one |

Make a new proof for each request; a proof is accepted once.

## Get a token

Send the proof for `POST` at the token endpoint, the issuer plus
`/oauth/token` as discovery advertises it:

```http
POST /oauth/token HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic <client credentials>
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Li4ufX0...

grant_type=client_credentials&scope=reports:read
```

```json
{"access_token": "...", "token_type": "DPoP", "expires_in": 600}
```

This applies to every grant: `authorization_code`, `refresh_token` and
`client_credentials`. An authorization request may also name the key in
`dpop_jkt` (its RFC 7638 thumbprint), so that only a token request with a
proof by that key can redeem the code.

## Call an API

Present the token with the `DPoP` scheme and a new proof for that request,
carrying the token's hash in `ath`:

```http
GET /v1/reports?month=10 HTTP/1.1
Host: api.example.com
Authorization: DPoP <access token>
DPoP: <proof with htm=GET, htu=https://api.example.com/v1/reports, ath=...>
```

A bound token sent as `Bearer` is always refused. The `htu` is the URL the
client calls. When the API sits behind a proxy that changes the path, its
operator sets the external base URL on the server (`dpop.resource_base_url`
for SystemAuth, `DPoPConfig.BaseURL` in the middlewares); the client still
uses the URL it calls.

## Server nonces

SystemAuth may require a nonce it issued (`dpop.require_nonce`; the
`identity/oauth` provider has the same option). It then refuses a proof
without a current one and sends the nonce in a `DPoP-Nonce` response
header:

| Where | Response |
|---|---|
| Token endpoint | `400` with `"error": "use_dpop_nonce"` |
| SystemAuth's own endpoints, such as userinfo | `401` with `WWW-Authenticate: DPoP error="use_dpop_nonce"` |

Retry once with a new proof carrying that nonce, and keep using the latest
`DPoP-Nonce` the server sent. Nonces expire after 5 minutes by default.

## In Go

`github.com/grokify/goauth/dpop` makes the key and the proofs:

```go
key, err := dpop.GenerateKeyPair() // ES256
if err != nil {
	return err
}

// Token request: no access token, so no ath.
proof, err := dpop.CreateProof(key, http.MethodPost, "https://auth.example.com/oauth/token")

// API call: bind the proof to the token, and carry a nonce when asked.
proof, err = dpop.CreateProofWithOptions(key, http.MethodGet, "https://api.example.com/v1/reports",
	dpop.ProofOptions{AccessToken: accessToken, Nonce: nonce})
req.Header.Set("Authorization", "DPoP "+accessToken)
req.Header.Set("DPoP", proof)
```

`key.SerializeJSON` and `dpop.DeserializeKeyPairJSON` store and load the
key.

A relying party built on `identity/relyingparty` does all of this itself:
`relyingparty.Client` sends a proof by `Config.DPoPKey` with every token
request, presents tokens to SystemAuth with the `DPoP` scheme, and retries
once with a server nonce. Give every instance that shares sessions the same
`DPoPKey`; the default is a key generated per process.

## Errors

| Response | Cause | What to do |
|---|---|---|
| `400` `invalid_dpop_proof` at the token endpoint | No proof, or one that fails a check (signature, `htm`, `htu`, `iat`, replayed `jti`) | Send a new, correct proof |
| `400` `invalid_grant` | A refresh token or code bound to another key | Use the key the token was issued to |
| `401` at an API | No proof, a proof without `ath` or one that fails a check, a bound token sent as `Bearer`, or an unbound token where bearer tokens are not allowed. SystemAuth and `relyingparty.BearerMiddleware` name the cause in `WWW-Authenticate` (`invalid_dpop_proof` or `invalid_token`) | Send the token with the `DPoP` scheme and a new proof for this request |
| `use_dpop_nonce` | The server requires a nonce | Retry with the `DPoP-Nonce` value |

## Clients that cannot use DPoP yet

Unbound bearer tokens are a legacy exception, switched on in two places:

| Where | Setting |
|---|---|
| SystemAuth, per client | `allow_bearer_tokens: true` in the client's configuration (`ClientConfig.AllowBearerTokens`), or the `sf_oauth_apps.allow_bearer_tokens` column. The client may then omit the proof and gets `token_type: Bearer` |
| Each API that must accept them | `BearerConfig.AllowBearerTokens` (`identity/relyingparty`), `DPoPConfig.AllowBearer` (`session/middleware` and `multiapp.AuthMiddleware`), or the bearer-only `HTTPAuthBearer` variants |

```yaml
clients:
  - id: legacy-reporting
    type: confidential
    name: Legacy reporting job
    secret: ${LEGACY_REPORTING_SECRET}
    grant_types: [client_credentials]
    allow_bearer_tokens: true   # remove once the job sends DPoP proofs
```

A bearer token works for whoever holds a copy, so keep the list of such
clients short and move each to DPoP.

## The SCIM exception

SCIM tenant tokens are always sent with the `Bearer` scheme, because the
identity providers that call SCIM endpoints do not send DPoP proofs. They
are long random secrets bound to one organization and rotated N / N-1; see
[SCIM Provisioning](../identity/scim.md#why-scim-tokens-are-bearer-tokens).
